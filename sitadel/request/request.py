from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from http.cookiejar import CookieJar
from urllib.parse import urljoin, urlsplit, urlunsplit

import urllib3
from requests import ConnectionError, Request, RequestException, Session, Timeout
from requests.adapters import HTTPAdapter
from requests.cookies import RequestsCookieJar, create_cookie
from requests.utils import requote_uri

from sitadel.utils.container import Services
from . import ragent as ragent

# Sized to the attack phase's bounded thread pools so connections are reused.
_POOL_SIZE = 20

# Redirect status codes handled by the explicit hop-by-hop resolver below.
_REDIRECT_STATUSES = (301, 302, 303, 307, 308)

# Match requests' own redirect ceiling.
_MAX_REDIRECTS = 30

_DEFAULT_PORTS = {"http": 80, "https": 443}

# Headers that always carry authentication material. Authenticator headers
# (which can be an API key, a custom token header, ...) are added dynamically.
_BASE_SENSITIVE_HEADERS = {
    "auth",
    "authentication",
    "authorization",
    "proxy-authorization",
    "cookie",
    "cookie2",
}

_SENSITIVE_NAME_HINTS = (
    "authorization",
    "api-key",
    "apikey",
    "auth-token",
    "access-token",
    "csrf",
    "secret",
    "session",
    "session-token",
    "token",
)

_COOKIE_ATTRIBUTES = {
    "comment",
    "domain",
    "expires",
    "httponly",
    "max-age",
    "path",
    "samesite",
    "secure",
    "version",
}


def _origin(url: str) -> tuple[str, str, int] | None:
    """Return a normalized ``(scheme, host, port)`` origin for ``url``.

    ``None`` means the URL has no parseable absolute origin (for example a
    relative URL or the bare ``test`` string used by legacy unit tests). Two
    opaque values share a credential scope; an opaque/absolute pair does not.
    """
    parts = urlsplit(url or "")
    scheme = (parts.scheme or "").lower()
    try:
        host = (parts.hostname or "").lower()
    except ValueError:
        return None
    if scheme not in _DEFAULT_PORTS or not host:
        return None
    try:
        port = parts.port
    except ValueError:
        return None
    if port is None:
        port = _DEFAULT_PORTS[scheme]
    return scheme, host, port


def _same_origin(left: str, right: str) -> bool:
    """Whether two URLs share a credential origin.

    The one intentional exception mirrors ``requests``: an HTTP -> HTTPS
    upgrade on the same host using the standard ports keeps credentials,
    because the request is only becoming safer.
    """
    left_origin = _origin(left)
    right_origin = _origin(right)
    if left_origin is None or right_origin is None:
        # Only two opaque URLs can safely share a credential scope; if just
        # one side is unparseable, do not attach credentials to the other.
        return left_origin == right_origin
    if left_origin == right_origin:
        return True
    return (
        left_origin[0] == "http"
        and right_origin[0] == "https"
        and left_origin[1] == right_origin[1]
        and left_origin[2] == 80
        and right_origin[2] == 443
    )


def _cookie_domain(host: str) -> str:
    """Return the domain a host-only cookie should be stored under.

    ``http.cookiejar`` treats a dotless host such as ``localhost`` as
    ``localhost.local``; using the bare name in a CookieJar would silently
    drop the cookie. IP literals (including IPv6) are used verbatim.
    """
    host = (host or "").lower()
    if not host or "." in host or ":" in host:
        return host
    return host + ".local"


def _normalize_localhost_cookies(jar, host: str):
    """Rewrite dotless-host cookies to the effective ``host.local`` domain.

    ``CookieJar`` itself stores host-only cookies for ``localhost`` as
    ``localhost.local``; a jar created by hand with ``domain="localhost"`` would
    otherwise be silently dropped even on the same host.
    """
    effective = _cookie_domain(host)
    if not host or effective == host:
        return jar
    for cookie in list(jar):
        domain = (cookie.domain or "").lower()
        if domain.lstrip(".") != host:
            continue
        try:
            jar.clear(cookie.domain, cookie.path, cookie.name)
        except KeyError:
            pass
        cookie.domain = effective
        cookie.domain_initial_dot = False
        jar.set_cookie(cookie)
    return jar


def _bind_domainless_cookies(jar, host: str):
    """Pin cookies without a domain to ``host``.

    ``RequestsCookieJar.set(name, value)`` creates a domainless cookie that
    cookies' policy treats as valid for *every* host. Bind such cookies to the
    transaction host so they can never become cross-origin supercookies.
    """
    domain = _cookie_domain(host)
    if not domain:
        return jar
    for cookie in list(jar):
        if (cookie.domain or "").strip():
            continue
        try:
            jar.clear(cookie.domain, cookie.path, cookie.name)
        except KeyError:
            pass
        cookie.domain = domain
        cookie.domain_initial_dot = False
        jar.set_cookie(cookie)
    return jar


def _url_in_scope(url: str, scope_hosts, scope_netlocs) -> bool:
    """Whether ``url``'s host is in scope. Empty scope => unrestricted."""
    if not scope_hosts:
        return True
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
    except ValueError:
        # No parseable host (relative/opaque) is treated as in-scope — it can
        # only resolve against the in-scope base.
        return True
    if not host:
        return True
    netloc = (parts.netloc or "").lower()
    return (
        host in scope_hosts
        or netloc in scope_hosts
        or netloc in scope_netlocs
    )


@dataclass
class _OriginTransaction:
    """One send call and every redirect hop it is allowed to make.

    The credential origin is the host/scheme/port of the URL the caller asked
    for. Authentication headers, caller-supplied cookies and the shared session
    cookie jar are only applied while a hop stays on that origin. Scope is
    checked separately for every hop, so an explicitly scoped host may still be
    visited -- just without credentials.
    """

    url: str
    method: str
    payload: object
    headers: dict | None
    cookies: object
    scope_hosts: frozenset
    scope_netlocs: frozenset

    def allows_credentials(self, url: str) -> bool:
        """Credentials are bound to the transaction's original origin."""
        return _same_origin(self.url, url)

    def in_scope(self, url: str) -> bool:
        return _url_in_scope(url, self.scope_hosts, self.scope_netlocs)


class _RateLimiter:
    """Global request spacer: at most ``rate`` requests/second across all threads.

    ``rate <= 0`` disables it (``acquire`` is a no-op), preserving full throughput.
    Each caller reserves the next time slot under a short lock, then sleeps outside
    the lock until the slot — so N worker threads are paced to one request every
    ``1/rate`` seconds without serializing the lock during the wait.
    """

    def __init__(self, rate: float):
        self.rate = float(rate or 0)
        self._interval = 1.0 / self.rate if self.rate > 0 else 0.0
        self._lock = threading.Lock()
        self._next = 0.0

    def acquire(self) -> None:
        if self._interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            slot = max(self._next, now)
            self._next = slot + self._interval
        wait = slot - time.monotonic()
        if wait > 0:
            time.sleep(wait)


class SingleRequest:
    def __init__(
        self,
        url: str | None = None,
        agent: str = "Sitadel",
        proxy: str | None = None,
        redirect: bool = True,
        timeout: int | None = None,
        random_agent: bool = False,
        verify: bool = False,
        rate_limit: float = 0.0,
        scope_hosts: set | list | None = None,
    ):
        self.url = url
        self.agent = agent
        self.proxy = proxy
        self.redirect = redirect
        self.timeout = timeout
        self.random_agent = random_agent
        self.verify = verify
        # Optional authentication context (headers + a shared cookie jar).
        self.authenticator = None

        # Global rate limiter shared by every request this factory sends.
        self.rate_limit = float(rate_limit or 0)
        self._limiter = _RateLimiter(self.rate_limit)

        # In-scope hosts. Defaults to the target's host so probes (and followed
        # redirects) never wander off-target; an empty set means "unrestricted"
        # (used by direct, url-less construction in tests). Explicit extra hosts
        # are added for multi-host targets.
        hosts = set()
        netlocs = set()
        if isinstance(scope_hosts, str):
            scope_hosts = [scope_hosts]
        for raw_host in (scope_hosts or []):
            if raw_host is None:
                continue
            text = str(raw_host).strip().lower().rstrip("/")
            if not text:
                continue
            try:
                if "://" in text:
                    parsed = urlsplit(text)
                    text = (parsed.netloc or "").lower()
                else:
                    parsed = urlsplit("//" + text)
            except ValueError:
                continue
            try:
                host = (parsed.hostname or "").lower()
            except ValueError:
                host = ""
            try:
                pinned_port = parsed.port
            except ValueError:
                pinned_port = None
            # A bare host means "any port on this host"; host:port (or a full
            # URL with a port) pins the exact netloc.
            if host and pinned_port is None:
                hosts.add(host)
            if text:
                netlocs.add(text)
        if url:
            try:
                target_host = urlsplit(url).hostname
            except ValueError:
                target_host = None
            if target_host:
                hosts.add(target_host.lower())
        self.scope_hosts = hosts
        # ``scope_hosts`` entries may pin a specific port (``host:8443`` or a
        # full URL); keep the exact netloc too so an explicit destination is
        # honored while a bare host still means "any port on that host".
        self.scope_netlocs = netlocs

        # Reuse one pooled session (keep-alive) across every request instead of
        # opening a fresh TCP/TLS connection per call.
        self.session = Session()
        adapter = HTTPAdapter(pool_connections=_POOL_SIZE, pool_maxsize=_POOL_SIZE)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        if not self.verify:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def _in_scope(self, url: str) -> bool:
        """Whether ``url``'s host is in scope. Empty scope => unrestricted."""
        return _url_in_scope(
            url, self.scope_hosts, getattr(self, "scope_netlocs", set())
        )

    def set_authenticator(self, authenticator):
        self.authenticator = authenticator

    def login(self):
        """Run the configured login flow, populating the session cookie jar."""
        if self.authenticator is not None and self.authenticator.has_login:
            return self.authenticator.login(self.session, self.verify, self.timeout)
        return None

    def send(self, url, method="GET", payload=None, headers=None, cookies=None,
             allow_redirects=None, _retry=True):
        output = Services.get("output")
        # ``allow_redirects`` defaults to the instance's ``redirect`` setting;
        # callers pass ``False`` to inspect a redirect (e.g. the open-redirect
        # check reads the Location header without following it off-site).
        follow = self.redirect if allow_redirects is None else allow_redirects
        # Scope gate: never initiate a request to an out-of-scope host (the
        # destination is what matters — an SSRF/open-redirect payload points
        # inward but the request itself still targets the in-scope host).
        if not self._in_scope(url):
            output.debug("Skipping out-of-scope request: %s" % url)
            return None

        transaction = _OriginTransaction(
            url=url,
            method=method,
            payload=payload,
            headers=headers,
            cookies=cookies,
            scope_hosts=frozenset(self.scope_hosts),
            scope_netlocs=frozenset(getattr(self, "scope_netlocs", set())),
        )
        # Real requests sessions get the explicit hop-by-hop resolver: letting
        # requests follow redirects itself is what leaked auth to the Location
        # host before the final response was discarded. Non-Session test doubles
        # keep the historical pass-through contract (their send() records the
        # allow_redirects value and does not create a real network destination).
        # ``issubclass(type(...))`` (rather than ``isinstance``) deliberately
        # does not treat ``Mock(spec=Session)`` as a live transport: test
        # doubles keep the historical pass-through path below.
        if issubclass(type(self.session), Session):
            resp = self._send_transaction(transaction, follow)
        else:
            resp = self._send_legacy(transaction, follow)

        if resp is None:
            return None
        # Defense in depth: a custom adapter/session could still hand back a
        # response whose URL wandered off-scope. Never let that content feed
        # detection.
        final_url = getattr(resp, "url", None) or url
        if self.scope_hosts and not (
            self._in_scope(final_url) and transaction.in_scope(final_url)
        ):
            output.debug("Discarding out-of-scope redirect to %s" % final_url)
            return None
        # If the session dropped (login page returned), re-authenticate once
        # and retry so a mid-scan session expiry doesn't silently degrade to
        # unauthenticated requests.
        is_redirect = self._redirect_location(resp) is not None
        if _retry and self.authenticator is not None \
                and _same_origin(url, final_url) \
                and not is_redirect \
                and self.authenticator.looks_logged_out(resp):
            self.authenticator.login(self.session, self.verify, self.timeout)
            return self.send(url, method, payload, headers, cookies,
                             allow_redirects=allow_redirects, _retry=False)
        return resp

    # ------------------------------------------------------------------ #
    # Redirect-safe origin transaction
    # ------------------------------------------------------------------ #
    def _sensitive_header_names(self) -> set:
        names = set(_BASE_SENSITIVE_HEADERS)
        if self.authenticator is not None:
            names.update(
                str(name).strip().lower()
                for name in getattr(self.authenticator, "headers", {})
            )
        return names

    def _is_sensitive_header(self, name) -> bool:
        """Whether ``name`` carries authentication material.

        Anything configured on the Authenticator is sensitive by definition;
        common token/API-key header names are recognized as well so a per-call
        ``Authorization``/``X-Api-Key`` is not forwarded across an origin
        boundary either.
        """
        text = str(name or "").strip().lower()
        if not text:
            return False
        if text in self._sensitive_header_names():
            return True
        compact = text.replace("_", "-")
        if compact.startswith("x-") and any(
            hint in compact
            for hint in ("auth", "token", "secret", "key", "session", "csrf")
        ):
            return True
        return any(hint in compact for hint in _SENSITIVE_NAME_HINTS)

    def _strip_sensitive_headers(self, headers) -> dict:
        return {
            name: value
            for name, value in (headers or {}).items()
            if not self._is_sensitive_header(name) and str(name).lower() != "host"
        }

    def _cookie_jar(self, url, cookies, *, include_session=True):
        """Build a domain-preserving jar for one hop.

        The old implementation flattened the session jar into a plain dict.
        ``requests`` turns such dict cookies into domainless cookies, which are
        then sent to *every* redirect host. Passing a real CookieJar keeps each
        cookie's domain/path, and caller-supplied cookies are pinned to the
        current URL's host.
        """
        jar = RequestsCookieJar()
        if include_session:
            session_jar = getattr(self.session, "cookies", None)
            if isinstance(session_jar, CookieJar):
                try:
                    jar.update(session_jar)
                except Exception:
                    pass

        try:
            host = (urlsplit(url).hostname or "").lower()
        except ValueError:
            host = ""
        target_host = host
        if self.url:
            try:
                target_host = (
                    urlsplit(self.url).hostname or host
                ).lower()
            except ValueError:
                target_host = host
        if include_session:
            _bind_domainless_cookies(jar, target_host)
        _normalize_localhost_cookies(jar, host)
        if cookies is None:
            return jar
        if isinstance(cookies, CookieJar):
            try:
                jar.update(cookies)
            except Exception:
                pass
            _bind_domainless_cookies(jar, host)
            _normalize_localhost_cookies(jar, host)
            return jar
        if isinstance(cookies, str):
            raw = cookies.strip()
            if raw.lower().startswith("cookie:"):
                raw = raw.split(":", 1)[1].strip()
            pairs = []
            for part in raw.split(";"):
                if "=" not in part:
                    continue
                name, value = part.split("=", 1)
                name = name.strip()
                if (
                    name
                    and not name.startswith("$")
                    and name.lower() not in _COOKIE_ATTRIBUTES
                ):
                    pairs.append((name, value.strip()))
        else:
            try:
                pairs = list(dict(cookies).items())
            except Exception:
                pairs = []

        domain = _cookie_domain(host)
        if not domain:
            # A relative/opaque URL cannot establish a cookie domain safely.
            return jar
        for name, value in pairs:
            try:
                jar.set_cookie(
                    create_cookie(
                        str(name), str(value), domain=domain, path="/"
                    )
                )
            except Exception:
                continue
        return jar

    def _trace_request(self, method, url, payload, prepped):
        # File-only trace of every network destination. Sensitive header names
        # are recorded (never their values) so a scan log shows exactly which
        # credential material was attached to each hop.
        sensitive = sorted(
            {
                str(name)
                for name in prepped.headers
                if self._is_sensitive_header(name)
            }
        )
        Services.get("output").trace(
            "REQUEST %s %s%s sensitive=%s"
            % (
                str(method).upper(),
                url,
                f" data={payload}" if payload else "",
                ",".join(sensitive) or "-",
            )
        )

    def _send_legacy(self, transaction, follow):
        """Historical pass-through path for non-``requests.Session`` doubles."""
        output = Services.get("output")
        prepped = self.prepare_request(
            transaction.url,
            transaction.method,
            transaction.payload,
            transaction.headers,
            transaction.cookies,
        )
        self._trace_request(
            transaction.method, transaction.url, transaction.payload, prepped
        )
        self._limiter.acquire()
        try:
            return self.session.send(
                prepped,
                timeout=self.timeout,
                proxies={"http": self.proxy, "https": self.proxy, "ftp": self.proxy},
                allow_redirects=follow,
                verify=self.verify,
            )
        except Timeout:
            output.error(f"Timeout error on the URL: {transaction.url}")
        except ConnectionError as err:
            output.error(f"Connection error on the URL: {transaction.url}\n {err}\n")
        except RequestException as err:
            output.error(f"Error while trying to contact the website:\n {err}\n")
        return None

    def _send_transaction(self, transaction, follow):
        """Resolve every redirect hop inside one origin transaction.

        Before each hop:
          * the destination host must be in scope;
          * credentials are attached only when the hop is on the transaction's
            original origin.
        A cross-origin Location is therefore never contacted with the
        Authorization/cookie material, and an off-scope Location is not
        contacted at all.
        """
        output = Services.get("output")
        current_url = transaction.url
        current_method = str(transaction.method).upper()
        current_payload = transaction.payload
        current_headers = dict(transaction.headers or {})
        current_cookies = transaction.cookies
        history = []

        for _ in range(_MAX_REDIRECTS + 1):
            if not self._in_scope(current_url) or not transaction.in_scope(
                current_url
            ):
                output.debug("Skipping out-of-scope request: %s" % current_url)
                return None

            credentials = transaction.allows_credentials(current_url)
            hop_headers = current_headers
            if not credentials:
                hop_headers = self._strip_sensitive_headers(hop_headers)

            try:
                prepped = self.prepare_request(
                    current_url,
                    current_method,
                    current_payload,
                    hop_headers,
                    current_cookies if credentials else None,
                    include_auth=credentials,
                )
            except RequestException:
                if current_url == transaction.url:
                    # Preserve the historical contract for the caller's own
                    # URL (e.g. MissingSchema for a relative target).
                    raise
                # A malformed redirect target is handled like any other
                # unusable hop: report it and stop the transaction.
                output.error("Invalid redirect target: %s" % current_url)
                return None
            self._trace_request(
                current_method, current_url, current_payload, prepped
            )
            self._limiter.acquire()
            try:
                resp = self.session.send(
                    prepped,
                    timeout=self.timeout,
                    proxies={
                        "http": self.proxy,
                        "https": self.proxy,
                        "ftp": self.proxy,
                    },
                    allow_redirects=False,
                    verify=self.verify,
                )
            except Timeout:
                # Never retry a timed-out hop: the safest point to stop is
                # before another Location can be followed.
                output.error(f"Timeout error on the URL: {current_url}")
                return None
            except ConnectionError as err:
                output.error(
                    f"Connection error on the URL: {current_url}\n {err}\n"
                )
                return None
            except RequestException as err:
                output.error(
                    "Error while trying to contact the website:\n %s\n" % err
                )
                return None
            if resp is None:
                return None

            if not follow:
                resp.history = history
                return resp

            location = self._redirect_location(resp)
            if location is None:
                resp.history = history
                return resp
            next_url = self._redirect_target(location, resp, current_url)
            if next_url is None:
                # The response asked for a redirect we cannot safely resolve
                # (non-HTTP scheme, missing host, ...). Treat it like requests'
                # handled InvalidURL/InvalidSchema: no response for detection.
                return None

            if not self._in_scope(next_url) or not transaction.in_scope(next_url):
                output.debug("Skipping out-of-scope redirect to %s" % next_url)
                return None

            next_method, next_payload, next_headers = self._redirect_request(
                resp, current_method, current_payload, current_headers
            )
            next_credentials = transaction.allows_credentials(next_url)
            if not next_credentials:
                # A Location may embed credentials in its userinfo. requests
                # would turn those into an Authorization header on the new
                # origin, so drop userinfo on cross-origin hops.
                next_url = self._without_userinfo(next_url)
            if not next_credentials and self._has_body(next_payload):
                # 307/308 preserve the body. Forwarding it across an origin
                # boundary could leak credentials (a login body, an API token
                # in a JSON field, ...), so stop with the redirect response.
                output.debug(
                    "Not forwarding request body across origin to %s" % next_url
                )
                return None

            resp.history = list(history)
            history.append(resp)
            try:
                resp.content  # consume so the connection can be released
                resp.close()
            except Exception:
                pass

            current_url = next_url
            current_method = next_method
            current_payload = next_payload
            current_headers = next_headers

        output.error("Too many redirects while contacting %s" % transaction.url)
        return None

    @staticmethod
    def _has_body(payload) -> bool:
        return payload not in (None, "", b"", {}, [])

    @staticmethod
    def _without_userinfo(url):
        parts = urlsplit(url)
        if parts.username is None and parts.password is None:
            return url
        host = parts.hostname or ""
        if ":" in host:
            host = f"[{host}]"
        netloc = host
        try:
            port = parts.port
        except ValueError:
            return url
        if port is not None:
            netloc += f":{port}"
        return urlunsplit(
            (parts.scheme, netloc, parts.path, parts.query, parts.fragment)
        )

    @staticmethod
    def _redirect_location(resp):
        """Return a redirect's Location header, or ``None`` if not a redirect."""
        status = getattr(resp, "status_code", None)
        if status not in _REDIRECT_STATUSES:
            return None
        headers = getattr(resp, "headers", None) or {}
        location = headers.get("Location") if hasattr(headers, "get") else None
        if location is None and hasattr(headers, "items"):
            for name, value in headers.items():
                if str(name).lower() == "location":
                    location = value
                    break
        if not location:
            return None
        if isinstance(location, bytes):
            location = location.decode("latin-1")
        location = str(location).strip()
        return location or None

    @staticmethod
    def _redirect_target(location, resp, current_url):
        """Resolve a Location value to the next absolute HTTP(S) URL."""
        try:
            target = urljoin(
                getattr(resp, "url", None) or current_url, location
            )
        except ValueError:
            return None
        parts = urlsplit(target)
        try:
            host = parts.hostname
        except ValueError:
            return None
        if parts.scheme.lower() not in _DEFAULT_PORTS or not host:
            return None
        try:
            return requote_uri(target)
        except Exception:
            return None

    @staticmethod
    def _redirect_request(resp, method, payload, headers):
        """Apply requests'/browser method rules for a redirect hop."""
        status = getattr(resp, "status_code", None)
        method = str(method).upper()
        next_headers = dict(headers or {})
        if status == 303 and method != "HEAD":
            method = "GET"
        elif status == 302 and method != "HEAD":
            method = "GET"
        elif status == 301 and method == "POST":
            method = "GET"
        if status not in (307, 308):
            payload = None
            entity_headers = {"content-length", "content-type", "transfer-encoding"}
            next_headers = {
                name: value
                for name, value in next_headers.items()
                if str(name).lower() not in entity_headers
            }
        return method, payload, next_headers

    def prepare_request(self, url, method, payload, headers, cookies,
                        *, include_auth=True):
        payload = payload or {}
        headers = dict(headers or {})
        if include_auth:
            # Start from the authentication headers (e.g. Authorization) so
            # every request carries them, then layer per-call headers on top.
            auth_headers = (
                dict(self.authenticator.headers) if self.authenticator else {}
            )
            auth_headers.update(headers)
            headers = auth_headers
            cookies = self._cookie_jar(url, cookies, include_session=True)
        else:
            # Cross-origin hop: no authenticator headers, no caller cookie
            # material and no shared session cookies.
            headers = self._strip_sensitive_headers(headers)
            cookies = None

        headers["User-Agent"] = (
            ragent.RandomUserAgent() if self.random_agent else self.agent
        )

        method = method.upper()
        # GET carries no body; every other method forwards the payload as data.
        match method:
            case "GET":
                request = Request(
                    method=method, url=url, headers=headers, cookies=cookies
                )
            case _:
                request = Request(
                    method=method,
                    url=url,
                    data=payload,
                    headers=headers,
                    cookies=cookies,
                )
        return request.prepare()
