from __future__ import annotations

import base64
import threading
from urllib.parse import urljoin, urlsplit

from selectolax.lexbor import LexborHTMLParser

# Redirect handling for the login entry point. Login bodies carry the actual
# credentials, so a redirect is followed only while it stays on the login URL's
# origin; a cross-origin Location is never contacted.
_REDIRECT_STATUSES = (301, 302, 303, 307, 308)
_MAX_REDIRECTS = 30
_DEFAULT_PORTS = {"http": 80, "https": 443}


def _origin(url: str):
    """Return ``(scheme, host, port)`` or ``None`` for an opaque URL."""
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
    left_origin = _origin(left)
    right_origin = _origin(right)
    if left_origin is None or right_origin is None:
        return left_origin == right_origin
    if left_origin == right_origin:
        return True
    # Same safe HTTP -> HTTPS default-port upgrade requests itself allows.
    return (
        left_origin[0] == "http"
        and right_origin[0] == "https"
        and left_origin[1] == right_origin[1]
        and left_origin[2] == 80
        and right_origin[2] == 443
    )


def _redirect_location(resp):
    """Return a redirect's Location value, or ``None`` if this is not one."""
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


def _resolve_redirect(location, resp, current_url: str):
    """Resolve a Location value to the next absolute HTTP(S) URL."""
    try:
        target = urljoin(getattr(resp, "url", None) or current_url, location)
    except ValueError:
        return None
    parts = urlsplit(target)
    try:
        host = parts.hostname
    except ValueError:
        return None
    if parts.scheme.lower() not in _DEFAULT_PORTS or not host:
        return None
    return target


class Authenticator:
    """Holds authentication state for a scan and applies it to requests.

    Supports HTTP Basic, static Bearer tokens, arbitrary extra headers, and
    form-based login (with optional CSRF-token extraction). Session cookies
    obtained at login live in the shared ``requests.Session`` cookie jar and
    are merged into every subsequent request by :class:`SingleRequest`.
    """

    def __init__(self, headers=None, login_url=None, login_data=None,
                 csrf_field=None, logged_in_check=None):
        self.headers = dict(headers or {})
        self.login_url = login_url
        self.login_data = dict(login_data or {})
        self.csrf_field = csrf_field
        self.logged_in_check = logged_in_check
        self._lock = threading.Lock()

    @classmethod
    def from_options(cls, *, basic=None, bearer=None, headers=None,
                     login_url=None, login_data=None, csrf_field=None,
                     logged_in_check=None):
        """Build an Authenticator from CLI-style options (or None if no auth)."""
        hdrs = {}
        for header in headers or []:
            if ":" in header:
                key, value = header.split(":", 1)
                hdrs[key.strip()] = value.strip()
        if basic:
            token = base64.b64encode(basic.encode()).decode()
            hdrs["Authorization"] = f"Basic {token}"
        if bearer:
            hdrs["Authorization"] = f"Bearer {bearer}"

        data = {}
        if login_data:
            for pair in login_data.split("&"):
                if "=" in pair:
                    key, value = pair.split("=", 1)
                    data[key] = value

        if not (hdrs or login_url):
            return None
        return cls(headers=hdrs, login_url=login_url, login_data=data,
                   csrf_field=csrf_field, logged_in_check=logged_in_check)

    @property
    def has_login(self):
        return bool(self.login_url)

    def _extract_csrf(self, session, verify, timeout):
        """GET the login page and pull the hidden CSRF token, if configured."""
        if not self.csrf_field:
            return {}
        try:
            resp = self._follow_same_origin(
                session, "GET", self.login_url, verify, timeout
            )
        except Exception:
            return {}
        if resp is None or getattr(resp, "status_code", None) in _REDIRECT_STATUSES:
            # A stopped redirect response (cross-origin Location or a
            # redirect-only body) is not the login form.
            return {}
        node = LexborHTMLParser(resp.text).css_first(
            f'input[name="{self.csrf_field}"]'
        )
        if node is not None:
            return {self.csrf_field: node.attributes.get("value", "") or ""}
        return {}

    @staticmethod
    def _request_once(session, method, url, verify, timeout, data=None):
        """Send one login-related request without letting requests redirect."""
        if method == "GET":
            return session.get(
                url, verify=verify, timeout=timeout, allow_redirects=False
            )
        if method == "HEAD":
            return session.head(
                url, verify=verify, timeout=timeout, allow_redirects=False
            )
        if method == "POST":
            return session.post(
                url,
                data=data,
                verify=verify,
                timeout=timeout,
                allow_redirects=False,
            )
        return session.request(
            method,
            url,
            data=data,
            verify=verify,
            timeout=timeout,
            allow_redirects=False,
        )

    def _follow_same_origin(self, session, method, url, verify, timeout,
                            data=None):
        """Follow login redirects only while they stay on ``url``'s origin.

        This keeps the existing form-login flow (including CSRF extraction and
        same-origin post-login redirects) while ensuring a cross-origin
        Location never receives the login body or the session's cookie jar.
        """
        history = []
        current_url = url
        current_method = str(method).upper()
        current_data = data

        for _ in range(_MAX_REDIRECTS + 1):
            resp = self._request_once(
                session, current_method, current_url, verify, timeout,
                data=current_data,
            )
            if resp is None:
                return None
            location = _redirect_location(resp)
            if location is None:
                resp.history = history
                return resp
            next_url = _resolve_redirect(location, resp, current_url)
            if next_url is None:
                return None
            if not _same_origin(current_url, next_url):
                # Stop on the redirect response. The Location host never sees
                # the login POST body, Authorization header, or cookies.
                resp.history = history
                return resp

            status = getattr(resp, "status_code", None)
            if status == 303 and current_method != "HEAD":
                current_method = "GET"
            elif status == 302 and current_method != "HEAD":
                current_method = "GET"
            elif status == 301 and current_method == "POST":
                current_method = "GET"
            if status not in (307, 308):
                current_data = None

            resp.history = list(history)
            history.append(resp)
            try:
                resp.content
                resp.close()
            except Exception:
                pass
            current_url = next_url

        return None

    def login(self, session, verify=False, timeout=None):
        """Perform the form login through the session (stores cookies)."""
        if not self.has_login:
            return None
        # Serialize concurrent logins (the attack phase is multi-threaded).
        with self._lock:
            data = dict(self.login_data)
            data.update(self._extract_csrf(session, verify, timeout))
            try:
                return self._follow_same_origin(
                    session, "POST", self.login_url, verify, timeout, data=data
                )
            except Exception:
                return None

    def looks_logged_out(self, resp):
        """True when a response suggests the session is no longer valid."""
        if resp is None or not (self.has_login and self.logged_in_check):
            return False
        return self.logged_in_check not in resp.text
