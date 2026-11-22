"""One coherent authorization-comparison transaction.

An authorization finding is only as trustworthy as the set of requests behind
it.  A session can be refreshed between two probes, an anonymous request can
follow a redirect to the login page, or a response can belong to a different
object id after a retry.  This module keeps the object URL, session generation,
every response and the final origin together, and refuses to compare a
transaction that crossed any of those boundaries.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable
from urllib.parse import urlsplit

from sitadel.request.request import SingleRequest

from .idutils import (
    canonical_url,
    looks_like_login_body,
    looks_like_login_url,
    response_status,
    response_text,
    response_url,
    same_object_url,
    soft_404_miss,
    url_origin,
)


def session_generation(sender) -> Any:
    """Return a sender's session generation, if it exposes one.

    ``Authenticator.generation`` is the canonical source.  Reading it through
    the request factory keeps test doubles and future request implementations
    working too, and ``None`` simply means "this sender has no auth session".
    """
    if sender is None:
        return None
    for name in ("session_generation", "generation"):
        value = getattr(sender, name, None)
        if callable(value):
            try:
                value = value()
            except TypeError:
                value = None
        if value is not None:
            return value
    authenticator = getattr(sender, "authenticator", None)
    if authenticator is not None:
        for name in ("generation", "session_generation"):
            value = getattr(authenticator, name, None)
            if value is not None:
                return value
    return None


@dataclass(frozen=True)
class ProbeSpec:
    """One request inside a comparison transaction."""

    role: str
    url: str
    sender: Any
    authenticated: bool = False
    required: bool = True
    expected_url: str | None = None
    strict_object: bool = True
    allow_redirects: bool | None = None


@dataclass
class ResponseSnapshot:
    """The parts of a response that the comparison is allowed to use."""

    role: str
    requested_url: str
    status_code: int
    final_url: str
    body: str
    session_generation: Any
    redirected: bool
    same_object: bool
    response: Any = field(default=None, repr=False, compare=False)

    @property
    def origin(self) -> str:
        return url_origin(self.final_url)

    @property
    def status(self) -> int:
        return self.status_code

    @property
    def url(self) -> str:
        return self.final_url

    @property
    def generation(self):
        return self.session_generation

    @property
    def text(self) -> str:
        """Alias used by the shared soft-404 helper."""
        return self.body


class ComparisonTransaction:
    """The immutable context of one authorization comparison.

    The transaction is deliberately stateful while probes run so that every
    response is validated against the *same* object URL, session generation
    and final origin.  ``committed`` is set only after all required probes
    succeeded.
    """

    def __init__(
        self,
        object_url: str,
        *,
        session_generation: Any = None,
        session_generation_value: Any = None,
        attempt: int = 1,
        authenticator=None,
        owner=None,
    ):
        self.object_url = object_url
        self.session_generation = (
            session_generation_value
            if session_generation_value is not None
            else session_generation
        )
        self.attempt = attempt
        self.authenticator = authenticator
        self.owner = owner
        self.responses: dict[str, ResponseSnapshot] = {}
        self.failures: list[str] = []
        self.optional_failures: dict[str, str] = {}
        self.final_origin: str | None = None
        self.final_origins: set[str] = set()
        self.refresh_observed = False
        self.valid = True
        self.committed = False
        self.reason: str | None = None

    @property
    def generation(self):
        """Short alias for :attr:`session_generation`."""
        return self.session_generation

    # ------------------------------------------------------------------ #
    # Response accessors
    # ------------------------------------------------------------------ #
    @property
    def authed(self) -> ResponseSnapshot | None:
        return self.responses.get("authed") or self.responses.get("base")

    @property
    def base(self) -> ResponseSnapshot | None:
        return self.responses.get("base") or self.responses.get("authed")

    @property
    def anonymous(self) -> ResponseSnapshot | None:
        return self.responses.get("anonymous")

    @property
    def anon(self) -> ResponseSnapshot | None:
        return self.anonymous

    @property
    def neighbor(self) -> ResponseSnapshot | None:
        return self.responses.get("neighbor")

    @property
    def neighbour(self) -> ResponseSnapshot | None:
        return self.neighbor

    @property
    def soft404_object(self) -> ResponseSnapshot | None:
        return self.responses.get("soft404_object")

    @property
    def soft404_path(self) -> ResponseSnapshot | None:
        return self.responses.get("soft404_path")

    @property
    def soft404(self) -> ResponseSnapshot | None:
        return self.soft404_object or self.soft404_path

    def is_soft_miss(self, role: str) -> bool:
        """Whether ``role``'s 200 response is a soft-404/error page."""
        record = self.responses.get(role)
        if record is None or record.status_code != 200:
            return False
        return soft_404_miss(
            record.body, self.soft404_object, self.soft404_path
        )

    # ------------------------------------------------------------------ #
    # Probing
    # ------------------------------------------------------------------ #
    def _reject(
        self,
        reason: str,
        *,
        required: bool,
        role: str,
        refresh: bool = False,
    ) -> None:
        self.failures.append("%s: %s" % (role, reason))
        if refresh:
            self.refresh_observed = True
        if required or refresh:
            if self.valid:
                self.reason = reason
            self.valid = False
        else:
            self.optional_failures[role] = reason

    def probe(self, spec: ProbeSpec) -> Any:
        """Send one probe and validate it against this transaction."""
        if not self.valid:
            return None

        # A refresh can happen between probes too (another worker using the
        # same request factory, or a server-side session rotation).  Check the
        # owning request factory before every probe, not only before the next
        # authenticated request.
        owner_generation = (
            session_generation(self.owner)
            if self.owner is not None else None
        )
        if (
            self.session_generation is not None
            and owner_generation is not None
            and owner_generation != self.session_generation
        ):
            self._reject(
                "session-generation-advanced",
                required=spec.required,
                role=spec.role,
                refresh=True,
            )
            return None

        before = session_generation(spec.sender)
        if (
            spec.authenticated
            and self.session_generation is not None
            and before != self.session_generation
        ):
            self._reject(
                "session-generation-advanced",
                required=spec.required,
                role=spec.role,
                refresh=True,
            )
            return None

        kwargs = {"url": spec.url, "method": "GET"}
        if spec.allow_redirects is not None:
            kwargs["allow_redirects"] = spec.allow_redirects
        try:
            response = spec.sender.send(**kwargs)
        except Exception as err:
            self._reject(
                "request-error: %s" % err,
                required=spec.required,
                role=spec.role,
            )
            return None

        after = session_generation(spec.sender)
        if before != after:
            # The response may be perfectly valid, but it was produced by a
            # different session generation than the other probes.  Never mix
            # them; the caller can retry the whole transaction.
            self._reject(
                "session-refresh",
                required=spec.required,
                role=spec.role,
                refresh=True,
            )
            return response

        if response is None:
            self._reject(
                "no-response", required=spec.required, role=spec.role
            )
            return None

        status = response_status(response)
        final_url = response_url(response, spec.url)
        expected_url = spec.expected_url or spec.url

        target_host = urlsplit_host(self.object_url)
        final_host = urlsplit_host(final_url)
        if target_host and final_host and target_host != final_host:
            self._reject(
                "final-origin-changed",
                required=spec.required,
                role=spec.role,
            )
            return response

        final_origin = url_origin(final_url)
        if not allowed_final_origin(self.object_url, final_url):
            self._reject(
                "final-origin-changed",
                required=spec.required,
                role=spec.role,
            )
            return response
        if self.final_origin is None:
            self.final_origin = final_origin
        elif final_origin != self.final_origin:
            self._reject(
                "final-origin-changed",
                required=spec.required,
                role=spec.role,
            )
            return response
        if final_origin:
            self.final_origins.add(final_origin)

        same_object = same_object_url(expected_url, final_url)
        redirected = (
            canonical_url(final_url) != canonical_url(expected_url)
            or bool(getattr(response, "history", None))
        )
        if spec.strict_object and not same_object:
            reason = (
                "login-redirect"
                if looks_like_login_url(final_url)
                else "redirected-object"
            )
            self._reject(
                reason, required=spec.required, role=spec.role
            )
            return response

        # A response that came from a retry for another object must never be
        # paired with this one.  ``requests`` keeps the prepared request on
        # the response; test doubles are allowed to omit it.
        sent_url = getattr(getattr(response, "request", None), "url", None)
        if sent_url and not (
            same_object_url(expected_url, sent_url)
            or same_object_url(final_url, sent_url)
        ):
            self._reject(
                "response-from-other-object",
                required=spec.required,
                role=spec.role,
            )
            return response

        body = response_text(response)
        if self._is_login_response(response, final_url, body, spec.role):
            self._reject(
                "login-page", required=spec.required, role=spec.role
            )
            return response

        self.responses[spec.role] = ResponseSnapshot(
            role=spec.role,
            requested_url=spec.url,
            status_code=status,
            final_url=final_url,
            body=body,
            session_generation=after,
            redirected=redirected,
            same_object=same_object,
            response=response,
        )
        return response

    def _is_login_response(self, response, final_url, body, role) -> bool:
        if looks_like_login_url(final_url):
            return True
        # The soft-404 baseline is expected to be absent from the logged-in
        # surface; a missing canary there does not mean the object probe hit a
        # login page.
        if not role.startswith("soft404") and self.authenticator is not None:
            checker = getattr(self.authenticator, "looks_logged_out", None)
            if callable(checker):
                try:
                    # Use an identity check so a loose test double/mock does
                    # not turn every response into a login page.
                    if checker(response) is True:
                        return True
                except Exception:
                    pass
        if looks_like_login_body(body):
            return True
        for hop in getattr(response, "history", None) or ():
            location = ""
            headers = getattr(hop, "headers", None) or {}
            try:
                location = headers.get("location") or headers.get("Location")
            except AttributeError:
                location = None
            if location and looks_like_login_url(location):
                return True
        return False

    # ------------------------------------------------------------------ #
    # Evidence
    # ------------------------------------------------------------------ #
    @staticmethod
    def _record_text(record: ResponseSnapshot) -> str:
        generation = (
            "n/a" if record.session_generation is None
            else str(record.session_generation)
        )
        return "%s@%s gen=%s" % (
            record.status_code, record.final_url, generation
        )

    def evidence(self, *, decision: str | None = None, extra=None) -> str:
        """Stable, report-safe evidence for the *committed* transaction."""
        generation = (
            "n/a" if self.session_generation is None
            else str(self.session_generation)
        )
        parts = [
            "session_generation=%s" % generation,
            "object_url=%s" % self.object_url,
            "object=%s" % self.object_url,
            "final_origin=%s" % (
                self.final_origin or url_origin(self.object_url)
            ),
            "attempts=%s" % self.attempt,
            "attempt=%s" % self.attempt,
        ]
        role_labels = (
            ("authed", ("authed",)),
            ("base", ("base",)),
            ("anonymous", ("anonymous", "anon")),
            ("neighbor", ("neighbor", "neighbour")),
            ("soft404_object", ("soft404_object",)),
            ("soft404_path", ("soft404_path",)),
        )
        for role, labels in role_labels:
            record = self.responses.get(role)
            if record is None:
                continue
            value = self._record_text(record)
            for label in labels:
                parts.append("%s=%s" % (label, value))
        if self.optional_failures:
            parts.append(
                "baseline_skipped=%s"
                % ",".join(sorted(self.optional_failures))
            )
        if decision:
            parts.append("decision=%s" % decision)
        if extra:
            parts.extend(extra if isinstance(extra, (list, tuple)) else [extra])
        return "; ".join(parts)


def urlsplit_host(url: str) -> str:
    """Lower-cased hostname of ``url``."""
    return (urlsplit(url or "").hostname or "").lower()


def allowed_final_origin(object_url: str, final_url: str) -> bool:
    """Whether a followed redirect stayed on the object's origin.

    An HTTP-to-HTTPS upgrade on the same host is accepted (a common canonical
    redirect); any other scheme/port change is treated as leaving the object.
    """
    object_origin = url_origin(object_url)
    final_origin = url_origin(final_url)
    if not object_origin or not final_origin:
        return True
    if object_origin == final_origin:
        return True
    original = urlsplit(object_url)
    final = urlsplit(final_url)
    try:
        original_port = original.port or 80
        final_port = final.port or 443
    except ValueError:
        return False
    if (
        (original.scheme or "").lower() == "http"
        and (final.scheme or "").lower() == "https"
        and (original.hostname or "").lower()
        == (final.hostname or "").lower()
        and original_port == 80
        and final_port == 443
    ):
        return True
    return False


def run_comparison(
    object_url: str,
    probes: Iterable[ProbeSpec],
    *,
    request=None,
    authenticator=None,
    max_attempts: int = 2,
    logger=None,
) -> ComparisonTransaction:
    """Run ``probes`` as one transaction, restarting after a refresh.

    Only a session-generation change is retried: redirects, login pages and
    malformed responses are decisions about the object and must not be papered
    over by re-sending requests.
    """
    specs = list(probes)
    owner = request
    if owner is None:
        for spec in specs:
            if spec.authenticated:
                owner = spec.sender
                break

    transaction = None
    for attempt in range(1, max(1, int(max_attempts)) + 1):
        generation = session_generation(owner) if owner is not None else None
        transaction = ComparisonTransaction(
            object_url,
            session_generation_value=generation,
            attempt=attempt,
            authenticator=authenticator,
            owner=owner,
        )
        for spec in specs:
            transaction.probe(spec)
            if not transaction.valid:
                break
        if transaction.valid:
            transaction.committed = True
            return transaction
        if not transaction.refresh_observed:
            break
        if logger is not None:
            logger.debug(
                "Retrying authorization comparison for %s after session "
                "refresh (attempt %s/%s)",
                object_url, attempt, max_attempts,
            )
    return transaction


def anonymous_request(request, target_url, request_class=SingleRequest):
    """Build a clean, unauthenticated request context for comparison probes.

    The anonymous side intentionally gets a new cookie jar and no authenticator
    headers, while still inheriting transport settings (proxy/TLS/timeouts)
    and the target's scope from the authenticated factory.
    """
    def value(name, default):
        return getattr(request, name, default)

    kwargs = {
        "url": target_url,
        "agent": value("agent", "Sitadel"),
        "proxy": value("proxy", None),
        "redirect": value("redirect", True),
        "timeout": value("timeout", None),
        "random_agent": value("random_agent", False),
        "verify": value("verify", False),
        "rate_limit": value("rate_limit", 0.0),
        "scope_hosts": value("scope_hosts", None),
    }
    try:
        return request_class(**kwargs)
    except TypeError:
        # A lightweight test double may not accept every transport setting.
        try:
            return request_class(
                timeout=kwargs["timeout"], verify=kwargs["verify"]
            )
        except TypeError:
            try:
                return request_class(url=target_url)
            except TypeError:
                return request_class()


# Friendly aliases for callers/tests that name the concept rather than the
# implementation.
AuthorizationTransaction = ComparisonTransaction
AuthzTransaction = ComparisonTransaction
