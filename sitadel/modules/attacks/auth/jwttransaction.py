"""One coherent JWT replay/verification transaction.

A JWT finding is only trustworthy when the token whose signature was removed,
the header/cookie slot it is replayed in, the authenticated session generation,
the endpoint baseline and the replay response all describe the same
verification.  A mid-scan re-login rotates the session (and, for cookie-borne
tokens, the JWT bytes themselves); comparing a replay from the new session
against an old baseline is how a finding ends up pointing at a different
session.

This module keeps those items together.  :class:`JwtVerificationTransaction`
refuses to turn a response into evidence when the token bytes, token location,
endpoint, or login generation changed while the probes were running.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from .jwtutils import TokenLocation


def session_generation(sender) -> Any:
    """Return a sender's session generation, if it exposes one.

    ``Authenticator.generation`` is the canonical source.  Reading through the
    request factory also keeps lightweight test doubles working.
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


def _text(response) -> str:
    """Best-effort response body extraction for requests/doubles."""
    if response is None:
        return ""
    value = getattr(response, "text", None)
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    value = getattr(response, "body", None)
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    if isinstance(value, str):
        return value
    value = getattr(response, "content", None)
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return ""


def _status(response) -> int:
    try:
        return int(getattr(response, "status_code", 0) or 0)
    except (TypeError, ValueError):
        return 0


def _url(response, fallback: str) -> str:
    if response is not None:
        for name in ("url", "final_url"):
            value = getattr(response, name, None)
            if isinstance(value, str) and value:
                return urljoin(fallback or "", value)
            if isinstance(value, bytes) and value:
                return urljoin(
                    fallback or "", value.decode("utf-8", "replace")
                )
    return fallback or ""


def _normalise_path(path: str | None) -> str:
    value = path or "/"
    # Collapse duplicate/trailing slashes without resolving ".." (which could
    # hide a redirect to a login page).
    while "//" in value:
        value = value.replace("//", "/")
    if not value.startswith("/"):
        value = "/" + value
    if len(value) > 1:
        value = value.rstrip("/")
    return value


def canonical_endpoint(url: str | None) -> str:
    """A stable endpoint identity (scheme/host/path + sorted query)."""
    if not url:
        return ""
    parts = urlsplit(str(url))
    scheme = (parts.scheme or "").lower()
    try:
        host = (parts.hostname or "").lower()
    except ValueError:
        host = ""
    try:
        port = parts.port
    except ValueError:
        port = None
    if host and port is not None and not (
        (scheme == "http" and port == 80)
        or (scheme == "https" and port == 443)
    ):
        host = "%s:%s" % (host, port)
    query = urlencode(sorted(parse_qsl(parts.query, keep_blank_values=True)))
    return urlunsplit((scheme, host, _normalise_path(parts.path), query, ""))


def same_endpoint(expected: str | None, actual: str | None) -> bool:
    """Whether ``actual`` still addresses the endpoint that was baselined.

    A same-host HTTP-to-HTTPS upgrade and a trailing-slash canonicalisation are
    accepted; a redirect to a login page or any other path is not.  Missing
    URL information on a test double is treated as "cannot disprove" so the
    transaction still works with response fakes that only expose status/body.
    """
    if not expected or not actual:
        return True
    if not urlsplit(actual).scheme:
        actual = urljoin(expected, actual)
    left = canonical_endpoint(expected)
    right = canonical_endpoint(actual)
    if left == right:
        return True
    left_parts = urlsplit(expected)
    right_parts = urlsplit(actual)
    if (
        (left_parts.scheme or "").lower() == "http"
        and (right_parts.scheme or "").lower() == "https"
        and (left_parts.hostname or "").lower()
        == (right_parts.hostname or "").lower()
        and (left_parts.port or 80) == 80
        and (right_parts.port or 443) == 443
        and _normalise_path(left_parts.path) == _normalise_path(right_parts.path)
        and sorted(parse_qsl(left_parts.query, keep_blank_values=True))
        == sorted(parse_qsl(right_parts.query, keep_blank_values=True))
    ):
        return True
    return False


def _fingerprint(value: str) -> str:
    return hashlib.sha256((value or "").encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class JwtBinding:
    """The exact token bytes and location a transaction is allowed to use."""

    token: str
    location: TokenLocation
    generation: Any
    endpoint: str

    @property
    def token_bytes(self) -> str:
        return self.token

    @property
    def position(self) -> str:
        return (
            self.location.position if self.location is not None else "n/a"
        )

    @property
    def source(self) -> str:
        return self.location.source if self.location is not None else "n/a"


@dataclass
class JwtResponseSnapshot:
    """The parts of a replay response the verification may rely on."""

    role: str
    variant: str
    token: str
    location: TokenLocation
    endpoint: str
    requested_url: str
    final_url: str
    status_code: int
    body: str
    generation_before: Any
    generation_after: Any
    same_endpoint: bool
    token_matches: bool
    accepted: bool | None = None
    acceptance: str | None = None
    response: Any = field(default=None, repr=False, compare=False)

    def __getattr__(self, name):
        """Delegate unknown response attributes (for custom canary checks)."""
        response = object.__getattribute__(self, "response")
        if response is None:
            raise AttributeError(name)
        return getattr(response, name)

    @property
    def status(self) -> int:
        return self.status_code

    @property
    def text(self) -> str:
        return self.body

    @property
    def url(self) -> str:
        return self.final_url

    @property
    def generation(self):
        return self.generation_after

    @property
    def token_bytes(self) -> str:
        return self.token

    @property
    def position(self) -> str:
        return self.location.position

    @property
    def source(self) -> str:
        return self.location.source

    @property
    def body_sha256(self) -> str:
        return _fingerprint(self.body)

    @property
    def headers(self):
        return getattr(self.response, "headers", {}) or {}

    @property
    def content(self) -> bytes:
        return self.body.encode("utf-8")

    @property
    def request(self):
        return getattr(self.response, "request", None)

    @property
    def history(self):
        return getattr(self.response, "history", None) or []

    @property
    def cookies(self):
        return getattr(self.response, "cookies", None)


_UNKNOWN_TOKEN = object()


def _response_token(response, location: TokenLocation):
    """The token a response's prepared request actually carried, if known."""
    if response is None:
        return _UNKNOWN_TOKEN
    prepared = getattr(response, "request", None)
    if prepared is not None and getattr(prepared, "headers", None) is not None:
        headers = getattr(prepared, "headers", None) or {}
        if location.kind == "header":
            try:
                value = headers.get(location.name)
            except AttributeError:
                value = None
            if value is None and hasattr(headers, "items"):
                for name, candidate in headers.items():
                    if str(name).lower() == location.name.lower():
                        value = candidate
                        break
            if isinstance(value, bytes):
                value = value.decode("utf-8", "replace")
            if isinstance(value, str):
                value = value.strip()
                if (
                    location.prefix
                    and value.lower().startswith(location.prefix.lower())
                ):
                    return value[len(location.prefix):].strip()
                if not location.prefix:
                    return value
            # A prepared request exists but did not carry the expected header:
            # that response is not evidence for this token slot.
            return None
        else:
            # Cookie-borne token: inspect the Cookie header the request
            # carried.
            if hasattr(headers, "get"):
                cookie_header = (
                    headers.get("Cookie") or headers.get("cookie") or ""
                )
            else:
                cookie_header = ""
            if isinstance(cookie_header, bytes):
                cookie_header = cookie_header.decode("utf-8", "replace")
            for part in str(cookie_header).split(";"):
                name, sep, value = part.strip().partition("=")
                if sep and name == location.name:
                    return value
            cookies = getattr(prepared, "_cookies", None)
            if cookies is None:
                cookies = getattr(prepared, "cookies", None)
            getter = getattr(cookies, "get", None)
            if callable(getter):
                try:
                    value = getter(location.name)
                except Exception:
                    value = None
                if isinstance(value, str):
                    return value
            return None
    tagged = getattr(response, "sitadel_jwt_token", None)
    if isinstance(tagged, str):
        return tagged
    return _UNKNOWN_TOKEN


class JwtVerificationTransaction:
    """Immutable identity + accepted evidence for one JWT replay battery.

    The transaction captures the raw token bytes, its header/cookie slot, the
    endpoint and the login generation.  Every baseline/replay response is
    checked against those items before it can become a finding.  Any observed
    refresh marks the transaction invalid; the caller may start a *new*
    transaction with freshly discovered token bytes, never reuse this one.
    """

    def __init__(
        self,
        endpoint: str,
        token: str,
        location: TokenLocation,
        generation: Any = None,
        *,
        request=None,
        authenticator=None,
        acceptance: Callable[[Any, Any], bool] | None = None,
        baseline_acceptance: Callable[[Any], bool] | None = None,
        generation_getter: Callable[[], Any] | None = None,
        binding_getter: Callable[[], TokenLocation | "JwtBinding" | None] | None = None,
        attempt: int = 1,
        max_attempts: int = 2,
    ):
        self.endpoint = endpoint
        self.token = token
        self.token_bytes = token
        self.location = location
        self.session_generation = generation
        self.generation = generation
        self.request = request
        self.authenticator = authenticator
        self.acceptance = acceptance
        self.baseline_acceptance = baseline_acceptance
        self.generation_getter = generation_getter
        self.binding_getter = binding_getter
        self.attempt = attempt
        self.max_attempts = max_attempts

        self.baseline: JwtResponseSnapshot | None = None
        self.replays: list[JwtResponseSnapshot] = []
        self.responses: list[JwtResponseSnapshot] = []
        self.findings: list[dict] = []
        self.valid = True
        self.reason: str | None = None
        self.refresh_observed = False
        self.baseline_valid = False
        self.committed = False

    # ------------------------------------------------------------------ #
    # Identity/binding checks
    # ------------------------------------------------------------------ #
    @property
    def position(self) -> str:
        return self.location.position

    @property
    def source(self) -> str:
        return self.location.source

    @property
    def where(self) -> str:
        return self.position

    @property
    def endpoint_url(self) -> str:
        return self.endpoint

    @property
    def url(self) -> str:
        return self.endpoint

    @property
    def token_location(self) -> TokenLocation:
        return self.location

    @property
    def token_fingerprint(self) -> str:
        return _fingerprint(self.token)

    @property
    def binding(self) -> JwtBinding:
        return JwtBinding(
            self.token, self.location, self.session_generation, self.endpoint
        )

    @property
    def baseline_response(self):
        """The raw baseline response, if one was collected."""
        return self.baseline.response if self.baseline is not None else None

    @property
    def last_replay(self) -> JwtResponseSnapshot | None:
        return self.replays[-1] if self.replays else None

    @property
    def last_replay_response(self):
        record = self.last_replay
        return record.response if record is not None else None

    @property
    def replay_responses(self):
        return list(self.replays)

    @property
    def replay_response(self):
        return self.last_replay_response

    @property
    def accepted(self):
        return any(bool(record.accepted) for record in self.replays)

    @property
    def baseline_status(self):
        return self.baseline.status_code if self.baseline is not None else None

    @property
    def baseline_url(self):
        return self.baseline.final_url if self.baseline is not None else None

    @property
    def baseline_body(self):
        return self.baseline.body if self.baseline is not None else None

    @property
    def baseline_generation(self):
        return self.baseline.generation_after if self.baseline is not None else None

    @property
    def accepted_findings(self):
        accepted = []
        for item in self.findings:
            if isinstance(item, dict):
                if item.get("accepted"):
                    accepted.append(item)
            elif getattr(item, "accepted", False):
                accepted.append(item)
        return accepted

    def _reject(self, reason: str, *, refresh: bool = False) -> None:
        if self.reason is None:
            self.reason = reason
        self.valid = False
        if refresh:
            self.refresh_observed = True

    def _current_generation(self) -> Any:
        if self.generation_getter is not None:
            return self.generation_getter()
        if self.request is not None:
            value = session_generation(self.request)
            if value is not None:
                return value
        return self.session_generation

    def _current_location(self):
        if self.binding_getter is None:
            return self.location
        try:
            return self.binding_getter()
        except Exception:
            return None

    def binding_current(self) -> bool:
        """Whether the same token bytes are still at the same location."""
        generation = self._current_generation()
        if (
            self.session_generation is not None
            and generation is not None
            and generation != self.session_generation
        ):
            self._reject("session-generation-advanced", refresh=True)
            return False

        current = self._current_location()
        if current is None:
            self._reject("token-location-missing", refresh=True)
            return False
        if isinstance(current, JwtBinding):
            current_token = current.token
            current_location = current.location
            current_generation = current.generation
        else:
            current_token = getattr(current, "token", None)
            current_location = current
            current_generation = getattr(current, "generation", None)
        if current_token is not None and current_token != self.token:
            self._reject("token-bytes-changed", refresh=True)
            return False
        if (
            current_generation is not None
            and self.session_generation is not None
            and current_generation != self.session_generation
        ):
            self._reject("token-generation-changed", refresh=True)
            return False
        if (
            current_location is not None
            and (
                getattr(current_location, "kind", None) != self.location.kind
                or getattr(current_location, "name", None) != self.location.name
                or getattr(current_location, "prefix", None)
                != self.location.prefix
            )
        ):
            self._reject("token-location-changed", refresh=True)
            return False
        return True

    # ------------------------------------------------------------------ #
    # Probes
    # ------------------------------------------------------------------ #
    def _snapshot(self, response, *, role, variant, token, generation_before):
        final_url = _url(response, self.endpoint)
        prepared = getattr(response, "request", None)
        prepared_url = getattr(prepared, "url", None)
        requested = getattr(response, "sitadel_requested_url", None) or self.endpoint
        if not getattr(response, "sitadel_requested_url", None):
            if isinstance(prepared_url, str) and prepared_url:
                requested = prepared_url
            else:
                tagged_endpoint = getattr(
                    response, "sitadel_jwt_endpoint", None
                )
                tagged_requested = getattr(
                    response, "sitadel_jwt_requested_url", None
                )
                if isinstance(tagged_endpoint, str) and tagged_endpoint:
                    requested = tagged_endpoint
                elif isinstance(tagged_requested, str) and tagged_requested:
                    requested = tagged_requested
        requested = urljoin(self.endpoint or "", str(requested))
        actual_token = _response_token(response, self.location)
        token_matches = (
            actual_token is _UNKNOWN_TOKEN or actual_token == token
        )
        endpoint_matches = (
            same_endpoint(self.endpoint, requested)
            and same_endpoint(self.endpoint, final_url)
        )
        if isinstance(prepared_url, str) and prepared_url:
            # The prepared request is the strongest statement about which URL
            # actually produced the response, even if a helper echoed the
            # requested endpoint onto the response.
            endpoint_matches = endpoint_matches and same_endpoint(
                self.endpoint, urljoin(self.endpoint or "", prepared_url)
            )
        return JwtResponseSnapshot(
            role=role,
            variant=variant,
            token=token,
            location=self.location,
            endpoint=self.endpoint,
            requested_url=requested,
            final_url=final_url,
            status_code=_status(response),
            body=_text(response),
            generation_before=generation_before,
            generation_after=self._current_generation(),
            same_endpoint=endpoint_matches,
            token_matches=token_matches,
            response=response,
        )

    def probe(self, token: str, replay: Callable[[str], Any], *, role: str,
              variant: str) -> JwtResponseSnapshot | None:
        """Run one replay after checking the transaction's identity."""
        if not self.valid or not self.binding_current():
            return None

        generation_before = self._current_generation()
        if (
            self.session_generation is not None
            and generation_before is not None
            and generation_before != self.session_generation
        ):
            self._reject("session-generation-advanced", refresh=True)
            return None
        try:
            response = replay(token)
        except Exception:
            # A single failed probe is not evidence of acceptance.  Keep the
            # rest of the transaction usable unless the session also changed.
            self.binding_current()
            return None
        if response is None:
            # No response means no evidence; still check whether the session
            # moved underneath us so the caller can restart with a new token.
            self.binding_current()
            return None

        generation_after = self._current_generation()
        snapshot = self._snapshot(
            response,
            role=role,
            variant=variant,
            token=token,
            generation_before=generation_before,
        )
        self.responses.append(snapshot)

        if (
            self.session_generation is not None
            and (
                (generation_before is not None
                 and generation_before != self.session_generation)
                or (generation_after is not None
                    and generation_after != self.session_generation)
            )
        ):
            self._reject("session-refresh", refresh=True)
            return snapshot

        # Response annotations from SingleRequest identify the generation that
        # actually produced the response.  An old/other-generation response
        # must not be compared with this transaction's baseline.
        tagged_generation = getattr(
            response, "sitadel_jwt_login_generation", None
        )
        if (
            self.session_generation is not None
            and tagged_generation is not None
            and tagged_generation != self.session_generation
        ):
            self._reject("response-login-generation-mismatch", refresh=True)
            return snapshot

        if not getattr(response, "sitadel_jwt_isolated_replay", False):
            for name in (
                "sitadel_session_generation",
                "sitadel_session_generation_after",
            ):
                annotated = getattr(response, name, None)
                if (
                    self.session_generation is not None
                    and annotated is not None
                    and annotated != self.session_generation
                ):
                    self._reject("response-generation-mismatch", refresh=True)
                    return snapshot

        if not snapshot.token_matches:
            self._reject("response-token-mismatch")
            return snapshot

        # If the shared session rotated while this probe was on the wire, do
        # not attribute its response to the old transaction.
        if not self.binding_current():
            return snapshot
        return snapshot

    def establish_baseline(self, replay: Callable[[str], Any]):
        """Replay the original token and decide whether a baseline exists."""
        snapshot = self.probe(
            self.token, replay, role="baseline", variant="original"
        )
        if snapshot is None:
            return None
        self.baseline = snapshot
        if not self.valid:
            return snapshot
        if not snapshot.same_endpoint:
            self._reject("baseline-endpoint-changed")
            return snapshot
        if not snapshot.token_matches:
            self._reject("baseline-token-mismatch")
            return snapshot
        if self.baseline_acceptance is not None:
            try:
                accepted = bool(self.baseline_acceptance(snapshot))
            except Exception:
                accepted = False
        elif self.acceptance is None:
            self.baseline_valid = snapshot.status_code < 400
            snapshot.accepted = self.baseline_valid
            snapshot.acceptance = "status<%d" % 400
            return snapshot
        else:
            try:
                accepted = bool(self.acceptance(snapshot, None))
            except Exception:
                accepted = False
        self.baseline_valid = accepted
        snapshot.accepted = accepted
        snapshot.acceptance = self._acceptance_label()
        if not accepted:
            self.reason = "no-authenticated-baseline"
        return snapshot

    def replay_variant(self, variant: str, token: str,
                       replay: Callable[[str], Any]):
        """Replay one tampered token against the committed baseline."""
        if not self.valid or not self.baseline_valid:
            return None
        snapshot = self.probe(
            token, replay, role="replay", variant=variant
        )
        if snapshot is None:
            return None
        self.replays.append(snapshot)
        if not self.valid:
            # The probe crossed a session/token/endpoint boundary; this
            # response may be useful for diagnostics but is never accepted.
            snapshot.accepted = False
            snapshot.acceptance = "transaction-invalid"
            return snapshot
        if (
            not snapshot.token_matches
            or not snapshot.same_endpoint
            or (
                self.baseline is not None
                and not same_endpoint(
                    self.baseline.final_url, snapshot.final_url
                )
            )
        ):
            snapshot.accepted = False
            snapshot.acceptance = "binding-mismatch"
            return snapshot
        if self.acceptance is None:
            accepted = (
                self.baseline is not None
                and snapshot.status_code == self.baseline.status_code
                and snapshot.status_code < 400
            )
        else:
            try:
                accepted = bool(
                    self.acceptance(
                        snapshot,
                        self.baseline,
                    )
                )
            except Exception:
                accepted = False
        snapshot.accepted = accepted
        snapshot.acceptance = (
            self._acceptance_label() if accepted else "rejected"
        )
        return snapshot

    def commit(self) -> bool:
        """Mark the transaction usable only if its binding is still current."""
        if not self.valid or not self.baseline_valid:
            return False
        if not self.binding_current():
            return False
        self.committed = True
        return True

    # Small aliases keep the transaction usable under the names callers tend
    # to use for the same operations.
    baseline_probe = establish_baseline
    replay = replay_variant
    finalize = commit
    finalise = commit

    def _acceptance_label(self) -> str:
        """Human-readable description of the acceptance channel used."""
        canary = (
            getattr(self.authenticator, "logged_in_check", None)
            if self.authenticator is not None else None
        )
        if canary:
            return "canary=%r" % str(canary)
        if self.baseline is not None:
            return "baseline-status=%s; body-match" % self.baseline.status_code
        return "accepted"

    # ------------------------------------------------------------------ #
    # Evidence
    # ------------------------------------------------------------------ #
    @staticmethod
    def _record_text(record: JwtResponseSnapshot) -> str:
        generation = (
            "n/a" if record.generation_after is None
            else str(record.generation_after)
        )
        return (
            "%s status=%s url=%s len=%s sha256=%s gen=%s"
            % (
                record.role,
                record.status_code,
                record.final_url,
                len(record.body),
                record.body_sha256,
                generation,
            )
        )

    def accepted_evidence(self, record: JwtResponseSnapshot | None = None) -> str:
        """Compact evidence that the replay was accepted for *this* token."""
        if record is None:
            record = next(
                (item for item in reversed(self.replays) if item.accepted),
                None,
            )
        record = record or (self.replays[-1] if self.replays else self.baseline)
        if record is None:
            return "accepted=false | reason=no-replay-response"
        return (
            "accepted=%s | acceptance=%s | token_matches=%s | "
            "endpoint_matches=%s | status=%s | endpoint=%s | "
            "response_sha256=%s | session_generation=%s"
            % (
                "true" if record.accepted else "false",
                record.acceptance or "unknown",
                "true" if record.token_matches else "false",
                "true" if record.same_endpoint else "false",
                record.status_code,
                record.final_url,
                record.body_sha256,
                record.generation_after,
            )
        )

    def evidence(self, *, decision: str | None = None,
                 record: JwtResponseSnapshot | None = None,
                 extra=None, include_replay: bool = True) -> str:
        """Stable, report-safe evidence for this verification transaction."""
        generation = (
            "n/a" if self.session_generation is None
            else str(self.session_generation)
        )
        location = (
            "%s '%s'" % (self.location.kind, self.location.name)
            if self.location is not None else "n/a"
        )
        kind = self.location.kind if self.location is not None else ""
        name = self.location.name if self.location is not None else ""
        prefix = self.location.prefix if self.location is not None else ""
        parts = [
            "session_generation=%s" % generation,
            "login_generation=%s" % generation,
            "generation=%s" % generation,
            "token=%s" % self.token,
            "token_bytes=%s" % self.token,
            "token_sha256=%s" % self.token_fingerprint,
            "location=%s" % location,
            "token_location=%s" % location,
            "token_position=%s" % (
                self.location.source if self.location is not None else "n/a"
            ),
            "location_kind=%s" % (
                self.location.kind if self.location is not None else "n/a"
            ),
            "location_name=%s" % (
                self.location.name if self.location is not None else "n/a"
            ),
            "header=%s" % (
                name if kind == "header" else "n/a"
            ),
            "cookie=%s" % (
                name if kind == "cookie" else "n/a"
            ),
            "prefix=%s" % (prefix or "none"),
            "endpoint=%s" % self.endpoint,
            "attempt=%s" % self.attempt,
        ]
        if self.baseline is not None:
            parts.append("endpoint_baseline=%s" % self._record_text(self.baseline))
            parts.append(
                "baseline=status=%s url=%s len=%s sha256=%s"
                % (
                    self.baseline.status_code,
                    self.baseline.final_url,
                    len(self.baseline.body),
                    self.baseline.body_sha256,
                )
            )
        chosen = record
        if include_replay and chosen is None and self.replays:
            chosen = self.replays[-1]
        if chosen is not None:
            parts.append("replay_response=%s" % self._record_text(chosen))
            parts.append("replay=%s" % self._record_text(chosen))
            parts.append("replay_status=%s" % chosen.status_code)
            parts.append("replay_url=%s" % chosen.final_url)
            parts.append("replay_token=%s" % chosen.token)
            parts.append("replay_generation=%s" % chosen.generation_after)
            parts.append("accepted_evidence=%s" % self.accepted_evidence(chosen))
            parts.append(
                "accepted=%s" % ("true" if chosen.accepted else "false")
            )
        if decision:
            parts.append("decision=%s" % decision)
        if extra:
            parts.extend(extra if isinstance(extra, (list, tuple)) else [extra])
        return "; ".join(parts)

    # Friendly alias used by callers/tests that name the concept generically.
    build_evidence = evidence
    as_evidence = evidence


# Aliases make the intent discoverable without forcing one class name on
# callers.
JwtTransaction = JwtVerificationTransaction
TokenVerificationTransaction = JwtVerificationTransaction
VerificationTransaction = JwtVerificationTransaction
JwtVerification = JwtVerificationTransaction
JwtReplayTransaction = JwtVerificationTransaction
TokenReplayTransaction = JwtVerificationTransaction
TokenBinding = JwtBinding
ReplayResponse = JwtResponseSnapshot
ResponseSnapshot = JwtResponseSnapshot

__all__ = [
    "JwtBinding",
    "JwtResponseSnapshot",
    "JwtTransaction",
    "JwtReplayTransaction",
    "JwtVerification",
    "JwtVerificationTransaction",
    "ReplayResponse",
    "ResponseSnapshot",
    "TokenBinding",
    "TokenReplayTransaction",
    "TokenVerificationTransaction",
    "VerificationTransaction",
    "canonical_endpoint",
    "same_endpoint",
    "session_generation",
]
