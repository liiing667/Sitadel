"""JWT / token security attack plugin.

When the scan carries a JWT (an ``Authorization: Bearer`` header or a session
cookie), replay tampered variants against a protected endpoint and see whether
the server accepts them. Covers the classic, high-impact flaws:

* ``alg:none``               - signature stripped, still accepted.
* RS256->HS256 confusion     - re-signed with the server's RSA public key.
* ``kid`` path traversal     - key resolved to an empty file (``/dev/null``).
* weak HMAC secret           - offline brute-force of the signing key.
* claim enforcement          - expired ``exp`` accepted (checked via alg:none).

All acceptance decisions go through a single canary channel: the configured
``--logged-in-check`` string when present, otherwise a comparison against the
authenticated baseline response.  The exact token bytes, their header/cookie
slot, the login generation and the endpoint baseline are captured in one
``JwtVerificationTransaction``; a mid-scan re-login invalidates that
transaction and the tests restart with the newly issued token instead of
comparing a new-session replay with an old-session baseline.  The plugin no-ops
when no JWT is present, so it never fires false positives on tokenless targets.
(OWASP API2, CWE-347.)
"""

from __future__ import annotations

import json

from requests.utils import dict_from_cookiejar

from sitadel.config.settings import Risk
from sitadel.request.request import SingleRequest
from sitadel.utils.container import Services
from .. import AttackPlugin
from . import jwtutils as ju
from .jwttransaction import JwtVerificationTransaction

# Small built-in fallback list so weak-secret detection works out of the box.
_FALLBACK_SECRETS = [
    "secret", "password", "changeme", "admin", "jwt", "test", "key",
    "your-256-bit-secret", "supersecret", "123456", "s3cr3t",
]
# Bad enough to be worth flagging even when the endpoint can't be validated.
_STATUS_UNAUTHORIZED = (401, 403)

# One initial verification plus one retry after a session refresh.  A retry
# always starts a brand-new transaction with freshly read token bytes; it never
# reuses the old baseline.
_MAX_TRANSACTION_ATTEMPTS = 2


class Jwt(AttackPlugin):
    # Tampering + replay against a live endpoint is exploitation-stage.
    level = Risk.DANGEROUS

    def process(self, start_url, crawled_urls):
        output = Services.get("output")
        request = Services.get("request_factory")
        logger = Services.get("logger")
        # Kept for callers/tests that want to inspect the exact token/session
        # bindings behind the findings.  The findings themselves carry the
        # same information as report-safe evidence.
        self.transactions = []
        self.last_transaction = None

        tokens = self._discover(request)
        if not tokens:
            output.info(
                "No JWT found in the session (Authorization bearer / cookie); "
                "skipping JWT tests"
            )
            return

        output.info("Checking JWT / token security...")
        secrets = self._load_secrets()
        for loc in tokens:
            try:
                self._test_token(loc, start_url, request, secrets, output, logger)
            except Exception as err:  # one bad token must not abort the scan
                logger.error(err)
                output.debug("JWT test error: %s" % err)

    # ------------------------------------------------------------------ #
    # Discovery
    # ------------------------------------------------------------------ #
    @staticmethod
    def _discover(request):
        """Discover tokens and stamp them with the current login generation.

        ``TokenLocation.generation`` is part of the token's identity for every
        subsequent replay: the exact bytes, their header/cookie slot and the
        authenticated session they came from must stay together.
        """
        auth = getattr(request, "authenticator", None)
        headers = dict(getattr(auth, "headers", {}) or {}) if auth is not None else {}
        cookies = {}
        session = getattr(request, "session", None)
        if session is not None:
            try:
                cookies = dict_from_cookiejar(session.cookies)
            except Exception:
                cookies = {}
        generation = Jwt._session_generation(request)
        return ju.discover_tokens(headers, cookies, generation=generation)

    @staticmethod
    def _session_generation(request):
        """Return the request factory's authenticated-session generation."""
        if request is None:
            return None
        for name in (
            "session_generation",
            "current_session_generation",
            "generation",
        ):
            value = getattr(request, name, None)
            if callable(value):
                try:
                    value = value()
                except TypeError:
                    value = None
            if value is not None:
                return value
        authenticator = getattr(request, "authenticator", None)
        if authenticator is not None:
            for name in ("generation", "session_generation"):
                value = getattr(authenticator, name, None)
                if callable(value):
                    try:
                        value = value()
                    except TypeError:
                        value = None
                if value is not None:
                    return value
        return 0

    def _current_location(self, request, location):
        """Re-read the same token slot from the current authenticated session."""
        for candidate in self._discover(request):
            if (
                candidate.kind == location.kind
                and candidate.name == location.name
            ):
                return candidate
        return None

    def _load_secrets(self):
        try:
            datastore = Services.get("datastore")
            with datastore.open("jwt-secrets.txt", "r") as fh:
                words = [line.rstrip("\n") for line in fh if line.strip()]
            if words:
                return words
        except Exception:
            pass
        return list(_FALLBACK_SECRETS)

    # ------------------------------------------------------------------ #
    # Replay + acceptance channel
    # ------------------------------------------------------------------ #
    @staticmethod
    def _new_replay_request(request):
        """Build an isolated sender for a token replay.

        The replay must carry exactly the token under test, not the scanner's
        live cookie jar or Authorization header.  In particular it must not
        auto-re-login when the target rejects the tampered token: a fresh
        session would make the rejected token look accepted.
        """
        kwargs = {
            "url": getattr(request, "url", None),
            "agent": getattr(request, "agent", "Sitadel"),
            "proxy": getattr(request, "proxy", None),
            "redirect": getattr(request, "redirect", True),
            "timeout": getattr(request, "timeout", None),
            "random_agent": getattr(request, "random_agent", False),
            "verify": getattr(request, "verify", False),
            "rate_limit": getattr(request, "rate_limit", 0.0),
            "scope_hosts": getattr(request, "scope_hosts", None),
        }
        try:
            return SingleRequest(**kwargs)
        except TypeError:
            # Lightweight request doubles used by callers/tests may not accept
            # every transport setting.
            try:
                return SingleRequest(
                    timeout=kwargs["timeout"], verify=kwargs["verify"]
                )
            except TypeError:
                try:
                    return SingleRequest(url=kwargs["url"])
                except TypeError:
                    return SingleRequest()

    @staticmethod
    def _tag_replay_response(response, endpoint, loc, token):
        """Bind a replay response to its exact endpoint/token/location."""
        if response is None:
            return response
        try:
            # This response came from a deliberately isolated sender (no
            # scanner cookie jar / authenticator), so its own generation is
            # not the transaction's login generation.  Mark it so the
            # transaction validates the shared session before/after the send
            # instead of comparing against this isolated sender's generation.
            response.sitadel_jwt_isolated_replay = True
            response.sitadel_jwt_endpoint = endpoint
            response.sitadel_jwt_requested_url = endpoint
            response.sitadel_jwt_final_url = getattr(
                response, "url", endpoint
            )
            response.sitadel_jwt_token = token
            response.sitadel_jwt_location_kind = loc.kind
            response.sitadel_jwt_location_name = loc.name
            response.sitadel_jwt_prefix = loc.prefix
            response.sitadel_jwt_location = loc
            response.sitadel_jwt_position = loc.position
            if getattr(response, "request", None) is None:
                response.sitadel_requested_url = endpoint
        except Exception:
            # Some response doubles use ``__slots__``; transaction checks fall
            # back to the prepared request / requested URL available on them.
            pass
        return response

    def _replay(self, endpoint, loc, new_token, request):
        """Send ``new_token`` in the same location the original was found."""
        fresh = self._new_replay_request(request)
        if loc.kind == "header":
            headers = {loc.name: f"{loc.prefix}{new_token}"}
            response = fresh.send(url=endpoint, method="GET", headers=headers)
        else:
            fresh.session.cookies.set(loc.name, new_token)
            response = fresh.send(url=endpoint, method="GET")
        response = self._tag_replay_response(
            response, endpoint, loc, new_token
        )
        if response is not None:
            try:
                generation = self._session_generation(request)
                response.sitadel_jwt_login_generation = generation
                # The isolated sender has no authenticator of its own, so its
                # SingleRequest annotation would be 0.  Expose the shared
                # login generation on the replay response instead: downstream
                # evidence must be able to bind the response to that session.
                response.sitadel_session_generation = generation
                response.sitadel_session_generation_after = generation
                response.sitadel_login_generation = generation
                response.sitadel_login_generation_after = generation
            except Exception:
                pass
        return response

    @staticmethod
    def _bodies_match(a, b, tolerance=0.1):
        if not a or not b:
            return False
        longest = max(len(a), len(b))
        if longest < 50:
            return a == b
        return abs(len(a) - len(b)) / longest <= tolerance

    def _accepted(self, resp, baseline, auth):
        """Whether a tampered token was accepted (i.e. treated as logged in)."""
        if resp is None or resp.status_code in _STATUS_UNAUTHORIZED:
            return False
        # Prefer the explicit logged-in canary when configured.
        if auth is not None and getattr(auth, "logged_in_check", None):
            return not auth.looks_logged_out(resp)
        if baseline is None:
            return False
        return (
            resp.status_code == baseline.status_code
            and resp.status_code < 400
            and self._bodies_match(resp.text, baseline.text)
        )

    def _baseline_accepted(self, resp, auth):
        """Whether the untampered replay is a valid authenticated baseline.

        With a canary configured the canary must be present; without one, the
        historical status-code baseline is used.  Keeping this distinct from
        :meth:`_accepted` preserves anonymous/cookie scans that have no
        ``--logged-in-check``.
        """
        if resp is None:
            return False
        if auth is not None and getattr(auth, "logged_in_check", None):
            return self._accepted(resp, None, auth)
        return resp.status_code < 400

    # ------------------------------------------------------------------ #
    # Per-token test battery
    # ------------------------------------------------------------------ #
    def _test_token(self, loc, endpoint, request, secrets, output, logger):
        auth = getattr(request, "authenticator", None)
        current = loc
        if not hasattr(self, "transactions"):
            self.transactions = []
            self.last_transaction = None

        for attempt in range(1, _MAX_TRANSACTION_ATTEMPTS + 1):
            generation = self._session_generation(request)
            current.generation = generation
            where = f"{current.kind} '{current.name}'"

            def replay(token, location=current):
                return self._replay(endpoint, location, token, request)

            tx = JwtVerificationTransaction(
                endpoint,
                current.token,
                current,
                generation,
                request=request,
                authenticator=auth,
                acceptance=(
                    lambda response, baseline: self._accepted(
                        response, baseline, auth
                    )
                ),
                baseline_acceptance=(
                    lambda response: self._baseline_accepted(response, auth)
                ),
                generation_getter=lambda: self._session_generation(request),
                binding_getter=(
                    lambda location=current: self._current_location(
                        request, location
                    )
                ),
                attempt=attempt,
                max_attempts=_MAX_TRANSACTION_ATTEMPTS,
            )
            self.transactions.append(tx)
            self.last_transaction = tx
            findings = []

            # The baseline is the original token replayed at the same location
            # and endpoint.  If the scan re-logs in while it is on the wire,
            # this transaction is discarded and retried with the *new* token.
            baseline = tx.establish_baseline(replay)
            if tx.refresh_observed:
                refreshed = self._retry_location(request, current, attempt)
                if refreshed is not None:
                    current = refreshed
                    continue
                output.info(
                    "JWT session changed during baseline replay for %s; "
                    "discarding the old baseline" % where
                )
                return
            if baseline is None or not tx.baseline_valid:
                # A protected endpoint rejecting the *original* token usually
                # means the scan's session expired.  If a form login is
                # configured, refresh it once and start a new transaction with
                # whatever token the login puts in the cookie jar.  The old
                # transaction is never revived.
                if (
                    baseline is not None
                    and not tx.refresh_observed
                    and self._should_reauthenticate(baseline, auth)
                    and self._reauthenticate(request, auth, attempt)
                ):
                    refreshed = self._current_location(request, current)
                    if refreshed is not None:
                        current = refreshed
                        continue
                self._report_offline_finding(
                    tx, where, secrets, output
                )
                output.info(
                    "Cannot validate JWT replay for %s (no authenticated "
                    "baseline / no --logged-in-check); ran offline checks only"
                    % where
                )
                return

            # Offline weak-secret brute never needs the server, but the
            # finding is still bound to this transaction's exact token bytes
            # and generation.  It is emitted only after the transaction is
            # proven to be current, so a re-login can never leave a finding
            # pointing at the previous session's JWT.
            weak = self._weak_secret_finding(tx, where, secrets)
            if weak is not None:
                findings.append(weak)

            # alg:none - signature not verified.
            none_accepted = False
            accepted_none_alg = None
            for header_alg in ("none", "None", "NONE"):
                claims = ju.decode_claims(tx.token)
                forged = ju.forge_alg_none(tx.token, claims=claims)
                # Re-mangle the header alg casing for the variant under test.
                forged = self._retag_alg(forged, header_alg)
                record = tx.replay_variant(
                    "alg:%s" % header_alg, forged, replay
                )
                if tx.refresh_observed or not tx.valid:
                    break
                if record is not None and record.accepted:
                    none_accepted = True
                    accepted_none_alg = header_alg
                    findings.append((
                        "JWT 'alg:%s' accepted in %s: the signature is not "
                        "verified, allowing authentication bypass "
                        "(CWE-347, API2)" % (header_alg, where),
                        self._sev("critical"),
                        "alg-none-accepted",
                        record,
                        ["alg=%s" % header_alg],
                    ))
                    break

            if tx.refresh_observed or not tx.valid:
                refreshed = self._retry_location(request, current, attempt)
                if refreshed is not None and tx.refresh_observed:
                    current = refreshed
                    continue
                return

            # Claim enforcement: an expired token minted via alg:none is
            # accepted.
            if none_accepted:
                expired = dict(ju.decode_claims(tx.token))
                expired["exp"] = 1  # 1970 - long expired
                forged = ju.forge_alg_none(tx.token, claims=expired)
                if accepted_none_alg:
                    forged = self._retag_alg(forged, accepted_none_alg)
                record = tx.replay_variant("expired", forged, replay)
                if tx.refresh_observed or not tx.valid:
                    refreshed = self._retry_location(request, current, attempt)
                    if refreshed is not None and tx.refresh_observed:
                        current = refreshed
                        continue
                    return
                if record is not None and record.accepted:
                    findings.append((
                        "JWT 'exp' claim is not enforced in %s: an expired "
                        "token is accepted (CWE-613/CWE-347)" % where,
                        self._sev("high"),
                        "exp-not-enforced",
                        record,
                        None,
                    ))

            # kid path-traversal to an empty key.
            forged = ju.forge_kid_empty(tx.token)
            record = tx.replay_variant("kid-empty", forged, replay)
            if tx.refresh_observed or not tx.valid:
                refreshed = self._retry_location(request, current, attempt)
                if refreshed is not None and tx.refresh_observed:
                    current = refreshed
                    continue
                return
            if record is not None and record.accepted:
                findings.append((
                    "JWT 'kid' path traversal accepted in %s: key resolves to "
                    "an empty file, so an empty-key HMAC token is honoured "
                    "(CWE-347)" % where,
                    self._sev("high"),
                    "kid-empty-key-accepted",
                    record,
                    None,
                ))

            # RS256->HS256 algorithm confusion (best effort: needs the public
            # key).
            if ju.is_rsa_alg(tx.token):
                pem = self._fetch_public_key(endpoint, request, logger)
                if pem:
                    forged = ju.forge_confusion(tx.token, pem)
                    record = tx.replay_variant(
                        "rs256-hs256", forged, replay
                    )
                    if tx.refresh_observed or not tx.valid:
                        refreshed = self._retry_location(
                            request, current, attempt
                        )
                        if refreshed is not None and tx.refresh_observed:
                            current = refreshed
                            continue
                        return
                    if record is not None and record.accepted:
                        findings.append((
                            "JWT RS256->HS256 algorithm confusion accepted in "
                            "%s: the RSA public key is honoured as an HMAC "
                            "secret (CWE-347)" % where,
                            self._sev("critical"),
                            "rs256-hs256-confusion-accepted",
                            record,
                            None,
                        ))

            if tx.refresh_observed or not tx.valid:
                refreshed = self._retry_location(request, current, attempt)
                if refreshed is not None and tx.refresh_observed:
                    current = refreshed
                    continue
                return
            if not tx.commit():
                refreshed = self._retry_location(request, current, attempt)
                if refreshed is not None and tx.refresh_observed:
                    current = refreshed
                    continue
                return

            # Final identity check immediately before emitting anything.  A
            # finding must never be produced from a transaction whose token,
            # location, endpoint or login generation has moved on.
            if not tx.binding_current():
                refreshed = self._retry_location(request, current, attempt)
                if refreshed is not None:
                    current = refreshed
                    continue
                return

            for title, severity, decision, record, extra in findings:
                if not tx.binding_current():
                    break
                parameter = "%s:%s:%s@%s" % (
                    tx.location.kind,
                    tx.location.name,
                    decision,
                    tx.token_fingerprint[:16],
                )
                evidence = tx.evidence(
                    decision=decision,
                    record=record,
                    extra=extra,
                    include_replay=(decision != "weak-hmac-secret"),
                )
                tx.findings.append({
                    "title": title,
                    "severity": severity,
                    "decision": decision,
                    "parameter": parameter,
                    "token": tx.token,
                    "location": tx.location.source,
                    "generation": tx.session_generation,
                    "endpoint": tx.endpoint,
                    "accepted": (
                        bool(record.accepted) if record is not None else False
                    ),
                    "evidence": evidence,
                })
                output.finding(
                    title,
                    severity=severity,
                    url=endpoint,
                    plugin="Jwt",
                    parameter=parameter,
                    evidence=evidence,
                    finding_type="jwt",
                    confidence="firm",
                )
            return

    def _retry_location(self, request, current, attempt):
        """The current token slot for a retry, or ``None`` when exhausted."""
        if attempt >= _MAX_TRANSACTION_ATTEMPTS:
            return None
        return self._current_location(request, current)

    def _weak_secret_finding(self, tx, where, secrets):
        """Build the offline weak-HMAC finding for this transaction."""
        if not ju.is_hmac_alg(tx.token):
            return None
        secret = ju.brute_hmac_secret(tx.token, secrets)
        if secret is None:
            return None
        try:
            alg = ju.decode_header(tx.token).get("alg")
        except Exception:
            alg = "?"
        return (
            "JWT signed with a weak/guessable HMAC secret (%s) in %s: "
            "'%s' - full token forgery is possible (CWE-347, API2)"
            % (alg, where, secret),
            self._sev("critical"),
            "weak-hmac-secret",
            None,
            ["secret=%s" % secret],
        )

    def _report_offline_finding(self, tx, where, secrets, output):
        """Emit the offline part of a token check when replay can't validate.

        This preserves the historical weak-secret behaviour (it does not need
        a live baseline), but only while the transaction's exact token bytes
        and login generation are still current.
        """
        weak = self._weak_secret_finding(tx, where, secrets)
        if weak is None or not tx.valid or not tx.binding_current():
            return
        title, severity, decision, record, extra = weak
        parameter = "%s:%s:%s@%s" % (
            tx.location.kind,
            tx.location.name,
            decision,
            tx.token_fingerprint[:16],
        )
        evidence = tx.evidence(
            decision=decision,
            record=record,
            extra=extra,
            include_replay=False,
        )
        tx.findings.append({
            "title": title,
            "severity": severity,
            "decision": decision,
            "parameter": parameter,
            "token": tx.token,
            "location": tx.location.source,
            "generation": tx.session_generation,
            "endpoint": tx.endpoint,
            "accepted": False,
            "evidence": evidence,
        })
        output.finding(
            title,
            severity=severity,
            url=tx.endpoint,
            plugin="Jwt",
            parameter=parameter,
            evidence=evidence,
            finding_type="jwt",
            confidence="firm",
        )

    @staticmethod
    def _reauthenticate(request, auth, attempt):
        """Refresh a form login once, for a retry with freshly issued tokens."""
        if attempt >= _MAX_TRANSACTION_ATTEMPTS:
            return False
        if auth is None or not getattr(auth, "has_login", False):
            return False
        try:
            login = getattr(request, "login", None)
            if callable(login):
                login()
            else:
                auth.login(
                    request.session,
                    getattr(request, "verify", False),
                    getattr(request, "timeout", None),
                )
        except Exception:
            return False
        return True

    @staticmethod
    def _should_reauthenticate(baseline, auth):
        """Whether a rejected baseline really looks like an expired session."""
        if baseline is None:
            return False
        if auth is None or not getattr(auth, "has_login", False):
            return False
        if baseline.status_code in _STATUS_UNAUTHORIZED:
            return True
        if baseline.same_endpoint:
            try:
                if auth.looks_logged_out(baseline):
                    return True
            except Exception:
                pass
        from urllib.parse import urlsplit
        path = (urlsplit(baseline.final_url or "").path or "").lower()
        return any(
            marker in path
            for marker in ("login", "log-in", "signin", "sign-in", "auth")
        )

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    @staticmethod
    def _sev(name):
        """Return a Severity if the report enum is available, else a string.

        Keeps the plugin working whether or not the finding-quality severity
        enrichment is present in this build.
        """
        try:
            from sitadel.report import Severity
            return getattr(Severity, name.upper())
        except Exception:
            return name

    @staticmethod
    def _retag_alg(forged_token, alg):
        """Rewrite the ``alg`` value in a forged token's header segment."""
        head_seg, rest = forged_token.split(".", 1)
        header = json.loads(ju.b64url_decode(head_seg))
        header["alg"] = alg
        return f"{ju.b64url_encode(json.dumps(header, separators=(',', ':')))}.{rest}"

    def _fetch_public_key(self, endpoint, request, logger):
        """Best-effort fetch of an RSA public key from common JWKS endpoints."""
        from urllib.parse import urlsplit
        parts = urlsplit(endpoint)
        origin = f"{parts.scheme}://{parts.netloc}"
        fresh = SingleRequest(
            timeout=getattr(request, "timeout", None),
            verify=getattr(request, "verify", False),
        )
        for path in ("/.well-known/jwks.json", "/jwks.json", "/.well-known/openid-configuration"):
            try:
                resp = fresh.send(url=origin + path, method="GET")
            except Exception:
                continue
            if resp is None or resp.status_code != 200:
                continue
            pem = self._jwks_to_pem(resp.text)
            if pem:
                return pem
        return None

    @staticmethod
    def _jwks_to_pem(body):
        try:
            data = json.loads(body)
        except Exception:
            return None
        keys = data.get("keys") if isinstance(data, dict) else None
        if not keys:
            return None
        for jwk in keys:
            if jwk.get("kty") != "RSA":
                continue
            try:
                from jwt.algorithms import RSAAlgorithm
                from cryptography.hazmat.primitives import serialization
                key = RSAAlgorithm.from_jwk(json.dumps(jwk))
                pem = key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                return pem.decode("ascii")
            except Exception:
                continue
        return None


# Friendly alias: callers/tests can import the transaction alongside the
# plugin without knowing the module's longer class name.
JwtTransaction = JwtVerificationTransaction
