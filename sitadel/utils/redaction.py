"""Single source of secret redaction, shared by every report surface.

The passive secret scanner must never let a raw credential reach any artifact
(page-body snapshots, finding evidence/URLs/titles, console output, or the
JSON/SARIF/HTML consumers). All of those surfaces call the functions in this
module so there is exactly one redaction implementation:

* :func:`mask_secret` turns one matched secret into a safe marker that keeps a
  few head/tail characters for triage but cannot be reversed;
* :func:`redact_text` masks every known secret anywhere in a string;
* :func:`redact_url` additionally masks secret values carried in a URL query;
* :func:`redact_finding`/:func:`redact_findings` apply the same pass to every
  string field of a report :class:`~sitadel.report.Finding`.

Redaction always happens *before* serialization, so JSON ``\\u`` escaping,
HTML entity encoding, write retries or producing a second output format can
only ever transform the already-masked text and never restore the original
value. All functions are idempotent: redacting redacted text is a no-op.
"""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlsplit, urlunsplit

# (label, pattern, firm?) — firm matches are high-precision; the rest are
# marked tentative because they can legitimately appear in page content. This
# list is the canonical pattern set used both for detection (the Secrets
# scanner) and for masking (every report consumer), so the two can never drift.
SECRET_PATTERNS: list[tuple[str, "re.Pattern[str]", bool]] = [
    ("AWS access key id", re.compile(r"AKIA[0-9A-Z]{16}"), True),
    ("Google API key", re.compile(r"AIza[0-9A-Za-z_\-]{35}"), True),
    ("Slack token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,48}"), True),
    ("Slack webhook", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+"), True),
    ("Stripe live secret key", re.compile(r"sk_live_[0-9A-Za-z]{24,}"), True),
    ("GitHub token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"), True),
    ("Google OAuth client secret", re.compile(r"GOCSPX-[0-9A-Za-z_\-]{20,}"), True),
    ("Private key block", re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"), True),
    ("JSON Web Token", re.compile(
        r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), False),
    ("Hardcoded secret assignment", re.compile(
        r"""(?i:(?:api[_-]?key|secret|token|passwd|password))"""
        r"""\s*[:=]\s*['"][A-Za-z0-9_\-]{16,}['"]"""), False),
]

# One alternation for the masking pass. Each alternative is wrapped in its own
# capture group so ``re.sub`` can mask whichever pattern matched without a
# second round of scanning that could miss overlapping occurrences.
_COMBINED = re.compile(
    "|".join("(%s)" % pattern.pattern for _, pattern, _ in SECRET_PATTERNS)
)


def mask_secret(match: str) -> str:
    """Return an irreversible marker for one matched secret.

    Only the first/last few characters are retained so triage still sees what
    kind of value was found, while the full credential is destroyed. Values of
    12 characters or less collapse to a head-only marker so a short secret can
    never be reconstructed from its head and tail together.
    """
    match = match.strip()
    if len(match) <= 12:
        return match[:2] + "***"
    return "%s...%s" % (match[:6], match[-4:])


def redact_text(text: str | None) -> str | None:
    """Mask every known secret occurring anywhere in ``text``.

    The masked output contains no fragment of the original value beyond the
    deliberately retained head/tail characters, so later JSON/HTML encoding
    cannot bring the secret back. Idempotent: already-masked markers do not
    match any secret pattern and are therefore left untouched.
    """
    if not text:
        return text
    return _COMBINED.sub(lambda m: mask_secret(m.group(0)), text)


def redact_url(url: str | None) -> str | None:
    """Redact secrets carried by a URL, including query-string values.

    A cloud token frequently leaks as a query parameter
    (``?token=AIza...``) where it sits split away from the pattern's usual
    context, so every query value is masked when it embeds a secret (or is
    itself a bare high-entropy credential). The scheme/host/path stay intact
    for triage. Non-URL or query-less strings fall through to
    :func:`redact_text`, which handles plain-text secrets in titles/evidence.
    """
    if not url:
        return url
    parts = urlsplit(url)
    if not parts.query:
        return redact_text(url)

    # parse_qsl keeps parameter order and percent-decoding consistent with the
    # values the browser/server would see.
    redacted_pairs = []
    for key, value in parse_qsl(parts.query, keep_blank_values=True):
        # Mask the whole value when it contains a recognizable secret or looks
        # like a bare credential on a sensitive parameter name.
        if _COMBINED.search(value) or _is_sensitive_param(key, value):
            value = mask_secret(value) if value else value
        else:
            value = redact_text(value)
        redacted_pairs.append((key, value))
    # Rebuild manually instead of via urlencode: mask markers only contain
    # [A-Za-z0-9.*] so they need no escaping, while untouched values keep
    # their original (un-decoded) representation.
    safe_query = "&".join("%s=%s" % (key, value) for key, value in redacted_pairs)
    safe_url = urlunsplit(
        (parts.scheme, parts.netloc, parts.path, safe_query, parts.fragment)
    )
    # Catch secrets that also appear outside the query (e.g. in the path).
    return redact_text(safe_url)


_SENSITIVE_QUERY_KEY = re.compile(
    r"(?i)(?:^|[_-])(api[_-]?key|secret|token|passwd|password|auth|credential)"
)

# Well-known cloud credential prefixes. A value beginning with one of these is
# a token even when its total length does not satisfy the full detector
# pattern (e.g. a GitHub token truncated in a query string), so the URL
# redactor must still mask it.
_CREDENTIAL_PREFIX = re.compile(
    r"^(?:AKIA|AIza|AGIA|ASIA|xox[baprs]-|gh[pousr]_|sk_live_|GOCSPX-|eyJ)"
)


def _is_sensitive_param(key: str, value: str) -> bool:
    """Whether ``key=value`` looks like a bare credential query parameter."""
    if not value:
        return False
    if _CREDENTIAL_PREFIX.search(value):
        return True
    if not _SENSITIVE_QUERY_KEY.search(key or ""):
        return False
    # Only treat reasonably long, non-trivial values as secrets so ordinary
    # flags like ``?token=1`` keep working unchanged.
    return len(value) >= 12 and " " not in value


# Finding fields that carry free-form text and therefore could embed a secret.
_TEXT_FIELDS = ("title", "url", "parameter", "evidence", "plugin",
                "cwe", "owasp", "wstg", "remediation")


def redact_finding(finding):
    """Apply the shared redaction pass to one report finding, in place.

    Every string field is treated as text except ``url``, which goes through
    :func:`redact_url` so query-string credentials are covered too. Works on
    any object exposing those attributes (duck-typed) to keep this module free
    of an import dependency on :mod:`sitadel.report`.
    """
    for field in _TEXT_FIELDS:
        value = getattr(finding, field, None)
        if not isinstance(value, str):
            continue
        if field == "url":
            setattr(finding, field, redact_url(value))
        else:
            setattr(finding, field, redact_text(value))
    other_urls = getattr(finding, "other_urls", None)
    if isinstance(other_urls, list):
        finding.other_urls = [redact_url(u) if isinstance(u, str) else u
                              for u in other_urls]
    return finding


def redact_findings(findings):
    """Redact a sequence of findings in place and return the same list."""
    for finding in findings:
        redact_finding(finding)
    return findings
