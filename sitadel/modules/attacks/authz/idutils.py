"""Shared helpers for the authorization (access-control) attack plugins.

The helpers in this module deliberately work on *objects* and their
*responses*, not just URL strings.  Authorization checks compare several
requests that must all describe the same object: session refreshes and
redirects can otherwise make a login page look like an anonymously reachable
resource.  Keeping URL canonicalisation, redirect detection and body
comparison here gives both authorization plugins one implementation of those
rules.
"""
from __future__ import annotations

import html
import posixpath
import re
from collections import Counter
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

# Query parameter names that usually reference an object.
ID_PARAMS = {
    "id", "uid", "user", "user_id", "userid", "account", "account_id",
    "pid", "oid", "num", "no", "doc", "docid", "file", "fileid", "order",
    "order_id", "invoice", "item", "item_id", "profile", "record",
}
UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I
)

_TOKEN_RE = re.compile(r"[^\W_]+", re.UNICODE)
_UUID_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    re.I,
)
_LONG_HEX_RE = re.compile(r"\b[0-9a-f]{16,}\b", re.I)
_LONG_TOKEN_RE = re.compile(r"\b[A-Za-z0-9+/_-]{24,}={0,2}\b")
_ISO_TIME_RE = re.compile(
    r"\b\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)?\b"
)
_EPOCH_TIME_RE = re.compile(r"\b(?:1[6-9]\d{8}|2[0-1]\d{8})\b")
_VOLATILE_ASSIGN_RE = re.compile(
    r"(?i)\b(?:csrf(?:[_-]?token)?|xsrf(?:[_-]?token)?|nonce|token|"
    r"request[_-]?id|trace[_-]?id|session[_-]?id|timestamp|ts)\b"
    r"[\"']?\s*[:=]\s*[\"']?[^\s<\"']{4,}"
)
_VOLATILE_INPUT_RE = re.compile(
    r"(?is)(<input\b[^>]*(?:name|id)\s*=\s*[\"'][^\"']*"
    r"(?:csrf|xsrf|nonce|token|authenticity)[^\"']*[\"'][^>]*"
    r"\bvalue\s*=\s*)[\"'][^\"']*[\"']"
)
_VOLATILE_ATTR_RE = re.compile(
    r"(?i)\b(?:nonce|data-nonce|csrf|xsrf|authenticity[_-]?token|"
    r"request[_-]?id|trace[_-]?id)\s*=\s*[\"'][^\"']*[\"']"
)
_CACHE_BUSTER_RE = re.compile(
    r"(?i)([?&](?:v|ver|cache|cb|ts|timestamp|_)=)[^&#\s\"']+"
)
_BANNER_BLOCK_RE = re.compile(
    r"(?is)<(div|section|aside|header|footer|ins|marquee|span|p|iframe)\b"
    r"(?=[^>]*(?:banner|advert|advertisement|promo|sponsor|notice|toast|"
    r"flash|ticker|rotator|carousel|dynamic|random|adsbygoogle|"
    r"ad[-_]?(?:slot|unit|container|wrapper)))"
    r"[^>]*>.*?</\1>"
)
_BANNER_LINE_RE = re.compile(
    r"(?im)^[ \t]*(?:dynamic[ \t]+)?(?:banner|promo|advert(?:isement)?|"
    r"notice)\b.*$"
)
_ACTIVE_CONTENT_RE = re.compile(
    r"(?is)<(script|style|template)\b[^>]*>.*?</\1>"
)
_COMMENT_RE = re.compile(r"(?is)<!--.*?-->")
_TAG_RE = re.compile(r"(?is)<[^>]+>")

_LOGIN_PATH_RE = re.compile(
    r"(?i)(?:^|/)(?:wp-)?(?:log[-_]?in|sign[-_]?in|sign[-_]?on|sso|"
    r"oauth|logout|auth(?:enticate)?)(?:[./?]|$)"
)
_LOGIN_BODY_RE = re.compile(
    r"(?i)(?:type\s*=\s*[\"']?password|name\s*=\s*[\"']?"
    r"(?:password|passwd|passcode)|please\s+(?:log|sign)\s*in|"
    r"sign\s*in\s+to\s+continue|session\s+(?:has\s+)?expired|"
    r"authentication\s+required|you\s+must\s+(?:be\s+)?log(?:ged)?\s*in)"
)
_MISSING_BODY_RE = re.compile(
    r"(?i)(?:\b404\b|soft\s*[-_ ]?\s*404|not\s+found|"
    r"could\s+not\s+be\s+found|not\s+available|unavailable|"
    r"does\s+not\s+exist|no\s+such\s+(?:page|object|resource)|"
    r"page\s+you\s+(?:requested|are\s+looking\s+for)|"
    r"页面不存在|未找到|找不到|不存在)"
)


def object_refs(url):
    """Return references to object identifiers in ``url``.

    Each reference is ``(location, key, value)`` where location is ``"query"``
    (key = parameter name) or ``"path"`` (key = the path segment itself).
    """
    parts = urlsplit(url)
    refs = []
    for key, value in parse_qsl(parts.query, keep_blank_values=True):
        if key.lower() in ID_PARAMS or value.isdigit() or UUID_RE.match(value):
            refs.append(("query", key, value))
    for segment in parts.path.split("/"):
        if segment.isdigit() or UUID_RE.match(segment):
            refs.append(("path", segment, segment))
    return refs


def replace_id(url, location, key, new_value):
    """Return ``url`` with the identified object id replaced by ``new_value``."""
    parts = urlsplit(url)
    if location == "query":
        params = parse_qsl(parts.query, keep_blank_values=True)
        params = [(k, str(new_value) if k == key else v) for k, v in params]
        query = urlencode(params)
        return urlunsplit(
            (parts.scheme, parts.netloc, parts.path, query, parts.fragment)
        )
    # path segment
    segments = [str(new_value) if s == key else s for s in parts.path.split("/")]
    return urlunsplit(
        (parts.scheme, parts.netloc, "/".join(segments), parts.query, parts.fragment)
    )


def object_parameter(url):
    """Human-readable description of the object references in ``url``."""
    refs = object_refs(url)
    return ", ".join("%s:%s=%s" % ref for ref in refs) or None


def _normalise_path(path):
    path = path or "/"
    normalised = posixpath.normpath(path)
    if path.startswith("/") and not normalised.startswith("/"):
        normalised = "/" + normalised
    if normalised == ".":
        normalised = "/"
    if normalised != "/":
        normalised = normalised.rstrip("/")
    return normalised


def canonical_url(url):
    """A stable identity for a URL (no fragment, sorted query)."""
    if not url:
        return ""
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    try:
        port = parts.port
    except ValueError:
        port = None
    if port is not None and not (
        (scheme == "http" and port == 80)
        or (scheme == "https" and port == 443)
    ):
        host = "%s:%s" % (host, port)
    query = urlencode(sorted(parse_qsl(parts.query, keep_blank_values=True)))
    return urlunsplit((scheme, host, _normalise_path(parts.path), query, ""))


def url_origin(url):
    """Return the normalised origin (scheme + host + non-default port)."""
    if not url:
        return ""
    parts = urlsplit(url)
    scheme = (parts.scheme or "").lower()
    host = (parts.hostname or "").lower()
    if not scheme or not host:
        return ""
    try:
        port = parts.port
    except ValueError:
        port = None
    if ":" in host:
        host = "[%s]" % host
    if port is not None and not (
        (scheme == "http" and port == 80)
        or (scheme == "https" and port == 443)
    ):
        host = "%s:%s" % (host, port)
    return "%s://%s" % (scheme, host)


def response_text(response):
    """Best-effort body extraction for requests responses and test doubles."""
    if response is None:
        return ""
    text = getattr(response, "text", None)
    if isinstance(text, str):
        return text
    if isinstance(text, (bytes, bytearray)):
        return bytes(text).decode("utf-8", "replace")
    body = getattr(response, "body", None)
    if isinstance(body, (bytes, bytearray)):
        return bytes(body).decode("utf-8", "replace")
    if isinstance(body, str):
        return body
    content = getattr(response, "content", None)
    if isinstance(content, (bytes, bytearray)):
        return bytes(content).decode("utf-8", "replace")
    return ""


def response_status(response):
    try:
        return int(getattr(response, "status_code", 0) or 0)
    except (TypeError, ValueError):
        return 0


def response_url(response, fallback):
    """The final URL of a response, falling back to the requested URL."""
    if response is not None:
        for attr in ("url", "final_url"):
            value = getattr(response, attr, None)
            if isinstance(value, str) and value:
                # ``requests`` always exposes an absolute URL here, but test
                # doubles sometimes use a relative Location/Location-like URL.
                return urljoin(fallback, value)
    return fallback


def same_object_url(requested, final):
    """Whether ``final`` still addresses the object requested in ``requested``.

    Redirects to a login page, a different object id, or a different path are
    not accepted.  Non-object query parameters (language, tracking, cache
    busters) may be added or removed by a canonicalising redirect, and a
    trailing slash is considered equivalent.
    """
    if not requested or not final:
        return False
    req = urlsplit(requested)
    fin = urlsplit(final)
    if (req.hostname or "").lower() != (fin.hostname or "").lower():
        return False
    if _normalise_path(req.path) != _normalise_path(fin.path):
        return False
    req_refs = _identity_refs(requested)
    fin_refs = _identity_refs(final)
    if req_refs:
        return req_refs == fin_refs
    # No object refs: allow a canonicalising redirect to add non-object query
    # parameters, but never let it silently drop the original query.
    req_query = Counter(parse_qsl(req.query, keep_blank_values=True))
    fin_query = Counter(parse_qsl(fin.query, keep_blank_values=True))
    return req_query == fin_query or req_query <= fin_query


def _identity_refs(url):
    """Object references that identify the resource (not numeric filters)."""
    refs = object_refs(url)
    explicit = [
        ref for ref in refs
        if ref[0] == "path" or ref[1].lower() in ID_PARAMS
    ]
    return Counter(explicit or refs)


def missing_object_url(url):
    """A same-shape object URL that should not exist, for soft-404 tests."""
    for location, key, value in object_refs(url):
        if value.isdigit():
            replacement = "987654321"
        elif UUID_RE.match(value):
            replacement = "00000000-0000-4000-8000-000000000000"
        else:
            continue
        candidate = replace_id(url, location, key, replacement)
        if canonical_url(candidate) != canonical_url(url):
            return candidate
    return None


def missing_path_url(url):
    """A random path on the target origin, for site-wide soft-404 tests."""
    parts = urlsplit(url)
    base = posixpath.dirname(parts.path or "/") or "/"
    if not base.endswith("/"):
        base += "/"
    return urlunsplit(
        (parts.scheme, parts.netloc,
         base + "sitadel-authz-not-here-4f3c9a1e", "", "")
    )


def looks_like_login_url(url):
    parts = urlsplit(url or "")
    return bool(_LOGIN_PATH_RE.search(parts.path or ""))


def looks_like_login_body(body):
    return bool(body and _LOGIN_BODY_RE.search(body))


def looks_like_missing_body(body):
    return bool(body and _MISSING_BODY_RE.search(body))


def normalized_body(text):
    """Normalise a response body for comparison.

    Volatile values such as CSRF tokens, request ids, UUIDs and timestamps are
    replaced before tags/whitespace are collapsed.  Dynamic ad/banner blocks
    are removed as a whole, because their content can change on every request
    even though the object itself is identical.
    """
    if not text:
        return ""
    value = str(text)
    value = _COMMENT_RE.sub(" ", value)
    value = _ACTIVE_CONTENT_RE.sub(" ", value)
    value = _BANNER_BLOCK_RE.sub(" ", value)
    value = _BANNER_LINE_RE.sub(" ", value)
    value = _CACHE_BUSTER_RE.sub(r"\1<volatile>", value)
    value = _VOLATILE_INPUT_RE.sub(r'\1"<volatile>"', value)
    value = _VOLATILE_ATTR_RE.sub(" volatile=<value>", value)
    value = _VOLATILE_ASSIGN_RE.sub(" volatile=<value>", value)
    value = _UUID_RE.sub(" <uuid> ", value)
    value = _ISO_TIME_RE.sub(" <time> ", value)
    value = _EPOCH_TIME_RE.sub(" <time> ", value)
    value = _LONG_HEX_RE.sub(" <hex> ", value)
    value = _LONG_TOKEN_RE.sub(" <token> ", value)
    value = _TAG_RE.sub(" ", value)
    value = html.unescape(value).lower()
    return re.sub(r"\s+", " ", value).strip()


def _overlap(left, right):
    if not left or not right:
        return 0.0, 0.0
    intersection = sum((left & right).values())
    union = sum((left | right).values())
    jaccard = intersection / union if union else 0.0
    return jaccard, float(intersection)


def equivalent(left, right):
    """Whether two bodies represent the same object after normalisation."""
    if not left or not right:
        return False
    normal_left = normalized_body(left)
    normal_right = normalized_body(right)
    if not normal_left or not normal_right:
        return False
    if normal_left == normal_right:
        return True
    left_tokens = Counter(_TOKEN_RE.findall(normal_left))
    right_tokens = Counter(_TOKEN_RE.findall(normal_right))
    if not left_tokens or not right_tokens:
        return False
    if max(len(normal_left), len(normal_right)) < 24:
        return False
    jaccard, _ = _overlap(left_tokens, right_tokens)
    if jaccard >= 0.95:
        return True
    # A dynamic banner (or a small extra navigation fragment) can add a
    # handful of tokens without changing the object.  Treat near-containment
    # as equality too, while still catching a changed object id.
    intersection = sum((left_tokens & right_tokens).values())
    smaller = min(sum(left_tokens.values()), sum(right_tokens.values()))
    larger = max(sum(left_tokens.values()), sum(right_tokens.values()))
    containment = intersection / smaller if smaller else 0.0
    extra = (larger - intersection) / larger if larger else 0.0
    return containment >= 0.97 and extra <= 0.08


def similar(a, b, tolerance=0.1):
    """True when two response bodies are of comparable, non-trivial size."""
    if not a or not b:
        return False
    normal_a = normalized_body(a)
    normal_b = normalized_body(b)
    if not normal_a or not normal_b:
        return False
    if normal_a == normal_b:
        return True
    longest = max(len(normal_a), len(normal_b))
    if longest < 50:
        return False
    if abs(len(normal_a) - len(normal_b)) / longest > tolerance:
        return False
    left = Counter(_TOKEN_RE.findall(normal_a))
    right = Counter(_TOKEN_RE.findall(normal_b))
    jaccard, _ = _overlap(left, right)
    return jaccard >= 0.70


def different(a, b):
    """True when two response bodies clearly describe distinct objects."""
    if not a or not b:
        return False
    normal_a = normalized_body(a)
    normal_b = normalized_body(b)
    if not normal_a or not normal_b or normal_a == normal_b:
        return False
    if max(len(str(a)), len(str(b))) <= 50:
        return False
    # For IDOR, a difference that survives volatile-content normalisation is
    # meaningful.  Only collapse near-identical bodies, where a dynamic
    # fragment may have escaped the banner/token patterns above.
    left = Counter(_TOKEN_RE.findall(normal_a))
    right = Counter(_TOKEN_RE.findall(normal_b))
    if left and right:
        jaccard, _ = _overlap(left, right)
        intersection = sum((left & right).values())
        containment = intersection / min(sum(left.values()), sum(right.values()))
        if jaccard >= 0.985 and containment >= 0.99:
            return False
    return True


def soft_404_miss(body, fake_object, missing_path=None):
    """Whether a 200 body is a soft-404 rather than a real object.

    ``fake_object`` and ``missing_path`` are response records/doubles with
    ``status_code`` and ``text``/``body`` attributes.
    """
    if not body:
        return False
    baselines = [
        record for record in (fake_object, missing_path)
        if record is not None and response_status(record) == 200
    ]
    if not baselines:
        return False
    body_text = response_text(body) if not isinstance(body, str) else body

    # A missing marker is the strongest signal, even when the error page is
    # rendered with the site's normal chrome and dynamic banners.
    for record in baselines:
        baseline = response_text(record)
        if looks_like_missing_body(baseline) and equivalent(body_text, baseline):
            return True

    # Generic "everything is 200" sites can have no missing marker.  A
    # redirect of either miss probe is a concrete soft-404 signal.  Without a
    # marker or redirect, an endpoint that returns the same valid document for
    # every id is treated as a real exposure (not a miss).
    fake = fake_object
    path = missing_path
    if fake is not None and path is not None:
        fake_text = response_text(fake)
        path_text = response_text(path)
        if (
            response_status(fake) == 200
            and response_status(path) == 200
            and (
                bool(getattr(fake, "redirected", False))
                or bool(getattr(path, "redirected", False))
            )
            and equivalent(body_text, fake_text)
            and equivalent(fake_text, path_text)
        ):
            return True
    return False
