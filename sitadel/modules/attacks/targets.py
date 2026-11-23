"""Injectable-target model shared by every injection surface.

A :class:`Target` is a uniform, *self-describing* description of something to
inject into: an HTML query string, an HTML form, or an API endpoint that takes
a JSON/XML/form body.  The important part for the attack phase is that a target
carries its **own** parameter location and provenance.  Consumers must never
infer "body" from a method, or recover old query parameters from a URL, because
a page can change shape between crawl attempts (for example a GET form becomes
a POST form at the same endpoint).

Producers (the crawler, API discovery, ...) emit targets through a
:class:`TargetLedger`.  The ledger versions complete page/spec snapshots so a
retry can replace an older target shape instead of leaving stale query
parameters in the attack profile.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field, replace
from hashlib import sha256
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from xml.sax.saxutils import escape as _xml_escape

# Body encodings we know how to taint.
BODY_FORMATS = ("form", "json", "xml")

# Parameter locations carried by a target.  A target has exactly one location;
# a request that needs both query and body parameters is represented by two
# targets (see API discovery), so each probe has unambiguous attribution.
TARGET_LOCATIONS = ("query", "body")

# Sources whose targets describe a crawled page.  When a page/spec snapshot is
# replaced, older page-derived targets for the same endpoint are retired.
PAGE_SOURCES = frozenset({"crawl", "page", "form", "legacy"})

_CONTENT_TYPE = {
    "form": "application/x-www-form-urlencoded",
    "json": "application/json",
    "xml": "application/xml",
}


def endpoint_of_url(url: str) -> str:
    """Return the canonical endpoint (scheme + host + path) for ``url``.

    Query strings and fragments are deliberately dropped: target identity is
    about where parameters are sent, not their sample/payload values.
    """
    parts = urlsplit(str(url or ""))
    return urlunsplit(
        (
            parts.scheme.lower(),
            parts.netloc.lower(),
            parts.path or "/",
            "",
            "",
        )
    )


def _ordered_unique(values) -> tuple:
    seen = set()
    result = []
    for value in values:
        key = str(value)
        if key not in seen:
            seen.add(key)
            result.append(key)
    return tuple(result)


@dataclass
class Target:
    """A single injectable request.

    ``location`` is the authoritative parameter location:

    * ``"query"`` — taint parameter values in ``url``;
    * ``"body"`` — taint ``params`` using ``body_format`` and leave the URL
      (including any fixed query parameters) untouched.

    For backwards compatibility ``location`` may be omitted.  It is then
    inferred from ``body_format``/``method``; old plugins that construct a body
    target with ``body_format="json"`` keep working.  New producers should
    always set it explicitly.

    ``source``/``source_url`` identify the producer (``crawl``, ``form``,
    ``api`` or ``legacy``) and the page/spec that supplied the target.
    ``generation`` is assigned by :class:`TargetLedger` when a complete page or
    spec snapshot is recorded.  A finding can therefore retain the exact target
    generation that produced it.

    ``fixed`` holds parameters that must be sent **verbatim** rather than
    tainted — hidden/CSRF form fields captured at crawl time.
    """

    url: str
    method: str = "GET"
    headers: dict = field(default_factory=dict)
    body_format: str | None = None
    params: dict = field(default_factory=dict)
    fixed: dict = field(default_factory=dict)
    location: str | None = None
    source: str = "legacy"
    source_url: str | None = None
    generation: int = 0

    def __post_init__(self) -> None:
        self.url = str(self.url or "")
        self.method = str(self.method or "GET").upper()
        self.headers = dict(self.headers or {})
        self.params = dict(self.params or {})
        self.fixed = dict(self.fixed or {})

        if self.body_format is not None:
            self.body_format = str(self.body_format).lower()
            if self.body_format not in BODY_FORMATS:
                raise ValueError(f"unknown body_format: {self.body_format}")

        if self.location is None:
            self.location = "body" if self.body_format in BODY_FORMATS else "query"
        else:
            self.location = str(self.location).lower()
        if self.location not in TARGET_LOCATIONS:
            raise ValueError(f"unknown target location: {self.location}")

        if self.location == "body" and self.body_format is None:
            # Legacy body targets occasionally omitted the encoding.  A form is
            # the safest wire representation for a non-GET request with fields.
            self.body_format = "form"
        if self.location == "query" and self.body_format is not None:
            raise ValueError(
                "a query target cannot also define a body_format; "
                "emit two targets for query+body requests"
            )

        self.source = str(self.source or "legacy").lower()
        if self.source_url is not None:
            self.source_url = str(self.source_url)
        try:
            self.generation = int(self.generation or 0)
        except (TypeError, ValueError):
            self.generation = 0

    # -- compatibility / convenience aliases --------------------------------
    @property
    def parameter_location(self) -> str:
        """Alias for :attr:`location` (the parameter's wire location)."""
        return self.location

    @property
    def param_location(self) -> str:
        """Alias for :attr:`location`."""
        return self.location

    @property
    def target_source(self) -> str:
        """Alias for :attr:`source`."""
        return self.source

    @property
    def target_generation(self) -> int:
        """Alias for :attr:`generation`."""
        return self.generation

    @property
    def endpoint(self) -> str:
        """Canonical scheme+host+path for this target."""
        return endpoint_of_url(self.url)

    @property
    def query_pairs(self) -> tuple[tuple[str, str], ...]:
        return tuple(parse_qsl(urlsplit(self.url).query, keep_blank_values=True))

    @property
    def query_parameter_names(self) -> tuple[str, ...]:
        return _ordered_unique(name for name, _ in self.query_pairs)

    @property
    def injected_parameter_names(self) -> tuple[str, ...]:
        """Names this target actually taints.

        Query targets taint every URL parameter except ``fixed``.  Body
        targets taint ``params``; an empty body target has the same implicit
        ``input`` field as :func:`taint_body`.
        """
        if self.location == "query":
            fixed = set(self.fixed)
            return tuple(
                name for name in self.query_parameter_names if name not in fixed
            )
        names = _ordered_unique(self.params)
        if names or self.fixed:
            return names
        return ("input",)

    @property
    def parameter_label(self) -> str | None:
        names = self.injected_parameter_names
        return ",".join(names) if names else None

    @property
    def identity(self) -> tuple:
        """Stable shape identity, independent of values/order/provenance.

        Two targets with the same endpoint, method, parameter location, body
        encoding and parameter names are the same injectable shape.  Query
        parameter order, percent-encoding, sample values and an OpenAPI
        ``$ref``'s expansion do not change it.  GET/query and POST/body are
        deliberately different identities.
        """
        parts = urlsplit(self.url)
        query_names = tuple(sorted(set(self.query_parameter_names)))
        injected = tuple(sorted(set(self.injected_parameter_names)))
        fixed = tuple(sorted(set(self.fixed)))
        return (
            parts.scheme.lower(),
            parts.netloc.lower(),
            parts.path or "/",
            self.method,
            self.location,
            self.body_format or "",
            query_names,
            injected,
            fixed,
        )

    @property
    def signature(self) -> tuple:
        """Alias for :attr:`identity` used by crawler de-duplication."""
        return self.identity

    @property
    def target_id(self) -> str:
        """Short stable id for a target shape (safe for reports/evidence)."""
        return sha256(repr(self.identity).encode("utf-8")).hexdigest()[:16]

    def with_generation(self, generation: int, source_url: str | None = None
                        ) -> "Target":
        """Return a copy stamped with ``generation`` and optional provenance."""
        updates = {"generation": int(generation)}
        if source_url is not None:
            updates["source_url"] = source_url
        return replace(self, **updates)

    def describe(self) -> str:
        if self.body_format:
            return f"{self.method} {self.url} ({self.body_format} body)"
        return self.url

    def describe_provenance(self) -> str:
        bits = [self.method, self.location, self.source]
        if self.source_url:
            bits.append(f"from {self.source_url}")
        if self.generation:
            bits.append(f"generation {self.generation}")
        return " ".join(bits)


def taint_url(url: str, payload: str, fixed=()) -> str | None:
    """Rebuild ``url`` with each query parameter value replaced by ``payload``.

    Parameter names listed in ``fixed`` keep their existing value.  Returns
    ``None`` when there are no query parameters to inject into.
    """
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    if not pairs:
        return None
    fixed = set(fixed)
    tainted = [
        (name, value if name in fixed else payload) for name, value in pairs
    ]
    return urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urlencode(tainted), parts.fragment)
    )


def taint_body(params: dict, payload: str, body_format: str, fixed: dict = None) -> str:
    """Encode ``params`` with every value replaced by ``payload``.

    Supports ``json`` (object), ``xml`` (``<root>`` with a child per param) and
    ``form`` (url-encoded).  ``fixed`` fields (hidden/CSRF) are merged in
    **verbatim** so token-protected forms submit a valid token.
    """
    fixed = fixed or {}
    names = list(params)
    if not names and not fixed:
        names = ["input"]
    if body_format == "json":
        data = {name: payload for name in names}
        data.update(fixed)
        return json.dumps(data)
    if body_format == "xml":
        body = "".join(
            f"<{name}>{_xml_escape(payload)}</{name}>" for name in names
        )
        body += "".join(
            f"<{name}>{_xml_escape(str(value))}</{name}>"
            for name, value in fixed.items()
        )
        return f"<root>{body}</root>"
    if body_format == "form":
        data = {name: payload for name in names}
        data.update(fixed)
        return urlencode(data)
    raise ValueError(f"unknown body_format: {body_format}")


def taint_target(target: Target, payload: str) -> dict | None:
    """Return ``SingleRequest.send`` kwargs that inject ``payload``.

    The decision is made **only** from ``target.location``.  In particular, a
    body target with an old query string in its URL does not parse that query
    into the body, and a query target never writes a body.  ``None`` means the
    target has nothing to inject into.
    """
    if target.location == "body":
        body = taint_body(target.params, payload, target.body_format, target.fixed)
        headers = dict(target.headers)
        headers.setdefault("Content-Type", _CONTENT_TYPE[target.body_format])
        method = target.method if target.method != "GET" else "POST"
        return {
            "url": target.url,
            "method": method,
            "payload": body,
            "headers": headers,
        }

    tainted = taint_url(target.url, payload, fixed=target.fixed.keys())
    if tainted is None:
        return None
    return {
        "url": tainted,
        "method": target.method or "GET",
        "payload": None,
        "headers": dict(target.headers) or None,
    }


@dataclass(frozen=True)
class TargetProbe:
    """Immutable snapshot of one tainted target/request.

    The attack runner reports findings from this object rather than re-reading
    the mutable target or deriving parameter names from the URL.  That keeps
    the request that was sent and the finding attribution on the same target
    generation.
    """

    target_id: str
    generation: int
    endpoint: str
    url: str
    method: str
    location: str
    body_format: str | None
    source: str
    source_url: str | None
    parameter: str | None
    payload: str
    headers: dict | None

    @property
    def request_kwargs(self) -> dict:
        return {
            "url": self.url,
            "method": self.method,
            "payload": self.payload if self.location == "body" else None,
            "headers": self.headers,
        }


def probe_target(target: Target, payload: str) -> TargetProbe | None:
    """Taint ``target`` once and return both request and attribution data."""
    kwargs = taint_target(target, payload)
    if kwargs is None:
        return None
    body_payload = kwargs.get("payload")
    return TargetProbe(
        target_id=target.target_id,
        generation=target.generation,
        endpoint=target.endpoint,
        url=kwargs["url"],
        method=kwargs["method"],
        location=target.location,
        body_format=target.body_format,
        source=target.source,
        source_url=target.source_url,
        parameter=target.parameter_label,
        payload=body_payload if body_payload is not None else payload,
        headers=kwargs.get("headers"),
    )


def merge_targets(targets) -> list[Target]:
    """De-duplicate targets by shape, keeping the last occurrence.

    This is intentionally value/order independent.  It prevents duplicate
    probes for the same shape while preserving genuinely different shapes such
    as GET/query and POST/body on one endpoint.
    """
    merged: list[Target] = []
    index: dict[tuple, int] = {}
    for target in targets or []:
        key = target.identity
        existing = index.get(key)
        if existing is None:
            index[key] = len(merged)
            merged.append(target)
        else:
            merged[existing] = target
    return merged


def wire_shape(target: Target) -> tuple:
    """Method/location/encoding part of a target shape (no parameter names)."""
    return (target.method, target.location, target.body_format or "")


class TargetLedger:
    """Versioned collection of the targets currently in scope for a scan.

    Producers submit **complete snapshots**:

    * :meth:`record_page` retires every target previously owned by that page
      and every older page-derived target for the endpoint(s) in the new
      snapshot.  A GET form that becomes a POST form therefore leaves only the
      POST/body shape in the attack profile.
    * :meth:`record_api` does the same for one spec source/endpoint set, so an
      OpenAPI document retry cannot mix old and new parameter locations.

    Legacy callers that only have a flat list can use :meth:`extend` (or the
    alias :meth:`add`); this keeps old plugins/tests working without weakening
    the snapshot semantics for the built-in producers.
    """

    def __init__(self, targets=None):
        self._targets: list[Target] = []
        self._generation = 0
        self._lock = threading.RLock()
        if targets:
            self.extend(targets)

    def __len__(self) -> int:
        with self._lock:
            return len(self._targets)

    def __iter__(self):
        return iter(self.snapshot())

    @property
    def generation(self) -> int:
        return self._generation

    def snapshot(self) -> list[Target]:
        with self._lock:
            return list(self._targets)

    def reset(self) -> None:
        with self._lock:
            self._targets = []
            self._generation = 0

    def _next_generation(self) -> int:
        self._generation += 1
        return self._generation

    @staticmethod
    def _prepare(target: Target, *, generation: int, source: str | None = None,
                 source_url: str | None = None) -> Target:
        updates: dict = {"generation": generation}
        if source is not None:
            updates["source"] = source
        if source_url is not None:
            updates["source_url"] = source_url
        return replace(target, **updates)

    def record_page(self, page_url: str, targets) -> list[Target]:
        """Record the complete target snapshot extracted from ``page_url``."""
        with self._lock:
            return self._record_page(page_url, targets)

    def _record_page(self, page_url: str, targets) -> list[Target]:
        """Record the complete target snapshot extracted from ``page_url``."""
        page_url = str(page_url)
        generation = self._next_generation()
        prepared: list[Target] = []
        for target in targets or []:
            source = target.source
            if source == "legacy":
                source = "form" if target.body_format is not None else "crawl"
            prepared.append(
                self._prepare(
                    target,
                    generation=generation,
                    source=source,
                    source_url=page_url,
                )
            )
        prepared = merge_targets(prepared)
        own_endpoint = endpoint_of_url(page_url)
        # Only the fetched page's own endpoint and explicit forms are
        # authoritative observations of a shape.  A plain link to another
        # endpoint must not overwrite what a direct fetch of that endpoint
        # already told us.
        authoritative = {
            target.endpoint
            for target in prepared
            if target.endpoint == own_endpoint or target.source == "form"
        }
        # Likewise, a link discovered on another page must not introduce a
        # second shape for an endpoint whose page/form shape is already known.
        known_shapes: dict[str, set[tuple]] = {}
        for target in self._targets:
            if target.source in {"page", "form"}:
                known_shapes.setdefault(target.endpoint, set()).add(
                    wire_shape(target)
                )
        prepared = [
            target for target in prepared
            if not (
                target.endpoint in known_shapes
                and target.endpoint != own_endpoint
                and target.source not in {"page", "form"}
                and wire_shape(target) not in known_shapes[target.endpoint]
            )
        ]

        keep = []
        for target in self._targets:
            # A page snapshot is complete: anything previously owned by this
            # page and not present now is stale.
            if target.source_url == page_url:
                continue
            # A later page observation is authoritative for its own endpoint.
            # This is what retires a link-derived GET target when the endpoint
            # is subsequently seen as a POST body.
            if target.source in PAGE_SOURCES and target.endpoint in authoritative:
                # A direct page/form observation supersedes an older shape only
                # when the method/location/encoding changed.  Distinct query
                # parameter sets on the same GET/query surface remain covered.
                if any(
                    new.endpoint == target.endpoint
                    and wire_shape(new) != wire_shape(target)
                    for new in prepared
                ):
                    continue
            keep.append(target)

        keep.extend(prepared)
        self._targets = merge_targets(keep)
        return list(prepared)

    def record_api(self, spec_url: str, targets) -> list[Target]:
        """Record the complete target snapshot extracted from an API spec."""
        with self._lock:
            return self._record_api(spec_url, targets)

    def _record_api(self, spec_url: str, targets) -> list[Target]:
        """Record the complete target snapshot extracted from an API spec."""
        spec_url = str(spec_url)
        generation = self._next_generation()
        prepared = [
            self._prepare(
                target,
                generation=generation,
                source="api",
                source_url=spec_url,
            )
            for target in (targets or [])
        ]
        prepared = merge_targets(prepared)
        endpoints = {target.endpoint for target in prepared}

        keep = []
        for target in self._targets:
            if target.source == "api" and (
                target.source_url == spec_url or target.endpoint in endpoints
            ):
                continue
            keep.append(target)

        keep.extend(prepared)
        # If an API target has exactly the same shape as a page target, the API
        # description is authoritative; merge_targets keeps the later entry.
        self._targets = merge_targets(keep)
        return list(prepared)

    def extend(self, targets, *, source: str | None = None) -> list[Target]:
        """Add legacy/flat targets, stamping untagged entries with a generation."""
        with self._lock:
            return self._extend(targets, source=source)

    def _extend(self, targets, *, source: str | None = None) -> list[Target]:
        """Add legacy/flat targets, stamping untagged entries with a generation."""
        generation = self._next_generation()
        prepared = []
        for target in targets or []:
            gen = target.generation or generation
            prepared.append(
                self._prepare(
                    target,
                    generation=gen,
                    source=source,
                    source_url=target.source_url,
                )
            )
        if prepared:
            self._generation = max(
                self._generation,
                max(target.generation for target in prepared),
            )
        self._targets = merge_targets([*self._targets, *prepared])
        return prepared

    # Friendly aliases for external/old plugins.
    add = extend
    replace_page = record_page
    replace_api = record_api


# Descriptive aliases; external integrations can use whichever name reads best.
TargetSet = TargetLedger
TargetRegistry = TargetLedger
TargetCatalog = TargetLedger
