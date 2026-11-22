"""Single target transaction shared by every scan stage.

A scan has exactly one *scope*: the set of hosts the operator authorized us to
touch. Historically that boundary lived only in :class:`SingleRequest` as a
last-line wire guard, while the API-discovery producer happily turned an
OpenAPI ``servers`` entry (or a Swagger ``basePath``) pointing at a third
party into an absolute, fully injectable :class:`Target`. The request layer
then skipped each off-target probe — but only after discovery had enumerated
the foreign host, the attack phase had scheduled its payloads, and a finding
could still be attributed to it. In other words, every stage owned a slightly
different idea of "the target".

:class:`TargetScope` is that single idea. It is built once from the scan
target (plus any explicitly authorized extra hosts) and handed to the spec
producer, the request factory, and the finding collector so they all make the
same allow/deny decision on the same host set:

* spec source fetching, ``servers``/``basePath`` resolution and endpoint
  construction filter against it *before* any request is scheduled;
* :meth:`SingleRequest.send` keeps enforcing it on the wire (including
  followed redirects and the re-authentication retry);
* :class:`~sitadel.utils.output.Output` refuses to record a finding whose URL
  escaped it, so off-target content can never reach the report.

Host comparison is intentionally host-only (case-insensitive, no scheme or
port): an explicit scope host covers every port/scheme the service exposes,
matching how :class:`SingleRequest` already scopes requests. A URL without a
parseable host (a relative reference) can only resolve against an in-scope
base, so it is always considered in scope.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlsplit


def host_of(url: str) -> str:
    """Lower-cased host component of ``url`` (``""`` when unparseable)."""
    try:
        return (urlsplit(url).hostname or "").lower()
    except Exception:
        return ""


@dataclass(frozen=True)
class TargetScope:
    """The immutable host allow-list of one scan (one target transaction).

    ``hosts`` always contains the scan target's host plus every explicitly
    authorized extra host (CLI ``--scope-host`` / config ``http.scope_hosts``).
    An empty instance means *unrestricted* and only exists for legacy
    url-less construction (and unit tests that build requests directly).
    """

    hosts: frozenset[str] = field(default_factory=frozenset)

    @classmethod
    def from_url(cls, url: str | None, extra_hosts=()) -> "TargetScope":
        """Build a scope from a target URL and explicit extra in-scope hosts."""
        hosts = {h.lower() for h in (extra_hosts or []) if h}
        if url:
            host = host_of(url)
            if host:
                hosts.add(host)
        return cls(frozenset(hosts))

    def allows(self, url: str) -> bool:
        """Whether a request/finding for ``url`` stays inside the transaction.

        An empty scope is unrestricted (back-compat for url-less factories).
        A host-less reference (relative/opaque) is in scope: it can only be
        resolved against an in-scope base.
        """
        if not self.hosts:
            return True
        host = host_of(url)
        return host in self.hosts if host else True

    def denied(self, url: str) -> bool:
        """Inverse of :meth:`allows`, for readable guard call sites."""
        return not self.allows(url)

    def with_hosts(self, extra_hosts=()) -> "TargetScope":
        """Return a copy authorizing ``extra_hosts`` in addition to this set."""
        merged = set(self.hosts)
        merged.update(h.lower() for h in (extra_hosts or []) if h)
        return TargetScope(frozenset(merged))
