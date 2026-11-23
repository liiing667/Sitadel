"""Per-scan state: one generation for crawl, fingerprint, attack and report.

A scan is not a single request: it fingerprints the target, crawls it, then
attacks the discovered surface, and finally serialises the findings.  Those
steps share mutable state (the crawl snapshot, the target profile and the
finding collector).  Keeping that state in process-global service slots makes
it too easy for a retry after a timeout to reuse the *previous* scan's pages,
profile or findings.

This module makes the generation explicit.  A :class:`ScanGeneration` owns the
mutable state for exactly one run; a :class:`CrawlSnapshot` is an immutable
view of the pages discovered during that run.  The services container installs
a new generation at the start of a scan and tags every generation-scoped
service with its owning generation, so a stale writer can never silently feed
the current report.

The classes are deliberately usable on their own (``ScanGeneration`` plus
``CrawlSnapshot``) and do not require the CLI.  Existing callers that never
create a generation keep their old behaviour.
"""

from __future__ import annotations

import itertools
import threading
import time
from collections.abc import Mapping as MappingABC
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping

from sitadel.model.profile import TargetProfile
from sitadel.report.report import Findings

__all__ = [
    "CrawlSnapshot",
    "ScanGeneration",
    "start_generation",
    "current_generation",
    "close_generation",
]


class _BodyMap(MappingABC):
    """Read-only page-body mapping that can also be called for a dict copy.

    Both ``snapshot.bodies["url"]`` and ``snapshot.bodies()`` are convenient
    spellings for consumers, so keep the snapshot immutable while supporting
    the obvious access patterns.
    """

    def __init__(self, data):
        self._data = MappingProxyType(dict(data or {}))

    def __getitem__(self, key):
        return self._data[key]

    def __iter__(self):
        return iter(self._data)

    def __len__(self):
        return len(self._data)

    def __call__(self):
        return dict(self._data)

    def __eq__(self, other):
        if isinstance(other, MappingABC):
            return dict(self._data) == dict(other)
        return NotImplemented

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return repr(dict(self._data))


@dataclass(frozen=True)
class CrawlSnapshot:
    """Immutable record of the crawl surface for one scan generation.

    ``urls`` are the crawled URLs (the start page included), ``form_targets``
    are the HTML forms discovered while crawling and ``page_bodies`` are the
    fetched bodies used by passive checks.  The snapshot is captured only after
    a crawl finishes, so a partially failed crawl can never leave a mixture of
    old and new pages behind.
    """

    generation: int
    urls: tuple[str, ...] = ()
    form_targets: tuple[Any, ...] = ()
    page_bodies: Mapping[str, str] = field(default_factory=dict)
    complete: bool = True

    @classmethod
    def capture(
        cls,
        generation,
        urls=(),
        form_targets=(),
        page_bodies: Mapping[str, str] | None = None,
        complete: bool = True,
    ) -> "CrawlSnapshot":
        """Build a snapshot, copying the mutable inputs into immutable form."""
        gen_id = getattr(generation, "id", generation)
        if gen_id is None:
            gen_id = 0
        bodies = dict(page_bodies or {})
        if isinstance(urls, (str, bytes)):
            urls = [urls]
        if isinstance(form_targets, (str, bytes)):
            form_targets = [form_targets]
        elif form_targets is not None and not hasattr(form_targets, "__iter__"):
            form_targets = [form_targets]
        return cls(
            generation=int(gen_id),
            urls=tuple(str(url) for url in (urls or ())),
            form_targets=tuple(form_targets or ()),
            page_bodies=MappingProxyType(bodies),
            complete=bool(complete),
        )

    def targets(self) -> list:
        """Return the injectable targets represented by this snapshot."""
        from sitadel.modules.attacks.targets import Target

        return [Target(url=url) for url in self.urls] + list(self.form_targets)

    @property
    def generation_id(self) -> int:
        """Alias for the owning generation number."""
        return self.generation

    @property
    def pages(self) -> tuple[str, ...]:
        """Alias for ``urls`` (the crawled page list)."""
        return self.urls

    @property
    def forms(self) -> tuple[Any, ...]:
        """Alias for ``form_targets``."""
        return self.form_targets

    @property
    def bodies(self):
        """The page-body mapping; call it for a mutable copy."""
        return _BodyMap(self.page_bodies)


class ScanGeneration:
    """Mutable state owned by one scan run.

    ``id`` is a process-local monotonically increasing generation number.  The
    object is intentionally small: its attributes are the pieces the scan
    phases share, and the services container exposes them under their historic
    names (``findings``, ``profile``, ``form_targets``, ...).
    """

    _counter = itertools.count(1)

    @classmethod
    def begin(cls, **kwargs) -> "ScanGeneration":
        """Install and return a fresh generation via the services container."""
        from sitadel.utils.container import Services

        return Services.begin_generation(**kwargs)

    @classmethod
    def start(cls, **kwargs) -> "ScanGeneration":
        """Alias for :meth:`begin`."""
        return cls.begin(**kwargs)

    @classmethod
    def current(cls) -> "ScanGeneration | None":
        """The generation currently installed, if any."""
        from sitadel.utils.container import Services

        return Services.current_generation()

    def __init__(
        self,
        number: int | None = None,
        *,
        findings: Findings | None = None,
        profile: TargetProfile | None = None,
        target: str | None = None,
        label: str | None = None,
    ) -> None:
        self.id = int(number) if number is not None else next(self._counter)
        self.number = self.id
        self.target = target
        self.label = label
        self.findings = findings if findings is not None else Findings()
        self.profile = profile if profile is not None else TargetProfile()
        self.crawl: CrawlSnapshot | None = None
        self.api_targets: list = []
        self.form_targets: list = []
        self.page_bodies: dict[str, str] = {}
        self.state = "active"
        self.started_at = time.time()
        self.finished_at: float | None = None
        self.error: BaseException | None = None
        self.report_path: str | None = None
        self.report_format: str | None = None
        self._lock = threading.RLock()

    # ------------------------------------------------------------------ state
    @property
    def active(self) -> bool:
        """Whether this generation can still contribute to its report."""
        return self.state == "active"

    def is_active(self) -> bool:
        return self.active

    @property
    def closed(self) -> bool:
        return not self.active

    @property
    def finished(self) -> bool:
        return self.finished_at is not None

    def finish(self, state: str = "complete", error: BaseException | None = None):
        """Close the generation.

        Closing is idempotent and only the first state transition wins, so a
        report written from a ``finally`` block cannot turn a completed scan
        into a failed one.
        """
        with self._lock:
            if self.state == "active":
                self.state = str(state)
                self.finished_at = time.time()
                if error is not None:
                    self.error = error
            return self

    def complete(self):
        return self.finish("complete")

    def close(self, state: str = "complete",
              error: BaseException | None = None):
        return self.finish(state, error)

    def fail(self, error: BaseException | None = None):
        return self.finish("failed", error)

    def supersede(self):
        return self.finish("superseded")

    def cancel(self):
        return self.finish("cancelled")

    # --------------------------------------------------------------- crawl state
    def clear_crawl(self) -> None:
        """Drop the previous crawl surface before a new crawl starts."""
        with self._lock:
            self.crawl = None
            self.api_targets = []
            self.form_targets = []
            self.page_bodies = {}
        self._sync_services(
            crawl_snapshot=None,
            api_targets=[],
            form_targets=[],
            page_bodies={},
        )

    def snapshot_crawl(self, urls=(), form_targets=(), page_bodies=None):
        """Capture a completed crawl, or ``None`` if the generation is closed."""
        with self._lock:
            if not self.active:
                return None
            snapshot = CrawlSnapshot.capture(
                self, urls, form_targets, page_bodies
            )
            self.crawl = snapshot
            self.form_targets = list(snapshot.form_targets)
            self.page_bodies = dict(snapshot.page_bodies)
        self._sync_services(
            crawl_snapshot=snapshot,
            form_targets=self.form_targets,
            page_bodies=self.page_bodies,
        )
        return snapshot

    def set_api_targets(self, targets=()) -> list:
        with self._lock:
            self.api_targets = list(targets or ())
            targets = self.api_targets
        self._sync_services(api_targets=targets)
        return targets

    @staticmethod
    def _services():
        from sitadel.utils.container import Services

        return Services

    def _sync_services(self, **values) -> None:
        """Mirror crawl state into the services container for current scans."""
        services = self._services()
        if services.current_generation() is not self or not self.active:
            return
        for name, value in values.items():
            if name == "crawl_snapshot" and value is None:
                services.pop_for_generation(self, name)
                continue
            services.register_for_generation(self, name, value)

    # ------------------------------------------------------------- findings
    def add_finding(self, finding) -> bool:
        """Record ``finding`` only while this generation is current."""
        with self._lock:
            if not self.active:
                return False
            if self.findings is None:
                return False
            self.findings.add(finding)
            return True

    def report_findings(self) -> list:
        """Return the findings that belong to this generation's report."""
        with self._lock:
            if self.findings is None:
                return []
            return self.findings.all()

    def write_report(self, fmt: str, path: str) -> list:
        """Serialise this generation's findings (never another scan's)."""
        from sitadel.report.report import write_report

        findings = self.report_findings()
        write_report(findings, fmt, path)
        self.record_report(fmt, path)
        return findings

    def record_report(self, fmt: str, path: str) -> None:
        """Remember where this generation's report was written."""
        self.report_format = fmt
        self.report_path = path

    # -------------------------------------------------------------- services
    def bind_service(self, name: str, value) -> None:
        """Keep the generation object in sync with a scoped service value."""
        with self._lock:
            if name == "findings":
                self.findings = value
            elif name == "profile":
                self.profile = value
            elif name == "api_targets":
                self.api_targets = (
                    value if isinstance(value, list) else list(value or ())
                )
            elif name == "form_targets":
                self.form_targets = (
                    value if isinstance(value, list) else list(value or ())
                )
            elif name == "page_bodies":
                self.page_bodies = (
                    value if isinstance(value, dict) else dict(value or {})
                )
            elif name == "crawl_snapshot":
                self.crawl = value

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<ScanGeneration %s target=%r state=%s>" % (
            self.id,
            self.target,
            self.state,
        )

    @property
    def generation_id(self) -> int:
        """Alias for ``id`` for callers that prefer an explicit name."""
        return self.id

    @property
    def crawl_snapshot(self) -> CrawlSnapshot | None:
        """Alias for ``crawl``."""
        return self.crawl

    @property
    def crawl_urls(self) -> list[str]:
        """URLs from the completed crawl, or an empty list before one."""
        snapshot = self.crawl
        return list(snapshot.urls) if snapshot is not None else []


# --------------------------------------------------------------------------- #
# Small module-level helpers
# --------------------------------------------------------------------------- #
def start_generation(**kwargs) -> ScanGeneration:
    """Start (and install) a fresh scan generation."""
    return ScanGeneration.begin(**kwargs)


def current_generation() -> ScanGeneration | None:
    """The generation owning the current scan, or ``None`` in legacy mode."""
    return ScanGeneration.current()


def close_generation(
    generation: ScanGeneration | None = None,
    state: str = "complete",
    error: BaseException | None = None,
):
    """Close ``generation`` (default: the current one)."""
    from sitadel.utils.container import Services

    return Services.end_generation(generation, state, error)
