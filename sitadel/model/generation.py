"""Shared rule generation (a.k.a. rule epoch) for a single scan attempt.

The four places that used to reason about a scan independently now share one
object:

* the **plugin sets** (the fingerprint/attack classes imported for this scan),
* the **profile conditions** (the :class:`TargetProfile` gating those plugins),
* the **attack execution** (which selected plugins are actually allowed to
  run),
* and the **finding source** (every finding is stamped with the generation it
  belongs to).

A fingerprint retry, a plugin reload or a second scan therefore starts a fresh
generation: plugins re-register on the process-wide ``IPlugin`` registries, but
each generation freezes its own snapshot at start time and only accepts
findings carrying its id. Rules, profile, execution and findings can never mix
across generations, so a plugin that contradicts the *final* profile (e.g. an
HTML-only attack once the target was identified as an API) cannot run or emit
findings under the new generation.
"""
from __future__ import annotations

from itertools import count
from threading import Lock

from sitadel.utils.container import Services

#: Service key under which the active generation is registered.
SERVICE_KEY = "rule_generation"

_counter = count(1)
_counter_lock = Lock()


def current_generation():
    """Return the active :class:`RuleGeneration`, or ``None`` outside a scan.

    Fail-open by design: every call site treats ``None`` exactly like the
    pre-generation behavior (all enabled plugins, every finding accepted), so
    library callers and unit tests that never start a generation are
    unaffected.
    """
    try:
        return Services.get(SERVICE_KEY)
    except NameError:
        return None


class RuleGeneration:
    """One rule epoch shared by every phase of a scan attempt.

    Its identity (``id``) and captured profile never change. Plugin snapshots
    are frozen lazily on first use and then stay fixed, and the lifecycle flag
    only moves open -> closed.
    ``generation`` ids are monotonically increasing, so "old" is a simple id
    comparison — useful when a worker thread from a previous attempt is still
    finishing probes after a new generation has started.
    """

    def __init__(self, profile=None, name: str | None = None):
        with _counter_lock:
            self.id: int = next(_counter)
        self.name: str = name or f"generation-{self.id}"
        # The profile is captured at start time. Phases mutate the same object
        # (fingerprinting adds technologies, discovery sets the API surface),
        # so gating always sees the live, final profile while the snapshot
        # below stays frozen to the plugins selected for this generation.
        self.profile = profile
        # Frozen plugin snapshots per registry base class:
        # {plugin base class: tuple(plugin classes, ...)}.
        self.plugin_sets: dict[type, tuple] = {}
        # Generations are active until the scan finishes or a newer one takes
        # over. Closed generations reject late findings from stale workers.
        self.closed = False

    # -- plugin sets ------------------------------------------------------- #
    def freeze_plugins(self, base_cls, plugins) -> tuple:
        """Freeze the plugins selected for this generation.

        Re-importing a plugin package on retry appends new registrations to the
        process-wide registry; the snapshot keeps this generation bound to the
        set it started with regardless of later registrations.
        """
        snapshot = tuple(plugins)
        self.plugin_sets[base_cls] = snapshot
        return snapshot

    def plugin_set(self, base_cls) -> tuple:
        """The plugins this generation froze for ``base_cls`` (or empty)."""
        return self.plugin_sets.get(base_cls, ())

    def includes(self, plugin_cls) -> bool:
        """Whether ``plugin_cls`` belongs to this generation's snapshot."""
        return any(plugin_cls in plugins for plugins in self.plugin_sets.values())

    # -- profile conditions ------------------------------------------------ #
    def applies(self, plugin) -> bool:
        """Delegate profile gating to the plugin, against the frozen profile.

        Kept as a method so the profile condition is consulted through the same
        generation object that selected the plugin and will accept its
        findings — the four rule consumers stay coupled by construction.
        """
        return plugin.applies_to(self.profile)

    # -- finding source ---------------------------------------------------- #
    def accepts_finding(self, generation_id) -> bool:
        """Whether a finding stamped ``generation_id`` may be recorded.

        Findings from the active generation are accepted; findings that carry
        an explicit but different id (a stale worker from an earlier attempt)
        are dropped. ``None`` means the producer is generation-unaware and is
        accepted fail-open, preserving legacy single-string finding calls.
        """
        if self.closed:
            return False
        if generation_id is None:
            return True
        return generation_id == self.id

    def close(self) -> None:
        self.closed = True

    def __repr__(self) -> str:
        return f"<RuleGeneration {self.name} id={self.id} closed={self.closed}>"


def start_generation(profile=None, name: str | None = None) -> RuleGeneration:
    """Open a new rule generation and register it as the active one.

    Any previously active generation is closed first, so its late findings can
    no longer reach the collector even if old worker threads are still alive.
    """
    previous = current_generation()
    if previous is not None:
        previous.close()
    generation = RuleGeneration(profile=profile, name=name)
    Services.register(SERVICE_KEY, generation)
    return generation


def close_generation() -> None:
    """Close the active generation, if any (called from a scan's cleanup)."""
    generation = current_generation()
    if generation is not None:
        generation.close()
