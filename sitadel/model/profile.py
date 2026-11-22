from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

#: Surfaces a target can expose. ``None`` means "not decided yet" and every
#: gate fails open; ``"html"`` / ``"api"`` positively identify the surface so
#: surface-specific plugins can be skipped when they contradict the profile.
SURFACE_HTML = "html"
SURFACE_API = "api"


@dataclass
class TargetProfile:
    """Structured picture of the target built by the fingerprint phase.

    Technologies are grouped by category (``server``, ``lang``, ``framework``,
    ``cms``, ``frontend``, ``cdn``, ``waf``, ``system`` … — the same names as
    the fingerprint plugin packages). The attack phase consults this profile to
    decide which attack classes are worth launching (see ``AttackPlugin``).
    """

    technologies: dict[str, set[str]] = field(
        default_factory=lambda: defaultdict(set)
    )
    # Detected API style, e.g. "rest" or "graphql". Set by the API-discovery
    # step (or fingerprinting) and consulted to gate API-only attacks.
    api_type: str | None = None
    # Positive surface identification. Discovery writes ``"api"`` when a spec
    # or REST prefix is confirmed; the crawler writes ``"html"`` once real HTML
    # pages/forms are seen. Left ``None`` on an empty/undecided profile so the
    # attack gates stay fail-open.
    surface: str | None = None

    def add(self, category: str, name) -> None:
        if category and name:
            self.technologies[str(category).lower()].add(str(name))

    def is_api(self) -> bool:
        """Whether the target looks like an API worth body-injection testing."""
        return self.surface == SURFACE_API or self.api_type in ("rest", "graphql")

    def is_html(self) -> bool:
        """Whether the target was positively identified as an HTML surface."""
        return self.surface == SURFACE_HTML

    def mark_api(self, api_type: str = "rest") -> None:
        """Record a confirmed API surface (used by the discovery step)."""
        self.api_type = api_type
        self.surface = SURFACE_API

    def mark_html(self) -> None:
        """Record a confirmed HTML surface (used by the crawler)."""
        # An explicit API identification always wins: a target may serve HTML
        # somewhere while its injectable surface is an API.
        if self.surface != SURFACE_API:
            self.surface = SURFACE_HTML

    def get(self, category: str) -> str | None:
        """Return the detections for a category as a string, or None."""
        values = self.technologies.get(str(category).lower())
        return ", ".join(sorted(values)) if values else None

    def has(self, category: str) -> bool:
        return bool(self.technologies.get(str(category).lower()))

    def as_dict(self) -> dict:
        return {cat: sorted(names) for cat, names in self.technologies.items()}

    def summary(self) -> str:
        return "; ".join(
            f"{cat}={self.get(cat)}" for cat in sorted(self.technologies)
        )
