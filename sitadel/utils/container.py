from __future__ import annotations

import sys
import threading
from typing import Any


class ServiceNotFound(NameError):
    """Raised when a service is requested but not registered.

    Subclasses ``NameError`` so existing ``except NameError`` guards (used
    throughout as an "is this service registered?" check) keep working, while
    tracebacks and targeted ``except ServiceNotFound`` reads clearly.
    """


class Services:
    services: dict[str, Any] = {}
    # The service names that belong to one scan generation.  Everything else
    # (logger, output, request factory, cancel event, event bus, datastore) is
    # deliberately shared for the lifetime of the process/front-end.
    generation_scoped = frozenset(
        {
            "findings",
            "profile",
            "crawl_snapshot",
            "api_targets",
            "form_targets",
            "page_bodies",
        }
    )

    _generation = None
    # Parallel ownership map for generation-scoped slots.  Keeping the values
    # themselves in ``services`` (unwrapped) preserves the historical contract
    # that callers/tests can inspect or ``pop`` that dict directly.
    _owners: dict[str, Any] = {}
    _lock = threading.RLock()

    @classmethod
    def get(cls, key: str) -> Any:
        with cls._lock:
            service = cls.services.get(key)
            if key not in cls.services:
                raise ServiceNotFound(
                    f"No service registered under {key!r}"
                )
            owner = cls._owners.get(key)
            if owner is not None and owner is not cls._generation:
                raise ServiceNotFound(
                    "No service registered under %r for the current scan "
                    "generation" % key
                )
        if service is None:
            raise ServiceNotFound(f"No service registered under {key!r}")
        return service

    @classmethod
    def register(cls, name: str, instance: Any) -> None:
        with cls._lock:
            generation = cls._generation
            if (
                name in cls.generation_scoped
                and generation is not None
                and generation.active
            ):
                cls.services[name] = instance
                cls._owners[name] = generation
                generation.bind_service(name, instance)
            else:
                cls._owners.pop(name, None)
                if (
                    name == "output"
                    and generation is not None
                    and generation.active
                ):
                    binder = getattr(instance, "bind_generation", None)
                    if callable(binder):
                        binder(generation)
                cls.services[name] = instance
        # Plugin module imports can be lazy; refresh outside the container lock
        # so an import that itself touches Services cannot deadlock.
        cls._refresh_plugin_services(name, instance)

    @classmethod
    def _refresh_plugin_services(cls, name: str, instance: Any) -> None:
        """Keep class-level plugin references on the current service object.

        Several attack/fingerprint plugins capture ``output``/``request`` and
        friends at import time (``output = Services.get("output")``).  Without
        this refresh, a module first imported by an earlier test/scan would
        keep writing to that old channel after a retry.  Refreshing here keeps
        the legacy direct-call contract while the generation-scoped checks in
        ``Output`` still reject genuinely stale workers.
        """
        attr = {
            "output": "output",
            "logger": "logger",
            "request_factory": "request",
            "datastore": "datastore",
        }.get(name)
        if attr is None:
            return
        plugins = []
        # Only touch packages that are already imported: importing a plugin
        # package as a side effect of registering a service would be a
        # surprising (and potentially circular) dependency.
        attack_module = sys.modules.get("sitadel.modules.attacks")
        attack_plugin = getattr(attack_module, "AttackPlugin", None)
        if attack_plugin is not None:
            plugins.extend(list(attack_plugin.plugins))
        fingerprint_module = sys.modules.get("sitadel.modules.fingerprints")
        fingerprint_plugin = getattr(
            fingerprint_module, "FingerprintPlugin", None
        )
        if fingerprint_plugin is not None:
            plugins.extend(list(fingerprint_plugin.plugins))
        for plugin in plugins:
            try:
                setattr(plugin, attr, instance)
            except Exception:
                pass

    @classmethod
    def get_optional(cls, key: str, default: Any = None) -> Any:
        """``get`` without the "not registered" exception (legacy-friendly)."""
        try:
            return cls.get(key)
        except NameError:
            return default

    @classmethod
    def register_for_generation(cls, generation, name: str, instance: Any) -> bool:
        """Register a scoped value only if ``generation`` is still current.

        This is the atomic form used by a crawl completing in the background:
        checking the generation and writing the value must happen together, or
        a retry starting in between could receive the old page surface.
        """
        with cls._lock:
            if cls._generation is not generation or not generation.active:
                return False
            if name not in cls.generation_scoped:
                return False
            cls.services[name] = instance
            cls._owners[name] = generation
            generation.bind_service(name, instance)
            return True

    @classmethod
    def pop_for_generation(cls, generation, name: str) -> bool:
        """Remove a scoped value only while ``generation`` is current."""
        with cls._lock:
            if cls._generation is not generation or not generation.active:
                return False
            cls.services.pop(name, None)
            cls._owners.pop(name, None)
            return True

    # ------------------------------------------------------------------ scan
    @classmethod
    def current_generation(cls):
        """The generation owning the current scan, or ``None`` (legacy mode)."""
        return cls._generation

    @classmethod
    def begin_generation(cls, **kwargs):
        """Start a fresh generation and reset every generation-scoped slot.

        The previous generation is closed before the new one becomes visible,
        so a late worker cannot write into the new scan's report.  All mutable
        crawl/profile/finding state is seeded with empty values; a missing
        result in the new scan therefore never falls back to the old one.
        """
        from sitadel.utils.generation import ScanGeneration

        with cls._lock:
            previous = cls._generation
            if previous is not None:
                previous.supersede()

            generation = ScanGeneration(**kwargs)
            cls._generation = generation
            # The generation pointer itself is intentionally global: it is how
            # a caller asks "which scan am I part of?".
            cls.services["generation"] = generation
            cls.services["scan_generation"] = generation

            # Seed every generation-scoped key.  Writing empty containers is
            # important: it distinguishes "this scan found nothing" from
            # "this scan did not touch the slot", which used to leak the prior
            # generation's targets/bodies.
            cls.register("findings", generation.findings)
            cls.register("profile", generation.profile)
            cls.register("api_targets", [])
            cls.register("form_targets", [])
            cls.register("page_bodies", {})
            cls.services.pop("crawl_snapshot", None)
            cls._owners.pop("crawl_snapshot", None)
            generation.crawl = None
            return generation

    @classmethod
    def start_generation(cls, **kwargs):
        """Alias for :meth:`begin_generation`."""
        return cls.begin_generation(**kwargs)

    @classmethod
    def end_generation(cls, generation=None, state: str = "complete",
                       error: BaseException | None = None):
        """Close ``generation`` (default: the current one)."""
        with cls._lock:
            target = generation if generation is not None else cls._generation
            if target is not None:
                target.finish(state, error)
            return target

    @classmethod
    def close_generation(cls, generation=None, state: str = "complete",
                         error: BaseException | None = None):
        """Alias for :meth:`end_generation`."""
        return cls.end_generation(generation, state, error)

    @classmethod
    def reset(cls) -> None:
        """Drop all services and the current generation (mainly for tests)."""
        with cls._lock:
            previous = cls._generation
            if previous is not None:
                previous.supersede()
            cls._generation = None
            cls.services.clear()
            cls._owners.clear()
