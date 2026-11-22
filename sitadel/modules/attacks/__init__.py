import importlib
import os
import pkgutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import parse_qsl, urlsplit

from sitadel.config import settings
from sitadel.config.settings import Risk
from sitadel.model.generation import current_generation
from sitadel.utils.container import Services
from sitadel.utils.events import (
    PageTesting,
    ProgressSnap,
    ProgressStep,
    ProgressTotal,
)
from .. import IPlugin
from .targets import Target, taint_body, taint_target, taint_url


def _publish(event) -> None:
    """Publish to the event bus if one is registered (TUI mode); else no-op."""
    try:
        bus = Services.get("events")
    except NameError:
        return
    bus.publish(event)


def _cancelled() -> bool:
    """Whether the user asked to stop the scan (TUI quit); else False."""
    try:
        return Services.get("cancel").is_set()
    except NameError:
        return False

__all__ = ["AttackPlugin", "Attacks", "Target", "taint_body", "taint_target"]


class AttackPlugin(metaclass=IPlugin):
    # Default risk level for attack modules is NOISY since it sends requests
    level = Risk.NOISY

    # Optional profile requirements, e.g. {"lang": "php"}. Empty means the
    # attack applies to any target.
    requires: dict = {}

    # Target surfaces this attack makes sense on. ``"any"`` (the default,
    # including for every legacy plugin that never declares a surface) runs
    # everywhere; plugins may declare ``("html",)`` or ``("api",)`` so the
    # generation's profile conditions can skip them when the final profile
    # positively identifies a different surface.
    surfaces: tuple = ("any",)

    def applies_to(self, profile):
        """Whether this attack is relevant given the fingerprint profile.

        Fail-open: an attack is skipped only when the profile *positively*
        contradicts a requirement (e.g. it requires PHP but a different
        language was detected). When the relevant signal is unknown, the
        attack still runs, so gating never hides a real vulnerability just
        because fingerprinting missed the stack.
        """
        if profile is None:
            return True
        # Surface conditions, same fail-open rule: only a positively
        # identified surface can exclude a plugin. An empty/undecided profile
        # (``surface is None``) never skips anything, and a surface-agnostic
        # plugin (``"any"``) always passes this check.
        declared = tuple(str(s).lower() for s in (self.surfaces or ("any",)))
        if "any" not in declared:
            if profile.is_api() and "api" not in declared:
                return False
            if profile.is_html() and "html" not in declared:
                return False
        for key, expected in self.requires.items():
            detected = profile.get(key)
            if detected is None:
                continue
            if str(expected).lower() not in detected.lower():
                return False
        return True

    @classmethod
    def enabled(cls):
        """Registered plugins whose risk level is within the configured risk.

        Filtering is done here, at run time, so changing the risk level (or
        loading the configuration after the plugins were imported) always
        takes effect instead of depending on import ordering.

        When a :class:`RuleGeneration` is active, the risk-filtered registry is
        also intersected with the plugin set that generation froze at start
        time: plugins imported afterwards (e.g. on a retry after a profile
        change) cannot leak into the running generation's attack collection.
        """
        eligible = [
            plugin
            for plugin in cls.plugins
            if getattr(plugin, "level", Risk.NO_DANGER) <= settings.risk
        ]
        generation = current_generation()
        if generation is None:
            return eligible
        snapshot = generation.plugin_set(cls)
        if not snapshot:
            # No frozen set yet: freeze now, at first consultation, so the
            # selection is stable for the rest of this generation.
            snapshot = generation.freeze_plugins(cls, eligible)
        return [plugin for plugin in eligible if plugin in snapshot]

    # ``taint_url`` stays available for any plugin still working URL-first; the
    # implementation now lives in ``targets`` alongside the body taints.
    taint_url = staticmethod(taint_url)

    @staticmethod
    def build_targets(crawled_urls):
        """Assemble the injectable targets for this scan.

        Every crawled URL becomes a GET query-string target (URLs without
        parameters are skipped later by ``taint_target``), and any API targets
        discovered by the discovery step (registered under ``api_targets``) are
        appended so body injection reaches JSON/XML endpoints too.
        """
        targets = [Target(url=url) for url in (crawled_urls or [])]
        try:
            api_targets = Services.get("api_targets")
        except NameError:
            api_targets = None
        if api_targets:
            targets.extend(api_targets)
        # HTML forms discovered by the crawler (registered like api_targets), so
        # every injection module reaches POST/GET form parameters too (#70).
        try:
            form_targets = Services.get("form_targets")
        except NameError:
            form_targets = None
        if form_targets:
            targets.extend(form_targets)
        return targets

    def run_injection(self, payloads, crawled_urls, detector, workers=20):
        """Test ``payloads`` against every injectable target with one pool.

        ``detector(response, payload)`` returns a human label when the response
        indicates the injection worked (e.g. ``"MySQL Injection"``), or a falsy
        value otherwise. The response signature is identical across GET query
        and JSON/XML/form body targets, so a module writes its detection once
        and it runs against every surface.
        """
        output = Services.get("output")
        logger = Services.get("logger")
        request = Services.get("request_factory")
        targets = self.build_targets(crawled_urls)
        # Freeze the generation id once: every probe and finding produced by
        # this module is attributed to the same rule epoch, so a generation
        # switch mid-run (fingerprint retry/plugin reload) makes the stale
        # worker's findings get rejected instead of polluting the new profile.
        generation = current_generation()
        generation_id = generation.id if generation is not None else None
        # Announce each endpoint under test once (not per payload) so the crawl
        # tree can mark it without flooding the event bus.
        announced: set = set()

        def probe(payload, target):
            try:
                if _cancelled():
                    return
                # The generation may have been superseded while this probe was
                # queued; stop attacking under rules that no longer match the
                # final profile.
                active = current_generation()
                if active is not None and active.id != generation_id:
                    return
                kwargs = taint_target(target, payload)
                if kwargs is None:
                    return
                if target.url not in announced:
                    announced.add(target.url)
                    _publish(PageTesting(target.url))
                    # One progress unit per (module, target) as it is reached.
                    _publish(ProgressStep(1))
                output.debug("Testing: %s" % target.describe())
                resp = request.send(**kwargs)
                if resp is None:
                    return
                label = detector(resp, payload)
                if label:
                    # Record which field carried the payload so the report (and
                    # its de-duplication) can tell apart issues on one endpoint:
                    # the body fields for a JSON/XML/form target, else the query
                    # parameters taint_url rewrote.
                    if target.body_format:
                        parameter = ",".join(target.params) or None
                    else:
                        parameter = self.tainted_params(target.url)
                    output.finding(
                        "That site may be vulnerable to %s at %s\nInjection: %s"
                        % (label, target.describe(), payload),
                        url=kwargs["url"],
                        plugin=type(self).__name__,
                        parameter=parameter,
                        evidence="payload=%s | matched=%s" % (payload, label),
                        generation_id=generation_id,
                    )
            except Exception as err:
                logger.error(err)
                output.debug("Injection error: %s" % err)

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [
                executor.submit(probe, payload, target)
                for payload in payloads
                for target in targets
            ]
            try:
                for future in as_completed(futures):
                    if _cancelled():
                        # Drop queued probes; in-flight ones finish on their own.
                        executor.shutdown(cancel_futures=True)
                        break
                    future.result()
            except KeyboardInterrupt:
                executor.shutdown(False)
                raise

    @staticmethod
    def tainted_params(url):
        """Comma-joined names of the query parameters ``taint_url`` injects.

        Recorded on findings as the ``parameter`` field so the report (and its
        de-duplication) can distinguish issues on the same endpoint. Returns
        ``None`` when the URL carries no query parameters.
        """
        params = dict(parse_qsl(urlsplit(url).query))
        return ", ".join(params) if params else None

    def process(self, start_url, crawled_urls):
        raise NotImplementedError(str(self) + ": Process method not found")

    def __repr__(self):
        parent_module = self.__class__.__module__.split(".")[-2]
        return parent_module.title()


class Attacks:
    def __init__(self, start_url, crawled_urls):
        self.output = Services.get("output")
        self.logger = Services.get("logger")
        self.start_url = start_url
        self.crawled_urls = crawled_urls

    def run(self, plugins_activated):
        self.output.info("Launching attacks modules...")
        # Register the plugins from configuration
        for p in plugins_activated:
            currentdir = os.path.dirname(os.path.realpath(__file__))
            pkgpath = os.path.dirname(currentdir + "/%s/" % p)
            modules = [name for _, name, _ in pkgutil.iter_modules([pkgpath])]
            for module in modules:
                importlib.import_module(
                    ".{pkg}.{mod}".format(pkg=p, mod=module), __package__
                )

        # Consult the fingerprint profile (if any) to skip attack classes that
        # do not apply to the detected stack.
        try:
            profile = Services.get("profile")
        except NameError:
            profile = None

        try:
            generation = current_generation()
            # Freeze this generation's attack plugin set *before* anything
            # runs: later imports (retry/reload) append to the process-wide
            # registry but cannot alter the snapshot this scan executes.
            if generation is not None:
                if not generation.plugin_set(AttackPlugin):
                    generation.freeze_plugins(
                        AttackPlugin,
                        [
                            plugin
                            for plugin in AttackPlugin.plugins
                            if getattr(plugin, "level", Risk.NO_DANGER)
                            <= settings.risk
                        ],
                    )
            selected = []
            for plugin in AttackPlugin.enabled():
                instance = plugin()
                # Profile conditions are evaluated through the generation so
                # the plugin set, the gating and the finding source share one
                # rule epoch and see the same (final) profile.
                if generation is not None:
                    applicable = generation.applies(instance)
                else:
                    applicable = instance.applies_to(profile)
                if applicable:
                    selected.append(instance)
                else:
                    self.output.info(
                        "Skipping {name} (not applicable to target)".format(
                            name=instance.__class__.__name__
                        )
                    )
            # Progress denominator: one unit per (attack module × target), so a
            # scan of N modules over M targets is N*M units. Injection modules
            # advance it per target (ProgressStep above); every module also
            # snaps to its full share when it finishes, so modules that do not
            # iterate targets still move the bar.
            unit = max(len(AttackPlugin.build_targets(self.crawled_urls)), 1)
            _publish(ProgressTotal(len(selected) * unit))
            attacks = []
            for i, instance in enumerate(selected):
                if _cancelled():
                    break
                # A superseded generation must not keep executing attack
                # collections that contradict the new profile.
                active = current_generation()
                if (
                    generation is not None
                    and active is not None
                    and active.id != generation.id
                ):
                    break
                result = instance.process(self.start_url, self.crawled_urls)
                attacks.append((instance, result))
                _publish(ProgressSnap((i + 1) * unit))
            for category, result in attacks:
                if result is not None:
                    self.output.finding(
                        "{category} detected: {result}".format(
                            category=category, result=result
                        ),
                        generation_id=(
                            generation.id if generation is not None else None
                        ),
                    )

        except Exception as e:
            self.logger.error(e)
            raise e
