import importlib
import os
import pkgutil
from urllib.parse import parse_qsl, urlsplit

from .. import IPlugin
from .batch import Batch, BatchClosed, is_cancelled as _batch_cancelled
from .targets import Target, taint_body, taint_target, taint_url
from sitadel.config import settings
from sitadel.config.settings import Risk
from sitadel.utils.container import Services
from sitadel.utils.events import (
    PageTesting,
    ProgressSnap,
    ProgressStep,
    ProgressTotal,
)


def _publish(event) -> None:
    """Publish to the event bus if one is registered (TUI mode); else no-op."""
    try:
        bus = Services.get("events")
    except NameError:
        return
    bus.publish(event)


def _cancelled() -> bool:
    """Whether the user asked to stop the scan (TUI quit); else False."""
    return _batch_cancelled()

__all__ = ["AttackPlugin", "Attacks", "Target", "taint_body", "taint_target"]


class AttackPlugin(metaclass=IPlugin):
    # Default risk level for attack modules is NOISY since it sends requests
    level = Risk.NOISY

    # Optional profile requirements, e.g. {"lang": "php"}. Empty means the
    # attack applies to any target.
    requires: dict = {}

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
        """
        return [
            plugin
            for plugin in cls.plugins
            if getattr(plugin, "level", Risk.NO_DANGER) <= settings.risk
        ]

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

        The whole run is one :class:`~sitadel.modules.attacks.batch.Batch`: the
        request budget, worker futures, cancel signal and finding submission
        share its state, so after a cancel or a request error every worker
        converges and no finding can be written after the batch completed.
        """
        output = Services.get("output")
        logger = Services.get("logger")
        request = Services.get("request_factory")
        targets = self.build_targets(crawled_urls)
        # Announce each endpoint under test once (not per payload) so the crawl
        # tree can mark it without flooding the event bus.
        announced: set = set()
        work = [(payload, target) for payload in payloads for target in targets]

        # One batch binds the request budget, futures, cancel signal and the
        # Findings gate: once it ends, no queued probe (including ones parked
        # on the rate limiter) can start or report.
        with Batch(workers=workers,
                   name=type(self).__name__) as batch:

            def probe(payload, target):
                # Gate 1: a cancelled/aborted batch never probes.
                if batch.cancelled():
                    return
                try:
                    kwargs = taint_target(target, payload)
                    if kwargs is None:
                        return
                    if target.url not in announced:
                        announced.add(target.url)
                        _publish(PageTesting(target.url))
                        # One progress unit per (module, target) as reached.
                        _publish(ProgressStep(1))
                    output.debug("Testing: %s" % target.describe())
                    resp = request.send(**kwargs)
                    if resp is None:
                        # Transport failure / cancel / scope skip: nothing to
                        # detect; the worker converges without a finding.
                        return
                    label = detector(resp, payload)
                    if label:
                        # Record which field carried the payload so the report
                        # (and its de-duplication) can tell apart issues on one
                        # endpoint: the body fields for a JSON/XML/form target,
                        # else the query parameters taint_url rewrote.
                        if target.body_format:
                            parameter = ",".join(target.params) or None
                        else:
                            parameter = self.tainted_params(target.url)
                        # Gate 2: the batch owns Findings submission — a late
                        # worker after close() cannot reach the collector.
                        batch.finding(
                            output,
                            "That site may be vulnerable to %s at %s\nInjection: %s"
                            % (label, target.describe(), payload),
                            url=kwargs["url"],
                            plugin=type(self).__name__,
                            parameter=parameter,
                            evidence="payload=%s | matched=%s" % (payload, label),
                        )
                except Exception as err:
                    logger.error(err)
                    output.debug("Injection error: %s" % err)

            try:
                batch.run([(probe, (p, t)) for p, t in work])
            except BatchClosed:
                return

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
            selected = []
            for plugin in AttackPlugin.enabled():
                instance = plugin()
                if instance.applies_to(profile):
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
                result = instance.process(self.start_url, self.crawled_urls)
                attacks.append((instance, result))
                _publish(ProgressSnap((i + 1) * unit))
            for category, result in attacks:
                if result is not None:
                    self.output.finding(
                        "{category} detected: {result}".format(
                            category=category, result=result
                        )
                    )

        except Exception as e:
            self.logger.error(e)
            raise e
