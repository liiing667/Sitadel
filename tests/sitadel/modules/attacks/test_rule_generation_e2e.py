"""End-to-end acceptance for the shared rule generation (rule epoch).

Reproduces the original defect: the fingerprint phase identifies the target
as an API on retry, yet the attack phase still launches HTML-only attacks
because the plugin set, the profile conditions, execution and the findings
collector each reasoned independently. With one rule generation shared by all
four, a retry that flips the final profile to API must make the HTML-only
attack collection impossible to run — and findings from the previous attempt
must be rejected.
"""
import logging

from sitadel.config.settings import Risk
from sitadel.model import TargetProfile, start_generation
from sitadel.modules.attacks import AttackPlugin, Attacks
from sitadel.report import Findings
from sitadel.utils.container import Services
from sitadel.utils.output import Output


class _EpochMarker:
    """Tag so the test can recognize its own plugins on the global registry."""

    epoch_test = True


def _make_html_only(ran):
    class _HtmlOnlyAttack(_EpochMarker, AttackPlugin):
        surfaces = ("html",)

        def process(self, start_url, crawled_urls):
            ran.append(self.__class__.__name__)
            return None

    return _HtmlOnlyAttack


def _make_generic(ran, emit=False):
    class _GenericAttack(_EpochMarker, AttackPlugin):
        def process(self, start_url, crawled_urls):
            ran.append(self.__class__.__name__)
            if emit:
                from sitadel.model.generation import current_generation

                generation = current_generation()
                Services.get("output").finding(
                    "finding from %s" % self.__class__.__name__,
                    plugin=self.__class__.__name__,
                    generation_id=(
                        generation.id if generation is not None else None
                    ),
                )
            return None

    return _GenericAttack


def _register_services():
    Services.register("output", Output(quiet=True))
    Services.register("logger", logging.getLogger("test-epoch-e2e"))
    Services.register("findings", Findings())


def _cleanup(original_plugins):
    # Remove every plugin this test registered so the global IPlugin registry
    # is not polluted for later tests.
    AttackPlugin.plugins = original_plugins
    for key in ("rule_generation", "findings", "output", "logger",
                "api_targets", "form_targets"):
        Services.services.pop(key, None)


def _run_attacks():
    # ``plugins_activated=[]``: no real package is imported, the test plugins
    # were registered directly on the metaclass registry.
    Attacks("http://target.example", []).run([])


def _epoch_plugins():
    return {
        plugin
        for plugin in AttackPlugin.plugins
        if getattr(plugin, "epoch_test", False)
    }


def test_retry_to_api_profile_never_runs_html_only_attacks():
    original_plugins = list(AttackPlugin.plugins)
    _register_services()
    try:
        ran_first = []
        html_only = _make_html_only(ran_first)
        generic = _make_generic(ran_first, emit=True)

        # --- Attempt 1: fingerprint sees an ordinary HTML target ---------- #
        html_profile = TargetProfile()
        html_profile.mark_html()
        generation_one = start_generation(profile=html_profile)
        _run_attacks()

        if html_only.__name__ not in ran_first:
            raise AssertionError("HTML-only attacks must run on an HTML target")
        if generic.__name__ not in ran_first:
            raise AssertionError("generic attacks must run on an HTML target")
        first_generation_findings = list(Services.get("findings").all())
        if not first_generation_findings:
            raise AssertionError("the first attempt must record findings")
        if all(f.generation_id != generation_one.id
               for f in first_generation_findings):
            raise AssertionError("findings must be stamped with their epoch")

        # --- Retry: the fingerprint now conclusively identifies an API ---- #
        # Same profile object is reused, as in a real retry within one scan,
        # and a fresh generation starts for the new rule set.
        html_profile.mark_api("rest")
        generation_two = start_generation(profile=html_profile)
        if generation_two.id <= generation_one.id:
            raise AssertionError("a retry must open a newer generation")

        ran_second = []
        # Rebind the plugins' recorder for the second run by subclassing; the
        # original classes stay registered on the frozen first generation.
        class _HtmlOnlyRetry(_EpochMarker, AttackPlugin):
            surfaces = ("html",)

            def process(self, start_url, crawled_urls):
                ran_second.append(self.__class__.__name__)
                return None

        class _GenericRetry(_EpochMarker, AttackPlugin):
            def process(self, start_url, crawled_urls):
                ran_second.append(self.__class__.__name__)
                return None

        _run_attacks()

        if any(name.endswith("HtmlOnlyRetry") for name in ran_second):
            raise AssertionError(
                "after the retry identifies an API, an HTML-only attack "
                "collection must not run"
            )
        if "_GenericRetry" not in ran_second:
            raise AssertionError(
                "surface-agnostic attacks still apply to an API target"
            )

        # A stale worker from attempt 1 can no longer write findings: its
        # generation is closed/superseded.
        before = len(Services.get("findings").all())
        Services.get("output").finding(
            "late finding from the pre-retry attempt",
            generation_id=generation_one.id,
        )
        after = Services.get("findings").all()
        if len(after) != before:
            raise AssertionError(
                "stale-generation findings must be rejected by the collector"
            )
        if any(f.generation_id == generation_two.id and
               "pre-retry" in (f.title or "") for f in after):
            raise AssertionError
    finally:
        _cleanup(original_plugins)


def test_plugin_reload_after_freeze_cannot_join_the_running_generation():
    original_plugins = list(AttackPlugin.plugins)
    _register_services()
    try:
        profile = TargetProfile()
        profile.mark_api("rest")
        generation = start_generation(profile=profile)

        ran = []
        html_only = _make_html_only(ran)
        generic = _make_generic(ran)

        # Freeze explicitly, then "reload": a brand-new plugin registers while
        # the generation is already running.
        generation.freeze_plugins(
            AttackPlugin,
            [p for p in AttackPlugin.plugins
             if getattr(p, "level", Risk.NO_DANGER) <= Risk.NOISY],
        )

        class _ReloadedLate(_EpochMarker, AttackPlugin):
            def process(self, start_url, crawled_urls):
                ran.append("reloaded-late")
                return None

        _run_attacks()

        if "reloaded-late" in ran:
            raise AssertionError(
                "a plugin reloaded after the generation froze must not run"
            )
        if generic.__name__ not in ran:
            raise AssertionError("frozen generic plugins still execute")
        if html_only.__name__ in ran:
            raise AssertionError(
                "the frozen HTML-only plugin still contradicts the API profile"
            )

        # The next generation picks the reload up normally.
        next_generation = start_generation(profile=profile)
        next_generation.freeze_plugins(AttackPlugin, AttackPlugin.enabled())
        if _ReloadedLate not in next_generation.plugin_set(AttackPlugin):
            raise AssertionError(
                "a fresh generation must see plugins reloaded in between"
            )
    finally:
        _cleanup(original_plugins)


def test_empty_profile_keeps_everything_running_fail_open():
    original_plugins = list(AttackPlugin.plugins)
    _register_services()
    try:
        start_generation(profile=TargetProfile())  # no surface decided
        ran = []
        html_only = _make_html_only(ran)
        generic = _make_generic(ran)
        _run_attacks()
        if html_only.__name__ not in ran or generic.__name__ not in ran:
            raise AssertionError(
                "an empty/undecided profile must not gate any attack"
            )
    finally:
        _cleanup(original_plugins)


def test_disabled_plugins_never_run_even_when_profile_matches():
    original_plugins = list(AttackPlugin.plugins)
    _register_services()
    from sitadel.config import settings

    settings.risk = Risk.NO_DANGER
    try:
        profile = TargetProfile()
        profile.mark_html()
        start_generation(profile=profile)
        ran = []

        class _DisabledHtmlOnly(_EpochMarker, AttackPlugin):
            level = Risk.DANGEROUS  # above the allowed risk -> disabled
            surfaces = ("html",)

            def process(self, start_url, crawled_urls):
                ran.append("disabled")
                return None

        _run_attacks()
        if "disabled" in ran:
            raise AssertionError(
                "risk-disabled plugins must stay excluded under a generation"
            )
    finally:
        settings.risk = Risk.NOISY
        _cleanup(original_plugins)
