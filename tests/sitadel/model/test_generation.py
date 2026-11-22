"""Rule generation (rule epoch): one shared epoch for plugin sets, profile
conditions, attack execution and the finding source.

These tests pin the four behaviors the convergence work must preserve:

* legacy plugins, an empty profile and risk-disabled plugins keep behaving
  exactly as before;
* each scan attempt/retry freezes its own plugin snapshot, so plugins
  registered after the freeze (a reload) cannot join the running generation;
* findings are attributed to the generation that produced them and stale
  generations can no longer write to the collector.
"""
import logging

from sitadel.model import (
    RuleGeneration,
    TargetProfile,
    close_generation,
    current_generation,
    start_generation,
)
from sitadel.config.settings import Risk
from sitadel.modules.attacks import AttackPlugin
from sitadel.modules.fingerprints import FingerprintPlugin
from sitadel.report import Findings
from sitadel.utils.container import Services
from sitadel.utils.output import Output


def _services():
    Services.register("output", Output(quiet=True))
    Services.register("logger", logging.getLogger("test-generation"))
    Services.register("findings", Findings())


def _cleanup():
    for key in ("rule_generation", "findings", "output", "logger"):
        Services.services.pop(key, None)


def test_generation_ids_are_monotonic_and_registered():
    _services()
    try:
        first = start_generation(profile=TargetProfile())
        second = start_generation(profile=TargetProfile())
        if second.id <= first.id:
            raise AssertionError("generation ids must be strictly increasing")
        if current_generation() is not second:
            raise AssertionError("the newest generation must be active")
        # Starting a generation closes the previous one.
        if first.closed is not True:
            raise AssertionError("the previous generation must be closed")
        close_generation()
        if current_generation().closed is not True:
            raise AssertionError("close_generation must seal the active one")
    finally:
        _cleanup()


def test_plugin_snapshot_is_frozen_per_generation():
    _services()
    generation = start_generation(profile=TargetProfile())
    try:

        class EarlyAttack(AttackPlugin):
            def process(self, start_url, crawled_urls):
                pass

        generation.freeze_plugins(AttackPlugin, AttackPlugin.enabled())

        # A plugin imported afterwards (retry/reload) lands on the global
        # registry but must not join this generation's frozen set.
        class LateAttack(AttackPlugin):
            def process(self, start_url, crawled_urls):
                pass

        enabled = AttackPlugin.enabled()
        if EarlyAttack not in enabled:
            raise AssertionError("frozen plugins must stay enabled")
        if LateAttack in enabled:
            raise AssertionError(
                "a plugin registered after the freeze must not leak in"
            )
        if not generation.includes(EarlyAttack):
            raise AssertionError
        if generation.includes(LateAttack):
            raise AssertionError
    finally:
        _cleanup()


def test_new_generation_picks_up_plugins_reloaded_afterwards():
    _services()
    first = start_generation(profile=TargetProfile())
    try:

        class ReloadedAttack(AttackPlugin):
            def process(self, start_url, crawled_urls):
                pass

        if ReloadedAttack in first.plugin_set(AttackPlugin):
            raise AssertionError("the old generation cannot know a new plugin")
    finally:
        _cleanup()

    # A fresh generation freezes the current registry, including the plugin
    # that only existed since the previous attempt — the reload takes effect
    # for the new epoch without contaminating the old one.
    _services()
    second = start_generation(profile=TargetProfile())
    try:
        second.freeze_plugins(AttackPlugin, AttackPlugin.enabled())
        if ReloadedAttack not in second.plugin_set(AttackPlugin):
            raise AssertionError("the new generation must include the reload")
    finally:
        _cleanup()


def test_risk_disabled_plugins_remain_excluded_under_a_generation():
    from sitadel.config import settings

    _services()
    settings.risk = Risk.NO_DANGER
    generation = start_generation(profile=TargetProfile())
    try:

        class NoisyAttack(AttackPlugin):
            level = Risk.NOISY

            def process(self, start_url, crawled_urls):
                pass

        generation.freeze_plugins(AttackPlugin, AttackPlugin.enabled())
        if NoisyAttack in AttackPlugin.enabled():
            raise AssertionError(
                "risk filtering must still exclude disabled plugins"
            )
    finally:
        settings.risk = Risk.NOISY
        _cleanup()


def test_finding_source_is_stamped_and_stale_generations_are_dropped():
    _services()
    active = start_generation(profile=TargetProfile())
    output = Services.get("output")
    try:
        output.finding("belongs to the active generation",
                       generation_id=active.id)
        # Untagged findings stay fail-open (legacy single-string callers).
        output.finding("legacy untagged finding", generation_id=None)
        output.finding("a stale worker from an old attempt",
                       generation_id=active.id - 1)

        titles = [f.title for f in Services.get("findings").all()]
        if "belongs to the active generation" not in titles:
            raise AssertionError
        if "legacy untagged finding" not in titles:
            raise AssertionError("untagged findings must remain accepted")
        if "a stale worker from an old attempt" in titles:
            raise AssertionError("stale-generation findings must be dropped")

        stamped = next(
            f for f in Services.get("findings").all()
            if f.title == "belongs to the active generation"
        )
        if stamped.generation_id != active.id:
            raise AssertionError("the finding source must carry the epoch id")

        # Once the generation is closed (scan finished), even its own id is
        # rejected so draining threads cannot append late findings.
        active.close()
        output.finding("late finding", generation_id=active.id)
        if any(f.title == "late finding" for f in Services.get("findings").all()):
            raise AssertionError("closed generations accept no findings")
    finally:
        _cleanup()


def test_without_a_generation_everything_fails_open():
    # No RuleGeneration registered: enabled()/findings behave historically.
    if current_generation() is not None:
        raise AssertionError

    class OrphanAttack(AttackPlugin):
        def process(self, start_url, crawled_urls):
            pass

    if OrphanAttack not in AttackPlugin.enabled():
        raise AssertionError("without a generation every enabled plugin runs")


def test_fingerprint_and_attack_registries_have_independent_snapshots():
    _services()
    generation = start_generation(profile=TargetProfile())
    try:
        class _Fingerprint(FingerprintPlugin):
            def process(self, headers, content):
                pass

        class _Attack(AttackPlugin):
            def process(self, start_url, crawled_urls):
                pass

        generation.freeze_plugins(AttackPlugin, AttackPlugin.enabled())
        generation.freeze_plugins(
            FingerprintPlugin, FingerprintPlugin.enabled()
        )
        if _Attack not in generation.plugin_set(AttackPlugin):
            raise AssertionError
        if _Fingerprint not in generation.plugin_set(FingerprintPlugin):
            raise AssertionError
        # A plugin from one registry never appears in the other's snapshot.
        if _Attack in generation.plugin_set(FingerprintPlugin):
            raise AssertionError
    finally:
        _cleanup()


def test_rule_generation_is_a_dataclass_free_object():
    generation = RuleGeneration(profile=TargetProfile())
    if generation.profile is None or generation.name is None:
        raise AssertionError
    if not generation.accepts_finding(None):
        raise AssertionError
