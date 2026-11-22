from sitadel.model import TargetProfile
from sitadel.modules.attacks import AttackPlugin


class _PhpOnly(AttackPlugin):
    requires = {"lang": "php"}

    def process(self, start_url, crawled_urls):
        pass


def test_applies_to_fail_open_and_contradiction():
    php = _PhpOnly()

    # No profile at all -> run.
    if php.applies_to(None) is not True:
        raise AssertionError

    # Profile present but language unknown -> still run (fail-open).
    empty = TargetProfile()
    if php.applies_to(empty) is not True:
        raise AssertionError

    # Language detected as PHP -> run.
    php_profile = TargetProfile()
    php_profile.add("lang", "PHP")
    if php.applies_to(php_profile) is not True:
        raise AssertionError

    # Language positively detected as something else -> skip.
    py_profile = TargetProfile()
    py_profile.add("lang", "Python")
    if php.applies_to(py_profile) is not False:
        raise AssertionError


def test_default_plugin_applies_everywhere():
    class _Any(AttackPlugin):
        def process(self, start_url, crawled_urls):
            pass

    profile = TargetProfile()
    profile.add("lang", "Python")
    if _Any().applies_to(profile) is not True:
        raise AssertionError


class _HtmlOnly(AttackPlugin):
    surfaces = ("html",)

    def process(self, start_url, crawled_urls):
        pass


class _ApiOnly(AttackPlugin):
    surfaces = ("api",)

    def process(self, start_url, crawled_urls):
        pass


class _LegacyNoSurface(AttackPlugin):
    # Deliberately no ``surfaces`` declaration: every pre-existing plugin is
    # surface-agnostic and must keep running everywhere.
    def process(self, start_url, crawled_urls):
        pass


def test_surface_gating_fails_open_on_empty_profile():
    empty = TargetProfile()
    if not _HtmlOnly().applies_to(empty):
        raise AssertionError
    if not _ApiOnly().applies_to(empty):
        raise AssertionError
    if not _LegacyNoSurface().applies_to(empty):
        raise AssertionError
    if not _HtmlOnly().applies_to(None):
        raise AssertionError


def test_html_only_attack_skipped_when_final_profile_is_api():
    api_profile = TargetProfile()
    api_profile.mark_api("rest")
    if _HtmlOnly().applies_to(api_profile):
        raise AssertionError("HTML-only attacks cannot run against an API")
    if not _ApiOnly().applies_to(api_profile):
        raise AssertionError
    # Legacy plugins stay fail-open even on a positively identified API.
    if not _LegacyNoSurface().applies_to(api_profile):
        raise AssertionError


def test_api_only_attack_skipped_on_html_surface():
    html_profile = TargetProfile()
    html_profile.mark_html()
    if _ApiOnly().applies_to(html_profile):
        raise AssertionError
    if not _HtmlOnly().applies_to(html_profile):
        raise AssertionError
