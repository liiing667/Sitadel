from sitadel.model import TargetProfile


def test_add_get_has_summary():
    profile = TargetProfile()
    profile.add("lang", "PHP")
    profile.add("Lang", "PHP")          # case-insensitive, de-duplicated
    profile.add("server", "nginx")
    profile.add("empty", None)          # ignored

    if profile.get("lang") != "PHP":
        raise AssertionError
    if not profile.has("server"):
        raise AssertionError
    if profile.get("cms") is not None:
        raise AssertionError
    if profile.has("empty"):
        raise AssertionError
    if "lang=PHP" not in profile.summary():
        raise AssertionError


def test_surface_starts_undecided_and_fails_open():
    profile = TargetProfile()
    # An empty profile never claims a surface, so every plugin gate fails open.
    if profile.is_api() or profile.is_html() or profile.surface is not None:
        raise AssertionError


def test_mark_api_identifies_an_api_surface():
    profile = TargetProfile()
    profile.mark_api("rest")
    if not profile.is_api() or profile.api_type != "rest":
        raise AssertionError
    if profile.surface != "api":
        raise AssertionError


def test_api_identification_wins_over_later_html_marks():
    # The final profile says API: an HTML mark arriving afterwards must not
    # downgrade it (HTML-only attacks would otherwise run against an API).
    profile = TargetProfile()
    profile.mark_api()
    profile.mark_html()
    if not profile.is_api() or profile.is_html():
        raise AssertionError


def test_mark_html_identifies_an_html_surface():
    profile = TargetProfile()
    profile.mark_html()
    if not profile.is_html() or profile.is_api():
        raise AssertionError
