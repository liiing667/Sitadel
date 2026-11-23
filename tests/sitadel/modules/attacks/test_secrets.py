"""Passive secret scan over crawler-cached page bodies."""
import json
import logging

import pytest

from sitadel.report import Findings, to_html, to_json, to_sarif
from sitadel.utils.container import Services
from sitadel.utils.output import Output


# A realistic cloud token reused across body, URL query and report formats.
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
GOOGLE_KEY = "AIzaSyA1234567890123456789012345678901234"
GITHUB_TOKEN = "ghp_" + "a" * 36


@pytest.fixture(autouse=True)
def _services():
    Services.register("output", Output(quiet=True))
    Services.register("logger", logging.getLogger("secrets"))
    Services.register("findings", Findings())
    yield
    for k in ("output", "logger", "findings", "page_bodies", "request_factory", "cancel"):
        Services.services.pop(k, None)


def _run(bodies):
    Services.register("page_bodies", bodies)
    from sitadel.modules.attacks.other.secrets import Secrets
    Secrets().process("http://ex.com/", [])
    return Services.get("findings").all()


def test_aws_key_is_flagged_and_redacted():
    findings = _run({"http://ex.com/app.js": "var k='%s';" % AWS_KEY})
    hit = [f for f in findings if "AWS" in (f.parameter or "")]
    if not hit:
        raise AssertionError("AWS key must be flagged")
    if AWS_KEY in (hit[0].evidence or ""):
        raise AssertionError("the raw secret must be redacted in evidence")


def test_page_body_snapshot_is_republished_redacted():
    body = "config = {token: '%s'};" % GOOGLE_KEY
    _run({"http://ex.com/config.js": body})
    snapshot = Services.get("page_bodies")
    published = snapshot["http://ex.com/config.js"]
    if GOOGLE_KEY in published:
        raise AssertionError("the shared page-body snapshot must be redacted")
    if "..." not in published:
        raise AssertionError("the redacted marker must replace the raw secret")


def test_url_query_token_is_redacted_in_finding_and_every_report():
    url = "http://ex.com/callback?token=%s&id=1" % GOOGLE_KEY
    findings = _run({url: "see token in the url"})
    # The finding itself must not retain the raw token anywhere.
    blob = json.dumps([vars(f) for f in findings], default=str)
    if GOOGLE_KEY in blob:
        raise AssertionError("raw query token must not survive on the finding")
    # Every consumer format shares the same redacted data.
    for rendered in (to_json(findings), to_sarif(findings), to_html(findings)):
        if GOOGLE_KEY in rendered:
            raise AssertionError("raw token leaked into a report artifact")


def test_html_and_unicode_encoding_cannot_restore_secret():
    findings = _run({"http://ex.com/a": "key %s" % GITHUB_TOKEN})
    html_out = to_html(findings)
    json_out = to_json(findings)
    sarif_out = to_sarif(findings)
    for rendered in (html_out, json_out, sarif_out):
        if GITHUB_TOKEN in rendered:
            raise AssertionError("raw token must not appear in any format")
    # Entity / \u escapes of the masked text must not hide the original.
    import html as _html
    if GITHUB_TOKEN in _html.unescape(html_out):
        raise AssertionError("HTML entity decoding must not restore the token")


def test_all_artifacts_acceptance_search_full_secret(tmp_path):
    # Acceptance: search every produced artifact for the complete secret.
    from sitadel.report import write_report
    bodies = {
        "http://ex.com/app.js": "var k='%s';" % AWS_KEY,
        "http://ex.com/g?api_key=%s" % GITHUB_TOKEN: "link",
    }
    findings = _run(bodies)
    paths = []
    for fmt in ("json", "sarif", "html"):
        path = str(tmp_path / ("report." + fmt))
        write_report(findings, fmt, path)
        paths.append(path)
    snapshot_blob = json.dumps(Services.get("page_bodies"))
    for path in paths:
        with open(path, encoding="utf-8") as fh:
            content = fh.read()
        for secret in (AWS_KEY, GITHUB_TOKEN, GOOGLE_KEY):
            if secret and secret in content:
                raise AssertionError(
                    "full secret %s found in artifact %s" % (secret, path)
                )
        if AWS_KEY in snapshot_blob or GITHUB_TOKEN in snapshot_blob:
            raise AssertionError("full secret remains in the body snapshot")


def test_second_format_and_retry_cannot_recover_value(tmp_path):
    from sitadel.report import write_report
    findings = _run({"http://ex.com/a": "k='%s'" % AWS_KEY})
    first = str(tmp_path / "a.json")
    second = str(tmp_path / "b.html")
    write_report(findings, "json", first)
    # Re-serialize to another format from the same in-memory findings.
    write_report(findings, "html", second)
    for path in (first, second):
        with open(path, encoding="utf-8") as fh:
            if AWS_KEY in fh.read():
                raise AssertionError("retry/second format restored the secret")


def test_short_match_is_masked_head_only():
    from sitadel.utils.redaction import mask_secret
    short = mask_secret("AKIA12345678")  # 12 chars -> head-only marker
    if short != "AK***":
        raise AssertionError("short secrets collapse to a head-only marker")
    if "12345678" in short:
        raise AssertionError("tail of a short secret must be discarded")


def test_redaction_is_idempotent():
    from sitadel.utils.redaction import redact_text
    once = redact_text("token %s end" % GOOGLE_KEY)
    twice = redact_text(once)
    if once != twice:
        raise AssertionError("redacting redacted text must be a no-op")
    if GOOGLE_KEY in twice:
        raise AssertionError


def test_private_key_block_is_flagged():
    body = "-----BEGIN RSA PRIVATE KEY-----\nMIIabc...\n-----END RSA PRIVATE KEY-----"
    findings = _run({"http://ex.com/x": body})
    if not any("Private key" in (f.parameter or "") for f in findings):
        raise AssertionError("private key block must be flagged")
    if "BEGIN RSA PRIVATE KEY" in to_json(findings):
        raise AssertionError("private key marker must be redacted in reports")


def test_clean_page_no_findings():
    if _run({"http://ex.com/": "<html>nothing secret here</html>"}):
        raise AssertionError("a clean page must not produce findings")


def test_multiple_reports_and_pages_stay_redacted(tmp_path):
    from sitadel.report import write_report
    findings = _run({
        "http://ex.com/1": "aws %s" % AWS_KEY,
        "http://ex.com/2": "gcp %s" % GOOGLE_KEY,
        "http://ex.com/3": "clean page",
    })
    if len(findings) < 2:
        raise AssertionError("each secret page still yields its finding")
    for fmt in ("json", "sarif", "html"):
        path = str(tmp_path / ("multi." + fmt))
        write_report(findings, fmt, path)
        with open(path, encoding="utf-8") as fh:
            rendered = fh.read()
        if AWS_KEY in rendered or GOOGLE_KEY in rendered:
            raise AssertionError("multi-report artifact still holds a secret")


def test_fallback_fetches_when_no_cache(monkeypatch):
    # No page_bodies registered -> the scanner fetches via request_factory.
    class _Resp:
        text = "token = '%s'" % GOOGLE_KEY
        status_code = 200

    class _Req:
        def send(self, url, method="GET", payload=None, headers=None, cookies=None):
            return _Resp()

    Services.register("request_factory", _Req())
    from sitadel.modules.attacks.other.secrets import Secrets
    Secrets().process("http://ex.com/", [])
    findings = Services.get("findings").all()
    if not any("Google" in (f.parameter or "") for f in findings):
        raise AssertionError("fallback fetch path should scan and flag")
    if any(GOOGLE_KEY in (f.evidence or "") for f in findings):
        raise AssertionError("fallback path must redact the matched span")
    if GOOGLE_KEY in json.dumps(Services.get("page_bodies")):
        raise AssertionError("fallback snapshot must be redacted too")
