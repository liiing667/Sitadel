"""Unit tests for the shared secret-redaction engine."""
from sitadel.report import Finding, Severity, to_html, to_json, to_sarif
from sitadel.utils.redaction import (
    mask_secret,
    redact_findings,
    redact_finding,
    redact_text,
    redact_url,
)


AWS = "AKIAIOSFODNN7EXAMPLE"
GCP = "AIzaSyA1234567890123456789012345678901234"


def test_mask_secret_keeps_only_head_and_tail():
    masked = mask_secret(AWS)
    if masked == AWS or AWS in masked:
        raise AssertionError("the full secret must be destroyed")
    if not masked.startswith(AWS[:6]) or not masked.endswith(AWS[-4:]):
        raise AssertionError("head/tail fragments are retained for triage")
    if "..." not in masked:
        raise AssertionError


def test_mask_short_secret_drops_tail():
    masked = mask_secret("AKIA12345678")  # exactly 12 chars
    if masked != "AK***":
        raise AssertionError("values <= 12 chars collapse to a head marker")


def test_redact_text_handles_empty_and_plain_input():
    if redact_text("") != "":
        raise AssertionError
    if redact_text(None) is not None:
        raise AssertionError
    plain = "nothing sensitive here at all"
    if redact_text(plain) != plain:
        raise AssertionError("clean text must be untouched")


def test_redact_text_masks_every_known_secret():
    text = "aws=%s gcp=%s end" % (AWS, GCP)
    out = redact_text(text)
    if AWS in out or GCP in out:
        raise AssertionError("all secret occurrences must be masked")
    if out.count("...") != 2:
        raise AssertionError("each occurrence gets its own marker")


def test_redact_text_is_idempotent():
    once = redact_text("key %s" % GCP)
    if redact_text(once) != once:
        raise AssertionError("re-redaction must be stable")


def test_redact_url_masks_query_secret_and_keeps_endpoint():
    url = "https://host/callback?token=%s&next=/home" % GCP
    safe = redact_url(url)
    if GCP in safe:
        raise AssertionError("query-string token must be masked")
    if "https://host/callback" not in safe or "next=/home" not in safe:
        raise AssertionError("endpoint and other params must be preserved")


def test_redact_url_catches_bare_credential_on_sensitive_param():
    url = "https://host/api?api_key=abcdefABCDEF1234567890&x=1"
    safe = redact_url(url)
    if "abcdefABCDEF1234567890" in safe:
        raise AssertionError("bare credential value must be masked")
    if "x=1" not in safe:
        raise AssertionError


def test_redact_url_leaves_normal_urls_unchanged():
    url = "http://host/item?id=1&name=foo"
    if redact_url(url) != url:
        raise AssertionError("non-secret URLs must not be modified")
    if redact_url(None) is not None:
        raise AssertionError


def test_redact_url_covers_secret_in_path_too():
    url = "https://host/x/%s?y=1" % AWS
    if AWS in redact_url(url):
        raise AssertionError("secrets outside the query must also be masked")


def test_redact_finding_covers_every_text_field():
    f = Finding(
        title="token %s leaked" % GCP,
        severity=Severity.HIGH,
        url="https://h/?token=%s" % GCP,
        evidence="saw %s" % GCP,
        parameter="Google API key",
        other_urls=["https://h/2?secret=%s" % AWS],
    )
    redact_finding(f)
    blob = to_json([f]) + to_sarif([f]) + to_html([f])
    if GCP in blob or AWS in blob:
        raise AssertionError("no serialized form may retain the raw secret")
    if GCP in f.other_urls[0]:
        raise AssertionError("other_urls must be redacted as well")


def test_redact_findings_does_not_mutate_through_serialization_twice():
    findings = [Finding(title="k %s" % AWS, url="https://h/?t=%s" % GCP)]
    redact_findings(findings)
    first = to_json(findings)
    second = to_html(findings)
    if AWS in first or GCP in first or AWS in second or GCP in second:
        raise AssertionError


def test_unicode_and_html_escapes_never_reintroduce_secret():
    f = Finding(title="x", evidence="cred %s" % GCP,
                url="https://h/?token=%s" % GCP)
    html_out = to_html([f])
    json_out = to_json([f])
    # HTML-escape and JSON \u escaping happen after redaction; decode them
    # back and prove the original token still cannot be reconstructed.
    import html
    import json
    decoded_html = html.unescape(html_out)
    decoded_json = json.loads(json_out)[0]
    if GCP in decoded_html:
        raise AssertionError("HTML entity decoding restored the secret")
    if GCP in json.dumps(decoded_json) or GCP in str(decoded_json):
        raise AssertionError("JSON unicode decoding restored the secret")
