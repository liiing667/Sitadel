import json
import os

from sitadel.report import (
    Finding,
    Findings,
    Severity,
    to_html,
    to_json,
    to_sarif,
    write_report,
)


def _sample():
    return [
        Finding(title="SQL Injection", severity=Severity.HIGH,
                url="http://host/p?id=1", evidence="MySQL error", plugin="Sql"),
        Finding(title="Missing CSP header", severity=Severity.LOW,
                url="http://host/"),
    ]


def test_collector_add_and_all():
    coll = Findings()
    if len(coll) != 0:
        raise AssertionError
    coll.add(_sample()[0])
    if len(coll) != 1 or coll.all()[0].title != "SQL Injection":
        raise AssertionError


def test_to_json_is_valid_and_serializes_severity():
    data = json.loads(to_json(_sample()))
    if len(data) != 2:
        raise AssertionError
    if data[0]["severity"] != "high":  # enum serialized to its string value
        raise AssertionError
    if data[0]["title"] != "SQL Injection":
        raise AssertionError


def test_to_sarif_is_valid():
    doc = json.loads(to_sarif(_sample()))
    if doc["version"] != "2.1.0":
        raise AssertionError
    if doc["runs"][0]["tool"]["driver"]["name"] != "Sitadel":
        raise AssertionError
    if len(doc["runs"][0]["results"]) != 2:
        raise AssertionError


def test_to_html_contains_findings():
    out = to_html(_sample())
    if "SQL Injection" not in out or "Missing CSP header" not in out:
        raise AssertionError


def test_write_report(tmp_path):
    path = os.path.join(str(tmp_path), "report.json")
    write_report(_sample(), "json", path)
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if len(data) != 2:
        raise AssertionError


def test_dedup_collapses_same_issue_across_urls():
    coll = Findings()
    # Same plugin + endpoint + parameter, only the query value differs: one
    # finding with an occurrence count, plus the extra URLs recorded.
    for i in range(5):
        coll.add(Finding(title="SQLi", plugin="Sql", parameter="id",
                         url=f"http://host/item?id={i}"))
    if len(coll) != 1:
        raise AssertionError("repeats must collapse to a single finding")
    item = coll.all()[0]
    if item.occurrences != 5:
        raise AssertionError("occurrences must count every repeat")
    if item.url != "http://host/item?id=0":
        raise AssertionError("first seen URL is kept as representative")
    if len(item.other_urls) != 4:
        raise AssertionError("distinct extra URLs must be recorded")


def test_dedup_keeps_distinct_types_and_params_separate():
    coll = Findings()
    coll.add(Finding(title="SQLi", plugin="Sql", parameter="id",
                     url="http://host/item?id=1"))
    coll.add(Finding(title="SQLi", plugin="Sql", parameter="name",
                     url="http://host/item?name=x"))  # different param
    coll.add(Finding(title="XSS", plugin="Xss", parameter="id",
                     url="http://host/item?id=1"))     # different type
    coll.add(Finding(title="SQLi", plugin="Sql", parameter="id",
                     url="http://host/other?id=1"))    # different endpoint
    if len(coll) != 4:
        raise AssertionError("distinct type/param/endpoint must not collapse")


def test_json_serializes_enriched_fields():
    f = Finding(title="SQLi", severity=Severity.HIGH, plugin="Sql",
                cwe="CWE-89", owasp="A03:2021-Injection", wstg="WSTG-INPV-05",
                remediation="Use prepared statements", occurrences=3)
    data = json.loads(to_json([f]))[0]
    for key in ("cwe", "owasp", "wstg", "remediation", "occurrences",
                "confidence", "parameter"):
        if key not in data:
            raise AssertionError(f"{key} must be serialized")
    if data["occurrences"] != 3 or data["cwe"] != "CWE-89":
        raise AssertionError


def test_sarif_carries_rule_help_and_standards():
    f = Finding(title="SQLi", severity=Severity.HIGH, plugin="Sql",
                url="http://host/x", cwe="CWE-89",
                owasp="A03:2021-Injection", wstg="WSTG-INPV-05",
                remediation="Use prepared statements")
    doc = json.loads(to_sarif([f]))
    driver = doc["runs"][0]["tool"]["driver"]
    rules = driver["rules"]
    if not rules or rules[0]["id"] != "Sql":
        raise AssertionError("a rule must be registered per rule id")
    if rules[0]["help"]["text"] != "Use prepared statements":
        raise AssertionError("remediation must land in rule.help")
    if "CWE-89" not in rules[0]["properties"]["tags"]:
        raise AssertionError("standards must be exposed as rule tags")
    result = doc["runs"][0]["results"][0]
    if result["level"] != "error":  # high -> error
        raise AssertionError


def test_html_shows_evidence_remediation_and_count():
    f = Finding(title="SQLi", severity=Severity.HIGH, url="http://host/x",
                evidence="MySQL syntax error", remediation="Use prepared statements",
                cwe="CWE-89", occurrences=7)
    out = to_html([f])
    for needle in ("MySQL syntax error", "Use prepared statements", "CWE-89", "7"):
        if needle not in out:
            raise AssertionError(f"HTML must show {needle!r}")


SECRET = "AKIAIOSFODNN7EXAMPLE"
GCP = "AIzaSyA1234567890123456789012345678901234"


def _secret_finding():
    return Finding(
        title="Secret leaked at https://h/cb?token=%s" % GCP,
        severity=Severity.HIGH,
        url="https://h/cb?token=%s&id=1" % GCP,
        evidence="matched AWS access key id: %s" % SECRET,
        plugin="Secrets",
        parameter="AWS access key id",
        other_urls=["https://h/x?api_key=%s" % SECRET],
    )


def test_every_format_is_redacted_through_the_shared_pass():
    finding = _secret_finding()
    for rendered in (to_json([finding]), to_sarif([finding]), to_html([finding])):
        if SECRET in rendered or GCP in rendered:
            raise AssertionError("a report format still contains the raw secret")


def test_serializers_do_not_mutate_the_callers_findings():
    finding = _secret_finding()
    original_evidence = finding.evidence
    to_json([finding])
    to_sarif([finding])
    to_html([finding])
    if finding.evidence != original_evidence:
        raise AssertionError("redaction must work on detached copies")
    if SECRET not in finding.evidence:
        raise AssertionError("the caller's in-memory finding must stay intact")


def test_html_escaping_cannot_recover_the_secret():
    import html as _html
    rendered = to_html([_secret_finding()])
    if SECRET in _html.unescape(rendered):
        raise AssertionError("unescaping the HTML must not restore the secret")


def test_write_failure_leaves_no_artifact_with_raw_secret(tmp_path):
    # Point the report at a path whose parent directory does not exist: the
    # atomic write must fail and no temp file carrying the (redacted) payload
    # may be left behind anywhere.
    bad_path = os.path.join(str(tmp_path), "missing-dir", "report.json")
    raised = False
    try:
        write_report([_secret_finding()], "json", bad_path)
    except OSError:
        raised = True
    if not raised:
        raise AssertionError("the write was expected to fail")
    leftovers = [
        n for n in os.listdir(str(tmp_path))
        if n.startswith(".sitadel-report-")
    ]
    if leftovers:
        raise AssertionError("failed write must not leave temp files behind")


def test_retry_and_second_format_never_recover_value(tmp_path):
    finding = _secret_finding()
    json_path = os.path.join(str(tmp_path), "r.json")
    html_path = os.path.join(str(tmp_path), "r.html")
    sarif_path = os.path.join(str(tmp_path), "r.sarif")
    # Simulate a retry: write the same findings twice to the same path.
    write_report([finding], "json", json_path)
    write_report([finding], "json", json_path)
    write_report([finding], "html", html_path)
    write_report([finding], "sarif", sarif_path)
    for path in (json_path, html_path, sarif_path):
        with open(path, encoding="utf-8") as fh:
            content = fh.read()
        if SECRET in content or GCP in content:
            raise AssertionError("retry/second format exposed the secret")


def test_empty_findings_still_render_in_every_format():
    if json.loads(to_json([])) != []:
        raise AssertionError
    if '"results": []' not in to_sarif([]):
        raise AssertionError
    if "No findings" not in to_html([]):
        raise AssertionError
