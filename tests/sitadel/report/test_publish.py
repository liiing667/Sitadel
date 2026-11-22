"""Atomic publish-transaction tests.

A scan's findings snapshot, every requested output format, and the public
completion status share one publish transaction (:func:`publish_report`):
either every report file is committed or none is. These tests prove that a
failed or retried export never leaves truncated, clean-looking, or
mixed-generation report artifacts behind, and that the single-file
``write_report`` API keeps its old behaviour.
"""
import json
import os
from unittest import mock

from sitadel.report import (
    Finding,
    ReportError,
    Severity,
    parse_formats,
    plan_outputs,
    publish_report,
    to_html,
    to_json,
    to_sarif,
    write_report,
)


def _gen(n):
    """A findings snapshot tagged by scan generation."""
    return [
        Finding(title=f"gen-{n} SQL Injection", severity=Severity.HIGH,
                url="http://host/item?id=1", evidence="MySQL error",
                plugin="Sql"),
        Finding(title=f"gen-{n} Missing CSP header", severity=Severity.LOW,
                url="http://host/"),
    ]


def _read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _assert_dir_clean(directory):
    """No staged temps or rollback backups may survive a transaction."""
    for entry in os.listdir(directory):
        if entry.startswith(".sitadel-") or ".sitadel-backup-" in entry:
            raise AssertionError(f"leftover transaction artifact: {entry}")
        if entry.endswith(".tmp"):
            raise AssertionError(f"leftover temp artifact: {entry}")


# ------------------------------------------------------------------ #
# Happy path: one snapshot, every format committed together
# ------------------------------------------------------------------ #
def test_publish_writes_all_formats_from_one_snapshot(tmp_path):
    findings = _gen(1)
    paths = [os.path.join(str(tmp_path), f"report.{fmt}")
             for fmt in ("json", "sarif", "html")]
    committed = publish_report(
        findings, [("json", paths[0]), ("sarif", paths[1]), ("html", paths[2])]
    )
    if committed != [os.path.abspath(p) for p in paths]:
        raise AssertionError("committed paths must be returned in order")
    # Every file carries the same generation of findings.
    if _read(paths[0]) != to_json(findings):
        raise AssertionError("json report must match the snapshot")
    if _read(paths[1]) != to_sarif(findings):
        raise AssertionError("sarif report must match the snapshot")
    if _read(paths[2]) != to_html(findings):
        raise AssertionError("html report must match the snapshot")
    data = json.loads(_read(paths[0]))
    if [f["title"] for f in data] != ["gen-1 SQL Injection",
                                      "gen-1 Missing CSP header"]:
        raise AssertionError("json report must contain the snapshot findings")
    _assert_dir_clean(str(tmp_path))


def test_publish_empty_findings_keeps_old_behaviour(tmp_path):
    paths = [os.path.join(str(tmp_path), f"empty.{fmt}")
             for fmt in ("json", "html", "sarif")]
    publish_report([], [("json", paths[0]), ("html", paths[1]),
                        ("sarif", paths[2])])
    if json.loads(_read(paths[0])) != []:
        raise AssertionError("empty findings must serialize to []")
    if "No findings" not in _read(paths[1]):
        raise AssertionError("empty HTML report must keep the placeholder row")
    doc = json.loads(_read(paths[2]))
    if doc["version"] != "2.1.0" or doc["runs"][0]["results"] != []:
        raise AssertionError("empty SARIF report must keep the 2.1.0 schema")


# ------------------------------------------------------------------ #
# Failure atomicity: no clean-looking or mixed-generation artifacts
# ------------------------------------------------------------------ #
def test_publish_failure_leaves_no_artifacts(tmp_path):
    good = os.path.join(str(tmp_path), "report.json")
    bad = os.path.join(str(tmp_path), "no-such-dir", "report.sarif")
    try:
        publish_report(_gen(1), [("json", good), ("sarif", bad)])
    except ReportError:
        pass
    else:
        raise AssertionError("a failing output must abort the transaction")
    if os.path.exists(good):
        raise AssertionError("the json output must not be committed alone")
    _assert_dir_clean(str(tmp_path))


def test_publish_failure_preserves_previous_generation(tmp_path):
    json_path = os.path.join(str(tmp_path), "report.json")
    sarif_path = os.path.join(str(tmp_path), "report.sarif")
    # Generation 1 committed successfully.
    publish_report(_gen(1), [("json", json_path), ("sarif", sarif_path)])
    gen1_json, gen1_sarif = _read(json_path), _read(sarif_path)

    # Generation 2: the SARIF staging fails -> nothing of gen 2 may survive.
    bad_sarif = os.path.join(str(tmp_path), "gone", "report.sarif")
    try:
        publish_report(_gen(2), [("json", json_path), ("sarif", bad_sarif)])
    except ReportError:
        pass
    else:
        raise AssertionError("the failing publish must raise ReportError")
    if _read(json_path) != gen1_json:
        raise AssertionError("json must still hold the previous generation")
    if _read(sarif_path) != gen1_sarif:
        raise AssertionError("sarif must still hold the previous generation")
    _assert_dir_clean(str(tmp_path))


def test_publish_rolls_back_when_commit_fails_midway(tmp_path):
    json_path = os.path.join(str(tmp_path), "report.json")
    sarif_path = os.path.join(str(tmp_path), "report.sarif")
    publish_report(_gen(1), [("json", json_path), ("sarif", sarif_path)])
    gen1_json, gen1_sarif = _read(json_path), _read(sarif_path)

    # Fail the *second* commit rename: the first output is already committed
    # and must be withdrawn, the backups restored -> generation 1 everywhere.
    real_replace = os.replace
    commits = {"n": 0}

    def flaky_replace(src, dst):
        if src.endswith(".tmp"):
            commits["n"] += 1
            if commits["n"] == 2:
                raise OSError("simulated commit failure")
        return real_replace(src, dst)

    with mock.patch("os.replace", flaky_replace):
        try:
            publish_report(_gen(2), [("json", json_path), ("sarif", sarif_path)])
        except ReportError:
            pass
        else:
            raise AssertionError("the failing publish must raise ReportError")
    if _read(json_path) != gen1_json:
        raise AssertionError("committed-then-failed output must be rolled back")
    if _read(sarif_path) != gen1_sarif:
        raise AssertionError("uncommitted output must keep the old generation")
    _assert_dir_clean(str(tmp_path))


def test_retry_after_failure_publishes_one_clean_generation(tmp_path):
    json_path = os.path.join(str(tmp_path), "report.json")
    sarif_path = os.path.join(str(tmp_path), "report.sarif")
    bad_sarif = os.path.join(str(tmp_path), "gone", "report.sarif")
    try:
        publish_report(_gen(1), [("json", json_path), ("sarif", bad_sarif)])
    except ReportError:
        pass
    # Retry with a fixed plan: the whole generation commits together.
    publish_report(_gen(1), [("json", json_path), ("sarif", sarif_path)])
    if "gen-1 SQL Injection" not in _read(json_path):
        raise AssertionError("retried json report must be complete")
    if "gen-1 SQL Injection" not in _read(sarif_path):
        raise AssertionError("retried sarif report must be complete")
    _assert_dir_clean(str(tmp_path))


def test_publish_rejects_duplicate_output_paths(tmp_path):
    path = os.path.join(str(tmp_path), "report.out")
    try:
        publish_report(_gen(1), [("json", path), ("sarif", path)])
    except ReportError:
        pass
    else:
        raise AssertionError("duplicate output paths must be rejected")
    if os.path.exists(path):
        raise AssertionError("a rejected plan must not write anything")


def test_publish_unknown_format_touches_nothing(tmp_path):
    good = os.path.join(str(tmp_path), "report.json")
    try:
        publish_report(_gen(1), [("json", good), ("xml", "x.xml")])
    except KeyError:
        pass  # unknown formats keep the historical KeyError
    else:
        raise AssertionError("unknown format must be rejected")
    if os.path.exists(good):
        raise AssertionError("no output may be written when the plan is invalid")


# ------------------------------------------------------------------ #
# write_report: the single-file API keeps working, now atomically
# ------------------------------------------------------------------ #
def test_write_report_still_writes_a_single_file(tmp_path):
    path = os.path.join(str(tmp_path), "report.json")
    write_report(_gen(1), "json", path)
    if len(json.loads(_read(path))) != 2:
        raise AssertionError("write_report must keep its old contract")


def test_write_report_failure_leaves_no_partial_file(tmp_path):
    path = os.path.join(str(tmp_path), "gone", "report.json")
    try:
        write_report(_gen(1), "json", path)
    except ReportError:
        pass
    else:
        raise AssertionError("an unwritable destination must fail")
    if os.path.exists(path):
        raise AssertionError("no partial file may be left behind")


# ------------------------------------------------------------------ #
# CLI plan helpers
# ------------------------------------------------------------------ #
def test_parse_formats_defaults_and_combinations():
    if parse_formats(None) != [] or parse_formats("") != []:
        raise AssertionError("stdout default means no file formats")
    if parse_formats("stdout") != []:
        raise AssertionError("stdout means no file formats")
    if parse_formats("json") != ["json"]:
        raise AssertionError
    if parse_formats("json,sarif") != ["json", "sarif"]:
        raise AssertionError("comma-separated formats must all be kept")
    if parse_formats(" JSON , Sarif ") != ["json", "sarif"]:
        raise AssertionError("parsing must be case/space tolerant")
    if parse_formats("json,json") != ["json"]:
        raise AssertionError("duplicates collapse")


def test_parse_formats_rejects_bad_combinations():
    for bad in ("stdout,json", "xml", "json,yaml"):
        try:
            parse_formats(bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"{bad!r} must be rejected")


def test_plan_outputs_maps_paths_in_order():
    if plan_outputs([], None) != []:
        raise AssertionError
    # stdout-only: extra -o paths are tolerated (TUI export default).
    if plan_outputs([], ["x.html"]) != []:
        raise AssertionError
    if plan_outputs(["json"], None) != [("json", "sitadel-report.json")]:
        raise AssertionError("default path must derive from the format")
    planned = plan_outputs(["json", "sarif"], ["a.json"])
    if planned != [("json", "a.json"), ("sarif", "sitadel-report.sarif")]:
        raise AssertionError("explicit paths map in order, rest default")
    try:
        plan_outputs(["json"], ["a.json", "b.json"])
    except ValueError:
        pass
    else:
        raise AssertionError("excess -o paths must be rejected")
