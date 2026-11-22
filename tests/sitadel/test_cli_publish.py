"""CLI completion-status tests for the report publish transaction.

``Sitadel._publish_reports`` is the seam where the findings snapshot, every
requested output format, and the public completion status (the "Wrote N
finding(s)" lines, and downstream the "Scan Finished" banner) share one
all-or-nothing publish: a failed export reports the error and emits no
success status, and leaves no partial or mixed-generation files behind.
"""
import os

import pytest

from sitadel.cli import Sitadel
from sitadel.report import Finding, Findings, Severity
from sitadel.utils.container import Services
from sitadel.utils.output import Output


def _findings():
    coll = Findings()
    coll.add(Finding(title="SQL Injection", severity=Severity.HIGH,
                     url="http://host/item?id=1", plugin="Sql"))
    coll.add(Finding(title="Missing CSP header", severity=Severity.LOW,
                     url="http://host/"))
    return coll


@pytest.fixture
def services():
    Services.register("findings", _findings())
    Services.register("output", Output())
    try:
        yield
    finally:
        Services.services.pop("findings", None)
        Services.services.pop("output", None)


def test_publish_reports_success_emits_completion_status(services, tmp_path,
                                                         capsys):
    path = os.path.join(str(tmp_path), "report.json")
    ok = Sitadel()._publish_reports([("json", path)])
    captured = capsys.readouterr()
    if not ok:
        raise AssertionError("a working plan must report success")
    if "Wrote 2 finding(s)" not in captured.out:
        raise AssertionError("the completion status must be published")
    if not os.path.exists(path):
        raise AssertionError("the report file must be committed")


def test_publish_reports_failure_emits_no_success_status(services, tmp_path,
                                                         capsys):
    good = os.path.join(str(tmp_path), "report.json")
    bad = os.path.join(str(tmp_path), "gone", "report.sarif")
    ok = Sitadel()._publish_reports([("json", good), ("sarif", bad)])
    captured = capsys.readouterr()
    if ok:
        raise AssertionError("a failing plan must report failure")
    if "Report export failed" not in captured.out:
        raise AssertionError("the failure must be surfaced")
    if "Wrote" in captured.out:
        raise AssertionError("no success status may be published on failure")
    if os.path.exists(good):
        raise AssertionError("the json output must not be committed alone")


def test_publish_reports_stdout_only_is_a_noop(services):
    if not Sitadel()._publish_reports([]):
        raise AssertionError("stdout-only reporting never fails")
