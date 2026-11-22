"""The report is the last link of the target transaction.

A finding whose URL escaped the shared :class:`TargetScope` must never reach
the :class:`Findings` collector or the serialized report, while in-scope
findings keep their producer ``source`` (report provenance). With no scope
registered the guard is open, preserving legacy behavior.
"""
import logging

import pytest

from sitadel.report import Findings, to_json
from sitadel.request.scope import TargetScope
from sitadel.modules.attacks.targets import Target
from sitadel.utils.container import Services
from sitadel.utils.output import Output


@pytest.fixture
def _wired():
    Services.register("findings", Findings())
    Services.register("target_scope",
                      TargetScope.from_url("http://target.test",
                                           ["api.target.test"]))
    out = Output(quiet=True)
    yield out, Services.get("findings")
    for key in ("findings", "target_scope"):
        Services.services.pop(key, None)


def test_out_of_scope_finding_is_refused(_wired, caplog):
    out, findings = _wired
    with caplog.at_level(logging.DEBUG, logger="sitadelLog"):
        out.finding("foreign result", url="http://evil.example.com/b",
                    source="/openapi.json")
    assert len(findings) == 0
    assert any("out-of-scope finding" in r.getMessage()
               for r in caplog.records)


def test_in_scope_finding_keeps_source(_wired):
    out, findings = _wired
    out.finding("local result", url="http://target.test/a?x=1",
                source="/openapi.json", plugin="Sql")
    items = findings.all()
    assert len(items) == 1
    assert items[0].source == "/openapi.json"
    # Provenance survives report serialization.
    assert '"source": "/openapi.json"' in to_json(items)


def test_explicit_scope_host_finding_is_allowed(_wired):
    out, findings = _wired
    out.finding("api host result", url="https://api.target.test/v2/items")
    assert len(findings) == 1


def test_sourceless_informational_finding_survives(_wired):
    # Legacy single-string findings carry no URL: the guard cannot scope them.
    out, findings = _wired
    out.finding("Found login page")
    assert len(findings) == 1


def test_no_scope_registered_is_legacy_open():
    Services.register("findings", Findings())
    try:
        Output(quiet=True).finding(
            "anything", url="http://other.example/")
        assert len(Services.get("findings")) == 1
    finally:
        Services.services.pop("findings", None)


class _SqlLikeResponse:
    status_code = 200
    headers = {}
    text = "You have an error in your SQL syntax; check the manual"
    url = "http://target.test/api/v1/login"


class _RecordingRequest:
    """Mimics the SingleRequest surface the injection plugin relies on."""

    def __init__(self, scope):
        self.scope = scope
        self.sent = []

    def send(self, url, method="GET", payload=None, headers=None,
             cookies=None, allow_redirects=None):
        self.sent.append(url)
        if self.scope.denied(url):
            return None
        return _SqlLikeResponse()


def test_finding_inherits_target_provenance_through_full_chain():
    # One target transaction flows spec target -> request gate -> finding.
    scope = TargetScope.from_url("http://target.test")
    request = _RecordingRequest(scope)
    Services.register("target_scope", scope)
    Services.register("findings", Findings())
    Services.register("output", Output(quiet=True))
    Services.register("logger", logging.getLogger("chain"))
    Services.register("request_factory", request)
    Services.register("datastore", object())
    spec_target = Target(
        url="http://target.test/api/v1/login",
        method="POST", body_format="json",
        params={"username": "1"}, source="/openapi.json",
    )
    Services.register("api_targets", [spec_target])
    try:
        from sitadel.modules.attacks.injection.sql import Sql
        Sql().run_injection(
            ["' OR '1'='1"], [],
            detector=lambda resp, payload: "MySQL Injection",
        )
        findings = Services.get("findings").all()
        assert len(findings) == 1
        assert findings[0].source == "/openapi.json"
        assert findings[0].url == "http://target.test/api/v1/login"
        # Every request stayed inside the transaction.
        assert all(scope.allows(u) for u in request.sent)
    finally:
        for key in ("target_scope", "findings", "request_factory",
                    "datastore", "api_targets"):
            Services.services.pop(key, None)
