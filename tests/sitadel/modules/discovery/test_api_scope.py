"""Target-transaction enforcement at the OpenAPI/Swagger discovery boundary.

The spec source, the declared ``servers``/``basePath``, every materialized
endpoint and the request/finding layers must share one :class:`TargetScope`.
In particular an *absolute* server on a foreign host must never become an
injectable target — not even one that the request layer would later skip —
while relative servers, path templates, explicitly scoped hosts, the no-spec
path and legacy (scope-less) callers keep working.
"""
import json
import logging
from urllib.parse import urlsplit

import pytest

from sitadel.model import TargetProfile
from sitadel.modules.discovery import discover
from sitadel.modules.discovery.api import targets_from_spec
from sitadel.request.request import SingleRequest
from sitadel.request.scope import TargetScope
from sitadel.utils.container import Services
from sitadel.utils.datastore import Datastore
from sitadel.utils.output import Output

ORIGIN = "http://target.test"
SCOPE = TargetScope.from_url(ORIGIN, ["api.target.test"])


class _RecordingOutput:
    """Captures the levels the producer emits (no colorama/logging needed)."""

    def __init__(self):
        self.debugs, self.infos, self.traces = [], [], []

    def debug(self, msg):
        self.debugs.append(msg)

    def info(self, msg):
        self.infos.append(msg)

    def trace(self, msg):
        self.traces.append(msg)

    def error(self, msg):
        pass

    def finding(self, *a, **k):
        pass


# --------------------------------------------------------------------------- #
# targets_from_spec: scope filtering + provenance
# --------------------------------------------------------------------------- #
def test_external_absolute_server_is_excluded_before_any_request():
    spec = {
        "openapi": "3.0.0",
        "servers": [{"url": "https://evil.example.com/v2"}],
        "paths": {
            "/pwn": {"get": {"parameters": [{"in": "query", "name": "q"}]}},
            "/boom": {"post": {"requestBody": {"content": {
                "application/json": {"schema": {
                    "properties": {"a": {}}}}}}}},
        },
    }
    out = _RecordingOutput()
    targets = targets_from_spec(spec, ORIGIN, scope=SCOPE,
                                source="/openapi.json", output=out)
    assert targets == []
    # The refusal is explained (acceptance: pre-request target set visible).
    assert any("out-of-scope API server" in m and
               "evil.example.com" in m for m in out.debugs)


def test_relative_server_and_path_templates_stay_in_scope():
    spec = {
        "openapi": "3.0.0",
        "servers": [{"url": "/api/v1"}],
        "paths": {
            "/items/{id}": {"get": {"parameters": [
                {"in": "query", "name": "filter"}]}},
        },
    }
    targets = targets_from_spec(spec, ORIGIN, scope=SCOPE, source="/openapi.json")
    assert len(targets) == 1
    t = targets[0]
    assert t.url == "http://target.test/api/v1/items/1?filter=1"
    assert t.source == "/openapi.json"  # provenance flows onto the target


def test_swagger_basepath_is_relative_and_retained():
    spec = {"swagger": "2.0", "basePath": "/rest",
            "paths": {"/users": {"post": {"parameters": [
                {"in": "body", "name": "b",
                 "schema": {"properties": {"email": {}}}}]}}}}
    targets = targets_from_spec(spec, ORIGIN, scope=SCOPE, source="/swagger.json")
    assert [t.url for t in targets] == ["http://target.test/rest/users"]
    assert targets[0].source == "/swagger.json"


def test_absolute_server_on_explicit_scope_host_is_kept():
    spec = {
        "openapi": "3.0.0",
        "servers": [{"url": "https://api.target.test/v2"}],
        "paths": {"/items/{id}": {"get": {}}},
    }
    targets = targets_from_spec(spec, ORIGIN, scope=SCOPE, source="/openapi.json")
    assert len(targets) == 1
    assert targets[0].url == "https://api.target.test/v2/items/1"


def test_absolute_server_on_target_origin_is_not_external():
    # Same host, different scheme/port: still the same target transaction.
    spec = {"openapi": "3.0.0",
            "servers": [{"url": "http://target.test:9000/"}],
            "paths": {"/h": {"get": {}}}}
    targets = targets_from_spec(spec, ORIGIN, scope=SCOPE, source="/openapi.json")
    assert [t.url for t in targets] == ["http://target.test:9000/h"]


def test_legacy_scopeless_call_keeps_all_endpoints():
    # Old API target: direct callers that pass no scope stay unrestricted.
    spec = {"openapi": "3.0.0",
            "servers": [{"url": "https://evil.example.com/v2"}],
            "paths": {"/pwn": {"get": {}}}}
    targets = targets_from_spec(spec, ORIGIN)
    assert len(targets) == 1
    assert targets[0].url == "https://evil.example.com/v2/pwn"
    assert targets[0].source is None


def test_all_paths_excluded_reports_zero_targets_without_wire_calls():
    spec = {
        "openapi": "3.0.0",
        "servers": [{"url": "https://evil.example.com"}],
        "paths": {f"/p{i}": {"get": {}} for i in range(3)},
    }
    targets = targets_from_spec(spec, ORIGIN, scope=SCOPE, source="/openapi.json")
    assert targets == []


def test_per_endpoint_guard_drops_any_foreign_materialization():
    # The per-endpoint guard is defense in depth: even if a future server
    # resolution produced an in-scope base with an endpoint that materializes
    # on a foreign host, that single endpoint is refused and the rest survive.
    from sitadel.modules.discovery import api as api_mod

    real = api_mod._base_url
    api_mod._base_url = lambda doc, origin: (ORIGIN + "/api", False)
    try:
        spec = {"openapi": "3.0.0",
                "paths": {
                    "/ok": {"get": {}},
                    "/x": {"get": {}},
                }}
        out = _RecordingOutput()
        # Force one materialized URL off-scope via a narrow endpoint stub.
        orig_endpoint = api_mod._endpoint_url
        api_mod._endpoint_url = lambda base, path, query: (
            "https://evil.example.com/foreign" if path == "/x"
            else orig_endpoint(base, path, query)
        )
        try:
            targets = targets_from_spec(spec, ORIGIN, scope=SCOPE,
                                        source="/openapi.json", output=out)
        finally:
            api_mod._endpoint_url = orig_endpoint
    finally:
        api_mod._base_url = real
    assert [t.url for t in targets] == ["http://target.test/api/ok"]
    assert any("evil.example.com" in m for m in out.debugs)


# --------------------------------------------------------------------------- #
# discover(): the request factory's scope is the discovery scope
# --------------------------------------------------------------------------- #
class _FakeResponse:
    def __init__(self, status_code=200, text="", headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}


class _FakeRequest:
    """Stand-in for SingleRequest: records every URL it is asked to send."""

    def __init__(self, spec_body, scope):
        self._spec = spec_body
        self.scope = scope
        self.requested = []

    def send(self, url, method="GET", **kwargs):
        self.requested.append((method, url))
        if url.endswith("/openapi.json"):
            return _FakeResponse(200, self._spec)
        return _FakeResponse(404, "")


def test_discover_shares_the_request_scope_and_excludes_external_server():
    spec = json.dumps({
        "openapi": "3.0.0",
        "servers": [{"url": "https://evil.example.com/v2"}],
        "paths": {"/pwn": {"get": {}}},
    })
    req = _FakeRequest(spec, SCOPE)
    out = _RecordingOutput()
    targets = discover(ORIGIN, req, profile=TargetProfile(), output=out)
    # Acceptance: the pre-request target set contains no foreign endpoint...
    assert targets == []
    # ...and the only wire traffic was fetching the in-scope spec itself.
    assert all(urlsplit(url).hostname in SCOPE.hosts
               for _, url in req.requested)
    assert any(u.endswith("/openapi.json") for _, u in req.requested)


def test_discover_keeps_relative_endpoints_and_marks_source():
    spec = json.dumps({
        "openapi": "3.0.0",
        "servers": [{"url": "/api/v1"}],
        "paths": {"/items/{id}": {"get": {}}},
    })
    req = _FakeRequest(spec, SCOPE)
    targets = discover(ORIGIN, req, output=_RecordingOutput())
    assert [t.url for t in targets] == ["http://target.test/api/v1/items/1"]
    assert targets[0].source == "/openapi.json"


@pytest.fixture
def _services():
    Services.register("output", Output(quiet=True))
    Services.register("logger", logging.getLogger("scope-test"))
    Services.register("datastore", Datastore("sitadel/data"))
    yield
    for key in ("output", "logger", "datastore", "api_targets",
                "request_factory", "target_scope", "findings"):
        Services.services.pop(key, None)


# --------------------------------------------------------------------------- #
# End-to-end: the request factory's own transaction drives discovery, and the
# foreign host receives zero wire calls (host-only scope, distinct hostnames).
# --------------------------------------------------------------------------- #
class _SpecServingRequest:
    """Mimics SingleRequest: serves the spec in-scope, counts every send."""

    def __init__(self, scope, spec_body):
        self.scope = scope
        self._spec = spec_body
        self.sent = []

    def send(self, url, method="GET", **kwargs):
        # Replicate the wire gate: an out-of-scope URL never leaves the client.
        if self.scope.denied(url):
            return None
        self.sent.append((method, url))
        if urlsplit(url).path == "/openapi.json":
            return _FakeResponse(200, self._spec)
        return _FakeResponse(404, "")


def test_foreign_server_receives_zero_attack_requests(_services):
    site = "http://target.test"
    # The exact SingleRequest transaction the CLI would build for this scan.
    factory = SingleRequest(url=site, timeout=5)
    spec_body = json.dumps({
        "openapi": "3.0.0",
        "servers": [{"url": "https://foreign.example.com/v2"}],
        "paths": {"/pwn": {"get": {
            "parameters": [{"in": "query", "name": "q"}]}}},
    })
    request = _SpecServingRequest(factory.scope, spec_body)
    targets = discover(site, request, output=Services.get("output"))
    # Acceptance: the pre-request target set contains no foreign endpoint...
    assert targets == []
    # ...and the only wire traffic was fetching the in-scope spec, i.e. the
    # foreign host was never contacted (no request was even scheduled).
    assert request.sent == [("GET", site + "/openapi.json")]
    assert all("foreign.example.com" not in url for _, url in request.sent)
