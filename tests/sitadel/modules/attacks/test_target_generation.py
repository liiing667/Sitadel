"""Target-shape generations keep old query params out of a new body attack."""

import json

import pytest

from sitadel.modules.attacks import AttackPlugin
from sitadel.modules.attacks.targets import Target, TargetLedger, taint_target
from sitadel.utils.container import Services


_SERVICES = (
    "page_targets",
    "form_targets",
    "api_targets",
    "target_generation",
    "target_ledger",
    "request_factory",
    "output",
    "logger",
    "findings",
)


@pytest.fixture(autouse=True)
def _clean_target_services():
    yield
    for key in _SERVICES:
        Services.services.pop(key, None)


class _Output:
    def __init__(self):
        self.reported = []

    def debug(self, *_args):
        pass

    def info(self, *_args):
        pass

    def finding(self, value, **kwargs):
        self.reported.append((value, kwargs))


class _Request:
    def __init__(self):
        self.calls = []

    def send(self, **kwargs):
        self.calls.append(kwargs)
        return type("Response", (), {
            "status_code": 500,
            "text": "You have an error in your SQL syntax",
            "headers": {},
        })()


class _Logger:
    def error(self, *_args):
        pass


def test_body_target_does_not_reinterpret_old_query_params():
    target = Target(
        url="http://host/item?id=old",
        method="POST",
        location="body",
        body_format="json",
        params={"name": "sample"},
    )

    request = taint_target(target, "PAYLOAD")

    assert request["url"] == "http://host/item?id=old"
    assert json.loads(request["payload"]) == {"name": "PAYLOAD"}
    assert "id" not in request["payload"]


def test_query_target_stays_query_only():
    target = Target(url="http://host/item?id=old", location="query")

    request = taint_target(target, "PAYLOAD")

    assert request["method"] == "GET"
    assert request["payload"] is None
    assert "id=PAYLOAD" in request["url"]


def test_target_identity_is_order_and_value_independent():
    first = Target(url="http://host/item?id=1&sort=asc")
    second = Target(url="http://host/item?sort=desc&id=2")
    post = Target(
        url="http://host/item",
        method="POST",
        location="body",
        body_format="form",
        params={"id": "1", "sort": "asc"},
    )

    assert first.identity == second.identity
    assert first.identity != post.identity


def test_page_retry_replaces_get_query_with_post_body():
    ledger = TargetLedger()
    ledger.record_page("http://host/item", [
        Target(url="http://host/item?id=1", location="query", source="form"),
    ])
    old_generation = ledger.snapshot()[0].generation

    ledger.record_page("http://host/item", [
        Target(
            url="http://host/item?id=old",
            method="POST",
            location="body",
            body_format="form",
            params={"name": ""},
            source="form",
        ),
    ])

    current = ledger.snapshot()
    assert len(current) == 1
    target = current[0]
    assert target.method == "POST"
    assert target.location == "body"
    assert target.parameter_location == "body"
    assert target.source == "form"
    assert target.source_url == "http://host/item"
    assert target.generation > old_generation
    assert "id" not in (taint_target(target, "PAYLOAD")["payload"] or "")


def test_later_link_does_not_reintroduce_old_query_shape():
    ledger = TargetLedger()
    ledger.record_page("http://host/item", [
        Target(
            url="http://host/item",
            method="POST",
            location="body",
            body_format="form",
            params={"name": ""},
            source="form",
        ),
    ])
    ledger.record_page("http://host/other", [
        Target(url="http://host/other", source="page"),
        Target(url="http://host/item?id=old"),
    ])

    item_targets = [
        target for target in ledger.snapshot()
        if target.endpoint == "http://host/item"
    ]
    assert len(item_targets) == 1
    assert item_targets[0].method == "POST"
    assert item_targets[0].location == "body"


def test_build_targets_drops_superseded_url_and_legacy_form():
    ledger = TargetLedger()
    ledger.record_page("http://host/item", [
        Target(
            url="http://host/item",
            method="POST",
            location="body",
            body_format="form",
            params={"name": ""},
            source="form",
        ),
    ])
    Services.register("page_targets", ledger.snapshot())
    Services.register("form_targets", [
        Target(url="http://host/item?id=old", location="query"),
    ])

    targets = AttackPlugin.build_targets(["http://host/item?id=old"])

    assert len(targets) == 1
    assert targets[0].method == "POST"
    assert targets[0].location == "body"
    assert targets[0].parameter_label == "name"


def test_attack_finding_uses_the_same_probed_target_shape():
    output = _Output()
    request = _Request()
    Services.register("output", output)
    Services.register("logger", _Logger())
    Services.register("request_factory", request)
    Services.register("page_targets", [
        Target(
            url="http://host/item?id=old",
            method="POST",
            location="body",
            body_format="form",
            params={"name": ""},
            source="form",
            source_url="http://host/item",
            generation=7,
        ),
    ])

    AttackPlugin().run_injection(
        ["PAYLOAD"],
        [],
        lambda _response, _payload: "MySQL Injection",
        workers=1,
    )

    assert len(request.calls) == 1
    assert request.calls[0]["method"] == "POST"
    assert request.calls[0]["url"] == "http://host/item?id=old"
    assert request.calls[0]["payload"] == "name=PAYLOAD"
    assert len(output.reported) == 1

    _title, finding = output.reported[0]
    assert finding["parameter"] == "name"
    assert finding["endpoint"] == "http://host/item"
    assert finding["method"] == "POST"
    assert finding["parameter_location"] == "body"
    assert finding["source"] == "form"
    assert finding["source_url"] == "http://host/item"
    assert finding["generation"] == 7
    assert "id" not in finding["evidence"].split("|")[0]


def test_legacy_body_target_without_location_still_works():
    target = Target(
        url="http://host/login",
        method="POST",
        body_format="form",
        params={"user": ""},
    )

    assert target.location == "body"
    assert taint_target(target, "PAYLOAD")["payload"] == "user=PAYLOAD"
