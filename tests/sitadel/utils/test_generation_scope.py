"""Generation scoping: one crawl/profile/finding/report surface per scan.

These tests exercise the public ``Services``/``ScanGeneration`` contract
without a network or the CLI: a retry must start from an empty surface, and a
worker bound to an older generation must not feed the new scan's report.
"""
import json
import logging

import pytest

from sitadel.report import Findings
from sitadel.utils.container import Services
from sitadel.utils.generation import (
    CrawlSnapshot,
    ScanGeneration,
    close_generation,
    current_generation,
    start_generation,
)
from sitadel.utils.output import Output


@pytest.fixture(autouse=True)
def _reset_services():
    Services.reset()
    yield
    Services.reset()


def _bind_output() -> Output:
    output = Output(quiet=True)
    Services.register("output", output)
    Services.register("logger", logging.getLogger("test-generation"))
    return output


def test_begin_generation_resets_every_scan_owned_service():
    first = start_generation(target="http://first/")
    output = _bind_output()
    output.finding("first finding", url="http://first/x")
    first.profile.add("lang", "PHP")
    first.snapshot_crawl(
        ["http://first/", "http://first/x"], [], {"http://first/": "<html>"}
    )

    second = start_generation(target="http://second/")

    assert first.id < second.id
    assert current_generation() is second
    assert first.active is False
    assert second.report_findings() == []
    assert Services.get("findings") is second.findings
    assert Services.get("profile") is second.profile
    assert Services.get("page_bodies") == {}
    assert Services.get("form_targets") == []
    with pytest.raises(NameError):
        Services.get("crawl_snapshot")


def test_snapshot_is_immutable_and_handles_single_and_empty_targets():
    generation = start_generation()

    single = generation.snapshot_crawl(
        "http://one/", [], {"http://one/": "<html>"}
    )
    assert single.pages == ("http://one/",)
    assert single.bodies["http://one/"] == "<html>"
    with pytest.raises((AttributeError, TypeError)):
        single.urls = ()
    with pytest.raises(TypeError):
        single.page_bodies["http://one/"] = "changed"

    empty = generation.snapshot_crawl([], [], {})
    assert empty.urls == ()
    assert empty.targets() == []

    direct = CrawlSnapshot.capture(
        generation, urls=None, form_targets=None, page_bodies=None
    )
    assert direct.generation == generation.id
    assert direct.urls == ()


def test_stale_output_cannot_write_to_the_retry_report():
    old_output = _bind_output()
    first = start_generation()
    old_output.finding("first generation finding")
    assert [f.title for f in first.report_findings()] == [
        "first generation finding"
    ]

    second = start_generation()
    old_output.finding("late first generation finding")
    assert second.report_findings() == []
    assert [f.title for f in first.report_findings()] == [
        "first generation finding"
    ]

    # Re-registering the channel explicitly (as the CLI does for every run)
    # moves it to the new generation.
    _bind_output().finding("second generation finding")
    assert [f.title for f in second.report_findings()] == [
        "second generation finding"
    ]


def test_closed_generation_accepts_no_late_findings():
    output = _bind_output()
    generation = start_generation()
    output.finding("kept")
    close_generation(generation, state="cancelled")

    output.finding("late")
    Output(quiet=True).finding("legacy after close")

    assert generation.state == "cancelled"
    assert [f.title for f in generation.report_findings()] == ["kept"]


def test_failed_recrawl_drops_the_previous_surface():
    generation = start_generation()
    generation.snapshot_crawl(
        ["http://old/"], [object()], {"http://old/": "<html>"}
    )

    # ``crawl`` clears the surface before fetching so a timeout cannot leave
    # the previous generation's pages in the current one.
    generation.clear_crawl()

    assert generation.crawl is None
    assert generation.crawl_urls == []
    assert Services.get("page_bodies") == {}
    assert Services.get("form_targets") == []
    with pytest.raises(NameError):
        Services.get("crawl_snapshot")

    close_generation(generation)
    assert generation.snapshot_crawl(["http://late/"]) is None
    assert generation.crawl is None


def test_report_is_built_only_from_the_owning_generation(tmp_path):
    first = start_generation()
    _bind_output().finding("first")
    first.snapshot_crawl(["http://first/"], [], {})

    second = start_generation()
    _bind_output().finding("second")
    second.snapshot_crawl(["http://second/"], [], {})

    path = tmp_path / "report.json"
    second.write_report("json", str(path))
    report = json.loads(path.read_text(encoding="utf-8"))

    assert [item["title"] for item in report] == ["second"]
    assert second.crawl_urls == ["http://second/"]
    assert first.crawl_urls == ["http://first/"]


def test_legacy_calls_without_a_generation_still_record_findings():
    collector = Findings()
    Services.register("findings", collector)
    Services.register("logger", logging.getLogger("test-generation"))

    Output(quiet=True).finding("legacy finding")

    assert [f.title for f in collector.all()] == ["legacy finding"]
