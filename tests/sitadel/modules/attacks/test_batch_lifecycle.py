"""Shared batch state: budget, futures, cancel and Findings move together.

Regression cover for the "late finding after completion" bug: after a cancel
or a request error, every worker must converge and no finding may reach the
report collector. The batch is also the single gate through which
``Output.finding`` submissions are checked during the attack phase.
"""
import logging
import threading
import time

import pytest

from sitadel.modules.attacks.batch import Batch, BatchClosed
from sitadel.report import Findings
from sitadel.request.request import (
    _RateLimiter,
    _interruptible_sleep,
)
from sitadel.utils.container import Services
from sitadel.utils.output import Output


@pytest.fixture
def services():
    Services.register("output", Output(quiet=True))
    Services.register("logger", logging.getLogger("batch"))
    Services.register("findings", Findings())
    yield
    for key in ("cancel", "attack_batch", "findings", "output", "logger"):
        Services.services.pop(key, None)


def _cancel_event(set_now=False):
    event = threading.Event()
    if set_now:
        event.set()
    Services.register("cancel", event)
    return event


# --------------------------------------------------------------- basics #
def test_normal_completion_records_every_finding(services):
    output = Services.get("output")
    with Batch(workers=4, name="ok") as batch:
        def work(i):
            batch.finding(output, "f%d" % i)
        batch.run([(work, (i,)) for i in range(8)])
    assert len(Services.get("findings")) == 8
    assert "attack_batch" not in Services.services


def test_submit_after_close_raises(services):
    batch = Batch(workers=2, name="closed")
    batch.close()
    with pytest.raises(BatchClosed):
        batch.submit(lambda: None)


def test_invalid_worker_count(services):
    with pytest.raises(ValueError):
        Batch(workers=0)


# ------------------------------------------------------------- cancel #
def test_inflight_cap_never_submits_after_cancel(services):
    workers, total = 4, 100
    release = threading.Event()
    all_in_flight = threading.Event()
    state = {"arrivals": 0}
    lock = threading.Lock()
    event = _cancel_event()
    entered = []

    def task(i):
        with lock:
            entered.append(i)
            state["arrivals"] += 1
            if state["arrivals"] == workers:
                all_in_flight.set()
        release.wait(5.0)

    with Batch(workers=workers, name="cap") as batch:
        runner = threading.Thread(
            target=lambda: batch.run([(task, (i,)) for i in range(total)])
        )
        runner.start()
        assert all_in_flight.wait(5.0)
        event.set()
        release.set()
        runner.join(5.0)
        assert not runner.is_alive()

    # Exactly one prime wave ever started; nothing past it was submitted.
    assert len(entered) == workers


def test_cancelled_batch_drops_findings_through_both_paths(services):
    event = _cancel_event()
    output = Services.get("output")
    with Batch(workers=2, name="late") as batch:
        assert batch.finding(output, "before cancel") is True
        event.set()
        assert batch.finding(output, "after cancel") is False
        # The global Output gate enforces the same for any code path.
        output.finding("raw late finding")
    titles = [f.title for f in Services.get("findings").all()]
    assert titles == ["before cancel"]


def test_abort_converges_and_blocks_findings(services):
    output = Services.get("output")
    with Batch(workers=1, name="abort") as batch:
        proceeded = []

        def work(i):
            if i == 0:
                batch.abort()
            if batch.cancelled():
                return
            proceeded.append(i)

        batch.run([(work, (i,)) for i in range(10)])
        assert batch.cancelled()
        assert batch.finding(output, "late") is False
        before = len(Services.get("findings"))
        output.finding("raw after abort")
        assert len(Services.get("findings")) == before
    assert proceeded == []
    assert len(Services.get("findings")) == 0


def test_budget_semaphore_blocks_and_releases(services):
    batch = Batch(workers=1, budget=1)
    try:
        assert batch.acquire()
        assert batch.acquire(timeout=0.05) is False
        batch.release()
        assert batch.acquire(timeout=0.05)
        batch.release()
    finally:
        batch.close()


# --------------------------------------------- rate limiter + cancel #
def test_rate_limiter_wait_is_cancel_interruptible():
    limiter = _RateLimiter(rate=2)  # 0.5s slots
    cancel = threading.Event()
    assert limiter.acquire() is True
    threading.Timer(0.05, cancel.set).start()
    start = time.monotonic()
    assert limiter.acquire(cancel) is False
    assert time.monotonic() - start < 0.2
    # The reserved slot was handed back, so the next acquire still works.
    assert limiter.acquire(threading.Event()) is True


def test_rate_limiter_without_cancel_keeps_spacing():
    limiter = _RateLimiter(rate=20)
    start = time.monotonic()
    for _ in range(4):
        assert limiter.acquire(threading.Event())
    assert time.monotonic() - start >= 0.1


def test_interruptible_sleep_reports_cancellation():
    event = threading.Event()
    threading.Timer(0.02, event.set).start()
    assert _interruptible_sleep(5.0, event) is False
    assert _interruptible_sleep(0.01) is True


def test_output_without_batch_is_unaffected(services):
    # No active batch gate: findings flow exactly as before.
    Services.services.pop("attack_batch", None)
    output = Services.get("output")
    output.finding("ungated finding")
    assert Services.get("findings").all()[0].title == "ungated finding"


def test_default_pool_size_matches_legacy_worker_bound(services):
    # The legacy attack pools all used max_workers=20; the batch must keep
    # that exact concurrency boundary.
    from sitadel.modules.attacks import AttackPlugin
    import inspect
    sig = inspect.signature(AttackPlugin.run_injection)
    assert sig.parameters["workers"].default == 20
    batch = Batch()
    try:
        assert batch._executor._max_workers == 20
    finally:
        batch.close()


def test_single_task_runs_once(services):
    calls = []
    with Batch(workers=20, name="single") as batch:
        batch.run([(calls.append, ("only",))])
    assert calls == ["only"]


def test_empty_task_set_is_a_clean_noop(services):
    with Batch(workers=4, name="empty") as batch:
        batch.run([])
    assert "attack_batch" not in Services.services


def test_worker_exception_propagates_but_still_closes(services):
    def boom():
        raise ValueError("worker blew up")

    with pytest.raises(ValueError):
        with Batch(workers=2, name="boom") as batch:
            batch.run([(boom, ())])
    # The context manager's close() still ran and released the gate.
    assert "attack_batch" not in Services.services


def test_late_worker_finding_after_completion_is_rejected(services):
    """Exact regression: a finding produced after the cancel/completion point
    must never reach the collector, regardless of worker timing."""
    event = _cancel_event()
    output = Services.get("output")
    collector = Services.get("findings")
    hold = threading.Event()

    with Batch(workers=2, name="late-worker") as batch:
        def slow_worker():
            # Worker is still in flight when cancel lands (simulating a
            # request parked in the rate-limiter queue).
            hold.wait(2.0)
            # Every submission path is gated by the same batch state.
            assert batch.finding(output, "from batch helper") is False
            output.finding("from raw output path")  # must be dropped too

        future = batch.submit(slow_worker)
        event.set()  # completion/cancel point
        hold.set()  # release the in-flight worker
        future.result(2.0)

    assert len(collector) == 0
    assert "attack_batch" not in Services.services
