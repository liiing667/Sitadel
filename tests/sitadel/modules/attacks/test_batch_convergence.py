"""End-to-end convergence of the injection runner under cancel and errors.

The fixed result the scanner must guarantee: after a cancel (including while
workers are parked in the rate-limiter queue) or after request errors, workers
converge, stop producing findings and never submit twice.
"""
import logging
import threading
import time

from sitadel.report import Findings
from sitadel.utils.container import Services
from sitadel.utils.datastore import Datastore
from sitadel.utils.output import Output


class _Resp:
    def __init__(self, status_code=200, text="ok"):
        self.status_code = status_code
        self.text = text
        self.headers = {}
        self.url = "http://h/p"


class _SlowRequest:
    """Simulates a request parked behind the global rate-limiter queue."""

    def __init__(self, delay=0.15, status_code=200, text="ok"):
        self.delay = delay
        self._status = status_code
        self._text = text
        self.sends = 0
        self._lock = threading.Lock()

    def send(self, **kwargs):
        time.sleep(self.delay)
        with self._lock:
            self.sends += 1
        return _Resp(self._status, self._text)


class _NoneRequest:
    def __init__(self):
        self.sends = 0

    def send(self, **kwargs):
        self.sends += 1
        return None


def _register(stub, cancelled=False):
    Services.register("output", Output(quiet=True))
    Services.register("logger", logging.getLogger("conv"))
    Services.register("datastore", Datastore("sitadel/data"))
    Services.register("findings", Findings())
    Services.register("request_factory", stub)
    event = threading.Event()
    if cancelled:
        event.set()
    Services.register("cancel", event)
    return event


def _cleanup():
    for key in ("cancel", "request_factory", "findings", "api_targets",
                "form_targets", "attack_batch", "output", "logger",
                "datastore"):
        Services.services.pop(key, None)


# Sql resolves Services at class-definition time; register a stub first.
_register(_SlowRequest())
from sitadel.modules.attacks.injection.sql import Sql  # noqa: E402


_URLS = ["http://h/p?id=1", "http://h/q?id=2", "http://h/r?id=3"]


def test_precancelled_scan_sends_nothing_and_records_nothing():
    stub = _SlowRequest()
    _register(stub, cancelled=True)
    try:
        Sql().process("http://h/", _URLS)
        assert stub.sends == 0
        assert len(Services.get("findings")) == 0
        assert "attack_batch" not in Services.services
    finally:
        _cleanup()


def test_cancel_while_queued_converges_without_late_finding():
    stub = _SlowRequest(delay=0.3)
    event = _register(stub)
    try:
        threading.Timer(0.05, event.set).start()
        Sql().process("http://h/", _URLS)
        # Only the prime in-flight wave (<= 20 workers) can have sent; the
        # rest of the 48-task queue (16 payloads x 3 urls) never starts.
        assert stub.sends <= 20
        assert len(Services.get("findings")) == 0
        assert "attack_batch" not in Services.services
        # Long grace window proving no straggler writes afterwards.
        time.sleep(0.5)
        assert len(Services.get("findings")) == 0
    finally:
        _cleanup()


def test_request_errors_converge_without_findings():
    stub = _NoneRequest()
    _register(stub)
    try:
        Sql().process("http://h/", ["http://h/p?id=1"])
        assert stub.sends > 0
        assert len(Services.get("findings")) == 0
        assert "attack_batch" not in Services.services
    finally:
        _cleanup()


def test_happy_path_still_records_findings():
    stub = _SlowRequest(delay=0.0,
                        text="You have an error in your SQL syntax;")
    _register(stub)
    try:
        Sql().process("http://h/", ["http://h/p?id=1"])
        assert stub.sends > 0
        assert len(Services.get("findings")) >= 1
    finally:
        _cleanup()


def test_429_responses_retry_then_converge(monkeypatch):
    import sitadel.request.request as reqmod
    stub = _SlowRequest(delay=0.0, status_code=429)
    _register(stub)
    monkeypatch.setattr(reqmod, "_BACKOFF_BASE", 0.01)
    monkeypatch.setattr(reqmod, "_BACKOFF_CAP", 0.05)
    try:
        start = time.monotonic()
        Sql().process("http://h/", ["http://h/p?id=1"])
        assert time.monotonic() - start < 10.0
        assert stub.sends > 0  # bounded retries did happen
        assert len(Services.get("findings")) == 0
    finally:
        _cleanup()
