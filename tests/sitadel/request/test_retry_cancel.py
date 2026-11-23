"""429/5xx bounded back-off and cancel-interruptible request waiting."""
import logging
import threading

import pytest
import requests

from sitadel.request.request import SingleRequest, _RETRY_STATUS
from sitadel.utils.container import Services
from sitadel.utils.output import Output


@pytest.fixture(autouse=True)
def _services():
    Services.register("output", Output(quiet=True))
    Services.register("logger", logging.getLogger("retry"))
    yield
    for k in ("output", "logger", "cancel"):
        Services.services.pop(k, None)


class _FakeSession:
    cookies = requests.cookies.RequestsCookieJar()

    def __init__(self, statuses):
        self._statuses = list(statuses)
        self.calls = 0

    def send(self, prepped, **kwargs):
        self.calls += 1
        status = self._statuses[min(self.calls - 1, len(self._statuses) - 1)]

        class _R:
            headers = {}
            url = prepped.url
        _R.status_code = status
        _R.text = ""
        return _R()


def _req(session, **kw):
    r = SingleRequest(**kw)
    r.session = session
    return r


def test_429_is_retried_then_returned(monkeypatch):
    import sitadel.request.request as mod
    monkeypatch.setattr(mod, "_BACKOFF_BASE", 0.01)
    monkeypatch.setattr(mod, "_BACKOFF_CAP", 0.05)
    session = _FakeSession([429, 429, 200])
    resp = _req(session).send(url="http://target.test/x")
    assert resp.status_code == 200
    assert session.calls == 3  # original + two bounded retries


def test_5xx_retries_are_bounded(monkeypatch):
    import sitadel.request.request as mod
    monkeypatch.setattr(mod, "_BACKOFF_BASE", 0.01)
    monkeypatch.setattr(mod, "_BACKOFF_CAP", 0.05)
    session = _FakeSession([503])
    resp = _req(session).send(url="http://target.test/x")
    # Exhausts the bounded retries and still returns the response instead of
    # hanging or raising.
    assert resp.status_code == 503
    assert session.calls == 1 + mod._MAX_HTTP_RETRIES


def test_retry_after_header_is_honored(monkeypatch):
    import sitadel.request.request as mod
    monkeypatch.setattr(mod, "_BACKOFF_BASE", 0.01)
    monkeypatch.setattr(mod, "_BACKOFF_CAP", 0.05)

    class _Session(_FakeSession):
        def send(self, prepped, **kwargs):
            resp = super().send(prepped, **kwargs)
            resp.headers = {"Retry-After": "0.02"}
            return resp

    session = _Session([429, 200])
    resp = _req(session).send(url="http://target.test/x")
    assert resp.status_code == 200
    assert session.calls == 2


def test_retryable_status_set_covers_429_and_5xx():
    assert {429, 500, 502, 503, 504} <= _RETRY_STATUS


def test_cancel_during_backoff_returns_none(monkeypatch):
    import sitadel.request.request as mod
    monkeypatch.setattr(mod, "_BACKOFF_BASE", 5.0)
    monkeypatch.setattr(mod, "_BACKOFF_CAP", 10.0)
    event = threading.Event()
    Services.register("cancel", event)
    threading.Timer(0.05, event.set).start()
    session = _FakeSession([429])
    resp = _req(session).send(url="http://target.test/x")
    assert resp is None


def test_cancel_before_send_skips_request_entirely():
    event = threading.Event()
    event.set()
    Services.register("cancel", event)
    session = _FakeSession([200])
    resp = _req(session).send(url="http://target.test/x")
    assert resp is None
    assert session.calls == 0
