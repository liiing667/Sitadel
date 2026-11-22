"""Redirect hops must share one origin transaction.

Credentials (authenticator headers, caller cookies and the session cookie jar)
belong to the origin of the URL passed to ``send``. Every redirect hop is
checked against scope *before* it is contacted, and only same-origin hops keep
the credential material.
"""
import requests
from requests.cookies import create_cookie

from sitadel.request.auth import Authenticator
from sitadel.request.request import SingleRequest
from sitadel.utils.container import Services
from sitadel.utils.output import Output


def _output():
    Services.register("output", Output(quiet=True))


class _Response:
    def __init__(self, status, url, location=None, body="ok"):
        self.status_code = status
        self.url = url
        self.headers = {}
        self.text = body
        self.content = body.encode()
        self.history = []
        if location is not None:
            self.headers["Location"] = location

    def close(self):
        pass


class _RecordingSession(requests.Session):
    def __init__(self, responses):
        super().__init__()
        self.responses = list(responses)
        self.records = []

    def send(self, prepped, **kwargs):
        self.records.append((prepped, dict(kwargs)))
        item = self.responses.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item


def _factory(responses, **kwargs):
    request = SingleRequest(**kwargs)
    request.session = _RecordingSession(responses)
    request.session.cookies.set_cookie(
        create_cookie("session", "SECRET", domain="target.test", path="/")
    )
    request.set_authenticator(
        Authenticator.from_options(
            bearer="TOK", headers=["X-Api-Key: KEY"]
        )
    )
    return request


def _headers(prepped):
    return {name.lower(): value for name, value in prepped.headers.items()}


def test_off_scope_redirect_is_never_contacted_with_credentials():
    _output()
    request = _factory(
        [_Response(302, "http://target.test/start", "http://evil.test/landing")],
        url="http://target.test/",
    )

    if request.send("http://target.test/start") is not None:
        raise AssertionError("off-scope redirect result must be discarded")
    if len(request.session.records) != 1:
        raise AssertionError("the evil.test redirect target was contacted")
    first = _headers(request.session.records[0][0])
    if first.get("authorization") != "Bearer TOK":
        raise AssertionError("same-origin initial hop lost Authorization")
    if first.get("cookie") != "session=SECRET":
        raise AssertionError("same-origin initial hop lost the session cookie")


def test_explicit_scope_host_is_followed_without_credentials():
    _output()
    request = _factory(
        [
            _Response(302, "http://target.test/start", "http://allowed.test/x"),
            _Response(200, "http://allowed.test/x"),
        ],
        url="http://target.test/",
        scope_hosts=["allowed.test"],
    )

    resp = request.send("http://target.test/start")
    if resp is None or resp.status_code != 200:
        raise AssertionError("explicit scope host must still be followed")
    if len(request.session.records) != 2:
        raise AssertionError("expected exactly one cross-origin hop")
    hop = _headers(request.session.records[1][0])
    for name in ("authorization", "cookie", "x-api-key"):
        if name in hop:
            raise AssertionError("credential %s leaked to explicit scope host" % name)


def test_same_origin_redirect_keeps_credentials():
    _output()
    request = _factory(
        [
            _Response(302, "http://target.test/start", "/step"),
            _Response(200, "http://target.test/step"),
        ],
        url="http://target.test/",
    )

    resp = request.send("http://target.test/start")
    if resp is None or resp.status_code != 200:
        raise AssertionError("same-origin redirect must be followed")
    if len(request.session.records) != 2:
        raise AssertionError("expected a second same-origin hop")
    for prepped, _ in request.session.records:
        hop = _headers(prepped)
        if hop.get("authorization") != "Bearer TOK":
            raise AssertionError("same-origin hop lost Authorization")
        if hop.get("cookie") != "session=SECRET":
            raise AssertionError("same-origin hop lost the session cookie")


def test_timeout_on_redirect_hop_stops_the_transaction():
    _output()
    request = _factory(
        [
            _Response(302, "http://target.test/start", "/next"),
            requests.Timeout("slow hop"),
        ],
        url="http://target.test/",
    )

    if request.send("http://target.test/start") is not None:
        raise AssertionError("a timed-out transaction must return None")
    if len(request.session.records) != 2:
        raise AssertionError("must not retry or continue after a timeout")


def test_session_cookies_are_not_flattened_into_supercookies():
    _output()
    request = SingleRequest()
    request.session.cookies.set_cookie(
        create_cookie("session", "SECRET", domain="target.test", path="/")
    )

    cross = request.prepare_request(
        "http://evil.test/x", "GET", None, None, None
    )
    if "Cookie" in cross.headers:
        raise AssertionError("host-only cookie leaked to another host")
    same = request.prepare_request(
        "http://target.test/x", "GET", None, None, None
    )
    if same.headers.get("Cookie") != "session=SECRET":
        raise AssertionError("host cookie was not sent to its own host")

    # Even a cookie created without a domain (session.cookies.set(name, value))
    # is pinned to the transaction host rather than becoming a supercookie.
    transaction = SingleRequest(url="http://target.test/")
    transaction.session.cookies.set("session", "SECRET")
    if "Cookie" in transaction.prepare_request(
        "http://evil.test/x", "GET", None, None, None
    ).headers:
        raise AssertionError("domainless cookie leaked to another host")
    if transaction.prepare_request(
        "http://target.test/x", "GET", None, None, None
    ).headers.get("Cookie") != "session=SECRET":
        raise AssertionError("domainless cookie was not pinned to the target")


class _LoginSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def _call(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        item = self.responses.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item

    def get(self, url, **kwargs):
        return self._call("GET", url, **kwargs)

    def head(self, url, **kwargs):
        return self._call("HEAD", url, **kwargs)

    def post(self, url, **kwargs):
        return self._call("POST", url, **kwargs)

    def request(self, method, url, **kwargs):
        return self._call(method, url, **kwargs)


def test_login_cross_origin_redirect_never_sees_the_login_body():
    _output()
    session = _LoginSession(
        [_Response(307, "http://target.test/login", "http://evil.test/steal")]
    )
    auth = Authenticator.from_options(
        login_url="http://target.test/login",
        login_data="user=admin&password=secret",
    )

    resp = auth.login(session)
    if resp is None or resp.status_code != 307:
        raise AssertionError("cross-origin login redirect must not be followed")
    if len(session.calls) != 1:
        raise AssertionError("login body was replayed to the redirect target")
    method, url, kwargs = session.calls[0]
    if method != "POST" or url != "http://target.test/login":
        raise AssertionError("login POST went to the wrong destination")
    if kwargs["data"].get("password") != "secret":
        raise AssertionError("login body missing on the legitimate entry point")


def test_login_same_origin_redirect_is_still_followed():
    _output()
    session = _LoginSession(
        [
            _Response(302, "http://target.test/login", "/home"),
            _Response(200, "http://target.test/home"),
        ]
    )
    auth = Authenticator.from_options(
        login_url="http://target.test/login",
        login_data="user=admin&password=secret",
    )

    resp = auth.login(session)
    if resp is None or resp.status_code != 200:
        raise AssertionError("same-origin post-login redirect must be followed")
    if [call[0] for call in session.calls] != ["POST", "GET"]:
        raise AssertionError("unexpected login redirect method sequence")
