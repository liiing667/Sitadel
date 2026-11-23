import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import TCPServer, ThreadingMixIn
from urllib.parse import urlsplit

import pytest

import sitadel.modules.crawler.crawler as crawler_module
from sitadel.config import settings
from sitadel.modules.crawler.crawler import crawl, url_signature
from sitadel.utils.container import Services
from sitadel.utils.output import Output


@pytest.fixture(autouse=True)
def _clean_target_snapshot():
    """A crawl snapshot is process-global; do not leak it between tests."""
    try:
        yield
    finally:
        for key in (
            "page_targets",
            "form_targets",
            "api_targets",
            "target_generation",
            "target_ledger",
        ):
            Services.services.pop(key, None)


# ---------------------------------------------------------------------------
# Unit tests for the parameter-signature de-duplication
# ---------------------------------------------------------------------------
def test_signature_collapses_parameter_values():
    a = url_signature("http://host/item?id=1")
    b = url_signature("http://host/item?id=2")
    # Same path + same parameter names => same signature (values ignored).
    if a != b:
        raise AssertionError


def test_signature_distinguishes_parameter_names_and_paths():
    base = url_signature("http://host/item?id=1")
    if url_signature("http://host/item?id=1&sort=asc") == base:
        raise AssertionError  # extra parameter name -> different shape
    if url_signature("http://host/other?id=1") == base:
        raise AssertionError  # different path -> different shape


def test_signature_ignore_params():
    a = url_signature("http://host/p?id=1&utm_source=x", ignore_params=("utm_source",))
    b = url_signature("http://host/p?id=1", ignore_params=("utm_source",))
    if a != b:
        raise AssertionError


def test_crawl_snapshot_retires_get_link_when_page_becomes_post(monkeypatch):
    """The same crawl sees /item as a GET link then as a POST form."""
    pages = {
        "http://host/": '<a href="/item?id=1">item</a>',
        "http://host/item?id=1": (
            '<form action="/item" method="post">'
            '<input name="name" type="text"></form>'
        ),
    }

    async def _fetch(_session, url, _timeout):
        return pages.get(url)

    class _Session:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

    class _Connector:
        def __init__(self, *args, **kwargs):
            pass

    monkeypatch.setattr(crawler_module, "_fetch", _fetch)
    monkeypatch.setattr(crawler_module.aiohttp, "ClientSession", _Session)
    monkeypatch.setattr(crawler_module.aiohttp, "TCPConnector", _Connector)

    cfg = dict(crawler_module._DEFAULTS)
    cfg.update({"max_depth": 3, "max_pages": 10, "concurrency": 2})
    try:
        urls, targets, _bodies = crawler_module.asyncio.run(
            crawler_module._crawl("http://host/", "test-agent", cfg)
        )
    finally:
        Services.services.pop("target_ledger", None)

    if "http://host/item?id=1" not in urls:
        raise AssertionError("the page should still be crawled")
    item_targets = [t for t in targets if t.endpoint == "http://host/item"]
    if len(item_targets) != 1:
        raise AssertionError(f"only the current shape may survive: {item_targets}")
    target = item_targets[0]
    if target.method != "POST" or target.location != "body":
        raise AssertionError((target.method, target.location))
    if target.parameter_label != "name":
        raise AssertionError(target.parameter_label)


# ---------------------------------------------------------------------------
# Integration test against a local synthetic site
# ---------------------------------------------------------------------------
class _Server(ThreadingMixIn, HTTPServer):
    daemon_threads = True

    def server_bind(self):
        # Skip HTTPServer's slow socket.getfqdn() reverse-DNS lookup.
        TCPServer.server_bind(self)
        host, port = self.socket.getsockname()[:2]
        self.server_name = host
        self.server_port = port


class _Handler(BaseHTTPRequestHandler):
    hits: list[str] = []

    def log_message(self, *args):  # silence the server
        pass

    def do_GET(self):
        _Handler.hits.append(self.path)
        path = urlsplit(self.path).path
        if path == "/":
            # 50 value-permutations of one shape, plus two other distinct shapes.
            links = "".join(f'<a href="/item?id={i}">i{i}</a>' for i in range(50))
            links += '<a href="/item?id=1&sort=asc">sorted</a>'
            links += '<a href="/page2">next</a>'
            links += '<a href="http://example.org/out">offsite</a>'
            body = f"<html><body>{links}</body></html>"
        else:
            body = "<html><body>leaf</body></html>"
        raw = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


@pytest.fixture
def local_site():
    _Handler.hits = []
    server = _Server(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        yield f"http://{host}:{port}/"
    finally:
        server.shutdown()
        server.server_close()


def test_crawl_collapses_parameter_permutations(local_site):
    Services.register("output", Output())
    settings.cfg["crawler"] = {"max_depth": 3, "max_pages": 500, "concurrency": 8}

    results = crawl(local_site, "test-agent")

    # 50 ?id=<n> links share one signature, so only ONE of them is fetched — not 50.
    item_fetches = [h for h in _Handler.hits if h.startswith("/item?id=") and "sort" not in h]
    if len(item_fetches) != 1:
        raise AssertionError(f"expected 1 /item fetch, got {len(item_fetches)}: {item_fetches}")

    # A representative parameterized URL is returned for the attack phase.
    if not any("/item?id=" in u for u in results):
        raise AssertionError("expected a representative parameterized URL in results")

    # Distinct shapes are still discovered; off-site links are excluded.
    if not any("/item?id=1&sort=asc" in u for u in results):
        raise AssertionError("distinct parameter shape should be crawled")
    if any("example.org" in u for u in results):
        raise AssertionError("off-site URLs must be excluded")


def test_crawl_respects_max_pages(local_site):
    Services.register("output", Output())
    settings.cfg["crawler"] = {"max_depth": 3, "max_pages": 2, "concurrency": 4}

    results = crawl(local_site, "test-agent")
    if len(results) > 2:
        raise AssertionError(f"max_pages not respected: {len(results)} results")


# ---------------------------------------------------------------------------
# Authenticated crawling (issue #87)
# ---------------------------------------------------------------------------
class _AuthedFactory:
    """Minimal stand-in for a logged-in request_factory."""

    def __init__(self, cookies, headers):
        import requests
        self.session = requests.Session()
        self.session.cookies.update(cookies)

        class _Auth:
            pass

        self.authenticator = _Auth()
        self.authenticator.headers = headers


def test_auth_context_reads_request_factory():
    from sitadel.modules.crawler.crawler import _auth_context

    Services.register(
        "request_factory",
        _AuthedFactory({"session": "abc"}, {"Authorization": "Bearer tok"}),
    )
    try:
        headers, cookies = _auth_context()
        if headers.get("Authorization") != "Bearer tok":
            raise AssertionError
        if cookies.get("session") != "abc":
            raise AssertionError
    finally:
        Services.services.pop("request_factory", None)


class _AuthHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, body):
        raw = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _authed(self):
        return "session=valid" in self.headers.get("Cookie", "")

    def do_GET(self):
        # The link is only revealed to an authenticated session.
        if urlsplit(self.path).path == "/":
            if self._authed():
                self._send('<a href="/secret?id=1">secret</a>')
            else:
                self._send("please login")
        else:
            self._send("leaf")


@pytest.fixture
def auth_site():
    server = _Server(("127.0.0.1", 0), _AuthHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    host, port = server.server_address
    Services.register("output", Output())
    try:
        yield f"http://{host}:{port}/"
    finally:
        server.shutdown()
        server.server_close()
        Services.services.pop("request_factory", None)


def test_authenticated_crawler_discovers_gated_links(auth_site):
    Services.register(
        "request_factory", _AuthedFactory({"session": "valid"}, {})
    )
    results = crawl(auth_site, "test-agent")
    if not any("/secret?id=1" in u for u in results):
        raise AssertionError("authenticated crawler should discover gated link")


def test_unauthenticated_crawler_does_not_see_gated_links(auth_site):
    Services.services.pop("request_factory", None)
    results = crawl(auth_site, "test-agent")
    if any("/secret" in u for u in results):
        raise AssertionError("gated link must not be discovered without auth")
