"""Passive secret/credential leak scanner — issue #105.

Scans response bodies for high-confidence secrets (cloud keys, tokens, private
keys). Reads the page bodies the crawler already fetched (registered under the
``page_bodies`` service key) so no page is re-fetched; when that cache is absent
(e.g. a direct call), it falls back to fetching the start URL and crawled URLs.

Passive and low-risk (``Risk.NO_DANGER``): it only reads content already served.
All raw credentials are destroyed in one redaction pass shared with the report
consumers: the re-published ``page_bodies`` snapshot, each matched span in the
evidence, and the finding URL (including query-string tokens) are all masked
via :mod:`sitadel.utils.redaction`, so no artifact — JSON, SARIF or HTML — can
ever store or re-encode the original value.
"""

from sitadel.config.settings import Risk
from sitadel.utils.redaction import (
    SECRET_PATTERNS,
    mask_secret,
    redact_text,
    redact_url,
)
from sitadel.utils.container import Services
from .. import AttackPlugin

# Detection reuses the canonical patterns so masking and detection never drift.
_SECRETS = SECRET_PATTERNS


class Secrets(AttackPlugin):
    level = Risk.NO_DANGER

    def _bodies(self, start_url, crawled_urls):
        """Prefer the crawler's cached bodies; else fetch (bounded)."""
        try:
            cached = Services.get("page_bodies")
        except NameError:
            cached = None
        if cached:
            return cached
        # Fallback: fetch start URL + crawled URLs (bounded) ourselves.
        request = Services.get("request_factory")
        urls = [str(start_url)] + [str(u) for u in (crawled_urls or [])]
        bodies = {}
        for url in urls[:100]:
            resp = request.send(url=url, method="GET", payload=None, headers=None)
            if resp is not None and resp.text:
                bodies[url] = resp.text
        return bodies

    def _scan(self, output, url, body):
        for label, pattern, firm in _SECRETS:
            m = pattern.search(body)
            if not m:
                continue
            # The matched span is masked with the shared redactor before it
            # reaches any artifact: evidence string, finding URL or snapshot.
            safe_span = mask_secret(m.group(0))
            safe_url = redact_url(str(url))
            output.finding(
                "Secret leaked in response (%s) at %s" % (label, safe_url),
                url=safe_url, plugin="Secrets", parameter=label,
                confidence="firm" if firm else "tentative",
                evidence="matched %s: %s" % (label, safe_span),
                finding_type="secret_leak",
            )

    def process(self, start_url, crawled_urls):
        output = Services.get("output")
        logger = Services.get("logger")

        output.info("Scanning responses for leaked secrets..")
        try:
            bodies = self._bodies(start_url, crawled_urls)
        except Exception as e:
            logger.error(e)
            return
        # Single redaction publication point. Scan the raw bodies first (so
        # pattern matching is unaffected), then replace the shared cache with
        # snapshots in which every secret is already masked. Every later
        # consumer — findings, logs, JSON/SARIF/HTML reports — therefore reads
        # only redacted text and no write retry or second format can recover
        # the raw credential.
        redacted_bodies = {}
        for url, body in bodies.items():
            if self._cancelled():
                break
            try:
                self._scan(output, url, body)
            except Exception as e:
                logger.error(e)
                output.debug("Secret-scan error on %s: %s" % (url, e))
            # Both the URL key (a token can ride the query string) and the
            # page text are replaced by redacted snapshots. The only consumer
            # of this cache is this scanner itself, which has finished
            # scanning by the time the snapshot is re-published.
            try:
                redacted_bodies[redact_url(str(url))] = redact_text(body)
            except Exception as e:
                logger.error(e)
        # Always re-publish, even when empty: an empty redacted snapshot must
        # replace (never leave behind) a raw cache, including on early cancel.
        Services.register("page_bodies", redacted_bodies)

    @staticmethod
    def _cancelled():
        try:
            return Services.get("cancel").is_set()
        except NameError:
            return False
