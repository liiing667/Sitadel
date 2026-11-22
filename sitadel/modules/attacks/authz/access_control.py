from sitadel.config.settings import Risk
from sitadel.request.request import SingleRequest
from sitadel.utils.container import Services
from .. import AttackPlugin
from .idutils import (
    canonical_url,
    equivalent,
    looks_like_missing_body,
    missing_object_url,
    missing_path_url,
    object_parameter,
    object_refs,
)
from .transaction import ProbeSpec, anonymous_request, run_comparison


class AccessControl(AttackPlugin):
    """Broken Access Control: object endpoints reachable without a session.

    For each crawled URL that references an object id, compare the response
    seen by the authenticated session against an anonymous request. If the
    anonymous request gets an equivalent 200 response, the object is served
    without authentication (OWASP A01 / CWE-284).  Both probes, the soft-404
    baselines and the resulting finding live in one comparison transaction.
    """

    level = Risk.DANGEROUS

    def process(self, start_url, crawled_urls):
        output = Services.get("output")
        request = Services.get("request_factory")
        logger = Services.get("logger")

        auth = getattr(request, "authenticator", None)
        if not (auth is not None and auth.has_login):
            output.info(
                "Skipping access-control checks (need an authenticated session "
                "to compare against)"
            )
            return

        output.info("Checking broken access control...")
        anonymous = anonymous_request(
            request, start_url, request_class=SingleRequest
        )
        seen = set()
        for url in crawled_urls or []:
            identity = canonical_url(url)
            if identity in seen or not object_refs(url):
                continue
            seen.add(identity)
            try:
                fake_object = missing_object_url(url)
                fake_path = missing_path_url(url)
                probes = [
                    ProbeSpec("authed", url, request, authenticated=True),
                    ProbeSpec("anonymous", url, anonymous),
                ]
                if fake_object:
                    probes.append(
                        ProbeSpec(
                            "soft404_object",
                            fake_object,
                            anonymous,
                            required=False,
                            expected_url=fake_object,
                            strict_object=False,
                        )
                    )
                if fake_path:
                    probes.append(
                        ProbeSpec(
                            "soft404_path",
                            fake_path,
                            anonymous,
                            required=False,
                            expected_url=fake_path,
                            strict_object=False,
                        )
                    )
                tx = run_comparison(
                    url,
                    probes,
                    request=request,
                    authenticator=auth,
                    logger=logger,
                )
            except Exception as err:
                logger.error(err)
                continue
            if tx is None or not tx.committed:
                continue
            authed = tx.authed
            anon = tx.anonymous
            if authed is None or anon is None:
                continue
            if authed.status_code != 200 or anon.status_code != 200:
                continue
            # 403/404 (including redirects to them) are legitimate denials.
            if (
                looks_like_missing_body(authed.body)
                or looks_like_missing_body(anon.body)
            ):
                continue
            if not equivalent(authed.body, anon.body):
                continue
            # A generic "not found" page rendered with 200 is not an exposure.
            if tx.is_soft_miss("authed") or tx.is_soft_miss("anonymous"):
                continue
            output.finding(
                "Possible Broken Access Control: %s is served without "
                "authentication (OWASP A01)" % url,
                url=url,
                plugin=type(self).__name__,
                parameter=object_parameter(url),
                evidence=tx.evidence(
                    decision="same-object-served-anonymously"
                ),
                finding_type="access_control",
                confidence="firm",
            )
