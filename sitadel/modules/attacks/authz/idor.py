from sitadel.config.settings import Risk
from sitadel.utils.container import Services
from .. import AttackPlugin
from .idutils import (
    canonical_url,
    different,
    looks_like_missing_body,
    missing_object_url,
    missing_path_url,
    object_refs,
    replace_id,
)
from .transaction import ProbeSpec, run_comparison


class Idor(AttackPlugin):
    """Insecure Direct Object Reference: neighbouring ids return other objects.

    For each crawled URL with a numeric object id, request the neighbouring id
    (value + 1). If it returns a distinct, valid 200 object, the endpoint likely
    exposes other users' objects by id manipulation (OWASP A01 / CWE-639).
    The base, neighbour and soft-404 baselines share one comparison
    transaction and the finding carries that transaction's evidence.
    """

    level = Risk.DANGEROUS

    def process(self, start_url, crawled_urls):
        output = Services.get("output")
        request = Services.get("request_factory")
        logger = Services.get("logger")

        output.info("Checking insecure direct object references (IDOR)...")
        auth = getattr(request, "authenticator", None)
        seen = set()
        for url in crawled_urls or []:
            identity = canonical_url(url)
            if identity in seen:
                continue
            seen.add(identity)
            for location, key, value in object_refs(url):
                if not value.isdigit():
                    continue
                neighbour = replace_id(url, location, key, int(value) + 1)
                fake_object = missing_object_url(neighbour)
                fake_path = missing_path_url(neighbour)
                probes = [
                    ProbeSpec(
                        "authed", url, request,
                        authenticated=auth is not None,
                    ),
                    ProbeSpec("neighbor", neighbour, request,
                              authenticated=auth is not None),
                ]
                if fake_object:
                    probes.append(
                        ProbeSpec(
                            "soft404_object",
                            fake_object,
                            request,
                            authenticated=auth is not None,
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
                            request,
                            authenticated=auth is not None,
                            required=False,
                            expected_url=fake_path,
                            strict_object=False,
                        )
                    )
                try:
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
                base = tx.authed
                other = tx.neighbor
                if base is None or other is None:
                    continue
                if base.status_code != 200 or other.status_code != 200:
                    continue
                if (
                    looks_like_missing_body(base.body)
                    or looks_like_missing_body(other.body)
                ):
                    continue
                if not different(base.body, other.body):
                    continue
                # A neighbouring soft-404 is not another user's object.
                if tx.is_soft_miss("neighbor"):
                    continue
                output.finding(
                    "Possible IDOR at %s: changing %s from %s to %s returns "
                    "a different valid object (OWASP A01)"
                    % (url, key, value, int(value) + 1),
                    url=url,
                    plugin=type(self).__name__,
                    parameter="%s:%s" % (location, key),
                    evidence=tx.evidence(
                        decision="neighbor-object-differs"
                    ),
                    finding_type="idor",
                    confidence="firm",
                )
                break  # one signal per URL is enough
