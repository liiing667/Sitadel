#!/usr/bin/env python
# -*- coding:utf-8 -*-
#
# @name:    Sitadel - Web Application Security Scanner
# @repo:    https://github.com/shenril/Sitadel
# @author:  Shenril
# @license: See the file 'LICENSE.txt'

import argparse
import os
import sys
import signal
import threading
from sitadel import __version__
from sitadel.config import settings
from sitadel.config.settings import Risk
from sitadel.request.request import SingleRequest
from sitadel.utils import banner, manager, output, validator
from sitadel.utils.container import Services
from sitadel.model import TargetProfile
from sitadel.modules.discovery import discover as discover_api
from sitadel.report import Findings, write_report
from sitadel.request.auth import Authenticator
from sitadel.utils.datastore import Datastore
from sitadel.utils.events import EventBus, Phase, RiskLevel
from sitadel.utils.logs import setup_logging
from sitadel.utils.output import Output


class Sitadel(object):
    bn = banner.Banner()
    ma = manager
    url = None

    def main(self):
        parser = argparse.ArgumentParser(
            formatter_class=argparse.ArgumentDefaultsHelpFormatter,
            usage=self.bn.banner(),
        )
        # Prepare the possible values for risk levels
        risk_values = [r.value for r in Risk]
        # Add arguments
        parser.add_argument("url", help="URL of the website to scan")
        parser.add_argument(
            "-r",
            "--risk",
            type=int,
            help="Level of risk allowed for the scan",
            choices=risk_values,
        )
        parser.add_argument(
            "-ua",
            "--user-agent",
            default=f"Sitadel {__version__}",
            help="User-agent to set for the scan requests",
        )
        parser.add_argument(
            "--redirect",
            dest="redirect",
            help="Whether or not the scan should follow redirection",
            action="store_true",
        )
        parser.add_argument(
            "--no-redirect",
            dest="redirect",
            help="Whether or not the scan should follow redirection",
            action="store_false",
        )
        parser.set_defaults(redirect=True)
        parser.add_argument(
            "-t",
            "--timeout",
            type=int,
            default=30,
            help="Timeout to set for the scan HTTP requests",
        )
        parser.add_argument(
            "-c", "--cookie", help="Cookie to set for the scan HTTP requests"
        )
        parser.add_argument(
            "-p", "--proxy", help="Proxy to set for the scan HTTP requests"
        )
        parser.add_argument(
            "--random-agent",
            dest="random_agent",
            action="store_true",
            help="Use a random User-Agent for each scan request",
        )
        parser.add_argument(
            "--verify",
            dest="verify",
            action="store_true",
            help="Verify the server's TLS certificate (off by default)",
        )
        parser.add_argument(
            "--rate-limit",
            dest="rate_limit",
            type=float,
            default=None,
            help="Max requests per second across the whole scan "
                 "(0 = unlimited; overrides http.rate_limit in the config)",
        )
        parser.add_argument(
            "--scope-host",
            dest="scope_hosts",
            action="append",
            help="Extra in-scope host to allow requests to (repeatable); the "
                 "target host is always in scope",
        )
        # Authentication options
        parser.add_argument(
            "--auth-basic", help="HTTP Basic credentials as user:password"
        )
        parser.add_argument(
            "--auth-bearer", help="Bearer token to send in the Authorization header"
        )
        parser.add_argument(
            "-H",
            "--header",
            dest="headers",
            action="append",
            help="Extra header 'Name: Value' (repeatable), e.g. an API key",
        )
        parser.add_argument(
            "--login-url", help="URL to POST credentials to for form login"
        )
        parser.add_argument(
            "--login-data",
            help="Form login body, e.g. 'username=admin&password=secret'",
        )
        parser.add_argument(
            "--csrf-field",
            help="Name of a hidden CSRF field to read from the login page",
        )
        parser.add_argument(
            "--logged-in-check",
            help="String expected on authenticated pages (drives re-auth)",
        )
        parser.add_argument(
            "--no-discovery",
            dest="discovery",
            action="store_false",
            help="Disable API-first discovery (OpenAPI/Swagger + REST probing)",
        )
        parser.set_defaults(discovery=True)
        parser.add_argument(
            "-f", "--fingerprint", nargs="+", help="Fingerprint modules to activate"
        )
        parser.add_argument(
            "-a", "--attack", nargs="+", help="Attack modules to activate"
        )
        parser.add_argument(
            "--config", help="Path to the config file", default="config/config.yml"
        )
        parser.add_argument(
            "-o", "--output", help="Path to write the findings report to"
        )
        parser.add_argument(
            "--format",
            dest="report_format",
            choices=["stdout", "json", "html", "sarif"],
            default="stdout",
            help="Report format for the findings (default: stdout only)",
        )
        parser.add_argument(
            "--tui",
            dest="tui",
            action="store_true",
            help="Show a live TUI dashboard (requires a real terminal)",
        )
        parser.add_argument(
            "-v",
            "--verbosity",
            action="count",
            default=0,
            help="Increase output verbosity",
        )
        parser.add_argument("--version", action="version", version=self.bn.version())
        args = parser.parse_args()

        # Decide the front-end. The live TUI runs only when explicitly requested
        # *and* attached to a real terminal (piped/CI runs fall back to stdout).
        # The scan engine is identical either way; the TUI is just a consumer of
        # the same event/finding stream, so it runs in a background worker while
        # the dashboard owns the main thread.
        use_tui = bool(getattr(args, "tui", False)) and sys.stdout.isatty()
        if use_tui:
            from sitadel.tui import run_tui

            bus = EventBus()
            cancel = threading.Event()
            Services.register("events", bus)
            Services.register("cancel", cancel)
            target = str(validator.validate_target(args.url))
            scan_generation = {"value": None}

            def reporter(fmt: str):
                """Write the collected findings in ``fmt``; return (path, n)."""
                generation = scan_generation["value"]
                # A scan that failed before installing its generation has no
                # findings of its own; never fall back to a prior run's.
                findings = []
                if generation is not None:
                    findings = generation.report_findings()
                path = args.output or f"sitadel-report.{fmt}"
                write_report(findings, fmt, path)
                if generation is not None:
                    generation.record_report(fmt, path)
                return path, len(findings)

            def scan():
                try:
                    self._execute(args, quiet=True)
                finally:
                    scan_generation["value"] = self.generation

            # Auto-prompt for a format at the end only when one wasn't already
            # requested on the command line (that path writes the report itself).
            run_tui(
                scan, bus, target, cancel,
                reporter=reporter,
                auto_export=(args.report_format == "stdout"),
            )
        else:
            self._execute(args, quiet=False)

    def _phase(self, name: str) -> None:
        """Announce a scan phase to the event bus (no-op without a TUI)."""
        try:
            Services.get("events").publish(Phase(name))
        except NameError:
            pass

    def _announce_risk(self) -> None:
        """Announce the configured risk level to the event bus (TUI header)."""
        try:
            bus = Services.get("events")
        except NameError:
            return
        risk = Risk(int(settings.risk))
        bus.publish(RiskLevel(risk.value, risk.name))

    def _execute(self, args, quiet: bool = False):
        # Reset per-scan handles first: a failure before begin_generation must
        # not leave a previous scan's generation looking current.
        self.generation = None
        self.scan_generation = None
        # The report path belongs to this run.  Drop a previous run's file
        # before any validation/config work, so a failure at any point cannot
        # leave an old report that looks like the current scan's output.
        if getattr(args, "report_format", "stdout") != "stdout":
            stale_report = (
                getattr(args, "output", None)
                or f"sitadel-report.{args.report_format}"
            )
            try:
                os.unlink(stale_report)
            except OSError:
                pass
        # Verify the target URL
        self.url = validator.validate_target(args.url)

        # Reading configuration
        settings.from_yaml(args.config)
        if args.risk is not None:
            settings.risk = Risk(args.risk)
        self._announce_risk()

        # Setting up the logger
        logger = setup_logging(args.verbosity)

        # HTTP tuning: CLI flags win, else the config's optional ``http`` block,
        # else safe defaults (unlimited rate; scope restricted to the target).
        http_cfg = getattr(settings, "http", None) or {}
        rate_limit = (
            args.rate_limit if args.rate_limit is not None
            else http_cfg.get("rate_limit", 0)
        )
        scope_hosts = list(http_cfg.get("scope_hosts", []) or [])
        if args.scope_hosts:
            scope_hosts.extend(args.scope_hosts)

        # Start a new scan generation *before* registering the output channel
        # and the mutable scan services.  Everything below (fingerprint
        # profile, crawl snapshot, attack findings, report) is then owned by
        # this generation; a retry starts a clean one instead of inheriting the
        # previous run's pages or findings.
        findings = Findings()
        profile = TargetProfile()
        generation = Services.begin_generation(
            target=str(self.url),
            label=getattr(args, "url", None),
            findings=findings,
            profile=profile,
        )
        self.generation = generation
        self.scan_generation = generation

        # Register services
        Services.register("datastore", Datastore(settings.datastore))
        Services.register("logger", logger)
        Services.register("output", Output(args.verbosity, quiet=quiet))
        Services.register("api_targets", [])
        Services.register(
            "request_factory",
            SingleRequest(
                url=self.url,
                agent=args.user_agent,
                proxy=args.proxy,
                redirect=args.redirect,
                timeout=args.timeout,
                random_agent=args.random_agent,
                verify=args.verify,
                rate_limit=rate_limit,
                scope_hosts=scope_hosts,
            ),
        )

        status = "complete"
        failure = None
        try:
            # Configure authentication (if any) and log in before scanning so
            # all phases run as an authenticated user.
            authenticator = Authenticator.from_options(
                basic=args.auth_basic,
                bearer=args.auth_bearer,
                headers=args.headers,
                login_url=args.login_url,
                login_data=args.login_data,
                csrf_field=args.csrf_field,
                logged_in_check=args.logged_in_check,
            )
            if authenticator is not None:
                request_factory = Services.get("request_factory")
                request_factory.set_authenticator(authenticator)
                if authenticator.has_login:
                    request_factory.login()
                    probe = request_factory.send(url=self.url, method="GET")
                    if authenticator.looks_logged_out(probe):
                        Services.get("output").error(
                            "Login may have failed: the 'logged-in' check did "
                            "not match after authenticating."
                        )
                    else:
                        Services.get("output").info(
                            "Authenticated to the target."
                        )

            # Display target and scan starting time (the TUI renders its own
            # header).
            if not quiet:
                self.bn.preamble(self.url)

            # Run the fingerprint modules
            self._phase("fingerprint")
            if (
                Services.current_generation() is not generation
                or not generation.active
            ):
                return
            self.ma.fingerprints(
                args.fingerprint,
                self.url,
                args.cookie,
            )

            # Show the assembled target profile that will drive attack selection
            if (
                Services.current_generation() is not generation
                or not generation.active
            ):
                return
            profile = Services.get("profile")
            if profile.technologies:
                Services.get("output").info(f"Target profile: {profile.summary()}")

            # Run the crawler to discover urls
            self._phase("crawl")
            discovered_urls = self.ma.crawler(self.url, args.user_agent)
            if (
                Services.current_generation() is not generation
                or not generation.active
            ):
                # A retry superseded this scan while its crawl was in flight.
                # Never let the old surface feed the new scan's attack phase.
                return

            # Record the crawl surface. The count goes to console + file; the
            # full list is file-only (-v) so the log lets you review every path
            # discovered before any attack is launched, without flooding stdout.
            output_svc = Services.get("output")
            output_svc.info(
                f"Crawler discovered {len(discovered_urls)} URL(s)"
            )
            for discovered in discovered_urls:
                output_svc.trace(f"Crawled URL: {discovered}")

            # API-first discovery: enumerate API endpoints from an OpenAPI/
            # Swagger spec (or detect a REST surface) and register them as
            # injectable targets so body injection reaches JSON/XML endpoints.
            # HTML-only targets expose no spec, so this is a clean no-op there.
            if args.discovery:
                api_targets = discover_api(
                    self.url,
                    Services.get("request_factory"),
                    profile=Services.get("profile"),
                    output=output_svc,
                )
                if api_targets:
                    Services.register("api_targets", api_targets)
                    output_svc.info(
                        f"API discovery added {len(api_targets)} endpoint "
                        f"target(s) for injection"
                    )

            # Hotfix on KeyboardInterrupt being redirected to scrapy crawler
            # process. ``signal.signal`` only works on the main thread, and in
            # TUI mode the scan runs in a worker thread — skip it there.
            if threading.current_thread() is threading.main_thread():
                signal.signal(signal.SIGINT, signal.default_int_handler)

            # Run the attack modules on discovered urls
            if (
                Services.current_generation() is not generation
                or not generation.active
            ):
                return
            self._phase("attack")
            self.ma.attacks(args.attack, self.url, discovered_urls)
        except KeyboardInterrupt as exc:
            status = "cancelled"
            failure = exc
            raise
        except BaseException as exc:
            status = "failed"
            failure = exc
            raise
        finally:
            # Write the findings report (console findings are printed live by
            # Output.finding regardless of the chosen format).  The report is
            # built from this generation's collector only, so a partially
            # failed scan can never append another run's findings.
            try:
                if (
                    args.report_format != "stdout"
                    and Services.current_generation() is generation
                ):
                    path = args.output or f"sitadel-report.{args.report_format}"
                    findings = generation.report_findings()
                    write_report(findings, args.report_format, path)
                    generation.record_report(args.report_format, path)
                    Services.get("output").info(
                        f"Wrote {len(findings)} finding(s) to {path}"
                    )
            finally:
                # Close the generation even if serialising the report failed;
                # any still-running worker for it can no longer add findings.
                Services.end_generation(generation, status, failure)
                if not quiet:
                    self.bn.postscript()


def main():
    """Console entry point (see ``[project.scripts]`` in pyproject.toml)."""
    try:
        Sitadel().main()
    except KeyboardInterrupt:
        sys.exit(output.Output().error("Interruption by the user, Quitting..."))


if __name__ == "__main__":
    main()
