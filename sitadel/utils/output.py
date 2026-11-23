from __future__ import annotations

import logging

from colorama import Fore, Style

from sitadel.report import Finding, Severity
from sitadel.report.knowledge import lookup as _lookup_knowledge
from sitadel.utils.container import Services
from sitadel.utils.events import FindingAdded, Log


class Output:
    r = Fore.RED
    g = Fore.GREEN
    y = Fore.YELLOW
    w = Fore.WHITE
    c = Fore.CYAN
    e = Style.RESET_ALL

    def __init__(self, level: int = 0, quiet: bool = False, generation=None):
        # ``level`` is the -v count; it gates how much reaches the console.
        self.level = level
        # ``quiet`` suppresses stdout (used by the TUI front-end, which owns the
        # screen and renders findings/logs itself from the event bus). The file
        # logger and the event bus are unaffected, so nothing is lost.
        self.quiet = quiet
        # Bind the output channel to the scan generation that created it.  A
        # worker that outlives its scan keeps pointing at the old generation,
        # so a late finding can never be recorded in the next scan's report.
        # ``None`` preserves the legacy behaviour for direct Output() users.
        self._explicit_generation = generation is not None
        if generation is None:
            generation = Services.current_generation()
            # A closed generation is history: a newly constructed channel is
            # a legacy/direct caller, not a late writer for that old scan.  The
            # per-finding path below keeps a legacy collector registered by
            # such a caller working without ever feeding the closed report.
            if generation is not None and not generation.active:
                generation = None
        self.generation = generation
        # File logging is owned by the ``sitadelLog`` logger. Every console
        # message is mirrored there, and ``trace`` adds file-only detail, so
        # the log file is always a superset of stdout.
        self.logger = logging.getLogger("sitadelLog")

    def bind_generation(self, generation) -> None:
        """Move this channel to ``generation`` (used when reusing an Output)."""
        self.generation = generation
        self._explicit_generation = False

    @staticmethod
    def _bus():
        """The registered event bus, or ``None`` in plain CLI mode."""
        try:
            return Services.get("events")
        except NameError:
            return None

    def finding(self, value: str, severity: Severity | None = None,
                url: str | None = None, plugin: str | None = None,
                parameter: str | None = None, evidence: str | None = None,
                confidence: str | None = None, cwe: str | None = None,
                owasp: str | None = None, wstg: str | None = None,
                remediation: str | None = None,
                finding_type: str | None = None) -> None:
        r"""Report a finding: print it, log it, and record it for the report.

        Only ``value`` is required, so legacy ``finding("text")`` calls keep
        working. Any triage field a plugin omits is filled from the
        remediation/standards knowledge base (keyed by ``finding_type`` or the
        ``plugin`` name), so even single-string findings gain a sane severity,
        confidence, and CWE/OWASP/WSTG mapping. Explicit arguments always win.
        """
        current = Services.current_generation()
        generation = self.generation
        if generation is None:
            if current is not None and current.active:
                # Bind an Output created before the scan started on first use.
                generation = current
                self.generation = current
        elif generation is not current or not generation.active:
            # A generation-scoped output is frozen once its scan is over.  A
            # direct caller can move the channel with ``bind_generation`` (or
            # by re-registering it through ``Services``), but a late worker
            # must never silently adopt a newer scan and pollute its report.
            self.logger.debug(
                "Dropping finding from inactive scan generation %s: %s",
                getattr(generation, "id", generation),
                value,
            )
            return

        if not self.quiet:
            print(f"{self.g}[+]{self.e} {self.w}{value}{self.e}", flush=True)
        self.logger.info("FINDING: %s", value)

        # Enrich from the knowledge base and build the Finding once; it feeds
        # both the report collector and the live event stream.
        kb = _lookup_knowledge(finding_type or plugin)

        def pick(explicit, key):
            return explicit if explicit is not None else kb.get(key)

        finding = Finding(
            title=value,
            severity=pick(severity, "severity") or Severity.INFO,
            url=url,
            parameter=parameter,
            evidence=evidence,
            confidence=pick(confidence, "confidence"),
            plugin=plugin,
            cwe=pick(cwe, "cwe"),
            owasp=pick(owasp, "owasp"),
            wstg=pick(wstg, "wstg"),
            remediation=pick(remediation, "remediation"),
        )

        # Record for report generation, when a collector is registered.  A
        # generation-owned Output writes to that generation's collector even if
        # a retry has already replaced the service slot.
        if generation is not None:
            if not generation.add_finding(finding):
                return
        else:
            try:
                collector = Services.get("findings")
            except NameError:
                collector = None
            # After a scan has closed, a fresh Output() is a legacy caller.
            # It must not append to the closed scan's collector merely because
            # that collector is still the last value in the service slot.
            if (
                collector is not None
                and current is not None
                and not current.active
                and collector is current.findings
            ):
                collector = None
            if collector is not None:
                collector.add(finding)

        # Publish to the live UI (TUI). No-op in plain CLI mode.
        bus = self._bus()
        if bus is not None:
            sev = (
                finding.severity.value
                if isinstance(finding.severity, Severity)
                else finding.severity
            )
            bus.publish(
                FindingAdded(
                    title=finding.title,
                    severity=sev or "info",
                    url=finding.url,
                    plugin=finding.plugin,
                    parameter=finding.parameter,
                    evidence=finding.evidence,
                    confidence=finding.confidence,
                    cwe=finding.cwe,
                    remediation=finding.remediation,
                )
            )

    def error(self, value: str) -> None:
        if not self.quiet:
            print(f"{self.r}[-]{self.e} {self.w}{value}{self.e}", flush=True)
        self.logger.error(value)
        bus = self._bus()
        if bus is not None:
            bus.publish(Log("error", value))

    def info(self, value: str) -> None:
        if not self.quiet:
            print(f"{self.y}[i]{self.e} {self.w}{value}{self.e}", flush=True)
        self.logger.info(value)
        bus = self._bus()
        if bus is not None:
            bus.publish(Log("info", value))

    def debug(self, value: str) -> None:
        # Debug is the -vvv tier: printed to the console only at -vvv, but
        # always forwarded to the file logger (which keeps it when the file
        # handler is at DEBUG, i.e. also -vvv).
        if self.level >= 3 and not self.quiet:
            print(f"{self.c}[d]{self.e} {self.w}{value}{self.e}", flush=True)
        self.logger.debug(value)

    def trace(self, value: str) -> None:
        """File-only detail — never printed, even at high verbosity.

        Used for the high-volume records that would drown the console but are
        valuable in the log: every URL the crawler discovered and every
        payload/pattern the attack modules test. These land in ``sitadel.log``
        only when the file handler is at DEBUG (i.e. any ``-v``).
        """
        self.logger.debug(value)
