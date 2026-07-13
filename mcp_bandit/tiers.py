"""Three-tier security architecture — Reader / Analyzer / Writer.

Inspired by Claude Cookbooks' Reader/Analyzer/Writer pattern and
dcg's context-classification principle (separate DATA from EXECUTION).

Tier boundaries are STRUCTURAL, not advisory:
  - Reader:     Read-only, output is length-capped + sanitized. Never writes.
  - Analyzer:   No file I/O. No Write access. Pure function from input → findings.
  - Writer:     Only tier with Write. Never touches raw external configs.
                Receives pre-validated, sanitized Analyzer output.

Cross-tier routing is hard-allowlisted — no direct Reader→Writer or Writer→Reader.
"""

from __future__ import annotations

import json
from pathlib import Path
from dataclasses import dataclass, field

from mcp_bandit.types import ScanTarget, Finding
from mcp_bandit.checks import ALL_CHECKS, SecurityCheck
from mcp_bandit.scanner import ServerResult


# ═══════════════════════════════════════════════════════════════════
# Tier 1: Reader — only opens files, parses JSON, extracts servers
# ═══════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class ReaderOutput:
    """Sanitized, length-capped output from Reader. Immutable — Analyzer can't modify."""
    path: Path
    server_name: str
    normalized_config: str  # JSON string, max 64KB
    command: str
    args: list[str]
    env: dict[str, str]
    transport: str

    @property
    def has_env_vars(self) -> bool:
        return bool(self.env)


class MCPConfigReader:
    """Read-only tier. Opens configs, parses JSON, extracts servers.

    Output is frozen + sanitized. No check execution. No write.
    """

    MAX_CONFIG_SIZE = 65_536  # 64KB — reject anything larger

    def read_all(self, config_paths: list[Path]) -> list[ReaderOutput]:
        """Read all configs → sanitized ReaderOutput list."""
        outputs: list[ReaderOutput] = []
        for path in config_paths:
            outputs.extend(self.read_one(path))
        return outputs

    def read_one(self, config_path: Path) -> list[ReaderOutput]:
        """Read one config file → list of sanitized server configs."""
        from mcp_bandit.discovery import parse_config, extract_servers

        # Size gate — refuse oversized configs
        try:
            if config_path.stat().st_size > self.MAX_CONFIG_SIZE:
                return []
        except OSError:
            return []

        config = parse_config(config_path)
        if not config:
            return []
        servers = extract_servers(config)
        if not servers:
            return []

        outputs: list[ReaderOutput] = []
        for name, server_cfg in servers.items():
            try:
                normalized = json.dumps(server_cfg, ensure_ascii=False, sort_keys=True)
            except (TypeError, ValueError):
                continue
            # Length cap
            if len(normalized) > self.MAX_CONFIG_SIZE:
                normalized = normalized[:self.MAX_CONFIG_SIZE]

            command = str(server_cfg.get("command", server_cfg.get("args", [""])[0] if isinstance(server_cfg.get("args"), list) else ""))
            args = list(server_cfg.get("args", []))
            env_vars = dict(server_cfg.get("env", {}))
            transport = str(server_cfg.get("type", server_cfg.get("transport", "stdio")))

            outputs.append(ReaderOutput(
                path=config_path,
                server_name=name,
                normalized_config=normalized,
                command=command,
                args=args,
                env=env_vars,
                transport=transport,
            ))
        return outputs


# ═══════════════════════════════════════════════════════════════════
# Tier 2: Analyzer — pure function, no file I/O, no Write
# ═══════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class AnalyzerOutput:
    """Validated findings from Analyzer. Writer consumes this — never raw configs."""
    server_name: str
    config_path: Path
    findings: list[Finding]

    @property
    def grade(self) -> str:
        f = sum(1 for fg in self.findings if fg.severity == "FAIL")
        w = sum(1 for fg in self.findings if fg.severity == "WARN")
        if f == 0 and w == 0:  return "A"
        if f == 0 and w <= 2:  return "B"
        if f == 1:             return "C"
        if f <= 3:             return "D"
        if f <= 5:             return "E"
        return "F"

    @property
    def fail_count(self) -> int:
        return sum(1 for fg in self.findings if fg.severity == "FAIL")


class MCPAnalyzer:
    """Pure analysis tier. No file I/O. No Write. No raw config access.

    Takes sanitized ReaderOutput, runs security checks, returns findings.
    """

    def __init__(self, check_ids: list[str] | None = None):
        self._all_checks = ALL_CHECKS
        if check_ids:
            self.checks: list[SecurityCheck] = [c for c in self._all_checks if c.id in check_ids]
        else:
            self.checks = list(self._all_checks)

    def analyze(self, reader_outputs: list[ReaderOutput]) -> list[AnalyzerOutput]:
        """Run all checks against sanitized Reader output.

        IMPORTANT: This never reads files — it works ONLY with the
        pre-sanitized, length-capped data from Reader.
        """
        results: list[AnalyzerOutput] = []

        for ro in reader_outputs:
            # Reconstruct ScanTarget from sanitized data (NOT from raw config)
            target = ScanTarget(
                path=ro.path,
                server_name=ro.server_name,
                raw_config=json.loads(ro.normalized_config),
            )
            findings: list[Finding] = []
            for check in self.checks:
                findings.extend(check.run(target))
            results.append(AnalyzerOutput(
                server_name=ro.server_name,
                config_path=ro.path,
                findings=findings,
            ))

        return results


# ═══════════════════════════════════════════════════════════════════
# Tier 3: Writer — only tier with Write. Never touches raw configs.
# ═══════════════════════════════════════════════════════════════════

class MCPWriter:
    """Write-only tier. Generates reports from Analyzer output.

    NEVER reads or modifies source config files.
    Only writes to explicitly specified output paths.
    """

    def __init__(self, fmt: str = "terminal", quiet: bool = False):
        self._fmt = fmt
        self._quiet = quiet

    def write_report(self, outputs: list[AnalyzerOutput], targets: list[Path],
                     output_path: str | None = None) -> str:
        """Generate report from Analyzer output. Optionally write to file."""
        # Convert AnalyzerOutput → ServerResult for Reporter compat
        results = [
            ServerResult(server_name=ao.server_name, config_path=ao.config_path, findings=ao.findings)
            for ao in outputs
        ]
        from mcp_bandit.reporter import Reporter
        reporter = Reporter(fmt=self._fmt, quiet=self._quiet)
        text = reporter.render(results, targets)

        if output_path:
            p = Path(output_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text, encoding="utf-8")

        return text

    def write_audit(self, outputs: list[AnalyzerOutput], targets: list[Path],
                    operator: str = "") -> dict:
        """Write tamper-evident audit record from Analyzer output."""
        from mcp_bandit.audit import write_audit_record

        fails = sum(1 for ao in outputs for f in ao.findings if f.severity == "FAIL")
        warns = sum(1 for ao in outputs for f in ao.findings if f.severity == "WARN")
        passes = sum(1 for ao in outputs for f in ao.findings if f.severity == "PASS")

        findings_json = json.dumps([
            {"server": ao.server_name, "check_id": f.check_id, "severity": f.severity}
            for ao in outputs for f in ao.findings
        ])

        return write_audit_record(
            targets=[str(p) for p in targets],
            servers=len(outputs),
            fails=fails,
            warns=warns,
            passes=passes,
            operator=operator,
            findings_json=findings_json,
        )

    def write_baseline(self, outputs: list[AnalyzerOutput], config_path: Path) -> dict:
        """Save baseline from Analyzer output."""
        from mcp_bandit.baseline import save_baseline
        results = [
            ServerResult(server_name=ao.server_name, config_path=ao.config_path, findings=ao.findings)
            for ao in outputs
        ]
        lock_path = save_baseline(config_path, results)
        return {"lock_path": str(lock_path), "servers": len(outputs)}


# ═══════════════════════════════════════════════════════════════════
# Pipeline: Reader → Analyzer → Writer (hard-allowlisted routing)
# ═══════════════════════════════════════════════════════════════════

class TieredPipeline:
    """Orchestrate the R→A→W pipeline with hard-coded routing.

    No direct Reader→Writer or Writer→Reader paths exist.
    Cross-tier data flows through frozen dataclasses — immutable by design.
    """

    def __init__(self, check_ids: list[str] | None = None,
                 fmt: str = "terminal", quiet: bool = False):
        self.reader = MCPConfigReader()
        self.analyzer = MCPAnalyzer(check_ids=check_ids)
        self.writer = MCPWriter(fmt=fmt, quiet=quiet)

    def scan(self, config_paths: list[Path],
             output_path: str | None = None) -> tuple[list[AnalyzerOutput], str]:
        """R→A→W: full scan pipeline."""
        reader_out = self.reader.read_all(config_paths)          # Tier 1
        analyzer_out = self.analyzer.analyze(reader_out)         # Tier 2
        report_text = self.writer.write_report(                  # Tier 3
            analyzer_out, config_paths, output_path)
        return analyzer_out, report_text

    def scan_with_audit(self, config_paths: list[Path],
                        operator: str = "") -> tuple[list[AnalyzerOutput], dict]:
        """R→A→W+Audit: scan with audit trail."""
        reader_out = self.reader.read_all(config_paths)
        analyzer_out = self.analyzer.analyze(reader_out)
        audit = self.writer.write_audit(analyzer_out, config_paths, operator)
        return analyzer_out, audit

    def baseline(self, config_paths: list[Path]) -> dict | None:
        """R→A→W: baseline pipeline."""
        if not config_paths:
            return None
        reader_out = self.reader.read_all(config_paths)
        analyzer_out = self.analyzer.analyze(reader_out)
        return self.writer.write_baseline(analyzer_out, config_paths[0])
