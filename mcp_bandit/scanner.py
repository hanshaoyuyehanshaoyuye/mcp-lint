"""Core scanner — discover → scan → audit → baseline → autofix → verify."""

import json
from pathlib import Path
from dataclasses import dataclass, field

from mcp_bandit.types import ScanTarget, Finding
from mcp_bandit.discovery import parse_config, extract_servers
from mcp_bandit.checks import ALL_CHECKS, SecurityCheck


@dataclass
class ServerResult:
    server_name: str
    config_path: Path
    findings: list[Finding] = field(default_factory=list)

    @property
    def grade(self) -> str:
        """A-F letter grade based on FAIL count."""
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

    @property
    def warn_count(self) -> int:
        return sum(1 for fg in self.findings if fg.severity == "WARN")


class Scanner:
    def __init__(self, check_ids: list[str] | None = None):
        self._all_checks = ALL_CHECKS
        if check_ids:
            self.checks: list[SecurityCheck] = [c for c in self._all_checks if c.id in check_ids]
        else:
            self.checks = list(self._all_checks)

    # ── scan ──────────────────────────────────

    def scan_all(self, config_paths: list[Path]) -> list[ServerResult]:
        """Scan all discovered config files."""
        results: list[ServerResult] = []

        for path in config_paths:
            config = parse_config(path)
            if not config:
                continue
            servers = extract_servers(config)
            for name, server_config in servers.items():
                target = ScanTarget(path=path, server_name=name, raw_config=server_config)
                sr = ServerResult(server_name=name, config_path=path)
                for check in self.checks:
                    sr.findings.extend(check.run(target))
                results.append(sr)

        return results

    # ── audit ─────────────────────────────────

    def scan_with_audit(
        self, config_paths: list[Path], operator: str = ""
    ) -> tuple[list[ServerResult], dict]:
        """Scan + write audit trail. Returns (results, audit_record)."""
        from mcp_bandit.audit import write_audit_record

        results = self.scan_all(config_paths)
        fails = sum(1 for r in results for f in r.findings if f.severity == "FAIL")
        warns = sum(1 for r in results for f in r.findings if f.severity == "WARN")
        passes = sum(1 for r in results for f in r.findings if f.severity == "PASS")

        findings_json = json.dumps([
            {"server": r.server_name, "check_id": f.check_id, "severity": f.severity}
            for r in results for f in r.findings
        ])

        audit = write_audit_record(
            targets=[str(p) for p in config_paths],
            servers=len(results),
            fails=fails,
            warns=warns,
            passes=passes,
            operator=operator,
            findings_json=findings_json,
        )
        return results, audit

    # ── baseline ──────────────────────────────

    def baseline(self, config_paths: list[Path]) -> dict | None:
        """Save or update baseline for the first config. Returns baseline dict."""
        from mcp_bandit.baseline import save_baseline

        results = self.scan_all(config_paths)
        if not config_paths:
            return None
        lock_path = save_baseline(config_paths[0], results)
        return {"lock_path": str(lock_path), "servers": len(results)}

    # ── verify ────────────────────────────────

    def verify(self, config_paths: list[Path]) -> dict:
        """Scan + compare against baseline. Returns delta report."""
        from mcp_bandit.baseline import load_baseline, compute_delta

        results = self.scan_all(config_paths)
        if not config_paths:
            return {"delta": None, "error": "no configs found"}

        baseline = load_baseline(config_paths[0])
        delta = compute_delta(results, baseline) if baseline else {
            "new_fails": [], "fixed": [], "unchanged": 0,
            "drift": False, "config_changed": False,
            "message": "no baseline — run 'mcp-bandit baseline' first",
        }
        return {"delta": delta, "baseline_age": baseline.get("created") if baseline else None}

    # ── autofix ───────────────────────────────

    def autofix(self, config_paths: list[Path], apply: bool = False) -> dict:
        """Scan + suggest auto-fixes. If apply=True, write changes."""
        from mcp_bandit.autofix import suggest_fixes, apply_autofix

        results = self.scan_all(config_paths)
        all_findings = [f for r in results for f in r.findings]
        suggestions = suggest_fixes(all_findings)

        applied = False
        if apply and config_paths:
            new_content = apply_autofix(config_paths[0], suggestions)
            if new_content:
                config_paths[0].write_text(new_content, encoding="utf-8")
                applied = True

        return {
            "suggestions": len(suggestions),
            "auto_applicable": sum(1 for s in suggestions if s["auto_applicable"]),
            "applied": applied,
            "details": [
                {"fix_id": s["fix_id"], "confidence": s["confidence"],
                 "finding": s["finding"].title}
                for s in suggestions
            ],
        }

    @property
    def check_count(self) -> int:
        return len(self.checks)
