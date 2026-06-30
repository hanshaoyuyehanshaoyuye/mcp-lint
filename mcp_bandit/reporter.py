"""Output formatters — terminal (rich), JSON, SARIF."""

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mcp_bandit.scanner import ServerResult, Finding


class Reporter:
    def __init__(self, fmt: str = "terminal", quiet: bool = False):
        self._fmt = fmt
        self._quiet = quiet

    def render(
        self, results: list["ServerResult"], targets: list
    ) -> str:
        if self._fmt == "json":
            return self._render_json(results)
        elif self._fmt == "sarif":
            return self._render_sarif(results)
        return self._render_terminal(results, targets)

    def _render_terminal(
        self, results: list["ServerResult"], targets: list
    ) -> str:
        """Terminal output with grades, CVE refs, autofix hints."""
        total = sum(len(r.findings) for r in results)
        fails = sum(r.fail_count for r in results)
        warns = sum(r.warn_count for r in results)
        passes = total - fails - warns

        lines = []
        lines.append("")
        lines.append("mcp-bandit v0.3.0 — MCP Security Linter")
        lines.append("=" * 56)

        target_str = ", ".join(str(t) for t in targets[:3])
        if len(targets) > 3:
            target_str += f" (+{len(targets) - 3} more)"
        lines.append(f"Targets: {target_str}")
        lines.append(f"Servers: {len(results)} | PASS: {passes} | WARN: {warns} | FAIL: {fails}")
        lines.append("=" * 56)

        for result in results:
            g = result.grade
            grade_bar = _grade_bar(g)
            lines.append(f"\n  [{g}] {result.server_name}  {grade_bar}")
            for f in result.findings:
                if f.severity == "PASS" and self._quiet:
                    continue
                tag = f"[{f.severity}]"
                cve_line = f"  CVE: {f.cve}" if f.cve else ""
                lines.append(f"    {tag} {f.owasp}: {f.title}")
                lines.append(f"         CVSS: {f.cvss} | {f.detail}")
                if cve_line:
                    lines.append(f"         {cve_line}")
                if f.fix:
                    lines.append(f"         Fix: {f.fix}")

        if not self._quiet:
            lines.append(f"\n{'=' * 56}")
            lines.append(f"Total: {total} findings — {fails} FAIL, {warns} WARN, {passes} PASS")
            if fails > 0:
                lines.append(f"\n*** Action required: {fails} critical issue(s) need remediation. ***")
                lines.append(f"    Run 'mcp-bandit autofix' to auto-apply high-confidence fixes.")
            elif warns > 0:
                lines.append(f"\nReview recommended: {warns} non-critical finding(s).")
            else:
                lines.append(f"\nAll checks passed. No security issues found.")

        return "\n".join(lines)


def _grade_bar(grade: str) -> str:
    bars = {"A": "[AAAAA]", "B": "[BBBB-]", "C": "[CCC--]",
            "D": "[DD---]", "E": "[E----]", "F": "[F----]"}
    return bars.get(grade, "[?????]")

    def _render_json(self, results: list["ServerResult"]) -> str:
        output = {
            "tool": "mcp-bandit",
            "version": "0.3.0",
            "servers": [
                {
                    "name": r.server_name,
                    "config_path": str(r.config_path),
                    "grade": r.grade,
                    "fails": r.fail_count,
                    "warns": r.warn_count,
                    "findings": [
                        {
                            "check_id": f.check_id,
                            "owasp": f.owasp,
                            "severity": f.severity,
                            "title": f.title,
                            "detail": f.detail,
                            "fix": f.fix,
                            "cvss": f.cvss,
                            "cve": f.cve,
                        }
                        for f in r.findings
                    ],
                }
                for r in results
            ],
        }
        return json.dumps(output, indent=2, ensure_ascii=False)

    def _render_sarif(self, results: list["ServerResult"]) -> str:
        """SARIF 2.1.0 format output."""
        runs = []
        for r in results:
            results_list = []
            for f in r.findings:
                if f.severity == "PASS":
                    continue
                level = "error" if f.severity == "FAIL" else "warning"
                results_list.append({
                    "ruleId": f.check_id,
                    "level": level,
                    "message": {"text": f"{f.owasp}: {f.detail}"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": str(r.config_path)}
                        }
                    }],
                    "properties": {
                        "cvss": f.cvss,
                        "owasp": f.owasp,
                        "fix": f.fix,
                    },
                })
            if results_list:
                runs.append({
                    "tool": {
                        "driver": {
                            "name": "mcp-bandit",
                            "version": "0.1.0",
                            "rules": [
                                {"id": f.check_id, "shortDescription": {"text": f.title}}
                                for f in r.findings
                            ],
                        }
                    },
                    "results": results_list,
                })

        return json.dumps({
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": runs,
        }, indent=2)
