"""MCP03: Tool Poisoning — malicious instructions hidden in tool descriptions."""

import re

from mcp_bandit.checks.base import SecurityCheck
from mcp_bandit.types import ScanTarget, Finding


class PoisoningCheck(SecurityCheck):
    id = "MCP03"
    name = "Tool Poisoning"
    owasp = "MCP03: Tool Poisoning"
    rule_file = "poisoning.yaml"

    def run(self, target: ScanTarget) -> list[Finding]:
        findings: list[Finding] = []
        rules = self._load_rules()
        raw = self._config_json(target).lower()

        for entry in rules.get("patterns", []):
            if re.search(entry["regex"], raw, re.IGNORECASE):
                cvss_f = float(entry["cvss"])
                detail = str(entry["detail"])
                if cvss_f >= 8.0:
                    findings.append(self._fail(target,
                        title="Tool poisoning pattern detected",
                        detail=detail,
                        fix="Verify tool description source. Remove instruction-manipulation language.",
                        cvss=cvss_f,
                        cve=entry.get('cve', ''),
                    ))
                else:
                    findings.append(self._warn(target,
                        title="Possible tool poisoning indicator",
                        detail=detail,
                        fix="Review tool description for trustworthiness.",
                        cvss=cvss_f,
                        cve=entry.get('cve', ''),
                    ))

        if not findings:
            findings.append(self._pass(target,
                title="No tool poisoning indicators",
                detail="No instruction injection, exfiltration, or obfuscation patterns found.",
            ))
        return findings
