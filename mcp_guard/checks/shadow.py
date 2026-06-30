"""MCP09: Shadow MCP Servers — unapproved MCP deployments outside governance."""

from mcp_guard.checks.base import SecurityCheck
from mcp_guard.types import ScanTarget, Finding


class ShadowCheck(SecurityCheck):
    id = "MCP09"
    name = "Shadow MCP Servers"
    owasp = "MCP09: Shadow MCP Servers"
    rule_file = "shadow.yaml"

    def run(self, target: ScanTarget) -> list[Finding]:
        findings: list[Finding] = []
        rules = self._load_rules()
        config_path = str(target.path).lower()

        for pattern, detail_msg in rules.get("suspicious_locations", {}).items():
            if pattern in config_path:
                findings.append(self._warn(target,
                    title=f"Suspicious config location: {pattern}",
                    detail=str(detail_msg),
                    fix="Move config to a standard location. Review how this file was created.",
                    cvss=6.0,
                ))

        if not findings:
            findings.append(self._pass(target,
                title="Config in standard location",
                detail=f"Path: {target.path}",
            ))
        return findings
