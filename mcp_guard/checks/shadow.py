"""MCP09: Shadow MCP Servers — unapproved MCP deployments outside governance."""

from mcp_guard.checks.base import SecurityCheck
from mcp_guard.types import ScanTarget, Finding

SUSPICIOUS_LOCATIONS = {
    "temp": "Config in temp directory — could be a test artifact or attack vector.",
    "downloads": "Config in Downloads folder — untrusted code may have placed it.",
    ".npm": "Config inside npm cache — may be from an npm postinstall script.",
    ".cache": "Config in cache directory — verify it was intentionally placed.",
    "node_modules": "Config in node_modules — may be from a dependency's postinstall.",
}


class ShadowCheck(SecurityCheck):
    id = "MCP09"
    name = "Shadow MCP Servers"
    owasp = "MCP09: Shadow MCP Servers"

    def run(self, target: ScanTarget) -> list[Finding]:
        findings: list[Finding] = []
        config_path = str(target.path).lower()

        for pattern, detail_msg in SUSPICIOUS_LOCATIONS.items():
            if pattern in config_path:
                findings.append(self._warn(
                    target,
                    title=f"Suspicious config location: {pattern}",
                    detail=detail_msg,
                    fix="Move config to a standard location. Review how this file was created.",
                    cvss=6.0,
                ))

        if not findings:
            findings.append(self._pass(target,
                title="Config in standard location",
                detail=f"Path: {target.path}",
            ))
        return findings
