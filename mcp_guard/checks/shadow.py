"""MCP09: Shadow MCP Servers — unapproved MCP deployments outside governance."""

import sys
from pathlib import Path

from mcp_guard.types import ScanTarget, Finding


class ShadowCheck:
    id = "MCP09"
    name = "Shadow MCP Servers"
    owasp = "MCP09: Shadow MCP Servers"

    def run(self, target: ScanTarget) -> list[Finding]:
        findings: list[Finding] = []

        # Check: is this config in an unexpected location?
        config_path = str(target.path).lower()

        suspicious_locations = {
            "temp": "Config found in temp directory — could be a test artifact or attack vector.",
            "downloads": "Config in Downloads folder — untrusted code may have placed it.",
            "appdata/roaming/microsoft": "Config in system app data — verify ownership.",
            ".npm": "Config inside npm cache — may be from an npm postinstall script.",
            ".cache": "Config in cache directory — verify it was intentionally placed.",
            "node_modules": "Config in node_modules — may be from a dependency's postinstall.",
        }

        for pattern, detail in suspicious_locations.items():
            if pattern in config_path:
                findings.append(Finding(
                    check_id="MCP09",
                    owasp=self.owasp,
                    server_name=target.server_name,
                    severity="WARN",
                    title=f"Suspicious config location: {pattern}",
                    detail=detail,
                    fix=f"Move config to a standard location. "
                         f"Review how this file was created.",
                    cvss=6.0,
                ))

        if not findings:
            findings.append(Finding(
                check_id="MCP09",
                owasp=self.owasp,
                server_name=target.server_name,
                severity="PASS",
                title="Config in standard location",
                detail=f"Config at: {target.path}",
                cvss=0,
            ))

        return findings
