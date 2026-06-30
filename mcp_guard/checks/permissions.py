"""MCP02: Privilege Escalation via Scope Creep."""

from mcp_guard.checks.base import SecurityCheck
from mcp_guard.types import ScanTarget, Finding


class PermissionsCheck(SecurityCheck):
    id = "MCP02"
    name = "Privilege Escalation via Scope Creep"
    owasp = "MCP02: Privilege Escalation"
    rule_file = "permissions.yaml"

    def run(self, target: ScanTarget) -> list[Finding]:
        findings: list[Finding] = []
        rules = self._load_rules()
        raw = self._config_json(target)

        for risk_path in rules.get("high_risk_paths", []):
            if str(risk_path) in raw:
                findings.append(self._warn(target,
                    title=f"Broad filesystem access: '{risk_path}'",
                    detail=f"Config references '{risk_path}'. Root-level FS access = read/write any file.",
                    fix="Restrict to a specific project directory (e.g. /home/user/projects/my-app/).",
                    cvss=7.0,
                ))

        if "url" in target.raw_config:
            url = str(target.raw_config["url"])
            for host in rules.get("high_risk_hosts", []):
                if str(host) in url:
                    findings.append(self._warn(target,
                        title=f"Server binds to unrestricted host: {host}",
                        detail=f"URL includes '{host}', accepting connections from all interfaces.",
                        fix="Bind to 127.0.0.1 unless remote access required.",
                        cvss=5.0,
                    ))
                    break

        if not findings:
            findings.append(self._pass(target,
                title="No privilege escalation vectors detected",
                detail="No overly broad filesystem paths or unrestricted network bindings found.",
            ))
        return findings
