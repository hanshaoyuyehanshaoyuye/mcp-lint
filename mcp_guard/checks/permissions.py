"""MCP02: Privilege Escalation via Scope Creep — overly broad permissions."""

from mcp_guard.types import ScanTarget, Finding

HIGH_RISK_PATHS: list[str] = [
    "/", "C:\\", "/root", "/home", "/etc", "/var", "/tmp",
    "~", "$HOME", "%USERPROFILE%", "%APPDATA%",
]

HIGH_RISK_HOSTS: list[str] = [
    "0.0.0.0", "::", "*", "localhost",
]


class PermissionsCheck:
    id = "MCP02"
    name = "Privilege Escalation via Scope Creep"
    owasp = "MCP02: Privilege Escalation"

    def run(self, target: ScanTarget) -> list[Finding]:
        findings: list[Finding] = []
        import json
        raw = json.dumps(target.raw_config)

        # Check 1: filesystem paths
        for risk_path in HIGH_RISK_PATHS:
            if risk_path in raw:
                findings.append(Finding(
                    check_id="MCP02",
                    owasp=self.owasp,
                    server_name=target.server_name,
                    severity="WARN",
                    title=f"Broad filesystem access: '{risk_path}'",
                    detail=f"Config references '{risk_path}'. "
                             "MCP servers with root-level filesystem access can read/write any file.",
                    fix=f"Restrict filesystem access to a specific project directory "
                         f"(e.g., /home/user/projects/my-app/).",
                    cvss=7.0,
                ))
                break

        # Check 2: unrestricted network binding
        if "url" in target.raw_config:
            url = str(target.raw_config["url"])
            for host in HIGH_RISK_HOSTS:
                if host in url:
                    findings.append(Finding(
                        check_id="MCP02",
                        owasp=self.owasp,
                        server_name=target.server_name,
                        severity="WARN",
                        title=f"Server binds to unrestricted host: {host}",
                        detail=f"Server URL includes '{host}', accepting connections from all interfaces.",
                        fix="Bind to 127.0.0.1 unless remote access is explicitly required.",
                        cvss=5.0,
                    ))
                    break

        # Check 3: transport type
        transport = target.raw_config.get("type", target.raw_config.get("transport", ""))
        if transport in ("sse", "streamable-http") and "url" not in str(target.raw_config):
            findings.append(Finding(
                check_id="MCP02",
                owasp=self.owasp,
                server_name=target.server_name,
                severity="INFO",
                title="SSE/HTTP transport without explicit URL binding",
                detail="Server uses network transport but URL binding is not explicitly configured.",
                fix="Verify the server binds to localhost unless remote access is intended.",
                cvss=3.0,
            ))

        if not findings:
            findings.append(Finding(
                check_id="MCP02",
                owasp=self.owasp,
                server_name=target.server_name,
                severity="PASS",
                title="No privilege escalation vectors detected",
                detail="No overly broad filesystem paths or unrestricted network bindings found.",
                cvss=0,
            ))

        return findings
