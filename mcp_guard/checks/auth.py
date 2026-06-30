"""MCP07: Insufficient Authentication & Authorization."""

from mcp_guard.types import ScanTarget, Finding

AUTH_INDICATORS = [
    "oauth", "token", "api_key", "apikey", "auth", "bearer",
    "jwt", "session", "login", "credentials", "secret",
    "AUTH", "TOKEN", "API_KEY", "JWT",
]

TRANSPORT_TYPES = ["stdio", "sse", "streamable-http", "streamable_http"]


class AuthCheck:
    id = "MCP07"
    name = "Insufficient Authentication & Authorization"
    owasp = "MCP07: Insufficient Auth"

    def run(self, target: ScanTarget) -> list[Finding]:
        findings: list[Finding] = []
        import json
        raw = json.dumps(target.raw_config).lower()

        transport = target.raw_config.get("type", target.raw_config.get("transport", "")).lower()

        # Check 1: network transport without auth
        if transport in ("sse", "streamable-http", "streamable_http"):
            has_auth = any(indicator in raw for indicator in AUTH_INDICATORS)
            if not has_auth:
                findings.append(Finding(
                    check_id="MCP07",
                    owasp=self.owasp,
                    server_name=target.server_name,
                    severity="FAIL",
                    title=f"Network transport ({transport}) without authentication",
                    detail=f"Server uses {transport} transport but no OAuth token, API key, "
                             "or authentication header is configured.",
                    fix="Add OAuth 2.1 with PKCE or at minimum a shared secret token "
                         "for transport-level authentication.",
                    cvss=8.5,
                ))

        # Check 2: stdio transport — generally OK but flag if no auth at all
        if transport in ("stdio", ""):
            all_text = json.dumps(target.raw_config)
            has_auth = any(indicator.lower() in raw for indicator in AUTH_INDICATORS)
            if not has_auth:
                findings.append(Finding(
                    check_id="MCP07",
                    owasp=self.owasp,
                    server_name=target.server_name,
                    severity="PASS",
                    title="Stdio transport — auth handled by local process boundary",
                    detail="Local stdio transport. Authentication relies on OS process isolation. "
                             "This is generally acceptable for local-only MCP servers.",
                    cvss=0,
                ))
            else:
                findings.append(Finding(
                    check_id="MCP07",
                    owasp=self.owasp,
                    server_name=target.server_name,
                    severity="PASS",
                    title="Auth indicators present in stdio config",
                    detail=f"Local stdio server with auth tokens configured. "
                             f"Valid for local development.",
                    cvss=0,
                ))

        # Check 3: no transport specified at all
        if not transport:
            findings.append(Finding(
                check_id="MCP07",
                owasp=self.owasp,
                server_name=target.server_name,
                severity="WARN",
                title="No transport type specified",
                detail="Server config does not declare a transport type (stdio/sse/streamable-http). "
                         "Default is typically stdio. Verify this is intentional.",
                fix="Explicitly declare 'type': 'stdio' for local servers or configure auth for network transports.",
                cvss=4.0,
            ))

        return findings
