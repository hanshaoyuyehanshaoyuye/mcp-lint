"""MCP07: Insufficient Authentication & Authorization."""

from mcp_guard.checks.base import SecurityCheck
from mcp_guard.types import ScanTarget, Finding

AUTH_INDICATORS = ["oauth", "token", "api_key", "apikey", "auth", "bearer",
                    "jwt", "session", "login", "credentials", "secret"]
NETWORK_TRANSPORTS = {"sse", "streamable-http", "streamable_http"}


class AuthCheck(SecurityCheck):
    id = "MCP07"
    name = "Insufficient Authentication & Authorization"
    owasp = "MCP07: Insufficient Auth"

    def run(self, target: ScanTarget) -> list[Finding]:
        findings: list[Finding] = []
        raw = self._config_json(target).lower()
        transport = target.raw_config.get("type",
                    target.raw_config.get("transport", "")).lower()

        if transport in NETWORK_TRANSPORTS:
            if not any(indicator in raw for indicator in AUTH_INDICATORS):
                findings.append(self._fail(
                    target,
                    title=f"Network transport ({transport}) without authentication",
                    detail=f"Server uses {transport} but no OAuth token, API key, "
                            "or authentication header is configured.",
                    fix="Add OAuth 2.1 with PKCE or at minimum a shared secret token.",
                    cvss=8.5,
                ))
            else:
                findings.append(self._pass(target,
                    title=f"Network transport ({transport}) with auth indicators",
                    detail="Auth tokens/keys detected in config. Verify they follow OAuth 2.1 best practices.",
                ))

        elif transport in ("stdio", ""):
            if any(indicator in raw for indicator in AUTH_INDICATORS):
                findings.append(self._pass(target,
                    title="Auth indicators present in stdio config",
                    detail="Local stdio server with auth tokens. Valid for local development.",
                ))
            else:
                findings.append(self._pass(target,
                    title="Stdio transport — auth handled by OS process boundary",
                    detail="Local stdio transport. Acceptable for local-only MCP servers.",
                ))
        else:
            findings.append(self._warn(
                target,
                title=f"Unknown transport type: '{transport}'",
                detail="Server declares an unrecognised transport type. Verify this is intentional.",
                fix="Explicitly set 'type' to 'stdio' (local) or 'streamable-http' (remote).",
                cvss=4.0,
            ))

        return findings
