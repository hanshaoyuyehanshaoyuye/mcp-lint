"""MCP07: Insufficient Authentication & Authorization."""

from mcp_bandit.checks.base import SecurityCheck
from mcp_bandit.types import ScanTarget, Finding


class AuthCheck(SecurityCheck):
    id = "MCP07"
    name = "Insufficient Authentication & Authorization"
    owasp = "MCP07: Insufficient Auth"
    rule_file = "auth.yaml"

    def run(self, target: ScanTarget) -> list[Finding]:
        findings: list[Finding] = []
        rules = self._load_rules()
        raw = self._config_json(target).lower()
        indicators = [str(i).lower() for i in rules.get("auth_indicators", [])]
        net_transports = set(rules.get("network_transports", []))

        transport = target.raw_config.get("type",
                     target.raw_config.get("transport", "")).lower()

        if transport in net_transports:
            if not any(i in raw for i in indicators):
                findings.append(self._fail(target,
                    title=f"Network transport ({transport}) without authentication",
                    detail=f"Server uses {transport} but no OAuth token, API key, or auth header configured.",
                    fix="Add OAuth 2.1 with PKCE or at minimum a shared secret token.",
                    cvss=8.5,
                ))
            else:
                findings.append(self._pass(target,
                    title=f"Network transport ({transport}) with auth indicators",
                    detail="Auth tokens/keys detected. Verify OAuth 2.1 best practices.",
                ))
        elif transport in ("stdio", ""):
            findings.append(self._pass(target,
                title="Stdio transport — auth handled by OS process boundary"
                      if not any(i in raw for i in indicators)
                      else "Auth indicators present in stdio config",
                detail="Local stdio. Acceptable for local-only MCP servers.",
            ))
        else:
            findings.append(self._warn(target,
                title=f"Unknown transport type: '{transport}'",
                detail="Unrecognised transport type. Verify this is intentional.",
                fix="Explicitly set 'type' to 'stdio' (local) or 'streamable-http' (remote).",
                cvss=4.0,
            ))

        return findings
