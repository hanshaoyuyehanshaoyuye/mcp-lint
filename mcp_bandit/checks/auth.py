"""MCP07: Insufficient Authentication & Authorization (enhanced — MCP 2026-07-28 PKCE + SSE deprecation)."""

import re
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
        deprecated_transports = set(rules.get("deprecated_transports", []))

        transport = target.raw_config.get("type",
                     target.raw_config.get("transport", "")).lower()

        # ── SSE deprecation warning (MCP 2026-07-28) ──
        if transport in deprecated_transports:
            findings.append(self._warn(target,
                title=f"Deprecated transport: {transport}",
                detail="SSE transport is deprecated in MCP 2026-07-28. Migrate to streamable-http.",
                fix="Replace 'sse' with 'streamable-http' transport. 12-month deprecation window.",
                cvss=4.0))

        # ── Auth indicator check ──
        if transport in net_transports:
            if not any(i in raw for i in indicators):
                findings.append(self._fail(target,
                    title=f"Network transport ({transport}) without authentication",
                    detail=f"Server uses {transport} but no OAuth token, API key, or auth header configured.",
                    fix="Add OAuth 2.1 with PKCE or at minimum a shared secret token.",
                    cvss=8.5))
            else:
                findings.append(self._pass(target,
                    title=f"Network transport ({transport}) with auth indicators",
                    detail="Auth tokens/keys detected. Verify OAuth 2.1 best practices."))
        elif transport in ("stdio", ""):
            findings.append(self._pass(target,
                title="Stdio transport — auth handled by OS process boundary"
                      if not any(i in raw for i in indicators)
                      else "Auth indicators present in stdio config",
                detail="Local stdio. Acceptable for local-only MCP servers."))
        else:
            findings.append(self._warn(target,
                title=f"Unknown transport type: '{transport}'",
                detail="Unrecognised transport type. Verify this is intentional.",
                fix="Explicitly set 'type' to 'stdio' (local) or 'streamable-http' (remote).",
                cvss=4.0))

        # ── PKCE depth checks (MCP 2026-07-28) ──
        if transport in net_transports and any(i in raw for i in indicators):
            raw_full = self._config_json(target)  # case-sensitive for field names
            for entry in rules.get("pkce_weak_patterns", []):
                if re.search(entry["regex"], raw_full, re.IGNORECASE):
                    cvss = float(entry["cvss"])
                    if cvss >= 8.0:
                        findings.append(self._fail(target,
                            title=entry["label"], detail=entry["detail"],
                            fix="Enforce PKCE with S256, HTTPS redirect URIs, and random state parameter.",
                            cvss=cvss))
                    else:
                        findings.append(self._warn(target,
                            title=entry["label"], detail=entry["detail"],
                            fix="Review OAuth 2.1 PKCE configuration.",
                            cvss=cvss))

        return findings
