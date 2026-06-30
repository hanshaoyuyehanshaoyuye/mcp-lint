"""MCP10: Context Injection & Over-Sharing — cross-server / multi-tenant leaks."""

from mcp_guard.checks.base import SecurityCheck
from mcp_guard.types import ScanTarget, Finding


class ContextSharingCheck(SecurityCheck):
    id = "MCP10"
    name = "Context Injection & Over-Sharing"
    owasp = "MCP10: Context Over-Sharing"
    rule_file = "context_sharing.yaml"

    def run(self, target: ScanTarget) -> list[Finding]:
        findings: list[Finding] = []
        rules = self._load_rules()
        raw = self._config_json(target).lower()

        indicators = rules.get("shared_context_indicators", [])
        high_risk = set(rules.get("high_risk_transports", []))
        multi_threshold = int(rules.get("multi_server_warning_threshold", 5))

        transport = target.raw_config.get("type",
                     target.raw_config.get("transport", "")).lower()

        for indicator in indicators:
            if indicator in raw:
                severity = "FAIL" if transport in high_risk else "WARN"
                cvss_val = 8.0 if transport in high_risk else 5.0
                detail = (f"'{indicator}' suggests persistent/shared context across sessions. "
                          f"With {transport} transport, cross-tenant data leakage is possible."
                          if transport in high_risk else
                          f"'{indicator}' enables context persistence. Verify isolation between sessions.")
                fix = ("Scope context windows per session. Use ephemeral memory. "
                       "Add field-level access controls and DLP scanning.")

                if severity == "FAIL":
                    findings.append(self._fail(target,
                        title=f"Context sharing indicator: '{indicator}'",
                        detail=detail, fix=fix, cvss=cvss_val,
                    ))
                else:
                    findings.append(self._warn(target,
                        title=f"Context sharing indicator: '{indicator}'",
                        detail=detail, fix=fix, cvss=cvss_val,
                    ))

        if not findings:
            findings.append(self._pass(target,
                title="No context over-sharing indicators",
                detail="No persistent/shared context configuration detected.",
            ))
        return findings
