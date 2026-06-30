"""MCP08: Lack of Audit & Telemetry."""

from mcp_bandit.checks.base import SecurityCheck
from mcp_bandit.types import ScanTarget, Finding


class AuditGapCheck(SecurityCheck):
    id = "MCP08"
    name = "Lack of Audit & Telemetry"
    owasp = "MCP08: Audit & Telemetry"
    rule_file = "audit_gap.yaml"

    def run(self, target: ScanTarget) -> list[Finding]:
        findings: list[Finding] = []
        rules = self._load_rules()
        raw = self._config_json(target).lower()
        indicators = rules.get("audit_indicators", [])
        has_audit = any(str(i).lower() in raw for i in indicators)

        transport = target.raw_config.get("type",
                     target.raw_config.get("transport", "stdio")).lower()

        if has_audit:
            findings.append(self._pass(target,
                title="Audit/telemetry indicators present",
                detail="Config references logging, tracing, or observability infrastructure.",
            ))
            return findings

        if transport in ("sse", "streamable-http", "streamable_http"):
            cvss = float(rules.get("network_transport_cvss", 7.0))
            findings.append(self._fail(target,
                title="Network transport without audit trail",
                detail=f"Server uses {transport} but no audit, telemetry, or observability config found.",
                fix="Integrate Langfuse, OpenTelemetry, or structured logging for all tool invocations.",
                cvss=cvss,
            ))
        else:
            cvss = float(rules.get("stdio_transport_cvss", 3.0))
            findings.append(self._warn(target,
                title="No audit/telemetry indicators found",
                detail="No logging, tracing, or observability configuration detected. "
                       "Without audit trails, tool invocations and token usage are invisible.",
                fix="Add a telemetry backend (Langfuse, LangSmith, OpenTelemetry).",
                cvss=cvss,
            ))

        return findings
