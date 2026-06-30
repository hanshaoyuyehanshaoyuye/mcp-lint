"""MCP06: Prompt Injection via Contextual Payloads — untrusted data sources."""

import re

from mcp_bandit.checks.base import SecurityCheck
from mcp_bandit.types import ScanTarget, Finding


class ContextInjectionCheck(SecurityCheck):
    id = "MCP06"
    name = "Prompt Injection via Contextual Payloads"
    owasp = "MCP06: Context Injection"
    rule_file = "context_injection.yaml"

    def run(self, target: ScanTarget) -> list[Finding]:
        findings: list[Finding] = []
        rules = self._load_rules()
        raw = self._config_json(target)

        for entry in rules.get("patterns", []):
            if re.search(entry["regex"], raw, re.IGNORECASE):
                cvss_f = float(entry["cvss"])
                detail = str(entry["detail"])
                if cvss_f >= 8.0:
                    findings.append(self._fail(target,
                        title="Context injection vector detected",
                        detail=detail,
                        fix="Validate data source authorship. Sanitize retrieved content before LLM consumption.",
                        cvss=cvss_f,
                        cve=entry.get('cve', ''),
                    ))
                else:
                    findings.append(self._warn(target,
                        title="Possible context injection surface",
                        detail=detail,
                        fix="Review data-source configuration for untrusted input.",
                        cvss=cvss_f,
                        cve=entry.get('cve', ''),
                    ))

        # Check for untrusted data source indicators
        for indicator in rules.get("untrusted_source_indicators", []):
            if indicator in raw:
                findings.append(self._warn(target,
                    title=f"Untrusted data source indicator: '{indicator}'",
                    detail=f"'{indicator}' suggests untrusted content feeds into LLM context.",
                    fix="Ensure content is sanitized and source-verified before injection into prompt.",
                    cvss=6.0,
                ))

        if not findings:
            findings.append(self._pass(target,
                title="No context injection vectors detected",
                detail="No untrusted data sources or injection patterns found.",
            ))
        return findings
