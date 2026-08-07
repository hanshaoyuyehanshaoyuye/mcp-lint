"""MCP12: _meta Field Forgery — spoofable metadata (NEW — MCP 2026-07-28)."""

import re
from mcp_bandit.checks.base import SecurityCheck
from mcp_bandit.types import ScanTarget, Finding


class MetaForgeryCheck(SecurityCheck):
    id = "MCP12"
    name = "_meta Field Forgery"
    owasp = "MCP12: _meta Forgery"
    rule_file = "meta_forgery.yaml"

    def run(self, target: ScanTarget) -> list[Finding]:
        findings: list[Finding] = []
        rules = self._load_rules()
        raw = self._config_json(target)

        for entry in rules.get("patterns", []):
            matches = list(re.finditer(entry["regex"], raw, re.IGNORECASE | re.DOTALL))
            if not matches:
                continue
            cvss = float(entry["cvss"])
            detail = str(entry["detail"])
            if cvss >= 8.0:
                findings.append(self._fail(target,
                    title=entry["label"], detail=detail,
                    fix="Sign _meta on server, validate signature on client. Never include secrets or task state in _meta.",
                    cvss=cvss))
            else:
                findings.append(self._warn(target,
                    title=entry["label"], detail=detail,
                    fix="Review _meta field usage against MCP 2026-07-28 spec constraints.",
                    cvss=cvss))

        if not findings:
            findings.append(self._pass(target,
                title="No _meta forgery indicators",
                detail="No spoofable metadata patterns detected."))
        return findings
