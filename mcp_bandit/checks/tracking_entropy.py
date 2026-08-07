"""MCP11: Tracking ID Entropy — weak/predictable tracking identifiers (NEW — MCP 2026-07-28)."""

import re
from mcp_bandit.checks.base import SecurityCheck
from mcp_bandit.types import ScanTarget, Finding


class TrackingEntropyCheck(SecurityCheck):
    id = "MCP11"
    name = "Tracking ID Entropy"
    owasp = "MCP11: Tracking ID Hijacking"
    rule_file = "tracking_entropy.yaml"

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
                    fix="Use crypto-random 128-bit+ tracking IDs. Validate immutability.",
                    cvss=cvss))
            else:
                findings.append(self._warn(target,
                    title=entry["label"], detail=detail,
                    fix="Review tracking ID generation for entropy and predictability.",
                    cvss=cvss))

        if not findings:
            findings.append(self._pass(target,
                title="No tracking ID entropy issues",
                detail="Tracking identifiers appear non-predictable."))
        return findings
