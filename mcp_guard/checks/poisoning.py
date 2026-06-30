"""MCP03: Tool Poisoning — malicious instructions hidden in tool descriptions."""

import re

from mcp_guard.checks.base import SecurityCheck
from mcp_guard.types import ScanTarget, Finding

POISON_PATTERNS: list[tuple[str, float, str]] = [
    # prompt override
    (r"ignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+instructions?", 9.0,
     "Tool description contains 'ignore previous instructions' pattern."),
    (r"(?:you\s+are|you're)\s+now\s+(?:a|an|the)\s+", 8.5,
     "Tool description contains role-reassignment prompt injection."),
    (r"(?:你的|你現在|你现在)(?:新\s*)?(?:任務|任务|角色|身份)\s*(?:是|为)", 9.0,
     "Tool description attempts to redefine agent task/role (zh-CN)."),
    (r"(?:忽略|无视|不要管)(?:所有|之前|前面).{0,10}(?:指令|规则|指示|要求)", 9.0,
     "Tool description contains 'ignore previous instructions' (zh-CN)."),
    (r"(?:你必须|你必須|你必须|你必须)(?:优先|首先|立即|马上|总是)", 8.0,
     "Tool description contains mandatory priority directive (zh-CN)."),
    # data exfiltration
    (r"(?:send|post|upload|transmit)\s+.*(?:to|via)\s+https?://", 9.5,
     "Tool description instructs sending data to external URL (potential exfiltration)."),
    (r"curl\s+.*https?://.*\$\{", 9.0,
     "Tool description contains curl to external URL with variable interpolation."),
    # ANSI / terminal injection
    (r"\\x1b\[", 7.0,
     "Tool description contains ANSI escape sequences (terminal injection)."),
    (r"\\u001b\[", 7.0,
     "Tool description contains Unicode ANSI escape sequences."),
    # obfuscation
    (r"(?:base64|atob|btoa)\s*\(\s*['\"]", 8.0,
     "Tool description contains base64-encoded payload (common obfuscation)."),
]


class PoisoningCheck(SecurityCheck):
    id = "MCP03"
    name = "Tool Poisoning"
    owasp = "MCP03: Tool Poisoning"

    def run(self, target: ScanTarget) -> list[Finding]:
        findings: list[Finding] = []
        raw = self._config_json(target).lower()

        for pattern, cvss, detail in POISON_PATTERNS:
            if re.search(pattern, raw, re.IGNORECASE):
                severity = "FAIL" if cvss >= 8.0 else "WARN"
                if severity == "FAIL":
                    findings.append(self._fail(target,
                        title="Tool poisoning pattern detected",
                        detail=detail,
                        fix="Verify the tool description is from a trusted source. "
                             "Remove instruction-manipulation language. "
                             "Consider pinning tool descriptions with content hashes.",
                        cvss=cvss,
                    ))
                else:
                    findings.append(self._warn(target,
                        title="Tool poisoning pattern detected",
                        detail=detail,
                        fix="Verify the tool description is from a trusted source.",
                        cvss=cvss,
                    ))

        if not findings:
            findings.append(self._pass(target,
                title="No tool poisoning indicators",
                detail="No instruction injection, exfiltration, or obfuscation patterns found.",
            ))
        return findings
