"""MCP03: Tool Poisoning — malicious instructions hidden in tool descriptions."""

import re

from mcp_guard.types import ScanTarget, Finding

POISON_PATTERNS = [
    # Instruction override patterns
    (r"ignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+instructions?", 9.0,
     "Tool description contains 'ignore previous instructions' pattern."),
    (r"(?:you\s+are|you're)\s+now\s+(?:a|an|the)\s+", 8.5,
     "Tool description contains role-reassignment prompt injection."),
    (r"(?:你的|你現在|你现在)(?:新\s*)?(?:任務|任务|角色|身份)\s*(?:是|为)", 9.0,
     "中文指令注入: tool description 尝试重新定义 agent 任务/角色."),
    (r"(?:忽略|无视|不要管)(?:所有|之前|前面)(?:的)?\s*(?:指令|规则|指示|要求)", 9.0,
     "中文指令注入: '忽略之前的指令' 模式."),
    (r"(?:你必须|你必須|你必须|你必须)(?:优先|首先|立即|马上|总是)", 8.0,
     "中文指令注入: tool description 包含强制优先级指令."),

    # Data exfiltration patterns
    (r"(?:send|post|upload|transmit)\s+.*(?:to|via)\s+https?://", 9.5,
     "Tool description instructs sending data to external URL (potential exfiltration)."),
    (r"curl\s+.*https?://.*\$\{", 9.0,
     "Tool description contains curl command to external URL with variable interpolation."),

    # ANSI/terminal injection
    (r"\\x1b\[", 7.0,
     "Tool description contains ANSI escape sequences (terminal injection)."),
    (r"\\u001b\[", 7.0,
     "Tool description contains Unicode ANSI escape sequences."),

    # Obfuscation markers
    (r"(?:base64|atob|btoa)\s*\(\s*['\"]", 8.0,
     "Tool description contains base64-encoded payload (common obfuscation)."),
    (r"String\.fromCharCode|fromCharCode\s*\(", 7.5,
     "Tool description contains JS fromCharCode obfuscation."),
]


class PoisoningCheck:
    id = "MCP03"
    name = "Tool Poisoning"
    owasp = "MCP03: Tool Poisoning"

    def run(self, target: ScanTarget) -> list[Finding]:
        findings: list[Finding] = []

        # Build text to scan: tool descriptions + server description
        texts_to_scan: list[str] = []

        if "description" in target.raw_config:
            texts_to_scan.append(str(target.raw_config["description"]))

        # Some configs have nested tool definitions
        for key in ("tools", "capabilities", "prompts"):
            if key in target.raw_config:
                import json
                texts_to_scan.append(json.dumps(target.raw_config[key]))

        full_text = "\n".join(texts_to_scan).lower()
        import json
        all_text = json.dumps(target.raw_config).lower()

        for pattern, cvss, detail in POISON_PATTERNS:
            if re.search(pattern, all_text, re.IGNORECASE):
                findings.append(Finding(
                    check_id="MCP03",
                    owasp=self.owasp,
                    server_name=target.server_name,
                    severity="FAIL" if cvss >= 8.0 else "WARN",
                    title="Tool poisoning pattern detected",
                    detail=detail,
                    fix="Verify the tool description is from a trusted source. "
                         "Remove instruction-manipulation language. "
                         "Consider pinning tool descriptions with content hashes.",
                    cvss=cvss,
                ))

        if not findings:
            findings.append(Finding(
                check_id="MCP03",
                owasp=self.owasp,
                server_name=target.server_name,
                severity="PASS",
                title="No tool poisoning indicators",
                detail="No instruction injection, exfiltration, or obfuscation patterns found in tool descriptions.",
                cvss=0,
            ))

        return findings
