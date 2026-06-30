"""MCP05: Command Injection & Unsafe Execution."""

import re

from mcp_guard.checks.base import SecurityCheck
from mcp_guard.types import ScanTarget, Finding


class InjectionCheck(SecurityCheck):
    id = "MCP05"
    name = "Command Injection & Unsafe Execution"
    owasp = "MCP05: Command Injection"
    rule_file = "injection.yaml"

    def run(self, target: ScanTarget) -> list[Finding]:
        findings: list[Finding] = []
        rules = self._load_rules()
        raw = self._config_json(target)

        for entry in rules.get("patterns", []):
            if re.search(entry["regex"], raw):
                findings.append(self._fail(target,
                    title=f"Unsafe execution: {entry['label']}",
                    detail=f"Config references {entry['label']}. User input could be injected.",
                    fix="Replace with subprocess.run(args_list, shell=False) or use shlex.quote().",
                    cvss=float(entry["cvss"]),
                ))

        args_str = self._args_str(target)
        if args_str and re.search(r"[;&|`$(){}]", args_str):
            findings.append(self._warn(target,
                title="Shell metacharacters in command args",
                detail="Startup command contains shell metacharacters (; & | ` $ ...).",
                fix="Use exec form (list of args) instead of shell form.",
                cvss=5.0,
            ))

        if not findings:
            findings.append(self._pass(target,
                title="No command injection vectors detected",
                detail="No shell=True, eval, exec, or unsafe string formatting found.",
            ))
        return findings
