"""MCP05: Command Injection & Unsafe Execution."""

import re

from mcp_guard.checks.base import SecurityCheck
from mcp_guard.types import ScanTarget, Finding

INJECTION_PATTERNS: list[tuple[str, str, float]] = [
    (r"os\.system\s*\(", "os.system()", 9.0),
    (r"subprocess\.(?:call|run|Popen)\s*\([^)]*shell\s*=\s*True", "subprocess(shell=True)", 9.5),
    (r"\beval\s*\(", "eval()", 9.5),
    (r"\bexec\s*\(", "exec()", 9.5),
    (r"os\.popen\s*\(", "os.popen()", 8.5),
    (r"commands\.getoutput\s*\(", "commands.getoutput()", 8.0),
]


class InjectionCheck(SecurityCheck):
    id = "MCP05"
    name = "Command Injection & Unsafe Execution"
    owasp = "MCP05: Command Injection"

    def run(self, target: ScanTarget) -> list[Finding]:
        findings: list[Finding] = []
        raw = self._config_json_indent(target)

        for pattern, label, cvss in INJECTION_PATTERNS:
            if re.search(pattern, raw):
                findings.append(self._fail(
                    target,
                    title=f"Unsafe execution: {label}",
                    detail=f"Config references {label}. User input could be injected.",
                    fix=f"Replace {label} with subprocess.run(args_list, shell=False) "
                         "or use shlex.quote() on user-supplied arguments.",
                    cvss=cvss,
                ))

        args = target.raw_config.get("args", [])
        if isinstance(args, list):
            args_str = " ".join(str(a) for a in args)
            if re.search(r"[;&|`$(){}]", args_str):
                findings.append(self._warn(
                    target,
                    title="Shell metacharacters in command args",
                    detail="Startup command contains shell metacharacters (; & | ` $ ...).",
                    fix="Use exec form (list of args) instead of shell form in Docker / direct execution.",
                    cvss=5.0,
                ))

        if not findings:
            findings.append(self._pass(target,
                title="No command injection vectors detected",
                detail="No shell=True, eval, exec, or unsafe string formatting found.",
            ))
        return findings
