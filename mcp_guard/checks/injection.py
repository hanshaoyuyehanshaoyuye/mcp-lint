"""MCP05: Command Injection & Unsafe Execution."""

import re

from mcp_guard.types import ScanTarget, Finding

INJECTION_PATTERNS: list[tuple[str, str, float]] = [
    (r"os\.system\(", "os.system() call", 9.0),
    (r"subprocess\.(?:call|run|Popen)\s*\([^)]*shell\s*=\s*True", "subprocess with shell=True", 9.5),
    (r"eval\s*\(", "eval() call", 9.5),
    (r"exec\s*\(", "exec() call", 9.5),
    (r"os\.popen\(", "os.popen() call", 8.5),
    (r"commands\.getoutput\(", "commands.getoutput() call", 8.0),
]

UNSAFE_INPUT_PATTERNS: list[str] = [
    r"f\"[^\"]*\$\{",
    r"f'[^']*\$\{",
    r"\.format\s*\(\s*input",
    r"%\s*%\s*input",
    r"\+\s*input",
    r"shell\s*=\s*True",
]


class InjectionCheck:
    id = "MCP05"
    name = "Command Injection & Unsafe Execution"
    owasp = "MCP05: Command Injection"

    def run(self, target: ScanTarget) -> list[Finding]:
        findings: list[Finding] = []

        # Check command/args field for injection patterns
        import json
        raw = json.dumps(target.raw_config, indent=2)

        for pattern, label, cvss in INJECTION_PATTERNS:
            if re.search(pattern, raw):
                findings.append(Finding(
                    check_id="MCP05",
                    owasp=self.owasp,
                    server_name=target.server_name,
                    severity="FAIL",
                    title=f"Unsafe execution: {label}",
                    detail=f"Config references {label}, which can lead to command injection "
                             "if user input is passed unsanitized.",
                    fix=f"Replace {label} with subprocess.run(args_list, shell=False) "
                         "or use shlex.quote() on all user-supplied arguments.",
                    cvss=cvss,
                ))

        # Check args for shell metacharacter patterns
        if "args" in target.raw_config:
            args_list = target.raw_config["args"]
            if isinstance(args_list, list):
                args_str = " ".join(str(a) for a in args_list)
                if re.search(r"[;&|`$(){}]", args_str):
                    findings.append(Finding(
                        check_id="MCP05",
                        owasp=self.owasp,
                        server_name=target.server_name,
                        severity="WARN",
                        title="Shell metacharacters in command args",
                        detail="Server startup command contains shell metacharacters (; & | ` $ ...). "
                               "These could enable injection.",
                        fix="Use exec form (list of args) instead of shell form in Docker/direct execution.",
                        cvss=5.0,
                    ))

        if not findings:
            findings.append(Finding(
                check_id="MCP05",
                owasp=self.owasp,
                server_name=target.server_name,
                severity="PASS",
                title="No command injection vectors detected",
                detail="No shell=True, eval, exec, or unsafe string formatting found.",
                cvss=0,
            ))

        return findings
