"""MCP13: Task Lifecycle DoS — resource exhaustion via unbound tasks (NEW — MCP 2026-07-28)."""

import re
from mcp_bandit.checks.base import SecurityCheck
from mcp_bandit.types import ScanTarget, Finding


class TaskDosCheck(SecurityCheck):
    id = "MCP13"
    name = "Task Lifecycle DoS"
    owasp = "MCP13: Task Lifecycle DoS"
    rule_file = "task_dos.yaml"

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
                    fix="Set maxTasks, taskTimeout, maxConcurrent, and rate limits on cancellable operations.",
                    cvss=cvss))
            else:
                findings.append(self._warn(target,
                    title=entry["label"], detail=detail,
                    fix="Add bounds and timeouts to task lifecycle configuration.",
                    cvss=cvss))

        if not findings:
            findings.append(self._pass(target,
                title="No task lifecycle DoS indicators",
                detail="Task queue, timeout, and concurrency settings appear bounded."))
        return findings
