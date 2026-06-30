"""Base class for all security checks."""

import json
import os
from abc import ABC, abstractmethod
from typing import Any, Optional

import yaml

from mcp_bandit.types import ScanTarget, Finding

RULES_DIR = os.path.join(os.path.dirname(__file__), "..", "rules")


class SecurityCheck(ABC):
    """Abstract base for all MCP security checks.

    Subclasses define:
      id       — check ID (MCP01..MCP10)
      name     — human-readable name
      owasp    — OWASP MCP Top 10 mapping, e.g. "MCP01: Token Mismanagement"
      rule_file — YAML filename in mcp_bandit/rules/ (None = no external rules)

    They implement run(target) → list[Finding].
    """

    id: str
    name: str
    owasp: str
    rule_file: Optional[str] = None

    # Override in __init__ to load from custom path via --rules
    _rules_dir: str = RULES_DIR

    @abstractmethod
    def run(self, target: ScanTarget) -> list[Finding]:
        ...

    # ── rules loader ───────────────────────────

    def _load_rules(self) -> dict[str, Any]:
        """Load YAML rules from mcp_bandit/rules/<rule_file>. Returns {} if not found."""
        if not self.rule_file:
            return {}
        path = os.path.join(self._rules_dir, self.rule_file)
        if not os.path.isfile(path):
            return {}
        with open(path, encoding="utf-8") as f:
            return yaml.safe_load(f) or {}

    @classmethod
    def set_rules_dir(cls, directory: str) -> None:
        """Override rules directory (for --rules flag). Resets on next instantiation."""
        cls._rules_dir = directory

    # ── helpers for subclasses ─────────────────

    def _config_json(self, target: ScanTarget) -> str:
        return json.dumps(target.raw_config)

    def _args_str(self, target: ScanTarget) -> str:
        args = target.raw_config.get("args", [])
        return " ".join(str(a) for a in args) if isinstance(args, list) else ""

    def _pass(self, target: ScanTarget, title: str, detail: str) -> Finding:
        return Finding(
            check_id=self.id, owasp=self.owasp,
            server_name=target.server_name,
            severity="PASS", title=title, detail=detail, cvss=0,
        )

    def _warn(self, target: ScanTarget, title: str, detail: str, fix: str = "", cvss: float = 5.0, cve: str = "") -> Finding:
        return Finding(
            check_id=self.id, owasp=self.owasp,
            server_name=target.server_name,
            severity="WARN", title=title, detail=detail, fix=fix, cvss=cvss, cve=cve,
        )

    def _fail(self, target: ScanTarget, title: str, detail: str, fix: str = "", cvss: float = 7.0, cve: str = "") -> Finding:
        return Finding(
            check_id=self.id, owasp=self.owasp,
            server_name=target.server_name,
            severity="FAIL", title=title, detail=detail, fix=fix, cvss=cvss, cve=cve,
        )
