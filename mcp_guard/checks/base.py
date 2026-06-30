"""Base class for all security checks."""

import json
from abc import ABC, abstractmethod
from typing import Literal

from mcp_guard.types import ScanTarget, Finding

Severity = Literal["FAIL", "WARN", "PASS"]


class SecurityCheck(ABC):
    """Abstract base for all MCP security checks.

    Subclasses define:
      id      — check ID (MCP01..MCP09)
      name    — human-readable name
      owasp   — OWASP MCP Top 10 mapping, e.g. "MCP01: Token Mismanagement"

    They implement run(target) → list[Finding]."""

    id: str
    name: str
    owasp: str

    @abstractmethod
    def run(self, target: ScanTarget) -> list[Finding]:
        ...

    # ---- helpers for subclasses ----

    def _config_json(self, target: ScanTarget) -> str:
        """config as single-line JSON for regex / substring scanning."""
        return json.dumps(target.raw_config)

    def _config_json_indent(self, target: ScanTarget) -> str:
        """config as multi-line JSON — better for human-readable matching."""
        return json.dumps(target.raw_config, indent=2)

    def _pass(self, target: ScanTarget, title: str, detail: str) -> Finding:
        """Return a PASS finding."""
        return Finding(
            check_id=self.id,
            owasp=self.owasp,
            server_name=target.server_name,
            severity="PASS",
            title=title,
            detail=detail,
            cvss=0,
        )

    def _warn(self, target: ScanTarget, title: str, detail: str, fix: str = "", cvss: float = 5.0) -> Finding:
        """Return a WARN finding."""
        return Finding(
            check_id=self.id, owasp=self.owasp,
            server_name=target.server_name,
            severity="WARN", title=title, detail=detail, fix=fix, cvss=cvss,
        )

    def _fail(self, target: ScanTarget, title: str, detail: str, fix: str = "", cvss: float = 7.0) -> Finding:
        """Return a FAIL finding."""
        return Finding(
            check_id=self.id, owasp=self.owasp,
            server_name=target.server_name,
            severity="FAIL", title=title, detail=detail, fix=fix, cvss=cvss,
        )
