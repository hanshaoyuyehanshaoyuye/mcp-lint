"""Shared data types — no imports from other mcp_bandit modules."""

from pathlib import Path
from dataclasses import dataclass, field


@dataclass
class ScanTarget:
    path: Path
    server_name: str
    raw_config: dict


@dataclass
class Finding:
    check_id: str
    owasp: str
    server_name: str
    severity: str  # "FAIL" | "WARN" | "PASS"
    title: str
    detail: str
    fix: str = ""
    cvss: float = 0.0
    cve: str = ""
