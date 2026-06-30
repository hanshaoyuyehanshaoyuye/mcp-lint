"""Core scanner orchestrator — discover, scan, score, report."""

from pathlib import Path
from dataclasses import dataclass, field

from mcp_guard.types import ScanTarget, Finding
from mcp_guard.discovery import parse_config, extract_servers
from mcp_guard.checks import ALL_CHECKS


@dataclass
class ServerResult:
    server_name: str
    config_path: Path
    findings: list[Finding] = field(default_factory=list)


class Scanner:
    def __init__(self, check_ids: list[str] | None = None):
        self._all_checks = ALL_CHECKS
        if check_ids:
            self.checks = [c for c in self._all_checks if c.id in check_ids]
        else:
            self.checks = list(self._all_checks)

    def scan_all(self, config_paths: list[Path]) -> list[ServerResult]:
        """Scan all discovered config files."""
        results: list[ServerResult] = []

        for path in config_paths:
            config = parse_config(path)
            if not config:
                continue

            servers = extract_servers(config)
            for name, server_config in servers.items():
                target = ScanTarget(path=path, server_name=name, raw_config=server_config)
                server_result = ServerResult(server_name=name, config_path=path)

                for check in self.checks:
                    findings = check.run(target)
                    server_result.findings.extend(findings)

                results.append(server_result)

        return results

    @property
    def check_count(self) -> int:
        return len(self.checks)
