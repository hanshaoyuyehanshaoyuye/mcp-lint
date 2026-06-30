"""Integration tests for mcp-bandit scanner."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from mcp_bandit.discovery import parse_config, extract_servers
from mcp_bandit.scanner import Scanner


FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_safe_config():
    config = parse_config(FIXTURES / "safe_config.json")
    assert config is not None
    servers = extract_servers(config)
    assert len(servers) == 2
    assert "safe-stdio" in servers
    assert "safe-http" in servers


def test_parse_vulnerable_config():
    config = parse_config(FIXTURES / "vulnerable_config.json")
    servers = extract_servers(config)
    assert len(servers) == 4


def test_scan_safe_config():
    scanner = Scanner()
    results = scanner.scan_all([FIXTURES / "safe_config.json"])
    assert len(results) == 2

    for r in results:
        fail_count = sum(1 for f in r.findings if f.severity == "FAIL")
        warn_count = sum(1 for f in r.findings if f.severity == "WARN")
        # Safe config should have no FAILs
        assert fail_count == 0, (
            f"{r.server_name}: expected 0 FAIL, got {fail_count}. "
            f"Warnings: {warn_count}"
        )


def test_scan_vulnerable_config():
    scanner = Scanner()
    results = scanner.scan_all([FIXTURES / "vulnerable_config.json"])
    assert len(results) == 4

    # Collect all findings
    all_findings = []
    for r in results:
        all_findings.extend(r.findings)

    fail_count = sum(1 for f in all_findings if f.severity == "FAIL")
    warn_count = sum(1 for f in all_findings if f.severity == "WARN")

    # The vulnerable config should have at least 3 FAILs
    # (MCP01 secrets, MCP03 poisoning, MCP07 no-auth-http)
    assert fail_count >= 3, f"Expected >= 3 FAIL, got {fail_count}"
    print(f"FAIL: {fail_count}, WARN: {warn_count}")

    # Check specific findings
    finding_details = [(f.severity, f.check_id, f.server_name) for f in all_findings]

    # MCP01: secrets in insecure-server
    mcp01_fails = [f for f in all_findings if f.check_id == "MCP01" and f.severity == "FAIL"]
    assert len(mcp01_fails) > 0, "Should detect hardcoded API keys"

    # MCP03: poisoning in poisoned-server
    mcp03_fails = [f for f in all_findings if f.check_id == "MCP03" and f.severity in ("FAIL", "WARN")]
    assert len(mcp03_fails) > 0, "Should detect tool poisoning"

    # MCP07: no auth on HTTP transport
    mcp07_fails = [f for f in all_findings if f.check_id == "MCP07" and f.severity == "FAIL"]
    assert len(mcp07_fails) > 0, "Should detect missing auth on HTTP transport"


def test_scanner_all_checks_registered():
    scanner = Scanner()
    assert scanner.check_count == 10  # OWASP MCP Top 10: complete coverage


if __name__ == "__main__":
    test_parse_safe_config()
    test_parse_vulnerable_config()
    test_scan_safe_config()
    test_scan_vulnerable_config()
    test_scanner_all_checks_registered()
    print("All tests PASSED")
