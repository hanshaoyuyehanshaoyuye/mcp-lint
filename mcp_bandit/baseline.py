"""Baseline Engine — snapshot, compare, track drift.

Lockfile format (.mcp-bandit.lock, placed next to mcp.json):
  {
    "version": 1,
    "created": "ISO8601",
    "server_count": 3,
    "findings": {
      "<server_name>": { "MCP01": "PASS", "MCP02": "WARN", ... }
    },
    "config_hash": "sha256(serialized config)",
    "remediated": []   # list of finding IDs that were accepted as known
  }

Workflow:
  1. mcp-bandit scan → report
  2. Review findings, fix issues
  3. mcp-bandit baseline → snapshot current state
  4. Later: mcp-bandit scan → compares against baseline, shows delta
  5. If new FAILs → gate blocks (CI exit 1)
  6. After review: mcp-bandit baseline --update
"""

import hashlib
import json
import os
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional


LOCKFILE_NAME = ".mcp-bandit.lock"


def hash_config(config_path: Path) -> str:
    """SHA-256 of config file content."""
    if not config_path.is_file():
        return ""
    return hashlib.sha256(config_path.read_bytes()).hexdigest()


def hash_findings(results: list) -> str:
    """Deterministic hash of findings array."""
    raw = json.dumps([
        {
            "server": r.server_name,
            "findings": [
                {"id": f.check_id, "severity": f.severity}
                for f in sorted(r.findings, key=lambda x: x.check_id)
            ],
        }
        for r in sorted(results, key=lambda x: x.server_name)
    ], sort_keys=True)
    return hashlib.sha256(raw.encode()).hexdigest()


def load_baseline(config_path: Path) -> Optional[dict]:
    """Load baseline lockfile, if it exists."""
    lock_path = config_path.parent / LOCKFILE_NAME
    if not lock_path.is_file():
        return None
    try:
        return json.loads(lock_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def save_baseline(config_path: Path, results: list, remediated: list[str] | None = None) -> Path:
    """Create or update baseline lockfile."""
    lock_path = config_path.parent / LOCKFILE_NAME

    findings_map: dict[str, dict[str, str]] = {}
    for r in results:
        findings_map[r.server_name] = {
            f.check_id: f.severity for f in r.findings
        }

    baseline = {
        "version": 1,
        "created": datetime.now(timezone.utc).isoformat(),
        "config_hash": hash_config(config_path),
        "findings_hash": hash_findings(results),
        "server_count": len(results),
        "findings": findings_map,
        "remediated": remediated or [],
    }

    lock_path.write_text(json.dumps(baseline, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return lock_path


def compute_delta(results: list, baseline: dict) -> dict:
    """Compare current findings against baseline.

    Returns:
      {
        "new_fails": ["server:check_id", ...],      # PASS/WARN → FAIL
        "fixed": ["server:check_id", ...],           # FAIL/WARN → PASS
        "unchanged": int,                            # count of unchanged
        "drift": bool,                               # True if anything changed
        "config_changed": bool,                      # config was modified
        "baseline_age": "X days ago",
      }
    """
    delta = {"new_fails": [], "fixed": [], "unchanged": 0, "drift": False, "config_changed": False}

    baseline_findings = baseline.get("findings", {})

    for r in results:
        name = r.server_name
        prev = baseline_findings.get(name, {})

        for f in r.findings:
            key = f"{name}:{f.check_id}"
            old_sev = prev.get(f.check_id, "PASS")

            if f.severity == "FAIL" and old_sev != "FAIL":
                delta["new_fails"].append(key)
                delta["drift"] = True
            elif f.severity == "PASS" and old_sev in ("FAIL", "WARN"):
                delta["fixed"].append(key)
                delta["drift"] = True
            else:
                delta["unchanged"] += 1

    # Also check for removed servers
    for prev_name in baseline_findings:
        if not any(r.server_name == prev_name for r in results):
            delta["drift"] = True

    delta["config_changed"] = baseline.get("config_hash") != hash_config(
        next((r.config_path for r in results), Path("."))
    )

    return delta
