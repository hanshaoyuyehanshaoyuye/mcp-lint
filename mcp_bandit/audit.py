"""Audit Trail — append-only, tamper-evident JSON Lines log.

Every scan produces one record with:
  - SHA-256(scan output)           ← integrity check
  - prev_record_hash               ← chain linking
  - timestamp, targets, findings summary
  - operator (user / CI / git SHA)
"""

import hashlib
import json
import os
import time
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional


AUDIT_FILE = os.path.expanduser("~/.mcp-bandit-audit.jsonl")


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()[:16]


def write_audit_record(
    targets: list[str],
    servers: int,
    fails: int,
    warns: int,
    passes: int,
    operator: str = "",
    findings_json: str = "",
) -> dict:
    """Append one audit record. Returns the record dict."""
    os.makedirs(os.path.dirname(AUDIT_FILE), exist_ok=True)

    prev_hash = ""
    if os.path.isfile(AUDIT_FILE):
        with open(AUDIT_FILE) as f:
            for line in f:
                line = line.strip()
                if line:
                    prev_hash = _sha256(line)

    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "targets": targets,
        "servers": servers,
        "fails": fails,
        "warns": warns,
        "passes": passes,
        "operator": operator or os.environ.get("USER", os.environ.get("USERNAME", "unknown")),
        "prev_hash": prev_hash,
        "findings_hash": _sha256(findings_json) if findings_json else "",
    }
    record["hash"] = _sha256(json.dumps(record, sort_keys=True))

    with open(AUDIT_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

    return record


def read_audit_log(limit: int = 10) -> list[dict]:
    """Read last N audit records."""
    if not os.path.isfile(AUDIT_FILE):
        return []
    records = []
    with open(AUDIT_FILE, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records[-limit:]


def verify_chain() -> tuple[bool, str]:
    """Verify the hash chain is intact. Returns (valid, message)."""
    records = read_audit_log(0)  # all
    if len(records) < 2:
        return True, "chain too short to verify"

    for i in range(1, len(records)):
        expected = _sha256(json.dumps(records[i - 1], sort_keys=True))
        actual = records[i].get("prev_hash", "")
        if expected != actual:
            return False, (
                f"Chain broken at record {i}: "
                f"expected prev_hash={expected}, got {actual}"
            )
    return True, f"chain intact ({len(records)} records)"
