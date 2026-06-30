"""Auto-fix Engine — deterministic fix templates for common issues.

Each fix is a template with:
  - match condition (which finding triggers it)
  - fix_action (what to do — replace / remove / add)
  - estimated_confidence (0.0–1.0)

Only high-confidence (≥0.9) fixes are auto-applied.
Lower-confidence fixes are suggested but require manual review.
"""

import re
from pathlib import Path
from typing import Optional


FIX_TEMPLATES = [
    {
        "id": "fix-secret-to-env-var",
        "match": {"check_id": "MCP01", "title_contains": "Sensitive env var"},
        "action": "template",
        "template": """# Replace hardcoded value with shell environment variable reference:
# Before: "ENV_VAR": "secret_value"
# After:  "ENV_VAR": "$ENV_VAR"   (set ENV_VAR in your shell profile)
""",
        "confidence": 0.7,
    },
    {
        "id": "fix-shell-true",
        "match": {"check_id": "MCP05", "title_contains": "subprocess(shell=True)"},
        "action": "template",
        "template": """# Replace shell=True with shell=False + args list:
# Before: subprocess.run(f"cmd {input}", shell=True)
# After:  subprocess.run(["cmd", input], shell=False)
""",
        "confidence": 0.6,
    },
    {
        "id": "fix-eval-exec",
        "match": {"check_id": "MCP05", "title_contains": "eval()"},
        "action": "template",
        "template": """# eval() is almost never safe. Replace with:
# - ast.literal_eval() for Python literals
# - json.loads() for JSON data
# - A custom parser for domain-specific input
""",
        "confidence": 0.8,
    },
    {
        "id": "fix-bind-localhost",
        "match": {"check_id": "MCP02", "title_contains": "binds to unrestricted"},
        "action": "template",
        "template": """# Replace 0.0.0.0 with 127.0.0.1 in the server URL:
# Before: "url": "http://0.0.0.0:9000/mcp"
# After:  "url": "http://127.0.0.1:9000/mcp"
""",
        "confidence": 0.9,
    },
    {
        "id": "fix-npx-no-y",
        "match": {"check_id": "MCP04", "title_contains": "npx -y"},
        "action": "template",
        "template": """# Remove -y flag from npx command:
# Before: ["npx", "-y", "@scope/pkg"]
# After:  ["npx", "@scope/pkg"]
""",
        "confidence": 0.9,
    },
    {
        "id": "fix-missing-auth-header",
        "match": {"check_id": "MCP07", "title_contains": "without authentication"},
        "action": "template",
        "template": """# Add an Authorization header to the server config:
# In your mcp.json, add:
#   "headers": {
#     "Authorization": "Bearer ${MCP_TOKEN}"
#   }
# Then set MCP_TOKEN in your environment.
""",
        "confidence": 0.8,
    },
    {
        "id": "fix-secret-in-args",
        "match": {"check_id": "MCP01", "title_contains": "command-line argument"},
        "action": "template",
        "template": """# Move secret from CLI args to environment variable:
# Before: ["--token", "ghp_xxxx"]
# After:  use env field instead: "env": {"GITHUB_TOKEN": "$GITHUB_TOKEN"}
""",
        "confidence": 0.9,
    },
]


def suggest_fixes(findings: list) -> list[dict]:
    """Match findings against fix templates. Returns list of {finding, fix_template}."""
    suggestions = []
    for f in findings:
        if f.severity == "PASS":
            continue
        for template in FIX_TEMPLATES:
            match = template["match"]
            if f.check_id == match["check_id"]:
                if "title_contains" in match:
                    if match["title_contains"].lower() in f.title.lower():
                        suggestions.append({
                            "finding": f,
                            "fix_id": template["id"],
                            "confidence": template["confidence"],
                            "description": template["template"],
                            "auto_applicable": template["confidence"] >= 0.9,
                        })
    return suggestions


def apply_autofix(config_path: Path, suggestions: list[dict]) -> Optional[str]:
    """Apply auto-fixable suggestions (confidence >= 0.9). Returns modified config as string."""
    auto_fixes = [s for s in suggestions if s["auto_applicable"]]
    if not auto_fixes:
        return None

    content = config_path.read_text(encoding="utf-8")

    for s in auto_fixes:
        fix_id = s["fix_id"]
        if fix_id == "fix-bind-localhost":
            content = content.replace("0.0.0.0", "127.0.0.1")
        elif fix_id == "fix-npx-no-y":
            content = content.replace('"-y", ', "").replace(', "-y"', "").replace('"-y"', "")
        elif fix_id == "fix-secret-in-args":
            # Complex: needs user to create env section. Template-only.
            pass

    return content
