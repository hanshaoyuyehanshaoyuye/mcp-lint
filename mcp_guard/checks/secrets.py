"""MCP01: Token Mismanagement & Secret Exposure."""

import re
from pathlib import Path

from mcp_guard.types import ScanTarget, Finding

# Patterns adapted from truffleHog + Gitleaks common detectors
SECRET_PATTERNS: list[tuple[str, str, float]] = [
    # (regex, label, cvss)
    (r"sk-[a-zA-Z0-9]{20,}", "OpenAI API Key", 8.5),
    (r"sk-ant-[a-zA-Z0-9_-]{20,}", "Anthropic API Key", 8.5),
    (r"AIza[0-9A-Za-z_-]{35}", "Google API Key", 8.0),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID", 9.0),
    (r"ghp_[0-9a-zA-Z]{36}", "GitHub Personal Access Token", 9.5),
    (r"github_pat_[0-9a-zA-Z_]{36,}", "GitHub Fine-grained PAT", 9.5),
    (r"gho_[0-9a-zA-Z]{36}", "GitHub OAuth Token", 9.5),
    (r"ghu_[0-9a-zA-Z]{36}", "GitHub User-to-Server Token", 9.5),
    (r"glpat-[0-9a-zA-Z_-]{20,}", "GitLab Personal Access Token", 8.5),
    (r"hf_[a-zA-Z0-9]{34}", "HuggingFace API Token", 8.0),
    (r"sk_live_[0-9a-zA-Z]{24,}", "Stripe Live Secret Key", 9.5),
    (r"xapp-[0-9a-zA-Z_-]{40,}", "Slack App Token", 7.5),
    (r"-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----", "Private Key", 9.8),
    (r"[a-zA-Z0-9+/=]{40,}", "Base64-encoded secret (heuristic)", 5.0),
]

# Config keys that suggest secrets
SENSITIVE_KEYS: list[str] = [
    "api_key", "apikey", "api_secret", "secret", "token", "password",
    "passwd", "auth", "credential", "private_key", "privatekey",
    "access_key", "secret_key", "bearer_token", "client_secret",
    "apiKey", "apiSecret", "API_KEY", "TOKEN", "PASSWORD", "SECRET",
]


class SecretsCheck:
    id = "MCP01"
    name = "Token Mismanagement & Secret Exposure"
    owasp = "MCP01: Token Mismanagement"

    def run(self, target: ScanTarget) -> list[Finding]:
        findings: list[Finding] = []

        # Serialize config to string for regex scan
        import json
        raw = json.dumps(target.raw_config, indent=2)

        # Check 1: regex patterns
        for pattern, label, cvss in SECRET_PATTERNS:
            matches = re.findall(pattern, raw)
            for match in matches[:3]:  # Limit to avoid flooding
                findings.append(Finding(
                    check_id="MCP01",
                    owasp=self.owasp,
                    server_name=target.server_name,
                    severity="FAIL",
                    title=f"Hardcoded {label} detected",
                    detail=f"Found: {_redact(match)}",
                    fix=f"Remove hardcoded {label} from config. Use environment variable or secret manager.",
                    cvss=cvss,
                ))

        # Check 2: sensitive env var names with short values (likely secrets)
        if "env" in target.raw_config:
            env_vars = target.raw_config["env"]
            if isinstance(env_vars, dict):
                for key, value in env_vars.items():
                    if any(sk.lower() in key.lower() for sk in SENSITIVE_KEYS):
                        if isinstance(value, str) and len(value) >= 8:
                            findings.append(Finding(
                                check_id="MCP01",
                                owasp=self.owasp,
                                server_name=target.server_name,
                                severity="WARN",
                                title=f"Sensitive env var '{key}' could be a secret",
                                detail=f"Environment variable '{key}' contains a value that looks like a secret. "
                                         f"Consider using a secret manager instead.",
                                fix=f"Move '{key}' to a secret manager (e.g., 1Password CLI, Vault, macOS Keychain).",
                                cvss=6.5,
                            ))

        # Check 3: args with inline tokens
        if "args" in target.raw_config:
            args_list = target.raw_config["args"]
            if isinstance(args_list, list):
                args_str = " ".join(str(a) for a in args_list)
                for pattern, label, cvss in SECRET_PATTERNS[:6]:  # Only high-certainty patterns
                    if re.search(pattern, args_str):
                        findings.append(Finding(
                            check_id="MCP01",
                            owasp=self.owasp,
                            server_name=target.server_name,
                            severity="FAIL",
                            title=f"Secret passed as command-line argument",
                            detail=f"A {label} appears in server startup arguments. "
                                     f"Command-line args are visible in process listings (ps aux).",
                            fix="Pass secrets via environment variables or a mounted secret file, not CLI args.",
                            cvss=8.0,
                        ))
                        break

        if not findings:
            findings.append(Finding(
                check_id="MCP01",
                owasp=self.owasp,
                server_name=target.server_name,
                severity="PASS",
                title="No hardcoded secrets detected",
                detail="No API keys, tokens, or private keys found in config.",
                cvss=0,
            ))

        return findings


def _redact(secret: str) -> str:
    if len(secret) <= 8:
        return "***"
    return secret[:4] + "***" + secret[-4:]
