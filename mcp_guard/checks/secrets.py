"""MCP01: Token Mismanagement & Secret Exposure."""

import re

from mcp_guard.checks.base import SecurityCheck
from mcp_guard.types import ScanTarget, Finding

SECRET_PATTERNS: list[tuple[str, str, float]] = [
    (r"sk-[a-zA-Z0-9]{20,}", "OpenAI API Key", 8.5),
    (r"sk-ant-[a-zA-Z0-9_-]{20,}", "Anthropic API Key", 8.5),
    (r"AIza[0-9A-Za-z_-]{35}", "Google API Key", 8.0),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID", 9.0),
    (r"ghp_[0-9a-zA-Z]{36}", "GitHub Personal Access Token", 9.5),
    (r"github_pat_[0-9a-zA-Z_]{36,}", "GitHub Fine-grained PAT", 9.5),
    (r"gho_[0-9a-zA-Z]{36}", "GitHub OAuth Token", 9.5),
    (r"glpat-[0-9a-zA-Z_-]{20,}", "GitLab PAT", 8.5),
    (r"hf_[a-zA-Z0-9]{34}", "HuggingFace API Token", 8.0),
    (r"sk_live_[0-9a-zA-Z]{24,}", "Stripe Live Key", 9.5),
    (r"xapp-[0-9a-zA-Z_-]{40,}", "Slack App Token", 7.5),
    (r"-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----", "Private Key", 9.8),
    (r"[a-zA-Z0-9+/=]{40,}", "Base64-encoded secret (heuristic)", 5.0),
]

SENSITIVE_KEYS = {
    "api_key", "apikey", "api_secret", "secret", "token", "password",
    "passwd", "auth", "credential", "private_key", "privatekey",
    "access_key", "secret_key", "bearer_token", "client_secret",
    "apiKey", "apiSecret", "API_KEY", "TOKEN", "PASSWORD", "SECRET",
}


class SecretsCheck(SecurityCheck):
    id = "MCP01"
    name = "Token Mismanagement & Secret Exposure"
    owasp = "MCP01: Token Mismanagement"

    def run(self, target: ScanTarget) -> list[Finding]:
        findings: list[Finding] = []
        raw = self._config_json(target)
        args_str = self._args_str(target)

        for pattern, label, cvss in SECRET_PATTERNS:
            for match in re.findall(pattern, raw)[:3]:
                findings.append(self._fail(
                    target,
                    title=f"Hardcoded {label} detected",
                    detail=f"Found: {_redact(match)}",
                    fix=f"Remove hardcoded {label} from config. Use environment variable or secret manager.",
                    cvss=cvss,
                ))

        if args_str and "args" in target.raw_config:
            for pattern, label, cvss in SECRET_PATTERNS[:6]:
                if re.search(pattern, args_str):
                    findings.append(self._fail(
                        target,
                        title="Secret passed as command-line argument",
                        detail=f"A {label} appears in server startup arguments. "
                                "Command-line args are visible in process listings (ps aux).",
                        fix="Pass secrets via environment variables or a mounted secret file, not CLI args.",
                        cvss=8.0,
                    ))
                    break

        if "env" in target.raw_config and isinstance(target.raw_config["env"], dict):
            for key, value in target.raw_config["env"].items():
                if any(sk.lower() in key.lower() for sk in SENSITIVE_KEYS):
                    if isinstance(value, str) and len(value) >= 8:
                        findings.append(self._warn(
                            target,
                            title=f"Sensitive env var '{key}' could be a secret",
                            detail=f"'{key}' contains a value that looks like a secret.",
                            fix=f"Move '{key}' to a secret manager (1Password CLI, Vault, macOS Keychain).",
                            cvss=6.5,
                        ))

        if not findings:
            findings.append(self._pass(target,
                title="No hardcoded secrets detected",
                detail="No API keys, tokens, or private keys found in config.",
            ))
        return findings

    @staticmethod
    def _args_str(target: ScanTarget) -> str:
        args = target.raw_config.get("args", [])
        return " ".join(str(a) for a in args) if isinstance(args, list) else ""


def _redact(secret: str) -> str:
    if len(secret) <= 8:
        return "***"
    return secret[:4] + "***" + secret[-4:]
