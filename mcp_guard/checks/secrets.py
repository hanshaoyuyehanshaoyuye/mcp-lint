"""MCP01: Token Mismanagement & Secret Exposure."""

import re

from mcp_guard.checks.base import SecurityCheck
from mcp_guard.types import ScanTarget, Finding


class SecretsCheck(SecurityCheck):
    id = "MCP01"
    name = "Token Mismanagement & Secret Exposure"
    owasp = "MCP01: Token Mismanagement"
    rule_file = "secrets.yaml"

    def run(self, target: ScanTarget) -> list[Finding]:
        findings: list[Finding] = []
        rules = self._load_rules()
        patterns = rules.get("patterns", [])
        sensitive_keys = set(rules.get("sensitive_keys", []))
        raw = self._config_json(target)
        args_str = self._args_str(target)

        for entry in patterns:
            regex = entry["regex"]
            label = entry["label"]
            cvss = float(entry["cvss"])
            for match in re.findall(regex, raw)[:3]:
                findings.append(self._fail(target,
                    title=f"Hardcoded {label} detected",
                    detail=f"Found: {_redact(match)}",
                    fix=f"Remove hardcoded {label}. Use environment variable or secret manager.",
                    cvss=cvss,
                ))

        if args_str and target.raw_config.get("args"):
            for entry in patterns[:6]:
                if re.search(entry["regex"], args_str):
                    findings.append(self._fail(target,
                        title="Secret passed as command-line argument",
                        detail=f"A {entry['label']} appears in server startup args (visible in ps aux).",
                        fix="Pass secrets via env vars or mounted secret file, not CLI args.",
                        cvss=8.0,
                    ))
                    break

        env = target.raw_config.get("env", {})
        if isinstance(env, dict):
            for key, value in env.items():
                if any(sk.lower() in key.lower() for sk in sensitive_keys):
                    if isinstance(value, str) and len(value) >= 8:
                        findings.append(self._warn(target,
                            title=f"Sensitive env var '{key}' could be a secret",
                            detail=f"'{key}' contains a value that looks like a secret.",
                            fix=f"Move '{key}' to a secret manager.",
                            cvss=6.5,
                        ))

        if not findings:
            findings.append(self._pass(target,
                title="No hardcoded secrets detected",
                detail="No API keys, tokens, or private keys found in config.",
            ))
        return findings


def _redact(secret: str) -> str:
    if len(secret) <= 8:
        return "***"
    return secret[:4] + "***" + secret[-4:]
