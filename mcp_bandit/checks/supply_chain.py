"""MCP04: Software Supply Chain Attacks & Dependency Tampering."""

import re

from mcp_bandit.checks.base import SecurityCheck
from mcp_bandit.types import ScanTarget, Finding


class SupplyChainCheck(SecurityCheck):
    id = "MCP04"
    name = "Supply Chain Attacks & Dependency Tampering"
    owasp = "MCP04: Supply Chain"
    rule_file = "supply_chain.yaml"

    def run(self, target: ScanTarget) -> list[Finding]:
        findings: list[Finding] = []
        rules = self._load_rules()
        raw = self._config_json(target)
        npm_re = re.compile(rules.get("npm_package_pattern", r"x^"), re.IGNORECASE)
        pip_re = re.compile(rules.get("pip_package_pattern", r"x^"), re.IGNORECASE)
        prefixes = rules.get("suspicious_prefixes", [])

        packages = []
        for text in [str(target.raw_config.get("command", "")), self._args_str(target)]:
            for m in npm_re.finditer(text):
                p = m.group(1)
                if p and len(p) > 2: packages.append(("npm", p))
            for m in pip_re.finditer(text):
                p = m.group(2)
                if p and len(p) > 2 and not p.startswith("-"): packages.append(("pip", p))

        for pkg_type, pkg in packages:
            pkg_name = pkg.split("@")[0] if "@" in pkg else pkg
            if "/" in pkg_name: continue
            if any(pkg_name.lower().startswith(p) for p in prefixes):
                findings.append(self._warn(target,
                    title=f"Unscoped {pkg_type} package: {pkg_name}",
                    detail=f"'{pkg_name}' is not scoped. Verify it's the legitimate package.",
                    fix="Pin to version hash. Check publisher on npm/PyPI.",
                    cvss=6.0,
                ))

        if re.search(r"npx\s+-y\b", raw):
            findings.append(self._warn(target,
                title="npx -y auto-confirms package installation",
                detail="'npx -y' skips install confirmation.",
                fix="Remove '-y' and review package before confirming.",
                cvss=6.5,
            ))

        if not findings:
            findings.append(self._pass(target,
                title="No obvious supply chain risks",
                detail=f"Found {len(packages)} package ref(s), none suspicious." if packages
                       else "No npm/pip package references in config.",
            ))
        return findings
