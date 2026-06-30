"""MCP04: Software Supply Chain Attacks & Dependency Tampering."""

import re

from mcp_guard.checks.base import SecurityCheck
from mcp_guard.types import ScanTarget, Finding

NPM_PKG = re.compile(
    r"(?:npx|npm)\s+(?:-y\s+)?(@?[a-z0-9][a-z0-9_.-]*/[a-z0-9][a-z0-9_.-]*|[a-z0-9][a-z0-9_.-]*)\b",
    re.IGNORECASE,
)
PIP_PKG = re.compile(
    r"(?:pip|pipx|uvx|uv)\s+(?:install|run)\s+(-r\s+\S+\s+)?(@?[a-zA-Z0-9][a-zA-Z0-9_.-]*)",
    re.IGNORECASE,
)

SUSPICIOUS_PREFIXES = ["mcp-", "ai-", "agent-", "llm-", "rag-", "chatgpt-", "openai-", "claude-"]


class SupplyChainCheck(SecurityCheck):
    id = "MCP04"
    name = "Supply Chain Attacks & Dependency Tampering"
    owasp = "MCP04: Supply Chain"

    def run(self, target: ScanTarget) -> list[Finding]:
        findings: list[Finding] = []
        raw = self._config_json(target)

        packages = self._extract_packages(target)

        unscoped = [(t, p) for t, p in packages
                    if self._is_unscoped_suspicious(p)]
        for pkg_type, pkg in unscoped:
            pkg_name = pkg.split("@")[0] if "@" in pkg else pkg
            findings.append(self._warn(
                target,
                title=f"Unscoped {pkg_type} package: {pkg_name}",
                detail=f"'{pkg_name}' is not scoped to a known publisher. "
                        "Verify this is the legitimate package, not a typosquatting attempt.",
                fix="Pin to a specific version hash. Check publisher on npm/PyPI.",
                cvss=6.0,
            ))

        if re.search(r"npx\s+-y\b", raw):
            findings.append(self._warn(
                target,
                title="npx -y auto-confirms package installation",
                detail="'npx -y' skips the install confirmation prompt.",
                fix="Remove '-y' and review the package before confirming installation.",
                cvss=6.5,
            ))

        if not findings:
            findings.append(self._pass(target,
                title="No obvious supply chain risks",
                detail=f"Found {len(packages)} package reference(s), none with suspicious patterns."
                       if packages else "No npm/pip package references in config.",
            ))
        return findings

    def _extract_packages(self, target: ScanTarget) -> list[tuple[str, str]]:
        pkgs: list[tuple[str, str]] = []
        texts = [str(target.raw_config.get("command", ""))]
        args = target.raw_config.get("args", [])
        if isinstance(args, list):
            texts.append(" ".join(str(a) for a in args))

        for text in texts:
            for m in NPM_PKG.finditer(text):
                p = m.group(1)
                if p and len(p) > 2:
                    pkgs.append(("npm", p))
            for m in PIP_PKG.finditer(text):
                p = m.group(2)
                if p and len(p) > 2 and not p.startswith("-"):
                    pkgs.append(("pip", p))
        return pkgs

    @staticmethod
    def _is_unscoped_suspicious(pkg: str) -> bool:
        pkg_name = pkg.split("@")[0] if "@" in pkg else pkg
        if "/" in pkg_name:
            return False  # scoped package
        return any(pkg_name.lower().startswith(p) for p in SUSPICIOUS_PREFIXES)
