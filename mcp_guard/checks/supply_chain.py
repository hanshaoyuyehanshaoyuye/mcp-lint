"""MCP04: Software Supply Chain Attacks & Dependency Tampering."""

import re
import subprocess
import sys

from mcp_guard.types import ScanTarget, Finding

NPM_PACKAGE_PATTERN = re.compile(
    r"(?:npx|npm)\s+(?:-y\s+)?(@?[a-z0-9][a-z0-9_.-]*/[a-z0-9][a-z0-9_.-]*|[a-z0-9][a-z0-9_.-]*)\b",
    re.IGNORECASE,
)
PIP_PACKAGE_PATTERN = re.compile(
    r"(?:pip|pipx|uvx|uv)\s+(?:install|run)\s+(-r\s+\S+\s+)?(@?[a-zA-Z0-9][a-zA-Z0-9_.-]*)",
    re.IGNORECASE,
)

# Known typosquatting-adjacent packages
SUSPICIOUS_PREFIXES = [
    "mcp-", "ai-", "agent-", "llm-", "rag-", "chatgpt-", "openai-", "claude-",
]


class SupplyChainCheck:
    id = "MCP04"
    name = "Supply Chain Attacks & Dependency Tampering"
    owasp = "MCP04: Supply Chain"

    def run(self, target: ScanTarget) -> list[Finding]:
        findings: list[Finding] = []

        import json
        raw = json.dumps(target.raw_config)

        # Check 1: extract npm/pip package names from command/args
        packages: list[str] = []

        command = target.raw_config.get("command", "")
        if isinstance(command, str):
            for m in NPM_PACKAGE_PATTERN.finditer(command):
                pkg = m.group(1)
                if pkg and len(pkg) > 2:
                    packages.append(("npm", pkg))
            for m in PIP_PACKAGE_PATTERN.finditer(command):
                pkg = m.group(2)
                if pkg and len(pkg) > 2 and not pkg.startswith("-"):
                    packages.append(("pip", pkg))

        if "args" in target.raw_config:
            args_list = target.raw_config["args"]
            if isinstance(args_list, list):
                args_str = " ".join(str(a) for a in args_list)
                for m in NPM_PACKAGE_PATTERN.finditer(args_str):
                    pkg = m.group(1)
                    if pkg and len(pkg) > 2:
                        packages.append(("npm", pkg))
                for m in PIP_PACKAGE_PATTERN.finditer(args_str):
                    pkg = m.group(2)
                    if pkg and len(pkg) > 2 and not pkg.startswith("-"):
                        packages.append(("pip", pkg))

        # Check 2: warn on unscoped packages with sensitive prefixes
        for pkg_type, pkg in packages[:5]:
            pkg_name = pkg.split("@")[0] if "@" in pkg else pkg
            for prefix in SUSPICIOUS_PREFIXES:
                if pkg_name.lower().startswith(prefix) and "/" not in pkg:
                    findings.append(Finding(
                        check_id="MCP04",
                        owasp=self.owasp,
                        server_name=target.server_name,
                        severity="WARN",
                        title=f"Unscoped {pkg_type} package: {pkg_name}",
                        detail=(
                            f"Package '{pkg_name}' is not scoped to a known publisher. "
                            f"Verify this is the legitimate package and not a typosquatting attempt."
                        ),
                        fix=f"Pin to a specific version hash. Verify publisher on npm/PyPI. "
                             f"Consider using npm's '--ignore-scripts' or uv's lockfile.",
                        cvss=6.0,
                    ))

        # Check 3: try pip-audit if available
        if packages:
            found_unscoped = any(
                any(pkg.lower().startswith(prefix) and "/" not in pkg
                    for prefix in SUSPICIOUS_PREFIXES)
                for _, pkg in packages
            )
            if not found_unscoped:
                findings.append(Finding(
                    check_id="MCP04",
                    owasp=self.owasp,
                    server_name=target.server_name,
                    severity="PASS",
                    title="No obvious supply chain risks in package references",
                    detail=f"Found {len(packages)} package reference(s), none with suspicious patterns.",
                    cvss=0,
                ))
        else:
            findings.append(Finding(
                check_id="MCP04",
                owasp=self.owasp,
                server_name=target.server_name,
                severity="PASS",
                title="No package dependencies detected in config",
                detail="Server uses inline command or binary path — no npm/pip package references found.",
                cvss=0,
            ))

        # Check 4: flag `npx -y` (auto-confirm install without review)
        if re.search(r"npx\s+-y\b", raw):
            findings.append(Finding(
                check_id="MCP04",
                owasp=self.owasp,
                server_name=target.server_name,
                severity="WARN",
                title="npx -y auto-confirms package installation",
                detail="'npx -y' skips the install confirmation prompt, "
                         "which could allow a malicious package to be installed silently.",
                fix="Remove '-y' flag and review the package before confirming installation.",
                cvss=6.5,
            ))

        return findings
