"""Auto-discover MCP config files across all supported IDEs."""

import os
import sys
from pathlib import Path


def discover_configs() -> list[Path]:
    """Find all MCP configuration files on this machine. Returns sorted list."""
    found: list[Path] = []

    if sys.platform == "win32":
        found += _discover_windows()
    elif sys.platform == "darwin":
        found += _discover_macos()
    else:
        found += _discover_linux()

    # Deduplicate by resolved path
    seen: set[str] = set()
    unique: list[Path] = []
    for p in found:
        try:
            resolved = str(p.resolve())
        except OSError:
            resolved = str(p)
        if resolved not in seen:
            seen.add(resolved)
            unique.append(p)

    return sorted(unique)


def _discover_windows() -> list[Path]:
    paths = []
    appdata = os.environ.get("APPDATA", "")
    userprofile = os.environ.get("USERPROFILE", "")
    localappdata = os.environ.get("LOCALAPPDATA", "")

    candidates = [
        # Claude Desktop / Claude Code
        Path(appdata) / "Claude" / "claude_desktop_config.json",
        Path(userprofile) / ".claude" / "mcp.json",
        Path(userprofile) / ".claude.json",
        # VS Code
        Path(appdata) / "Code" / "User" / "globalStorage",
        # Cursor
        Path(userprofile) / ".cursor" / "mcp.json",
        # Windsurf
        Path(userprofile) / ".windsurf" / "mcp.json",
        # Gemini CLI
        Path(userprofile) / ".gemini" / "mcp.json",
        # Codex CLI
        Path(userprofile) / ".codex" / "mcp.json",
    ]

    for c in candidates:
        if c.is_file():
            paths.append(c)
        elif c.is_dir():
            # Scan subdirectories for mcp*.json
            for child in sorted(c.rglob("mcp*.json")):
                if child.is_file():
                    paths.append(child)
            for child in sorted(c.rglob("claude_desktop_config.json")):
                if child.is_file():
                    paths.append(child)

    return paths


def _discover_macos() -> list[Path]:
    paths = []
    home = Path.home()

    candidates = [
        home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json",
        home / ".claude" / "mcp.json",
        home / ".claude.json",
        home / "Library" / "Application Support" / "Code" / "User" / "globalStorage",
        home / ".cursor" / "mcp.json",
        home / ".windsurf" / "mcp.json",
        home / ".gemini" / "mcp.json",
        home / ".codex" / "mcp.json",
    ]

    for c in candidates:
        if c.is_file():
            paths.append(c)
        elif c.is_dir():
            for child in sorted(c.rglob("mcp*.json")):
                if child.is_file():
                    paths.append(child)

    return paths


def _discover_linux() -> list[Path]:
    paths = []
    home = Path.home()
    config = os.environ.get("XDG_CONFIG_HOME", str(home / ".config"))

    candidates = [
        Path(config) / "Claude" / "claude_desktop_config.json",
        home / ".claude" / "mcp.json",
        home / ".claude.json",
        Path(config) / "Code" / "User" / "globalStorage",
        home / ".cursor" / "mcp.json",
        home / ".windsurf" / "mcp.json",
        home / ".gemini" / "mcp.json",
        home / ".codex" / "mcp.json",
    ]

    for c in candidates:
        if c.is_file():
            paths.append(c)
        elif c.is_dir():
            for child in sorted(c.rglob("mcp*.json")):
                if child.is_file():
                    paths.append(child)

    return paths


def parse_config(path: Path) -> dict | None:
    """Parse an MCP config JSON file. Returns None on failure."""
    import json

    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def extract_servers(config: dict) -> dict[str, dict]:
    """Extract server definitions from an MCP config. Returns {name: server_config}."""
    # Claude Desktop format
    if "mcpServers" in config:
        return config["mcpServers"]

    # VS Code / generic format
    if "servers" in config:
        return config["servers"]

    # Top-level might be server names directly
    servers = {}
    for key, value in config.items():
        if isinstance(value, dict) and ("command" in value or "url" in value or "type" in value):
            servers[key] = value

    return servers
