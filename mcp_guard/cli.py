"""MCP Guard CLI — entry point."""

import sys
from pathlib import Path

import click
from rich.console import Console

from mcp_guard import __version__
from mcp_guard.scanner import Scanner
from mcp_guard.reporter import Reporter

console = Console()


@click.group()
@click.version_option(__version__, prog_name="mcp-guard")
def main():
    """mcp-lint — the missing security linter for MCP. Scan your mcp.json for 7 OWASP Top 10 risks."""


@main.command()
@click.option(
    "--target", "-t",
    help="Path to MCP config file or directory. Auto-discovers if omitted.",
)
@click.option(
    "--format", "-f", "output_format",
    type=click.Choice(["terminal", "json", "sarif"]),
    default="terminal",
    help="Output format (default: terminal).",
)
@click.option("--json", "output_format", flag_value="json", help="Shortcut for --format json.")
@click.option("--sarif", "output_format", flag_value="sarif", help="Shortcut for --format sarif.")
@click.option(
    "--checks", "-c",
    help="Comma-separated check IDs to run (default: all).",
)
@click.option(
    "--output", "-o",
    help="Write report to file instead of stdout.",
)
@click.option(
    "--quiet", "-q", is_flag=True,
    help="Only print findings, no summary.",
)
def scan(target, output_format, checks, output, quiet):
    """Scan MCP server configurations for security risks."""

    targets = _resolve_targets(target)

    if not targets:
        console.print("[red]No MCP config files found.[/red]")
        console.print(
            "[dim]Specify --target or ensure MCP configs exist in standard locations.[/dim]"
        )
        sys.exit(1)

    check_ids = None
    if checks:
        check_ids = [c.strip() for c in checks.split(",")]

    scanner = Scanner(check_ids=check_ids)
    results = scanner.scan_all(targets)

    reporter = Reporter(fmt=output_format, quiet=quiet)
    output_text = reporter.render(results, targets)

    if output:
        Path(output).write_text(output_text, encoding="utf-8")
        if not quiet:
            console.print(f"Report saved to {output}", style="green")
    else:
        if output_format == "terminal":
            console.print(output_text, markup=False)
        else:
            console.print(output_text)

    # Exit code = number of FAIL findings
    fail_count = sum(
        1 for r in results for f in r.findings if f.severity == "FAIL"
    )
    sys.exit(min(fail_count, 255))


@main.command()
def list_checks():
    """List all available security checks."""
    from mcp_guard.scanner import Scanner

    scanner = Scanner()
    for check in scanner.checks:
        print(f"  {check.id:12s} {check.name:40s} [{check.owasp}]")


def _resolve_targets(target: str | None) -> list[Path]:
    if target:
        p = Path(target)
        if p.is_file():
            return [p]
        if p.is_dir():
            return sorted(p.glob("**/mcp*.json")) + sorted(p.glob("**/claude_desktop_config.json"))
        console.print(f"[yellow]Warning: {target} not found, falling back to auto-discovery[/yellow]")

    from mcp_guard.discovery import discover_configs
    return discover_configs()
