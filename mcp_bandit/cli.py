"""mcp-bandit CLI — scan / baseline / autofix / verify / audit."""

import sys
from pathlib import Path

import click
from rich.console import Console

from mcp_bandit import __version__
from mcp_bandit.scanner import Scanner
from mcp_bandit.reporter import Reporter

console = Console()


@click.group()
@click.version_option(__version__, prog_name="mcp-bandit")
def main():
    """mcp-bandit — the missing security linter for MCP."""


# ═══════════════════════════════════════════════════════════════════
# scan
# ═══════════════════════════════════════════════════════════════════

@main.command()
@click.option("--target", "-t", help="Path to MCP config or directory. Auto-discovers if omitted.")
@click.option("--format", "-f", "output_format",
              type=click.Choice(["terminal", "json", "sarif"]), default="terminal")
@click.option("--checks", "-c", help="Comma-separated check IDs (default: all).")
@click.option("--rules", "-r", help="Path to custom rules YAML or directory with check YAML files.")
@click.option("--output", "-o", help="Write report to file.")
@click.option("--quiet", "-q", is_flag=True, help="Only show FAIL/WARN, no summary.")
@click.option("--audit", "with_audit", is_flag=True, help="Write tamper-evident audit trail record.")
def scan(target, output_format, checks, output, quiet, with_audit, rules):
    """Scan MCP configs for security risks."""

    targets = _resolve_targets(target)
    if not targets:
        console.print("No MCP config files found.", style="red")
        console.print("[dim]Specify --target or ensure MCP configs exist in standard locations.[/dim]")
        sys.exit(1)

    check_ids = [c.strip() for c in checks.split(",")] if checks else None
    if rules:
        from mcp_bandit.checks.base import SecurityCheck
        SecurityCheck.set_rules_dir(rules)
    scanner = Scanner(check_ids=check_ids)

    if with_audit:
        results, audit_record = scanner.scan_with_audit(targets)
        console.print(f"[dim]Audit record: {audit_record['hash']} (chain: {'OK' if audit_record['prev_hash'] else 'genesis'})[/dim]")
    else:
        results = scanner.scan_all(targets)

    reporter = Reporter(fmt=output_format, quiet=quiet)
    output_text = reporter.render(results, targets)

    if output:
        Path(output).write_text(output_text, encoding="utf-8")
        if not quiet:
            console.print(f"Report saved to {output}", style="green")
    elif output_format == "terminal":
        console.print(output_text, markup=False)
    else:
        print(output_text)

    fail_count = sum(1 for r in results for f in r.findings if f.severity == "FAIL")
    sys.exit(min(fail_count, 255))


# ═══════════════════════════════════════════════════════════════════
# baseline
# ═══════════════════════════════════════════════════════════════════

@main.command()
@click.option("--target", "-t", help="Path to MCP config.")
@click.option("--show", "show_baseline", is_flag=True, help="Show current baseline.")
def baseline(target, show_baseline):
    """Snapshot current findings as baseline. Later scans show drift."""

    targets = _resolve_targets(target)
    if not targets:
        console.print("No targets found. Use --target to specify a config file.", style="red")
        sys.exit(1)

    scanner = Scanner()
    config_path = targets[0]

    if show_baseline:
        from mcp_bandit.baseline import load_baseline
        bl = load_baseline(config_path)
        if not bl:
            console.print("No baseline found. Run 'mcp-bandit baseline' first.", style="yellow")
            sys.exit(1)
        import json
        console.print(json.dumps(bl, indent=2, ensure_ascii=False))
        return

    result = scanner.baseline(targets)
    console.print(f"[green]Baseline saved: {result['lock_path']}[/green]")
    console.print(f"  Servers: {result['servers']}")
    console.print(f"  Run 'mcp-bandit verify' to check for drift.")


# ═══════════════════════════════════════════════════════════════════
# verify
# ═══════════════════════════════════════════════════════════════════

@main.command()
@click.option("--target", "-t", help="Path to MCP config.")
@click.option("--gate", is_flag=True, help="Exit 1 if new FAILs found (CI mode).")
def verify(target, gate):
    """Scan + compare against baseline. Show what changed."""

    targets = _resolve_targets(target)
    if not targets:
        console.print("No targets found.", style="red")
        sys.exit(1)

    scanner = Scanner()
    report = scanner.verify(targets)
    delta = report.get("delta", {})

    if delta.get("message"):
        console.print(f"[yellow]{delta['message']}[/yellow]")
        sys.exit(0)

    console.print(f"Baseline age: {report.get('baseline_age', '?')}")
    console.print(f"Drift detected: {'YES' if delta.get('drift') else 'NO'}")

    if delta.get("new_fails"):
        console.print(f"\n[red]NEW FAILS ({len(delta['new_fails'])}):[/red]")
        for item in delta["new_fails"]:
            console.print(f"  ✗ {item}")

    if delta.get("fixed"):
        console.print(f"\n[green]FIXED ({len(delta['fixed'])}):[/green]")
        for item in delta["fixed"]:
            console.print(f"  ✓ {item}")

    if not delta.get("new_fails") and not delta.get("fixed"):
        console.print("\n[green]No changes since baseline.[/green]")

    if gate and delta.get("new_fails"):
        console.print("\n[red]Gate: BLOCKED — new FAIL findings introduced.[/red]")
        sys.exit(1)
    elif gate:
        console.print("\n[green]Gate: PASSED.[/green]")


# ═══════════════════════════════════════════════════════════════════
# autofix
# ═══════════════════════════════════════════════════════════════════

@main.command()
@click.option("--target", "-t", help="Path to MCP config.")
@click.option("--apply", is_flag=True, help="Apply high-confidence fixes (default: preview only).")
def autofix(target, apply):
    """Suggest (or apply) automatic fixes for detected issues."""

    targets = _resolve_targets(target)
    if not targets:
        console.print("No targets found.", style="red")
        sys.exit(1)

    scanner = Scanner()
    result = scanner.autofix(targets, apply=apply)

    console.print(f"Suggestions: {result['suggestions']} total")
    console.print(f"Auto-applicable (confidence >= 0.9): {result['auto_applicable']}")
    console.print(f"Applied: {'YES' if result['applied'] else 'NO (preview mode)'}")

    if result["details"]:
        console.print()
        for d in result["details"]:
            tag = "[AUTO]" if d["confidence"] >= 0.9 else "[MANUAL]"
            console.print(f"  {tag} {d['fix_id']}")
            console.print(f"       → {d['finding']}")


# ═══════════════════════════════════════════════════════════════════
# audit
# ═══════════════════════════════════════════════════════════════════

@main.command()
@click.option("--verify", "verify_chain", is_flag=True, help="Verify hash chain integrity.")
@click.option("--limit", "-n", default=10, help="Number of records to show.")
def audit(verify_chain, limit):
    """Show audit trail or verify chain integrity."""

    from mcp_bandit.audit import read_audit_log, verify_chain as _verify

    if verify_chain:
        valid, msg = _verify()
        if valid:
            console.print(f"[green]Audit chain: {msg}[/green]")
        else:
            console.print(f"[red]Audit chain: {msg}[/red]")
            sys.exit(1)
        return

    records = read_audit_log(limit)
    if not records:
        console.print("No audit records found. Run 'mcp-bandit scan --audit' first.", style="yellow")
        return

    for r in records:
        icon = "✗" if r["fails"] > 0 else "✓"
        console.print(
            f"  {icon} {r['timestamp'][:19]}  "
            f"fail={r['fails']} warn={r['warns']} pass={r['passes']}  "
            f"hash={r['hash']}  op={r.get('operator', '?')}"
        )


# ═══════════════════════════════════════════════════════════════════
# list-checks
# ═══════════════════════════════════════════════════════════════════

@main.command()
def list_checks():
    """List all available security checks."""
    scanner = Scanner()
    for check in scanner.checks:
        print(f"  {check.id:6s}  {check.name:45s}  [{check.owasp}]")


# ═══════════════════════════════════════════════════════════════════
# helpers
# ═══════════════════════════════════════════════════════════════════

def _resolve_targets(target: str | None) -> list[Path]:
    if target:
        p = Path(target)
        if p.is_file():
            return [p]
        if p.is_dir():
            return sorted(p.glob("**/mcp*.json")) + sorted(p.glob("**/claude_desktop_config.json"))
        console.print(f"[red]Error: {target} not found.[/red]", style="red")
        console.print("[dim]Specify a valid file or directory path with --target, or omit to auto-discover.[/dim]")
        sys.exit(1)

    from mcp_bandit.discovery import discover_configs
    return discover_configs()
