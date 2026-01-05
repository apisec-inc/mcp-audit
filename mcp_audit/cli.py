"""
MCP Audit - Discover and audit MCP configurations
"""

import typer
from rich.console import Console
from typing import Optional

from mcp_audit.commands import scan, analyze, trust, policy, registry
from mcp_audit.data.risk_definitions import (
    get_risk_flag_info,
    get_all_flags,
    RISK_LEVELS,
    get_severity_for_flag
)

app = typer.Typer(
    name="mcp-audit",
    help="Discover and audit MCP (Model Context Protocol) configurations across your organization",
    add_completion=False,
)

console = Console()

# Register commands
app.add_typer(scan.app, name="scan")
app.add_typer(analyze.app, name="analyze")
app.add_typer(trust.app, name="trust")
app.add_typer(policy.app, name="policy")
app.add_typer(registry.app, name="registry")


@app.callback()
def main():
    """
    MCP Audit - Security visibility for Model Context Protocol

    Discover what MCPs exist in your environment, assess their risk,
    and validate against security policies.
    """
    pass


@app.command()
def version():
    """Show version information"""
    from mcp_audit import __version__
    console.print(f"mcp-audit version {__version__}")


@app.command()
def explain(
    flag: Optional[str] = typer.Argument(
        None, help="Risk flag to explain (e.g., shell-access, filesystem-access)"
    ),
    list_all: bool = typer.Option(
        False, "--list", "-l", help="List all known risk flags"
    ),
):
    """
    Explain what a risk flag means and how to remediate it.

    Examples:
        mcp-audit explain shell-access
        mcp-audit explain --list
    """
    if list_all:
        console.print("\n[bold]Known Risk Flags[/bold]\n")
        all_flags = get_all_flags()

        # Group by severity
        by_severity = {"critical": [], "high": [], "medium": [], "low": []}
        for f in all_flags:
            sev = get_severity_for_flag(f)
            if sev in by_severity:
                by_severity[sev].append(f)

        for severity in ["critical", "high", "medium", "low"]:
            if by_severity[severity]:
                if severity == "critical":
                    console.print(f"[bold red]{severity.upper()}[/bold red]")
                elif severity == "high":
                    console.print(f"[bold yellow]{severity.upper()}[/bold yellow]")
                elif severity == "medium":
                    console.print(f"[blue]{severity.upper()}[/blue]")
                else:
                    console.print(f"[green]{severity.upper()}[/green]")

                for f in by_severity[severity]:
                    info = get_risk_flag_info(f)
                    console.print(f"  • {f}: {info.get('explanation', '')[:60]}...")
                console.print()
        return

    if not flag:
        console.print("[yellow]Usage: mcp-audit explain <flag>[/yellow]")
        console.print("Example: mcp-audit explain shell-access")
        console.print("\nUse --list to see all known risk flags.")
        return

    info = get_risk_flag_info(flag)
    severity = info.get("severity", "unknown")

    # Header
    console.print(f"\n[bold]Risk Flag: {flag}[/bold]")

    if severity == "critical":
        console.print(f"[bold red]Severity: {severity.upper()}[/bold red]")
    elif severity == "high":
        console.print(f"[bold yellow]Severity: {severity.upper()}[/bold yellow]")
    elif severity == "medium":
        console.print(f"[blue]Severity: {severity.upper()}[/blue]")
    else:
        console.print(f"Severity: {severity.upper()}")

    # Why it matters
    console.print("\n[bold]Why it matters:[/bold]")
    console.print(f"  {info.get('explanation', 'Unknown risk flag.')}")

    # How to fix
    console.print("\n[bold]How to fix:[/bold]")
    detailed_steps = info.get("detailed_steps", [])
    if detailed_steps:
        for i, step in enumerate(detailed_steps, 1):
            console.print(f"  {i}. {step}")
    else:
        console.print(f"  {info.get('remediation', 'Review manually.')}")

    # Related flags
    related = info.get("related", [])
    if related:
        console.print("\n[bold]Related flags:[/bold]")
        console.print(f"  {', '.join(related)}")

    console.print()


if __name__ == "__main__":
    app()
