"""
Scan command - Discover MCPs on local machine
"""

import typer
from rich.console import Console
from rich.table import Table
from pathlib import Path
from typing import Optional
import json

from mcp_audit.scanners import claude, cursor, vscode, project, windsurf, zed, docker
from mcp_audit.outputs import formatter
from mcp_audit.models import ScanResult
from mcp_audit.data.risk_definitions import RISK_FLAGS, get_severity_for_flag, get_risk_flag_info

app = typer.Typer(help="Scan for MCP configurations")
console = Console()


@app.callback(invoke_without_command=True)
def scan_local(
    ctx: typer.Context,
    local: bool = typer.Option(
        True, "--local", "-l", help="Scan local machine for MCP configs"
    ),
    path: Optional[Path] = typer.Option(
        None, "--path", "-p", help="Scan a specific directory for project-level MCP configs"
    ),
    format: str = typer.Option(
        "table", "--format", "-f", help="Output format: table, json, markdown, csv"
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Write output to file"
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Show detailed output"
    ),
    with_trust: bool = typer.Option(
        False, "--with-trust", "-t", help="Include trust score check for each MCP"
    ),
    with_registry: bool = typer.Option(
        True, "--registry/--no-registry", help="Match MCPs against known registry (default: on)"
    ),
    remediation: bool = typer.Option(
        False, "--remediation", "-r", help="Show detailed findings and remediation guidance"
    ),
):
    """
    Scan for MCP configurations on local machine or in a directory.
    
    Examples:
        mcp-audit scan --local
        mcp-audit scan --path ./my-project
        mcp-audit scan --format json --output inventory.json
    """
    if ctx.invoked_subcommand is not None:
        return

    results: list[ScanResult] = []
    
    console.print("\n[bold blue]MCP Audit - Local Scan[/bold blue]\n")
    
    # Scan for desktop app configurations
    with console.status("[bold green]Scanning for MCP configurations..."):
        
        # Claude Desktop
        claude_results = claude.scan()
        if claude_results:
            results.extend(claude_results)
            if verbose:
                console.print(f"  [green]✓[/green] Claude Desktop: {len(claude_results)} MCP(s) found")
        elif verbose:
            console.print("  [dim]- Claude Desktop: No config found[/dim]")
        
        # Cursor
        cursor_results = cursor.scan()
        if cursor_results:
            results.extend(cursor_results)
            if verbose:
                console.print(f"  [green]✓[/green] Cursor: {len(cursor_results)} MCP(s) found")
        elif verbose:
            console.print("  [dim]- Cursor: No config found[/dim]")
        
        # VS Code / Continue
        vscode_results = vscode.scan()
        if vscode_results:
            results.extend(vscode_results)
            if verbose:
                console.print(f"  [green]✓[/green] VS Code/Continue: {len(vscode_results)} MCP(s) found")
        elif verbose:
            console.print("  [dim]- VS Code/Continue: No config found[/dim]")

        # Windsurf
        windsurf_results = windsurf.scan()
        if windsurf_results:
            results.extend(windsurf_results)
            if verbose:
                console.print(f"  [green]✓[/green] Windsurf: {len(windsurf_results)} MCP(s) found")
        elif verbose:
            console.print("  [dim]- Windsurf: No config found[/dim]")

        # Zed Editor
        zed_results = zed.scan()
        if zed_results:
            results.extend(zed_results)
            if verbose:
                console.print(f"  [green]✓[/green] Zed: {len(zed_results)} MCP(s) found")
        elif verbose:
            console.print("  [dim]- Zed: No config found[/dim]")

        # Project-level configs
        if path:
            project_results = project.scan(path)
            if project_results:
                results.extend(project_results)
                if verbose:
                    console.print(f"  [green]✓[/green] Project configs: {len(project_results)} MCP(s) found")

            # Docker/Kubernetes configs
            docker_results = docker.scan(path)
            if docker_results:
                results.extend(docker_results)
                if verbose:
                    console.print(f"  [green]✓[/green] Docker/K8s: {len(docker_results)} MCP(s) found")

    # Enrich with registry data if requested
    if with_registry:
        for r in results:
            r.enrich_from_registry()

    # Output results
    if not results:
        console.print("\n[yellow]No MCP configurations found.[/yellow]")
        console.print("\nChecked locations:")
        console.print("  • Claude Desktop config")
        console.print("  • Cursor config")
        console.print("  • VS Code/Continue config")
        console.print("  • Windsurf config")
        console.print("  • Zed config")
        if path:
            console.print(f"  • Project directory: {path}")
            console.print(f"  • Docker/Kubernetes configs in: {path}")
        return

    # Check trust if requested
    trust_results = {}
    if with_trust:
        from mcp_audit.commands.trust import check_source_trust
        console.print("\n[bold]Checking trust scores...[/bold]")
        for r in results:
            trust_info = check_source_trust(r.source)
            trust_results[r.name] = trust_info

    # Format and display
    formatted = formatter.format_results(results, format)

    if output:
        output.write_text(formatted)
        console.print(f"\n[green]Results written to {output}[/green]")
    else:
        if format == "table":
            _print_table(results, trust_results if with_trust else None, with_registry)
        else:
            console.print(formatted)

    # Summary
    _print_summary(results, trust_results if with_trust else None, with_registry)

    # Remediation guidance
    if remediation:
        _print_remediation(results)
    else:
        # Hint about remediation flag if there are risk flags
        with_risks = [r for r in results if r.risk_flags]
        if with_risks:
            console.print("\n[dim]Run `mcp-audit scan --remediation` for detailed findings and fix guidance.[/dim]")


def _print_table(results: list[ScanResult], trust_results: dict = None, with_registry: bool = False):
    """Print results as a rich table"""
    table = Table(title="MCP Inventory", show_header=True, header_style="bold cyan")

    table.add_column("MCP Name", style="white")
    table.add_column("Source", style="dim")
    table.add_column("Found In", style="blue")
    table.add_column("Type", style="magenta")

    if with_registry:
        table.add_column("Known", style="green")
        table.add_column("Provider", style="cyan")
        table.add_column("Reg Risk", style="yellow")

    table.add_column("Risk Flags", style="yellow")

    if trust_results:
        table.add_column("Trust", style="bold")

    for r in results:
        risk_flags = ", ".join(r.risk_flags) if r.risk_flags else "-"
        row = [
            r.name,
            _truncate(r.source, 40),
            r.found_in,
            r.server_type,
        ]

        if with_registry:
            known = "[green]Yes[/green]" if r.is_known else "[red]No[/red]"
            provider = r.provider or "-"
            reg_risk = r.registry_risk or "-"
            if reg_risk == "critical":
                reg_risk = "[red]CRITICAL[/red]"
            elif reg_risk == "high":
                reg_risk = "[yellow]HIGH[/yellow]"
            elif reg_risk == "medium":
                reg_risk = "[blue]MEDIUM[/blue]"
            elif reg_risk == "low":
                reg_risk = "[green]LOW[/green]"
            row.extend([known, provider, reg_risk])

        row.append(risk_flags)

        if trust_results:
            trust_info = trust_results.get(r.name, {})
            score = trust_info.get("score", "UNKNOWN")
            if score == "HIGH":
                row.append(f"[green]{score}[/green]")
            elif score == "MEDIUM":
                row.append(f"[yellow]{score}[/yellow]")
            else:
                row.append(f"[red]{score}[/red]")

        table.add_row(*row)

    console.print(table)


def _print_summary(results: list[ScanResult], trust_results: dict = None, with_registry: bool = False):
    """Print summary statistics"""
    console.print("\n[bold]Summary[/bold]")
    console.print(f"  Total MCPs found: {len(results)}")

    # Count by source app
    by_app = {}
    for r in results:
        by_app[r.found_in] = by_app.get(r.found_in, 0) + 1

    for app, count in by_app.items():
        console.print(f"  • {app}: {count}")

    # Registry summary
    if with_registry:
        console.print("\n[bold]Registry Match Summary[/bold]")
        known = [r for r in results if r.is_known]
        unknown = [r for r in results if not r.is_known]
        console.print(f"  [green]Known MCPs[/green]: {len(known)}")
        console.print(f"  [red]Unknown MCPs[/red]: {len(unknown)}")

        if known:
            # Count by registry risk level
            by_risk = {}
            for r in known:
                risk = r.registry_risk or "unknown"
                by_risk[risk] = by_risk.get(risk, 0) + 1

            console.print("\n  By Registry Risk Level:")
            for risk_level in ["critical", "high", "medium", "low"]:
                if risk_level in by_risk:
                    color = {"critical": "red", "high": "yellow", "medium": "blue", "low": "green"}[risk_level]
                    console.print(f"    [{color}]{risk_level.upper()}[/{color}]: {by_risk[risk_level]}")

        if unknown:
            console.print(f"\n  [yellow]Warning: {len(unknown)} MCP(s) not in known registry[/yellow]")
            for r in unknown:
                console.print(f"    • {r.name}: {r.source}")

    # Risk flags
    with_risks = [r for r in results if r.risk_flags]
    if with_risks:
        console.print(f"\n  [yellow]Warning: {len(with_risks)} MCP(s) with risk flags[/yellow]")
        for r in with_risks:
            console.print(f"    • {r.name}: {', '.join(r.risk_flags)}")

    # Trust summary
    if trust_results:
        console.print("\n[bold]Trust Summary[/bold]")
        high = sum(1 for t in trust_results.values() if t.get("score") == "HIGH")
        medium = sum(1 for t in trust_results.values() if t.get("score") == "MEDIUM")
        low = sum(1 for t in trust_results.values() if t.get("score") == "LOW")
        console.print(f"  [green]HIGH[/green]: {high}")
        console.print(f"  [yellow]MEDIUM[/yellow]: {medium}")
        console.print(f"  [red]LOW[/red]: {low}")
        if low > 0:
            console.print(f"\n  [red]Alert: {low} MCP(s) have LOW trust scores![/red]")


def _truncate(s: str, length: int) -> str:
    """Truncate string with ellipsis"""
    if len(s) <= length:
        return s
    return s[:length-3] + "..."


def _print_remediation(results: list[ScanResult]):
    """Print detailed findings and remediation guidance"""
    # Collect all risk flags across results
    flag_to_mcps: dict[str, list[str]] = {}
    for r in results:
        for flag in r.risk_flags:
            if flag not in flag_to_mcps:
                flag_to_mcps[flag] = []
            flag_to_mcps[flag].append(r.name)

    if not flag_to_mcps:
        console.print("\n[green]No risk flags detected. All MCPs appear safe.[/green]")
        return

    console.print("\n" + "─" * 60)
    console.print("[bold]FINDINGS & REMEDIATION[/bold]")
    console.print("─" * 60 + "\n")

    # Sort flags by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
    sorted_flags = sorted(
        flag_to_mcps.items(),
        key=lambda x: severity_order.get(get_severity_for_flag(x[0]), 4)
    )

    for flag, mcps in sorted_flags:
        info = get_risk_flag_info(flag)
        severity = info.get("severity", "unknown").upper()

        # Color based on severity
        if severity == "CRITICAL":
            severity_styled = f"[bold red]{severity}[/bold red]"
        elif severity == "HIGH":
            severity_styled = f"[bold yellow]{severity}[/bold yellow]"
        elif severity == "MEDIUM":
            severity_styled = f"[blue]{severity}[/blue]"
        else:
            severity_styled = f"[dim]{severity}[/dim]"

        console.print(f"[{severity_styled}] [bold]{flag}[/bold] ({len(mcps)} MCP(s) affected)")
        console.print(f"  [dim]Why:[/dim] {info.get('explanation', 'Unknown')}")
        console.print(f"  [dim]Fix:[/dim] {info.get('remediation', 'Review manually')}")
        console.print(f"  [dim]MCPs:[/dim] {', '.join(mcps)}")
        console.print()
