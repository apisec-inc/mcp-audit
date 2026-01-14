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
        "table", "--format", "-f", help="Output format: table, json, markdown, csv, cyclonedx, cyclonedx-xml"
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
    secrets_only: bool = typer.Option(
        False, "--secrets-only", help="Only show detected secrets, skip MCP inventory"
    ),
    no_secrets: bool = typer.Option(
        False, "--no-secrets", help="Skip secrets detection entirely"
    ),
    apis_only: bool = typer.Option(
        False, "--apis-only", help="Only show detected API endpoints, skip MCP inventory"
    ),
    no_apis: bool = typer.Option(
        False, "--no-apis", help="Skip API endpoint detection entirely"
    ),
    models_only: bool = typer.Option(
        False, "--models-only", help="Only show detected AI models, skip MCP inventory"
    ),
    no_models: bool = typer.Option(
        False, "--no-models", help="Skip AI model detection entirely"
    ),
    no_report: bool = typer.Option(
        False, "--no-report", help="Skip email prompt and PDF report offer"
    ),
    email: Optional[str] = typer.Option(
        None, "--email", help="Send PDF report to this email (non-interactive)"
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

    console.print("\n[bold blue]APIsec MCP Audit[/bold blue]")
    console.print("[dim]Privacy: All scanning happens locally. No data is sent unless you[/dim]")
    console.print("[dim]choose to receive a PDF report. Use --no-report to skip prompts.[/dim]\n")

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

    # Clear secrets if --no-secrets flag
    if no_secrets:
        for r in results:
            r.secrets = []
            if "secrets-detected" in r.risk_flags:
                r.risk_flags.remove("secrets-detected")

    # Clear APIs if --no-apis flag
    if no_apis:
        for r in results:
            r.apis = []

    # Clear models if --no-models flag
    if no_models:
        for r in results:
            r.model = None

    # Collect all secrets for display
    all_secrets = []
    for r in results:
        for s in r.secrets:
            secret_info = s.to_dict() if hasattr(s, 'to_dict') else s
            secret_info["mcp_name"] = r.name
            all_secrets.append(secret_info)

    # Collect all APIs for display
    all_apis = []
    for r in results:
        for a in r.apis:
            api_info = a.to_dict() if hasattr(a, 'to_dict') else a
            api_info["mcp_name"] = r.name
            all_apis.append(api_info)

    # Collect all AI models for display
    all_models = []
    for r in results:
        if r.model:
            model_info = r.model.copy() if isinstance(r.model, dict) else r.model
            if isinstance(model_info, dict):
                model_info["mcp_name"] = r.name
                all_models.append(model_info)

    # Show secrets section FIRST if any detected (highest priority)
    if all_secrets and not secrets_only and not apis_only and not models_only:
        _print_secrets_alert(all_secrets)

    # If secrets-only mode, show secrets and return
    if secrets_only:
        if all_secrets:
            _print_secrets_detail(all_secrets)
        else:
            console.print("\n[green]No secrets detected in MCP configurations.[/green]")
        return

    # Show API inventory section (after secrets, before MCP table)
    if all_apis and not apis_only and not models_only:
        _print_apis_inventory(all_apis)

    # Show AI Models summary (after APIs)
    if all_models and not secrets_only and not apis_only and not models_only:
        _print_models_summary(all_models)

    # If apis-only mode, show APIs and return
    if apis_only:
        if all_apis:
            _print_apis_inventory(all_apis, detailed=True)
        else:
            console.print("\n[green]No API endpoints detected in MCP configurations.[/green]")
        return

    # If models-only mode, show models and return
    if models_only:
        if all_models:
            _print_models_summary(all_models, detailed=True)
        else:
            console.print("\n[green]No AI models detected in MCP configurations.[/green]")
        return

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

        # CI/CD integration tip for JSON exports
        if format == "json":
            console.print()
            console.print("─" * 60)
            console.print("[bold blue]CI/CD Integration Tip:[/bold blue]")
            console.print("  Parse results to fail builds when critical risks are found.")
            console.print("  [dim]Example: jq '.mcps[] | select(.registry_risk == \"critical\")' " + str(output) + "[/dim]")
            console.print()
            console.print("  [dim]Docs: https://apisec-inc.github.io/mcp-audit/ci-cd[/dim]")
            console.print("─" * 60)
        return  # Skip email prompt when outputting to file
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

    # Email report handling
    if email:
        # Non-interactive mode: send report to specified email
        _send_report_to_email(email, results, all_secrets, all_apis)
    elif not no_report and not output:
        # Interactive mode: prompt for email
        _prompt_for_email_report(results, all_secrets, all_apis)


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

    # Check if any results have secrets
    has_secrets = any(r.secrets for r in results)
    if has_secrets:
        table.add_column("Secrets", style="red")

    # Check if any results have AI models
    has_models = any(r.model for r in results)
    if has_models:
        table.add_column("AI Model", style="magenta")

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

        # Add secrets column if any results have secrets
        if has_secrets:
            if r.secrets:
                # Count by severity
                critical = sum(1 for s in r.secrets if (s.severity if hasattr(s, 'severity') else s.get('severity')) == 'critical')
                high = sum(1 for s in r.secrets if (s.severity if hasattr(s, 'severity') else s.get('severity')) == 'high')
                if critical:
                    row.append(f"[bold red]{critical} critical[/bold red]")
                elif high:
                    row.append(f"[yellow]{high} high[/yellow]")
                else:
                    row.append(f"{len(r.secrets)} found")
            else:
                row.append("-")

        # Add AI model column if any results have models
        if has_models:
            if r.model:
                model_name = r.model.get("model_name", "Unknown")
                provider = r.model.get("provider", "")
                hosting = r.model.get("hosting", "unknown")
                if hosting == "cloud":
                    row.append(f"[blue]{model_name}[/blue]")
                elif hosting == "local":
                    row.append(f"[green]{model_name}[/green]")
                else:
                    row.append(model_name)
            else:
                row.append("-")

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


def _get_secret_remediation(secret: dict) -> list[str]:
    """Get provider-specific remediation steps for a secret type"""
    secret_type = secret.get("type", "")
    url = secret.get("rotation_url")

    steps = []

    if secret_type in ("github_pat", "github_oauth", "github_app"):
        steps.append(f"Go to {url} and delete this token")
        steps.append("Create a new token with minimum required scopes")
        steps.append("Update GITHUB_TOKEN in your MCP config")
    elif secret_type == "slack_token":
        steps.append(f"Go to {url} and regenerate the bot token")
        steps.append("Update SLACK_BOT_TOKEN in your MCP config")
    elif secret_type in ("openai_key", "openai_project_key"):
        steps.append(f"Go to {url} and revoke this key")
        steps.append("Create a new API key")
        steps.append("Update OPENAI_API_KEY in your MCP config")
    elif secret_type == "anthropic_key":
        steps.append(f"Go to {url} and delete this key")
        steps.append("Create a new API key")
        steps.append("Update ANTHROPIC_API_KEY in your MCP config")
    elif secret_type in ("aws_access_key", "aws_secret_key"):
        steps.append(f"Go to {url} and deactivate this access key")
        steps.append("Create new access key pair")
        steps.append("Update AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY")
    elif secret_type == "stripe_live":
        steps.append(f"[bold red]CRITICAL: This is a LIVE Stripe key![/bold red]")
        steps.append(f"Go to {url} and roll the secret key immediately")
        steps.append("Update your MCP config with the new key")
    elif secret_type in ("postgres_conn", "mysql_conn", "mongodb_conn", "redis_conn"):
        steps.append("Change database password in your database admin console")
        steps.append("Update connection string in MCP config with new password")
        steps.append("Review database access logs for unauthorized access")
    elif secret_type == "private_key":
        steps.append("Generate a new key pair")
        steps.append("Update systems using the corresponding public key")
        steps.append("Revoke certificates associated with old key")
    elif secret_type == "sendgrid_key":
        steps.append(f"Go to {url} and delete this key")
        steps.append("Create new API key with minimum permissions")
    elif secret_type == "discord_token":
        steps.append(f"Go to {url} and regenerate the bot token")
        steps.append("Update your MCP config with the new token")
    elif secret_type == "npm_token":
        steps.append(f"Go to {url} and delete this token")
        steps.append("Create new token with appropriate permissions")
    elif secret_type == "google_api_key":
        steps.append(f"Go to {url}")
        steps.append("Delete compromised key and create new one with API restrictions")
    else:
        # Generic
        if url:
            steps.append(f"Rotate credential at: {url}")
        else:
            steps.append("Rotate this credential through your provider's console")
        steps.append("Update your MCP configuration with the new value")

    # Common final steps
    steps.append("Remove hardcoded secret from config (use env vars instead)")
    steps.append("If in Git: scrub history with BFG or git filter-branch")

    return steps


def _print_secrets_alert(secrets: list):
    """Print prominent secrets alert banner"""
    # Count by severity
    critical = sum(1 for s in secrets if s.get("severity") == "critical")
    high = sum(1 for s in secrets if s.get("severity") == "high")
    medium = sum(1 for s in secrets if s.get("severity") == "medium")

    console.print()
    console.print("[bold red]" + "═" * 60 + "[/bold red]")
    console.print(f"[bold red]⚠️  {len(secrets)} SECRET(S) DETECTED - IMMEDIATE ACTION REQUIRED[/bold red]")
    console.print("[bold red]" + "═" * 60 + "[/bold red]")
    console.print()

    # Group by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2}
    sorted_secrets = sorted(secrets, key=lambda x: severity_order.get(x.get("severity", "medium"), 2))

    for s in sorted_secrets:
        severity = s.get("severity", "medium").upper()
        if severity == "CRITICAL":
            severity_styled = f"[bold red]{severity}[/bold red]"
        elif severity == "HIGH":
            severity_styled = f"[bold yellow]{severity}[/bold yellow]"
        else:
            severity_styled = f"[blue]{severity}[/blue]"

        console.print(f"[{severity_styled}] {s.get('description', 'Unknown secret')}")
        console.print(f"  [dim]Location:[/dim] {s.get('mcp_name', 'unknown')} → env.{s.get('env_key', 'unknown')}")
        console.print(f"  [dim]Value:[/dim] {s.get('value_masked', '****')} ({s.get('value_length', 0)} chars)")

        # Provider-specific remediation
        remediation_steps = _get_secret_remediation(s)
        console.print(f"  [dim]Remediation:[/dim]")
        for i, step in enumerate(remediation_steps, 1):
            console.print(f"    {i}. {step}")
        console.print()

    console.print("[bold red]" + "─" * 60 + "[/bold red]")
    summary_parts = []
    if critical:
        summary_parts.append(f"[red]{critical} critical[/red]")
    if high:
        summary_parts.append(f"[yellow]{high} high[/yellow]")
    if medium:
        summary_parts.append(f"[blue]{medium} medium[/blue]")
    console.print(f"[bold]Total: {len(secrets)} secrets ({', '.join(summary_parts)})[/bold]")
    console.print("[bold yellow]Rotate ALL exposed credentials before continuing.[/bold yellow]")
    console.print("[bold red]" + "─" * 60 + "[/bold red]")
    console.print()


def _print_secrets_detail(secrets: list):
    """Print detailed secrets list (for --secrets-only mode)"""
    console.print()
    console.print("[bold]⚠️  SECRETS DETECTED[/bold]")
    console.print("─" * 60)
    console.print()

    # Group by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2}
    sorted_secrets = sorted(secrets, key=lambda x: severity_order.get(x.get("severity", "medium"), 2))

    for s in sorted_secrets:
        severity = s.get("severity", "medium").upper()
        if severity == "CRITICAL":
            severity_styled = f"[bold red]{severity}[/bold red]"
        elif severity == "HIGH":
            severity_styled = f"[bold yellow]{severity}[/bold yellow]"
        else:
            severity_styled = f"[blue]{severity}[/blue]"

        console.print(f"[{severity_styled}] {s.get('description', 'Unknown secret')}")
        console.print(f"  Location: {s.get('mcp_name', 'unknown')} → env.{s.get('env_key', 'unknown')}")
        console.print(f"  Value: {s.get('value_masked', '****')} ({s.get('value_length', 0)} chars)")

        # Provider-specific remediation
        remediation_steps = _get_secret_remediation(s)
        console.print(f"  Remediation:")
        for i, step in enumerate(remediation_steps, 1):
            console.print(f"    {i}. {step}")
        console.print()

    console.print("─" * 60)
    critical = sum(1 for s in secrets if s.get("severity") == "critical")
    high = sum(1 for s in secrets if s.get("severity") == "high")
    medium = sum(1 for s in secrets if s.get("severity") == "medium")
    console.print(f"Total: {len(secrets)} secrets ({critical} critical, {high} high, {medium} medium)")


def _print_apis_inventory(apis: list, detailed: bool = False):
    """Print API endpoints inventory"""
    if not apis:
        return

    # Category display info
    category_info = {
        "database": {"name": "Database", "icon": "🗄️", "color": "cyan"},
        "rest_api": {"name": "REST API", "icon": "🌐", "color": "blue"},
        "websocket": {"name": "WebSocket", "icon": "🔌", "color": "magenta"},
        "sse": {"name": "SSE", "icon": "📡", "color": "yellow"},
        "saas": {"name": "SaaS", "icon": "☁️", "color": "green"},
        "cloud": {"name": "Cloud", "icon": "🏢", "color": "white"},
        "unknown": {"name": "Other", "icon": "❓", "color": "dim"},
    }

    # Group by category
    by_category = {}
    for api in apis:
        cat = api.get("category", "unknown")
        if cat not in by_category:
            by_category[cat] = []
        by_category[cat].append(api)

    console.print()
    console.print("═" * 60)
    console.print(f"[bold blue]📡 ENDPOINTS DISCOVERED[/bold blue] - {len(apis)} connection(s)")
    console.print("═" * 60)

    # Print by category
    category_order = ["database", "rest_api", "websocket", "sse", "saas", "cloud", "unknown"]
    for cat in category_order:
        if cat not in by_category:
            continue

        cat_apis = by_category[cat]
        info = category_info.get(cat, category_info["unknown"])
        color = info["color"]

        console.print()
        console.print(f"[bold {color}]{info['icon']} {info['name'].upper()} ({len(cat_apis)})[/bold {color}]")

        for api in cat_apis:
            mcp_name = api.get("mcp_name", "unknown")
            url = api.get("url", "unknown")  # Already masked in to_dict()
            description = api.get("description", "")
            source = api.get("source", "")
            source_key = api.get("source_key", "")

            if detailed:
                # Detailed mode for --apis-only
                console.print(f"  [{color}]•[/{color}] [bold]{mcp_name}[/bold]")
                console.print(f"      URL: {url}")
                console.print(f"      Description: {description}")
                console.print(f"      Source: {source} → {source_key}")
            else:
                # Compact mode for normal scan
                console.print(f"  [{color}]•[/{color}] {mcp_name} → {url}")

    console.print()
    console.print("─" * 60)


def _print_models_summary(models: list, detailed: bool = False):
    """Print AI Models summary section"""
    if not models:
        return

    # Group by provider
    by_provider = {}
    for m in models:
        provider = m.get("provider", "Unknown")
        if provider not in by_provider:
            by_provider[provider] = []
        by_provider[provider].append(m)

    # Group by hosting
    by_hosting = {"cloud": 0, "local": 0, "unknown": 0}
    for m in models:
        hosting = m.get("hosting", "unknown")
        if hosting in by_hosting:
            by_hosting[hosting] += 1

    console.print()
    console.print("═" * 60)
    console.print(f"[bold magenta]🤖 AI MODELS[/bold magenta] - {len(models)} model(s) detected")
    console.print("═" * 60)

    # By Provider
    console.print()
    console.print("[bold]By Provider:[/bold]")
    for provider, provider_models in sorted(by_provider.items(), key=lambda x: -len(x[1])):
        count = len(provider_models)
        bar = "█" * min(count * 4, 20)
        model_names = ", ".join(m.get("model_name", "Unknown") for m in provider_models[:3])
        if len(provider_models) > 3:
            model_names += f" +{len(provider_models) - 3} more"
        console.print(f"  {provider:15} [magenta]{bar}[/magenta] {count} ({model_names})")

    # By Hosting
    console.print()
    console.print("[bold]By Hosting:[/bold]")
    cloud_count = by_hosting.get("cloud", 0)
    local_count = by_hosting.get("local", 0)
    if cloud_count:
        bar = "█" * min(cloud_count * 4, 20)
        console.print(f"  Cloud           [blue]{bar}[/blue] {cloud_count}")
    if local_count:
        bar = "█" * min(local_count * 4, 20)
        console.print(f"  Local           [green]{bar}[/green] {local_count}")

    # Model Inventory
    console.print()
    console.print("[bold]Model Inventory:[/bold]")
    for m in models:
        model_name = m.get("model_name", "Unknown")
        provider = m.get("provider", "Unknown")
        hosting = m.get("hosting", "unknown")
        mcp_name = m.get("mcp_name", "unknown")

        hosting_label = f"[blue]Cloud[/blue]" if hosting == "cloud" else "[green]Local[/green]" if hosting == "local" else "[dim]Unknown[/dim]"
        console.print(f"  • {model_name} — {provider} ({hosting_label}) — [dim]{mcp_name}[/dim]")

    console.print()
    console.print("─" * 60)


def _validate_email(email: str) -> bool:
    """Basic email format validation"""
    import re
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def _build_scan_summary(results: list, all_secrets: list, all_apis: list) -> dict:
    """Build scan summary for report/backend (no actual secret values)"""
    # Risk distribution
    risk_dist = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    for r in results:
        risk = (r.registry_risk or "unknown").lower()
        if risk in risk_dist:
            risk_dist[risk] += 1

    # Secrets severity counts
    secrets_severity = {"critical": 0, "high": 0, "medium": 0}
    for s in all_secrets:
        sev = s.get("severity", "medium").lower()
        if sev in secrets_severity:
            secrets_severity[sev] += 1

    # API categories
    api_categories = {}
    for a in all_apis:
        cat = a.get("category", "unknown")
        api_categories[cat] = api_categories.get(cat, 0) + 1

    # Unverified MCPs
    unverified = [r for r in results if not r.is_known]

    # MCP summaries (no secret values)
    mcp_summaries = []
    for r in results:
        mcp_summaries.append({
            "name": r.name,
            "source": r.source,
            "risk": r.registry_risk or "unknown",
            "risk_flags": r.risk_flags,
            "secrets_count": len(r.secrets),
            "apis": [a.get("url", "") for a in r.apis] if hasattr(r, 'apis') else [],
            "is_known": r.is_known,
            "provider": r.provider,
        })

    return {
        "total_mcps": len(results),
        "risk_distribution": risk_dist,
        "secrets_count": len(all_secrets),
        "secrets_severity": secrets_severity,
        "apis_discovered": {
            "total": len(all_apis),
            **api_categories
        },
        "unverified_mcps": len(unverified),
        "mcps": mcp_summaries,
    }


def _prompt_for_email_report(results: list, all_secrets: list, all_apis: list):
    """Prompt user for email to receive PDF report"""
    console.print()
    console.print("─" * 60)
    console.print("[bold blue]📄 Get a PDF report to share with your team[/bold blue]")

    while True:
        email_input = console.input("   Email (press Enter to skip): ").strip()

        if not email_input:
            # User skipped
            console.print("[dim]   Skipped. Run with --email <email> to get a report later.[/dim]")
            return

        if not _validate_email(email_input):
            console.print("[red]   Invalid email format. Press Enter to skip or try again.[/red]")
            continue

        # Valid email - send report
        _send_report_to_email(email_input, results, all_secrets, all_apis)
        break

    console.print("─" * 60)


def _send_report_to_email(email: str, results: list, all_secrets: list, all_apis: list):
    """Send scan summary to backend for PDF generation and email delivery"""
    import requests
    from datetime import datetime

    # Build summary (no actual secret values)
    summary = _build_scan_summary(results, all_secrets, all_apis)

    # Determine scan type and target
    found_in_set = set(r.found_in for r in results)
    scan_type = "local"
    target = "local-machine"

    payload = {
        "email": email,
        "source": "cli",
        "scan_type": scan_type,
        "target": target,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "summary": summary,
    }

    # Backend endpoint (configurable)
    backend_url = "https://mcp-audit-api.vercel.app/api/report"
    api_key = "a85eeddadf75ea8ff5dea73b3e823a6ce804fddd0d7f7d8dd8147c5d112b5c52"

    try:
        console.print(f"\n[dim]   Sending report to {email}...[/dim]")

        response = requests.post(
            backend_url,
            json=payload,
            timeout=30,
            headers={
                "Content-Type": "application/json",
                "X-API-Key": api_key
            }
        )

        if response.status_code == 200:
            data = response.json()
            report_url = data.get("report_url", "")
            console.print(f"\n[green]✅ Report sent to {email}[/green]")
            if report_url:
                console.print(f"   View online: {report_url}")
        else:
            console.print(f"\n[yellow]⚠️  Couldn't send report (server returned {response.status_code})[/yellow]")
            console.print("[dim]   Results displayed above. Try again later with: mcp-audit scan --email <email>[/dim]")

    except requests.exceptions.Timeout:
        console.print("\n[yellow]⚠️  Request timed out. Results displayed above.[/yellow]")
        console.print("[dim]   Try again later with: mcp-audit scan --email <email>[/dim]")
    except requests.exceptions.ConnectionError:
        console.print("\n[yellow]⚠️  Couldn't connect to server. Results displayed above.[/yellow]")
        console.print("[dim]   Try again later with: mcp-audit scan --email <email>[/dim]")
    except Exception as e:
        console.print(f"\n[yellow]⚠️  Error sending report: {str(e)}[/yellow]")
        console.print("[dim]   Results displayed above. Try again later.[/dim]")


