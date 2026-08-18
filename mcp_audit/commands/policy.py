"""
Policy command - Validate MCPs against security policies
"""

import typer
from rich.console import Console
from rich.table import Table
from pathlib import Path
from typing import Optional
import json
import re
from datetime import datetime

from mcp_audit.models import ScanResult

app = typer.Typer(help="Validate MCPs against security policies")
console = Console()


@app.callback(invoke_without_command=True)
def policy(
    ctx: typer.Context,
    policy_file: Path = typer.Option(
        ..., "--policy", "-p", help="Path to policy file (YAML or JSON)"
    ),
    input_file: Path = typer.Option(
        ..., "--input", "-i", help="Path to MCP inventory file (JSON from scan)"
    ),
    format: str = typer.Option(
        "table", "--format", "-f", help="Output format: table, json, markdown"
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Write output to file"
    ),
    strict: bool = typer.Option(
        False, "--strict", help="Exit with error on any violation or warning"
    ),
):
    """
    Validate MCP configurations against a security policy.

    Examples:
        mcp-audit policy --policy policy.yaml --input inventory.json
        mcp-audit policy -p policy.yaml -i inventory.json --strict
        mcp-audit policy -p policy.json -i inventory.json --format json
    """
    if ctx.invoked_subcommand is not None:
        return

    console.print("\n[bold blue]MCP Audit - Policy Validation[/bold blue]\n")

    # Load policy
    if not policy_file.exists():
        console.print(f"[red]Error: Policy file not found: {policy_file}[/red]")
        raise typer.Exit(1)

    try:
        policy_data = _load_policy(policy_file)
    except Exception as e:
        console.print(f"[red]Error loading policy: {e}[/red]")
        raise typer.Exit(1)

    # Load inventory
    if not input_file.exists():
        console.print(f"[red]Error: Input file not found: {input_file}[/red]")
        raise typer.Exit(1)

    try:
        inventory = json.loads(input_file.read_text())
        mcps = inventory.get("mcps", [])
    except (json.JSONDecodeError, IOError) as e:
        console.print(f"[red]Error loading inventory: {e}[/red]")
        raise typer.Exit(1)

    console.print(f"Policy: [cyan]{policy_file.name}[/cyan]")
    console.print(f"Checking {len(mcps)} MCP(s)...\n")

    # Validate each MCP
    results = []
    for mcp in mcps:
        result = _validate_mcp(mcp, policy_data)
        results.append(result)

    # Output results
    violations = [r for r in results if r["status"] == "VIOLATION"]
    warnings = [r for r in results if r["status"] == "WARNING"]
    compliant = [r for r in results if r["status"] == "COMPLIANT"]

    if format == "table":
        _print_policy_table(results)
    elif format == "json":
        output_data = {
            "check_time": datetime.now().isoformat(),
            "policy_file": str(policy_file),
            "total_mcps": len(results),
            "violations": len(violations),
            "warnings": len(warnings),
            "compliant": len(compliant),
            "results": results,
        }
        formatted = json.dumps(output_data, indent=2)
        if output:
            output.write_text(formatted)
            console.print(f"\n[green]Results written to {output}[/green]")
        else:
            console.print(formatted)
    elif format == "markdown":
        formatted = _to_markdown(results, policy_file)
        if output:
            output.write_text(formatted)
            console.print(f"\n[green]Results written to {output}[/green]")
        else:
            console.print(formatted)

    # Summary
    _print_policy_summary(violations, warnings, compliant)

    # Exit code
    if violations:
        console.print("\n[red]Policy validation FAILED[/red]")
        raise typer.Exit(1)
    elif strict and warnings:
        console.print("\n[yellow]Policy validation FAILED (strict mode)[/yellow]")
        raise typer.Exit(1)
    else:
        console.print("\n[green]Policy validation PASSED[/green]")


def _load_policy(policy_file: Path) -> dict:
    """Load policy from YAML or JSON file"""
    content = policy_file.read_text()

    if policy_file.suffix in [".yaml", ".yml"]:
        # Basic YAML parsing without external dependency
        return _parse_simple_yaml(content)
    else:
        return json.loads(content)


def _parse_simple_yaml(content: str) -> dict:
    """Parse simple YAML without external dependency"""
    result = {}
    current_key = None
    current_list = None

    for line in content.splitlines():
        stripped = line.strip()

        # Skip empty lines and comments
        if not stripped or stripped.startswith("#"):
            continue

        # Check for list item
        if stripped.startswith("- "):
            if current_list is not None:
                value = stripped[2:].strip().strip('"').strip("'")
                current_list.append(value)
            continue

        # Check for key-value pair
        if ":" in stripped:
            parts = stripped.split(":", 1)
            key = parts[0].strip()
            value = parts[1].strip() if len(parts) > 1 else ""

            if not value:
                # This is a section header
                current_key = key
                result[key] = []
                current_list = result[key]
            else:
                # Simple key-value
                value = value.strip('"').strip("'")
                result[key] = value
                current_list = None

    return result


def _validate_mcp(mcp: dict, policy: dict) -> dict:
    """Validate a single MCP against policy"""
    name = mcp.get("name", "unknown")
    source = mcp.get("source", "")
    risk_flags = mcp.get("risk_flags", [])

    result = {
        "name": name,
        "source": source,
        "status": "COMPLIANT",
        "reasons": [],
    }

    # Check allowed_sources
    allowed_sources = policy.get("allowed_sources", [])
    if allowed_sources:
        is_allowed = False
        for pattern in allowed_sources:
            if _match_pattern(source, pattern):
                is_allowed = True
                break
        if not is_allowed:
            result["status"] = "VIOLATION"
            result["reasons"].append(f"Source not in allowed list")

    # Check denied_sources
    denied_sources = policy.get("denied_sources", [])
    for pattern in denied_sources:
        if _match_pattern(source, pattern):
            result["status"] = "VIOLATION"
            result["reasons"].append(f"Source matches denied pattern: {pattern}")

    # Check denied_capabilities
    denied_capabilities = policy.get("denied_capabilities", [])
    for cap in denied_capabilities:
        # Map policy capability names to risk flags
        cap_mapping = {
            "shell-access": "shell-access",
            "filesystem-access": "filesystem-access",
            "filesystem-write": "filesystem-access",
            "database-access": "database-access",
            "network-access": "network-access",
        }
        risk_flag = cap_mapping.get(cap, cap)
        if risk_flag in risk_flags:
            result["status"] = "VIOLATION"
            result["reasons"].append(f"Has denied capability: {cap}")

    # Check require_review
    require_review = policy.get("require_review", [])
    for flag in require_review:
        if flag in risk_flags:
            if result["status"] == "COMPLIANT":
                result["status"] = "WARNING"
            result["reasons"].append(f"Requires review: {flag}")

    # Check require_verified_source
    if policy.get("require_verified_source", False):
        verified = ["@anthropic/", "@modelcontextprotocol/", "@openai/"]
        is_verified = any(source.startswith(v) for v in verified)
        if not is_verified:
            if result["status"] == "COMPLIANT":
                result["status"] = "WARNING"
            result["reasons"].append("Source not from verified publisher")

    # Check max_risk_level
    max_risk = policy.get("max_risk_level", None)
    if max_risk:
        high_risk = ["shell-access", "unverified-source", "unsafe-command-allowlist"]
        medium_risk = ["filesystem-access", "database-access", "secrets-in-env"]

        if max_risk == "low":
            if any(r in risk_flags for r in high_risk + medium_risk):
                result["status"] = "VIOLATION"
                result["reasons"].append(f"Exceeds max risk level: {max_risk}")
        elif max_risk == "medium":
            if any(r in risk_flags for r in high_risk):
                result["status"] = "VIOLATION"
                result["reasons"].append(f"Exceeds max risk level: {max_risk}")

    if not result["reasons"]:
        result["reasons"].append("Passes all policy checks")

    return result


def _match_pattern(source: str, pattern: str) -> bool:
    """Match source against pattern (supports * wildcard)"""
    # Convert glob pattern to regex
    regex = pattern.replace("*", ".*")
    regex = f"^{regex}$"
    return bool(re.match(regex, source))


def _print_policy_table(results: list):
    """Print policy results as a table"""
    table = Table(title="Policy Validation Results", show_header=True, header_style="bold cyan")

    table.add_column("MCP Name", style="white")
    table.add_column("Source", style="dim")
    table.add_column("Status", style="bold")
    table.add_column("Reasons", style="dim")

    for r in results:
        status = r["status"]
        if status == "VIOLATION":
            status_display = f"[red]{status}[/red]"
        elif status == "WARNING":
            status_display = f"[yellow]{status}[/yellow]"
        else:
            status_display = f"[green]{status}[/green]"

        reasons = "\n".join(r["reasons"][:3])
        if len(r["reasons"]) > 3:
            reasons += f"\n(+{len(r['reasons']) - 3} more)"

        table.add_row(
            r["name"],
            _truncate(r["source"], 35),
            status_display,
            reasons
        )

    console.print(table)


def _print_policy_summary(violations: list, warnings: list, compliant: list):
    """Print summary of policy check"""
    console.print("\n[bold]Summary[/bold]")
    console.print(f"  [red]VIOLATIONS[/red]: {len(violations)}")
    console.print(f"  [yellow]WARNINGS[/yellow]: {len(warnings)}")
    console.print(f"  [green]COMPLIANT[/green]: {len(compliant)}")

    if violations:
        console.print("\n[bold red]Violations:[/bold red]")
        for v in violations:
            console.print(f"  • {v['name']}: {', '.join(v['reasons'])}")

    if warnings:
        console.print("\n[bold yellow]Warnings:[/bold yellow]")
        for w in warnings:
            console.print(f"  • {w['name']}: {', '.join(w['reasons'])}")


def _to_markdown(results: list, policy_file: Path) -> str:
    """Convert results to markdown"""
    violations = [r for r in results if r["status"] == "VIOLATION"]
    warnings = [r for r in results if r["status"] == "WARNING"]
    compliant = [r for r in results if r["status"] == "COMPLIANT"]

    lines = [
        "# MCP Policy Validation Report",
        "",
        f"**Check Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"**Policy File:** {policy_file.name}",
        f"**Total MCPs:** {len(results)}",
        "",
        "## Summary",
        "",
        f"- **VIOLATIONS:** {len(violations)}",
        f"- **WARNINGS:** {len(warnings)}",
        f"- **COMPLIANT:** {len(compliant)}",
        "",
        "## Results",
        "",
        "| MCP Name | Source | Status | Reasons |",
        "|----------|--------|--------|---------|",
    ]

    for r in results:
        reasons = "; ".join(r["reasons"][:2])
        lines.append(f"| {r['name']} | {r['source'][:30]} | **{r['status']}** | {reasons} |")

    if violations:
        lines.extend([
            "",
            "## Violations",
            "",
        ])
        for v in violations:
            lines.append(f"- **{v['name']}**: {', '.join(v['reasons'])}")

    return "\n".join(lines)


def _truncate(s: str, length: int) -> str:
    """Truncate string with ellipsis"""
    if len(s) <= length:
        return s
    return s[:length-3] + "..."
