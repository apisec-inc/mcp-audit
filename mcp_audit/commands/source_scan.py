"""``mcp-audit source-scan`` — scan MCP server source code for code-level vulnerabilities.

This is distinct from ``mcp-audit scan``:

* ``scan`` inventories MCP **configurations** across your machine (what's
  connected to Claude Desktop / Cursor / VS Code, what env vars they need,
  what tools they advertise).
* ``source-scan`` reads the MCP server's own **source code** and flags
  vulnerability patterns the server author introduced — today, the
  shell-injection sink from the "Prompt In, Shell Out" attack chain.

Typical workflow:

    $ mcp-audit scan                    # discover MCP servers
    $ mcp-audit source-scan ./my-mcp    # check the in-house one for shell injection

The command is intentionally minimal: ``--path`` (positional), ``--format``
for output, ``--exit-code`` so CI can gate merges on critical findings.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from mcp_audit.data.risk_definitions import get_risk_flag_info
from mcp_audit.scanners.source import scan_source

app = typer.Typer(help="Scan MCP server source code for vulnerability patterns")
console = Console()
err_console = Console(stderr=True)


def source_scan(
    path: Path = typer.Argument(
        Path("."),
        help="Path to the MCP server source tree. Defaults to current directory.",
    ),
    format: str = typer.Option(
        "table",
        "--format",
        "-f",
        help="Output format: table, json, sarif.",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Write output to FILE instead of stdout.",
    ),
    exit_code: bool = typer.Option(
        False,
        "--exit-code",
        help=(
            "Exit non-zero if any critical findings are detected. "
            "Useful as a CI gate on merges to main."
        ),
    ),
    explain: bool = typer.Option(
        False,
        "--explain",
        help="Print the full remediation guidance for each finding.",
    ),
) -> None:
    """Scan an MCP server source tree for code-level vulnerabilities.

    Examples:

        mcp-audit source-scan
        mcp-audit source-scan ./packages/my-mcp-server
        mcp-audit source-scan --format json --output findings.json
        mcp-audit source-scan --exit-code   # CI: fail on critical findings
    """
    if not path.exists():
        err_console.print(f"[red]error[/red]: path does not exist: {path}")
        raise typer.Exit(code=2)
    if not path.is_dir():
        err_console.print(f"[red]error[/red]: path is not a directory: {path}")
        raise typer.Exit(code=2)

    findings = scan_source(path)

    # Render
    fmt = format.lower()
    if fmt == "json":
        payload = {
            "scan_root": path.name or ".",
            "finding_count": len(findings),
            "findings": [f.to_dict() for f in findings],
        }
        text = json.dumps(payload, indent=2)
    elif fmt == "sarif":
        text = _render_sarif(findings, path)
    elif fmt == "table":
        if output is not None:
            # Capture-to-file falls back to plain text rendering.
            text = _render_text(findings, path, explain=explain)
        else:
            _render_table(findings, path, explain=explain)
            text = None
    else:
        err_console.print(f"[red]error[/red]: unknown format: {format}")
        raise typer.Exit(code=2)

    if text is not None:
        if output is not None:
            output.write_text(text, encoding="utf-8")
            err_console.print(f"[green]wrote[/green] {output}")
        else:
            # Bypass Rich for machine-readable formats — Rich's console.print
            # pretty-prints / wraps JSON and SARIF in ways that break piping
            # into ``jq`` or SARIF upload tools.
            sys.stdout.write(text)
            sys.stdout.write("\n")
            sys.stdout.flush()

    if exit_code:
        critical = [f for f in findings if f.severity == "critical"]
        if critical:
            err_console.print(
                f"[red]exit-code[/red]: {len(critical)} critical finding(s) — failing"
            )
            raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------


def _render_table(findings, path: Path, *, explain: bool) -> None:
    if not findings:
        console.print(
            f"\n[green]No source-level vulnerabilities found in [bold]{path}[/bold].[/green]\n"
            "\n[dim]Note: the scanner only inspects files that look like MCP server source "
            "(imports an MCP SDK). If you expected findings but got none, confirm the path "
            "points at an MCP server tree.[/dim]\n"
        )
        return

    console.print(f"\n[bold]MCP source-scan: {path}[/bold]")
    crit = sum(1 for f in findings if f.severity == "critical")
    high = sum(1 for f in findings if f.severity == "high")
    console.print(
        f"[red]{crit} critical[/red] · [yellow]{high} high[/yellow] · "
        f"{len(findings)} finding(s) total\n"
    )

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Severity", style="bold", no_wrap=True)
    table.add_column("Conf", no_wrap=True)
    table.add_column("File:Line", no_wrap=True)
    table.add_column("API", no_wrap=True)
    table.add_column("Snippet")

    for f in findings:
        sev_style = "red" if f.severity == "critical" else "yellow"
        conf_style = "red" if f.confidence == "high" else "yellow"
        table.add_row(
            f"[{sev_style}]{f.severity.upper()}[/{sev_style}]",
            f"[{conf_style}]{f.confidence}[/{conf_style}]",
            f"{f.file}:{f.line}",
            f.api_used,
            f.snippet[:80],
        )
    console.print(table)

    if explain:
        info = get_risk_flag_info("shell-injection-in-source")
        console.print("\n[bold]Why this matters[/bold]")
        console.print(f"  {info.get('explanation', '')}")
        console.print("\n[bold]How to fix[/bold]")
        for i, step in enumerate(info.get("detailed_steps", []), start=1):
            console.print(f"  {i}. {step}")
    else:
        console.print(
            "\n[dim]Run with --explain for full remediation guidance, or "
            "[bold]mcp-audit explain shell-injection-in-source[/bold].[/dim]"
        )

    console.print()


def _render_text(findings, path: Path, *, explain: bool) -> str:
    """Plain-text fallback for --output to a file."""
    if not findings:
        return f"No source-level vulnerabilities found in {path}.\n"
    lines: list[str] = []
    lines.append(f"MCP source-scan: {path}")
    crit = sum(1 for f in findings if f.severity == "critical")
    high = sum(1 for f in findings if f.severity == "high")
    lines.append(f"{crit} critical, {high} high, {len(findings)} total")
    lines.append("")
    for f in findings:
        lines.append(
            f"[{f.severity.upper()}] [{f.confidence}] {f.file}:{f.line}  {f.api_used}"
        )
        lines.append(f"    {f.snippet}")
        lines.append(f"    fix: {f.remediation}")
        lines.append("")
    if explain:
        info = get_risk_flag_info("shell-injection-in-source")
        lines.append("Why this matters:")
        lines.append(f"  {info.get('explanation', '')}")
        lines.append("")
        lines.append("How to fix:")
        for i, step in enumerate(info.get("detailed_steps", []), start=1):
            lines.append(f"  {i}. {step}")
    return "\n".join(lines) + "\n"


def _render_sarif(findings, path: Path) -> str:
    """Render findings as SARIF 2.1.0 so CI tools (GitHub code-scanning,
    GitLab, etc.) can ingest the output directly.

    Minimal compliant subset — enough for GitHub Advanced Security to render
    findings as code-scanning alerts. Reference:
    https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
    """
    info = get_risk_flag_info("shell-injection-in-source")
    runs = [
        {
            "tool": {
                "driver": {
                    "name": "mcp-audit",
                    "informationUri": "https://github.com/apisec-inc/mcp-audit",
                    "rules": [
                        {
                            "id": "shell-injection-in-source",
                            "shortDescription": {
                                "text": "MCP server pipes LLM-controlled input into a shell-spawning API"
                            },
                            "fullDescription": {"text": info.get("explanation", "")},
                            "helpUri": "https://github.com/apisec-inc/mcp-audit/blob/main/docs/SOURCE_SCAN.md",
                            "defaultConfiguration": {"level": "error"},
                        }
                    ],
                }
            },
            "results": [
                {
                    "ruleId": "shell-injection-in-source",
                    "level": "error" if f.severity == "critical" else "warning",
                    "message": {
                        "text": f"{f.api_used} called with {f.confidence}-confidence interpolation; replace with execFile/spawn or pass args as a list."
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": f.file},
                                "region": {"startLine": f.line, "startColumn": f.column},
                            }
                        }
                    ],
                    "properties": {
                        "api_used": f.api_used,
                        "confidence": f.confidence,
                        "snippet": f.snippet,
                    },
                }
                for f in findings
            ],
        }
    ]
    return json.dumps(
        {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": runs},
        indent=2,
    )
