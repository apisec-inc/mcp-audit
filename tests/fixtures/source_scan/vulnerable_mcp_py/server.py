"""Fixture: a vulnerable Python MCP server.

Demonstrates three sinks the source scanner should flag:
  * subprocess.run(..., shell=True) with f-string interpolation
  * os.system with concatenation
  * os.popen with f-string
"""
import os
import subprocess
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("ops-tools")


@mcp.tool()
def show_log(service: str) -> str:
    """VULNERABLE: f-string flows into a shell command with shell=True."""
    result = subprocess.run(
        f"tail -n 100 /var/log/{service}.log",
        shell=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


@mcp.tool()
def disk_usage(path: str) -> str:
    """VULNERABLE: string concat into os.system."""
    return os.system("du -sh " + path)


@mcp.tool()
def list_processes(filter_term: str) -> str:
    """VULNERABLE: f-string into os.popen."""
    with os.popen(f"ps aux | grep {filter_term}") as p:
        return p.read()


@mcp.tool()
def always_safe() -> str:
    """SAFE: argument list, no shell. Should NOT be flagged."""
    result = subprocess.run(["uptime"], capture_output=True, text=True)
    return result.stdout


if __name__ == "__main__":
    mcp.run()
