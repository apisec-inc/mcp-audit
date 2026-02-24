"""
VS Code and Continue extension MCP configuration scanner
"""

import json
import platform
from pathlib import Path

from mcp_audit.models import ScanResult


def get_vscode_paths() -> list[Path]:
    """Get VS Code settings paths for current OS"""
    paths = []
    home = Path.home()
    system = platform.system()
    
    if system == "Darwin":  # macOS
        base = home / "Library" / "Application Support"
        paths.extend([
            base / "Code" / "User" / "settings.json",
            base / "Code - Insiders" / "User" / "settings.json",
            base / "VSCodium" / "User" / "settings.json",
        ])
    elif system == "Windows":
        import os
        appdata = os.environ.get("APPDATA", "")
        if appdata:
            base = Path(appdata)
            paths.extend([
                base / "Code" / "User" / "settings.json",
                base / "Code - Insiders" / "User" / "settings.json",
                base / "VSCodium" / "User" / "settings.json",
            ])
    elif system == "Linux":
        base = home / ".config"
        paths.extend([
            base / "Code" / "User" / "settings.json",
            base / "Code - Insiders" / "User" / "settings.json",
            base / "VSCodium" / "User" / "settings.json",
        ])
    
    return paths


def get_continue_paths() -> list[Path]:
    """Get Continue extension config paths"""
    paths = []
    home = Path.home()
    
    # Continue stores config in ~/.continue
    paths.append(home / ".continue" / "config.json")
    paths.append(home / ".continue" / "config.yaml")
    
    return paths


def scan() -> list[ScanResult]:
    """Scan for VS Code and Continue MCP configurations"""
    results = []
    
    # Scan VS Code settings
    for config_path in get_vscode_paths():
        if not config_path.exists():
            continue
        
        try:
            config = json.loads(config_path.read_text())
        except (json.JSONDecodeError, IOError):
            continue
        
        # Look for MCP-related settings
        # This depends on extension implementation
        # Common patterns:
        mcp_settings = config.get("mcp.servers", {})
        if not mcp_settings:
            mcp_settings = config.get("claude.mcpServers", {})
        
        for name, server_config in mcp_settings.items():
            result = ScanResult.from_dict(
                {"name": name, **server_config},
                found_in="VS Code",
                config_path=str(config_path),
            )
            results.append(result)
    
    # Scan Continue extension
    for config_path in get_continue_paths():
        if not config_path.exists():
            continue

        try:
            if config_path.suffix == ".yaml":
                config = _parse_continue_yaml(config_path)
                if config is None:
                    continue
            else:
                config = json.loads(config_path.read_text())
        except (json.JSONDecodeError, IOError):
            continue

        # Continue >=v0.9 uses top-level "mcpServers" (list or dict)
        mcp_servers = config.get("mcpServers", [])

        # Older Continue uses "experimental" > "modelContextProtocolServers"
        if not mcp_servers:
            experimental = config.get("experimental", {})
            mcp_servers = experimental.get("modelContextProtocolServers", [])

        # mcpServers can be a list of dicts or a dict keyed by name
        if isinstance(mcp_servers, dict):
            for name, server in mcp_servers.items():
                if isinstance(server, dict):
                    result = ScanResult.from_dict(
                        {"name": name, **server},
                        found_in="Continue",
                        config_path=str(config_path),
                    )
                    results.append(result)
        elif isinstance(mcp_servers, list):
            for server in mcp_servers:
                if isinstance(server, dict):
                    name = server.get("name", server.get("transport", {}).get("command", "unknown"))
                    result = ScanResult.from_dict(
                        {"name": name, **server},
                        found_in="Continue",
                        config_path=str(config_path),
                    )
                    results.append(result)

    return results


def _parse_continue_yaml(config_path: Path) -> dict:
    """Basic YAML parsing for Continue config (no pyyaml dependency)"""
    try:
        content = config_path.read_text()
    except IOError:
        return None

    # Use the same simple YAML parser used in policy.py
    from mcp_audit.commands.policy import _parse_simple_yaml
    try:
        return _parse_simple_yaml(content)
    except Exception:
        return None
