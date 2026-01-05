"""
Data models for MCP Audit
"""

from dataclasses import dataclass, field
from typing import Optional
from pathlib import Path


@dataclass
class DetectedSecret:
    """A detected secret in MCP configuration"""
    type: str  # e.g., "aws_access_key", "github_pat"
    description: str  # Human-readable description
    severity: str  # critical, high, medium
    env_key: str  # The environment variable key
    value_masked: str  # Masked value for display
    value_length: int  # Length of original value
    confidence: str  # high, medium
    rotation_url: Optional[str] = None  # URL to rotate the credential

    def to_dict(self) -> dict:
        return {
            "type": self.type,
            "description": self.description,
            "severity": self.severity,
            "env_key": self.env_key,
            "value_masked": self.value_masked,
            "value_length": self.value_length,
            "confidence": self.confidence,
            "rotation_url": self.rotation_url,
        }


@dataclass
class ScanResult:
    """Result of scanning a single MCP configuration"""
    name: str
    source: str  # e.g., "@anthropic/mcp-server-filesystem" or "npx ..."
    found_in: str  # e.g., "Claude Desktop", "Cursor", "VS Code"
    server_type: str  # "npm", "python", "local", "docker", "unknown"
    config_path: str  # Path where config was found
    command: Optional[str] = None  # The command used to run the MCP
    args: list[str] = field(default_factory=list)  # Arguments passed
    env: dict[str, str] = field(default_factory=dict)  # Environment variables
    risk_flags: list[str] = field(default_factory=list)  # Identified risks
    raw_config: dict = field(default_factory=dict)  # Original config data
    secrets: list = field(default_factory=list)  # Detected secrets (list of DetectedSecret)
    # Registry match fields
    is_known: bool = False  # Whether found in known MCP registry
    provider: Optional[str] = None  # Provider from registry
    mcp_type: Optional[str] = None  # Type: official, vendor, community
    registry_risk: Optional[str] = None  # Risk level from registry
    verified: bool = False  # Whether verified in registry
    capabilities: list[str] = field(default_factory=list)  # Capabilities from registry

    def to_dict(self) -> dict:
        result = {
            "name": self.name,
            "source": self.source,
            "found_in": self.found_in,
            "server_type": self.server_type,
            "config_path": self.config_path,
            "command": self.command,
            "args": self.args,
            "env": {k: v for k, v in self.env.items()},  # Sanitize env
            "risk_flags": self.risk_flags,
        }
        # Add secrets if detected (always masked)
        if self.secrets:
            result["secrets"] = [s.to_dict() if hasattr(s, 'to_dict') else s for s in self.secrets]
        # Add registry info if available
        if self.is_known:
            result["registry"] = {
                "is_known": self.is_known,
                "provider": self.provider,
                "type": self.mcp_type,
                "risk_level": self.registry_risk,
                "verified": self.verified,
                "capabilities": self.capabilities,
            }
        return result

    def enrich_from_registry(self):
        """Enrich scan result with data from known MCP registry"""
        from mcp_audit.data import lookup_mcp

        # Pass both source and name for better matching (especially for remote MCPs)
        match = lookup_mcp(self.source, self.name)
        if match:
            self.is_known = True
            self.provider = match["provider"]
            self.mcp_type = match["type"]
            self.registry_risk = match["risk_level"]
            self.verified = match.get("verified", False)
            self.capabilities = match.get("capabilities", [])
        else:
            self.is_known = False
            self.provider = "Unknown"
            self.mcp_type = "unknown"
            self.registry_risk = "unknown"
            self.verified = False
            self.capabilities = []
    
    @classmethod
    def from_dict(cls, data: dict, found_in: str, config_path: str) -> "ScanResult":
        """Create ScanResult from raw config data"""
        name = data.get("name", "unknown")
        command = data.get("command", "")
        args = data.get("args", [])
        env = data.get("env", {})

        # Determine source and type (pass raw config for URL detection)
        source, server_type = _parse_source(command, args, data)

        # Identify risk flags
        risk_flags = _identify_risks(command, args, env, name)

        # Detect secrets in environment variables
        secrets = _detect_secrets_in_env(env, config_path, name)

        # Add secrets-detected flag if secrets found
        if secrets:
            if "secrets-detected" not in risk_flags:
                risk_flags.append("secrets-detected")
            # Remove the weaker secrets-in-env flag if we have actual secrets
            if "secrets-in-env" in risk_flags:
                risk_flags.remove("secrets-in-env")

        # Add remote-mcp flag for URL-based MCPs
        if server_type == "remote":
            if "remote-mcp" not in risk_flags:
                risk_flags.append("remote-mcp")

        return cls(
            name=name,
            source=source,
            found_in=found_in,
            server_type=server_type,
            config_path=config_path,
            command=command,
            args=args,
            env=env,
            risk_flags=risk_flags,
            raw_config=data,
            secrets=secrets,
        )


@dataclass
class CollectedConfig:
    """Configuration collected from a developer machine via MDM"""
    machine_id: str
    collected_at: str
    source_file: str
    mcps: list[ScanResult] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            "machine_id": self.machine_id,
            "collected_at": self.collected_at,
            "source_file": self.source_file,
            "mcps": [m.to_dict() for m in self.mcps],
        }
    
    @classmethod
    def from_dict(cls, data: dict, source_file: str = "") -> "CollectedConfig":
        """Parse collected config from MDM script output"""
        machine_id = data.get("machine_id", "unknown")
        collected_at = data.get("collected_at", "")
        
        mcps = []
        for mcp_data in data.get("mcps", []):
            # Each MCP in collected data has name and config
            found_in = mcp_data.get("found_in", "collected")
            config_path = mcp_data.get("config_path", "")
            
            result = ScanResult.from_dict(
                mcp_data.get("config", mcp_data),
                found_in=found_in,
                config_path=config_path,
            )
            result.name = mcp_data.get("name", result.name)
            mcps.append(result)
        
        return cls(
            machine_id=machine_id,
            collected_at=collected_at,
            source_file=source_file,
            mcps=mcps,
        )


def _parse_source(command: str, args: list[str], raw_config: dict = None) -> tuple[str, str]:
    """Parse command/args to determine source and server type"""
    command = command or ""
    raw_config = raw_config or {}

    # Check for remote/URL-based MCP first (SSE, HTTP endpoints)
    url = (
        raw_config.get("url") or
        raw_config.get("serverUrl") or
        raw_config.get("endpoint") or
        raw_config.get("uri")
    )
    if url:
        return url, "remote"

    # Check for transport-based config (some configs specify transport separately)
    transport = raw_config.get("transport", "").lower()
    if transport in ("sse", "http", "https", "websocket"):
        # Try to find URL in other fields
        for key in ["baseUrl", "host", "server"]:
            if raw_config.get(key):
                return raw_config[key], "remote"
        return f"remote:{transport}", "remote"

    # NPX packages
    if command == "npx" and args:
        # Skip -y flag if present
        package_args = [a for a in args if a != "-y"]
        package = package_args[0] if package_args else "unknown"
        return package, "npm"

    # Node with package
    if command == "node" and args:
        return args[0], "node"

    # Python/uvx
    if command in ("python", "python3", "uvx", "uv"):
        if args:
            return args[0], "python"
        return command, "python"

    # Docker
    if command == "docker":
        if "run" in args:
            idx = args.index("run")
            if idx + 1 < len(args):
                return args[idx + 1], "docker"
        return "docker", "docker"

    # Direct path
    if command.startswith("/") or command.startswith("./"):
        return command, "local"

    # Unknown
    return command or "unknown", "unknown"


def _identify_risks(command: str, args: list[str], env: dict, name: str) -> list[str]:
    """Identify potential risk flags from MCP configuration"""
    risks = []
    
    # Check for filesystem access
    filesystem_keywords = ["filesystem", "fs", "file", "directory", "path"]
    all_args = " ".join(args).lower()
    name_lower = name.lower()
    
    if any(kw in name_lower or kw in all_args for kw in filesystem_keywords):
        # Check if write access might be granted
        if any(p in all_args for p in ["/", "~", "$HOME", "."]):
            risks.append("filesystem-access")
    
    # Check for database access
    db_keywords = ["postgres", "mysql", "sqlite", "mongo", "redis", "database", "db"]
    if any(kw in name_lower or kw in all_args for kw in db_keywords):
        risks.append("database-access")
    
    # Check for shell/command execution
    shell_keywords = ["shell", "exec", "command", "bash", "terminal"]
    if any(kw in name_lower or kw in all_args for kw in shell_keywords):
        risks.append("shell-access")
    
    # Check for API/network access
    api_keywords = ["http", "api", "fetch", "request", "url"]
    if any(kw in name_lower or kw in all_args for kw in api_keywords):
        risks.append("network-access")
    
    # Check for secrets in env
    secret_keywords = ["key", "secret", "token", "password", "credential", "api_key"]
    for key in env.keys():
        if any(kw in key.lower() for kw in secret_keywords):
            risks.append("secrets-in-env")
            break
    
    # Check for unverified source
    if command == "npx":
        package = args[0] if args else ""
        # Verified publishers
        verified = ["@anthropic/", "@modelcontextprotocol/", "@openai/"]
        if not any(package.startswith(v) for v in verified):
            if not package.startswith("@"):  # Unscoped packages
                risks.append("unverified-source")
    
    # Check for local/unknown source
    if command and (command.startswith("./") or command.startswith("/")):
        risks.append("local-binary")

    return risks


def _detect_secrets_in_env(env: dict, config_path: str = None, mcp_name: str = None) -> list:
    """
    Detect secrets in MCP environment variables.
    Returns list of DetectedSecret objects.
    """
    try:
        from mcp_audit.data.secret_patterns import detect_secrets
    except ImportError:
        return []

    if not env:
        return []

    raw_secrets = detect_secrets(env, config_path, mcp_name)

    # Convert to DetectedSecret objects
    secrets = []
    for s in raw_secrets:
        secrets.append(DetectedSecret(
            type=s["type"],
            description=s["description"],
            severity=s["severity"],
            env_key=s["env_key"],
            value_masked=s["value_masked"],
            value_length=s["value_length"],
            confidence=s["confidence"],
            rotation_url=s.get("rotation_url"),
        ))

    return secrets
