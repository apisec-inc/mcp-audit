"""
Tests for MCP Audit data models
"""

import pytest
from mcp_audit.models import ScanResult, CollectedConfig, _parse_source, _identify_risks
from mcp_audit.data.allowlist_bypass_binaries import (
    ARG_INJECTION_PRONE_BINARIES,
    detect_unsafe_command_allowlist,
    get_reason,
    is_allowlist_env_key,
)


class TestScanResult:
    """Tests for ScanResult model"""

    def test_from_dict_npm_package(self):
        """Test creating ScanResult from npm package config"""
        data = {
            "name": "filesystem",
            "command": "npx",
            "args": ["@anthropic/mcp-server-filesystem", "/home/user"]
        }

        result = ScanResult.from_dict(data, found_in="Claude Desktop", config_path="/test/path")

        assert result.name == "filesystem"
        assert result.source == "@anthropic/mcp-server-filesystem"
        assert result.server_type == "npm"
        assert result.found_in == "Claude Desktop"
        assert "filesystem-access" in result.risk_flags

    def test_from_dict_python_package(self):
        """Test creating ScanResult from Python package config"""
        data = {
            "name": "shell-tools",
            "command": "uvx",
            "args": ["mcp-shell-tools"]
        }

        result = ScanResult.from_dict(data, found_in="Cursor", config_path="/test/path")

        assert result.name == "shell-tools"
        assert result.source == "mcp-shell-tools"
        assert result.server_type == "python"
        assert "shell-access" in result.risk_flags

    def test_from_dict_local_binary(self):
        """Test creating ScanResult from local binary config"""
        data = {
            "name": "custom-tool",
            "command": "./local/my-server.py",
            "args": []
        }

        result = ScanResult.from_dict(data, found_in="VS Code", config_path="/test/path")

        assert result.name == "custom-tool"
        assert result.server_type == "local"
        assert "local-binary" in result.risk_flags

    def test_from_dict_with_secrets_in_env(self):
        """Test detecting secrets in environment variables"""
        data = {
            "name": "postgres",
            "command": "npx",
            "args": ["server-postgres"],
            "env": {
                "POSTGRES_PASSWORD": "secret123"
            }
        }

        result = ScanResult.from_dict(data, found_in="Cursor", config_path="/test/path")

        # Value matches password pattern, so it's detected as an actual secret
        assert "secrets-detected" in result.risk_flags
        assert len(result.secrets) > 0

    def test_to_dict(self):
        """Test ScanResult serialization"""
        result = ScanResult(
            name="test",
            source="test-source",
            found_in="Test App",
            server_type="npm",
            config_path="/test/path",
            risk_flags=["test-risk"]
        )

        data = result.to_dict()

        assert data["name"] == "test"
        assert data["source"] == "test-source"
        assert data["risk_flags"] == ["test-risk"]


class TestCollectedConfig:
    """Tests for CollectedConfig model"""

    def test_from_dict(self, collected_config):
        """Test parsing collected config"""
        config = CollectedConfig.from_dict(collected_config, source_file="test.json")

        assert config.machine_id == "dev-machine-001"
        assert config.collected_at == "2024-01-15T10:30:00Z"
        assert len(config.mcps) == 2
        assert config.mcps[0].name == "filesystem"
        assert config.mcps[1].name == "github"

    def test_to_dict(self):
        """Test CollectedConfig serialization"""
        config = CollectedConfig(
            machine_id="test-machine",
            collected_at="2024-01-01T00:00:00Z",
            source_file="test.json",
            mcps=[]
        )

        data = config.to_dict()

        assert data["machine_id"] == "test-machine"
        assert data["mcps"] == []


class TestParseSource:
    """Tests for source parsing"""

    def test_npx_package(self):
        """Test parsing npx packages"""
        source, server_type = _parse_source("npx", ["@anthropic/mcp-server-filesystem"])
        assert source == "@anthropic/mcp-server-filesystem"
        assert server_type == "npm"

    def test_npx_with_y_flag(self):
        """Test parsing npx packages with -y flag"""
        source, server_type = _parse_source("npx", ["-y", "@modelcontextprotocol/server-github"])
        assert source == "@modelcontextprotocol/server-github"
        assert server_type == "npm"

    def test_python_uvx(self):
        """Test parsing uvx packages"""
        source, server_type = _parse_source("uvx", ["fastmcp"])
        assert source == "fastmcp"
        assert server_type == "python"

    def test_docker(self):
        """Test parsing docker commands"""
        source, server_type = _parse_source("docker", ["run", "mcp-server:latest"])
        assert source == "mcp-server:latest"
        assert server_type == "docker"

    def test_local_path(self):
        """Test parsing local paths"""
        source, server_type = _parse_source("./local/server.py", [])
        assert source == "./local/server.py"
        assert server_type == "local"

    def test_remote_url(self):
        """Test parsing remote URL-based MCPs"""
        source, server_type = _parse_source("", [], {"url": "https://mcp.github.com/sse"})
        assert source == "https://mcp.github.com/sse"
        assert server_type == "remote"

    def test_remote_server_url(self):
        """Test parsing remote serverUrl-based MCPs"""
        source, server_type = _parse_source("", [], {"serverUrl": "https://api.example.com/mcp"})
        assert source == "https://api.example.com/mcp"
        assert server_type == "remote"

    def test_remote_sse_transport(self):
        """Test parsing SSE transport MCPs"""
        source, server_type = _parse_source("", [], {"transport": "sse", "baseUrl": "https://mcp.linear.app"})
        assert source == "https://mcp.linear.app"
        assert server_type == "remote"


class TestIdentifyRisks:
    """Tests for risk identification"""

    def test_filesystem_access(self):
        """Test filesystem access detection"""
        risks = _identify_risks("npx", ["@anthropic/mcp-server-filesystem", "/home"], {}, "filesystem")
        assert "filesystem-access" in risks

    def test_database_access(self):
        """Test database access detection"""
        risks = _identify_risks("npx", ["server-postgres"], {}, "postgres")
        assert "database-access" in risks

    def test_shell_access(self):
        """Test shell access detection"""
        risks = _identify_risks("npx", [], {}, "shell-tools")
        assert "shell-access" in risks

    def test_secrets_in_env(self):
        """Test secrets detection in env vars"""
        risks = _identify_risks("npx", [], {"API_KEY": "test"}, "test")
        assert "secrets-in-env" in risks

    def test_unverified_source(self):
        """Test unverified source detection"""
        risks = _identify_risks("npx", ["random-mcp-server"], {}, "test")
        assert "unverified-source" in risks

    def test_verified_source(self):
        """Test verified source is not flagged"""
        risks = _identify_risks("npx", ["@anthropic/mcp-server"], {}, "test")
        assert "unverified-source" not in risks


class TestUnsafeCommandAllowlist:
    """Tests for the unsafe-command-allowlist flag (argv[0]-only allowlists)"""

    # Configs that MUST flag: an allowlist-style key naming a bare binary that
    # has an argument-level execution primitive.
    FLAGGED = [
        ({"ALLOW_COMMANDS": "git"}, ["git"]),
        ({"ALLOWED_COMMANDS": "ls,git,cat"}, ["git"]),
        ({"ALLOWED_PATTERNS": "find,ls"}, ["find"]),
        ({"COMMAND_ALLOWLIST": "tar"}, ["tar"]),
        ({"ALLOWLIST_COMMANDS": "npx"}, ["npx"]),
        ({"MCP_ALLOW_COMMANDS": "python3"}, ["python3"]),
        ({"ALLOW-COMMANDS": "perl"}, ["perl"]),  # dashes normalize to underscores
        ({"allow_commands": "GIT"}, ["git"]),  # case-insensitive both sides
        ({"ALLOW_COMMANDS": "/usr/bin/find"}, ["find"]),  # path form
        ({"ALLOW_COMMANDS": r"C:\tools\git"}, ["git"]),  # windows path form
        ({"ALLOW_PATTERNS": "^git$"}, ["git"]),  # anchored regex entry
        ({"ALLOW_COMMANDS": '"git";sed'}, ["git", "sed"]),  # quotes + ; separator
        ({"ALLOW_COMMANDS": "ls\nawk"}, ["awk"]),  # newline separator
        ({"ALLOW_COMMANDS": ["git", "ls"]}, ["git"]),  # list-valued env var
        # Binaries added on maintainer request
        ({"ALLOW_COMMANDS": "bash"}, ["bash"]),
        ({"ALLOW_COMMANDS": "sh"}, ["sh"]),
        ({"ALLOW_COMMANDS": "env"}, ["env"]),
        ({"ALLOW_COMMANDS": "xargs"}, ["xargs"]),
        ({"ALLOW_COMMANDS": "ssh"}, ["ssh"]),
    ]

    # Configs that MUST NOT flag. A false positive on a correct config is
    # expensive because this flag is critical severity.
    NOT_FLAGGED = [
        # Denylists are the opposite of this risk
        {"DISALLOW_COMMANDS": "git"},
        {"DISALLOWED_COMMANDS": "git"},
        {"DENY_COMMANDS": "git"},
        {"DENIED_COMMANDS": "git"},
        {"BLOCKED_COMMANDS": "git"},
        {"COMMAND_DENYLIST": "git"},
        {"COMMAND_BLOCKLIST": "git"},
        {"NO_ALLOW_COMMANDS": "git"},
        # Toggles that merely mention commands
        {"ALLOW_COMMAND_LOGGING": "true"},
        {"ALLOW_COMMAND_LOGGING": "git"},
        {"ALLOW_COMMANDS_ENABLED": "git"},
        # Unrelated keys
        {"GIT_COMMAND": "git"},
        {"COMMAND": "git"},
        {"ALLOW_ORIGINS": "git"},
        # Allowlists of binaries with no argument-level execution primitive
        {"ALLOW_COMMANDS": "ls,cat,echo"},
        # Full-argument-vector allowlists — the pattern this flag recommends
        {"ALLOW_COMMANDS": "git status"},
        {"ALLOW_COMMANDS": "git status,ls -la"},
        {"ALLOW_PATTERNS": "^git status$"},
        # Nothing to match
        {},
        {"ALLOW_COMMANDS": ""},
    ]

    @pytest.mark.parametrize("env,expected", FLAGGED)
    def test_flagged_allowlists(self, env, expected):
        """Bare risky binaries behind an allowlist key are flagged"""
        assert detect_unsafe_command_allowlist(env) == expected
        risks = _identify_risks("uvx", ["mcp-shell-server"], env, "runner")
        assert ("unsafe-command-allowlist" in risks) is bool(expected)

    @pytest.mark.parametrize("env", NOT_FLAGGED)
    def test_not_flagged_allowlists(self, env):
        """Denylists, toggles, safe binaries and full-argv allowlists are not flagged"""
        assert detect_unsafe_command_allowlist(env) == []
        risks = _identify_risks("uvx", ["mcp-shell-server"], env, "runner")
        assert "unsafe-command-allowlist" not in risks

    @pytest.mark.parametrize(
        "key",
        [
            "ALLOW_COMMANDS",
            "ALLOWED_COMMANDS",
            "ALLOW_PATTERNS",
            "ALLOWED_PATTERNS",
            "COMMAND_ALLOWLIST",
            "ALLOWLIST_COMMANDS",
            "MCP_ALLOW_COMMANDS",
            "WHITELIST_BINARIES",
            "allow_cmds",
        ],
    )
    def test_allowlist_key_recognized(self, key):
        """Allowlist-style keys are recognized"""
        assert is_allowlist_env_key(key) is True

    @pytest.mark.parametrize(
        "key",
        [
            "DISALLOW_COMMANDS",
            "DISALLOWED_COMMANDS",
            "DENY_COMMANDS",
            "BLOCKED_COMMANDS",
            "COMMAND_DENYLIST",
            "NO_ALLOW_COMMANDS",
            "ALLOW_COMMAND_LOGGING",
            "ALLOW_COMMANDS_ENABLED",
            "GIT_COMMAND",
            "ALLOW_ORIGINS",
            "",
        ],
    )
    def test_non_allowlist_key_rejected(self, key):
        """Deny-style keys, toggles and unrelated keys are not allowlist keys"""
        assert is_allowlist_env_key(key) is False

    def test_reason_available_for_every_binary(self):
        """Every listed binary carries a one-line execution-primitive description"""
        for binary in ARG_INJECTION_PRONE_BINARIES:
            assert get_reason(binary).strip()

    def test_from_dict_unsafe_command_allowlist(self):
        """Test ALLOW_COMMANDS=git allowlist is flagged end-to-end"""
        data = {
            "name": "shell",
            "command": "uvx",
            "args": ["mcp-shell-server"],
            "env": {"ALLOW_COMMANDS": "git"}
        }

        result = ScanResult.from_dict(data, found_in="Cursor", config_path="/test/path")

        assert "unsafe-command-allowlist" in result.risk_flags

    def test_from_dict_clean_command_allowlist(self):
        """Test an allowlist of safe binaries is not flagged end-to-end"""
        data = {
            "name": "notes",
            "command": "uvx",
            "args": ["mcp-notes-server"],
            "env": {"ALLOW_COMMANDS": "ls,cat,echo"}
        }

        result = ScanResult.from_dict(data, found_in="Cursor", config_path="/test/path")

        assert "unsafe-command-allowlist" not in result.risk_flags

    def test_from_dict_denylist_not_flagged(self):
        """Test a DISALLOW_COMMANDS denylist is not flagged end-to-end"""
        data = {
            "name": "notes",
            "command": "uvx",
            "args": ["mcp-notes-server"],
            "env": {"DISALLOW_COMMANDS": "git"}
        }

        result = ScanResult.from_dict(data, found_in="Cursor", config_path="/test/path")

        assert "unsafe-command-allowlist" not in result.risk_flags


class TestRegistryEnrichment:
    """Tests for registry matching and enrichment"""

    def test_enrich_known_mcp(self):
        """Test enriching with known MCP from registry"""
        result = ScanResult(
            name="filesystem",
            source="@anthropic/mcp-server-filesystem",
            found_in="Claude Desktop",
            server_type="npm",
            config_path="/test/path"
        )

        result.enrich_from_registry()

        assert result.is_known is True
        assert result.provider == "Anthropic"
        assert result.mcp_type == "official"
        assert result.registry_risk == "high"
        assert result.verified is True
        assert "file-read" in result.capabilities

    def test_enrich_unknown_mcp(self):
        """Test enriching with unknown MCP"""
        result = ScanResult(
            name="custom-tool",
            source="random-unknown-mcp-server",
            found_in="Cursor",
            server_type="npm",
            config_path="/test/path"
        )

        result.enrich_from_registry()

        assert result.is_known is False
        assert result.provider == "Unknown"
        assert result.mcp_type == "unknown"
        assert result.registry_risk == "unknown"
        assert result.verified is False

    def test_enrich_vendor_mcp(self):
        """Test enriching with vendor MCP"""
        result = ScanResult(
            name="stripe",
            source="stripe-mcp",
            found_in="Claude Desktop",
            server_type="npm",
            config_path="/test/path"
        )

        result.enrich_from_registry()

        assert result.is_known is True
        assert result.provider == "Stripe"
        assert result.mcp_type == "vendor"
        assert result.verified is True

    def test_to_dict_with_registry_info(self):
        """Test serialization includes registry info"""
        result = ScanResult(
            name="filesystem",
            source="@anthropic/mcp-server-filesystem",
            found_in="Claude Desktop",
            server_type="npm",
            config_path="/test/path"
        )

        result.enrich_from_registry()
        data = result.to_dict()

        assert "registry" in data
        assert data["registry"]["is_known"] is True
        assert data["registry"]["provider"] == "Anthropic"
        assert data["registry"]["type"] == "official"

    def test_enrich_remote_mcp_by_name(self):
        """Test enriching remote MCP matched by name"""
        result = ScanResult(
            name="github",
            source="https://mcp.github.com/sse",
            found_in="Cursor",
            server_type="remote",
            config_path="/test/path"
        )

        result.enrich_from_registry()

        assert result.is_known is True
        assert result.provider == "GitHub"
        assert result.mcp_type == "vendor"
        assert result.verified is True

    def test_enrich_remote_mcp_by_endpoint(self):
        """Test enriching remote MCP matched by endpoint URL"""
        result = ScanResult(
            name="some-random-name",
            source="https://mcp.github.com/sse",
            found_in="Cursor",
            server_type="remote",
            config_path="/test/path"
        )

        result.enrich_from_registry()

        # Should match by endpoint domain
        assert result.is_known is True
        assert result.provider == "GitHub"

    def test_from_dict_remote_mcp(self):
        """Test creating ScanResult from remote MCP config"""
        data = {
            "name": "github",
            "url": "https://mcp.github.com/sse",
            "transport": "sse"
        }

        result = ScanResult.from_dict(data, found_in="Cursor", config_path="/test/path")

        assert result.name == "github"
        assert result.source == "https://mcp.github.com/sse"
        assert result.server_type == "remote"
        assert "remote-mcp" in result.risk_flags
