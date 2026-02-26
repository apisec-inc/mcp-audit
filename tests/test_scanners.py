"""
Tests for MCP Audit scanners
"""

import pytest
import json
from pathlib import Path
from unittest.mock import patch, MagicMock

from mcp_audit.scanners import claude, cursor, vscode, project, docker


class TestClaudeScanner:
    """Tests for Claude Desktop scanner"""

    def test_scan_with_config(self, temp_dir, claude_desktop_config):
        """Test scanning when config exists"""
        config_path = temp_dir / "claude_desktop_config.json"
        config_path.write_text(json.dumps(claude_desktop_config))

        with patch.object(claude, 'get_config_path', return_value=config_path):
            results = claude.scan()

        assert len(results) == 3
        names = [r.name for r in results]
        assert "filesystem" in names
        assert "slack" in names
        assert "custom-tool" in names

    def test_scan_no_config(self, temp_dir):
        """Test scanning when no config exists"""
        with patch.object(claude, 'get_config_path', return_value=temp_dir / "nonexistent.json"):
            results = claude.scan()

        assert len(results) == 0

    def test_scan_invalid_json(self, temp_dir):
        """Test scanning with invalid JSON config"""
        config_path = temp_dir / "claude_desktop_config.json"
        config_path.write_text("not valid json")

        with patch.object(claude, 'get_config_path', return_value=config_path):
            results = claude.scan()

        assert len(results) == 0


class TestCursorScanner:
    """Tests for Cursor scanner"""

    def test_scan_with_config(self, temp_dir, cursor_config):
        """Test scanning when config exists"""
        config_path = temp_dir / "mcp.json"
        config_path.write_text(json.dumps(cursor_config))

        with patch.object(cursor, 'get_config_paths', return_value=[config_path]):
            results = cursor.scan()

        assert len(results) == 2
        names = [r.name for r in results]
        assert "postgres" in names
        assert "shell-tools" in names

    def test_scan_multiple_paths(self, temp_dir, cursor_config):
        """Test scanning multiple config paths"""
        path1 = temp_dir / "mcp1.json"
        path2 = temp_dir / "mcp2.json"

        path1.write_text(json.dumps({"mcpServers": {"server1": {"command": "npx", "args": ["test"]}}}))
        path2.write_text(json.dumps({"mcpServers": {"server2": {"command": "npx", "args": ["test2"]}}}))

        with patch.object(cursor, 'get_config_paths', return_value=[path1, path2]):
            results = cursor.scan()

        assert len(results) == 2


class TestProjectScanner:
    """Tests for project-level scanner"""

    def test_scan_mcp_json(self, temp_dir):
        """Test scanning mcp.json file"""
        config = {
            "mcpServers": {
                "project-server": {
                    "command": "npx",
                    "args": ["@test/mcp-server"]
                }
            }
        }
        (temp_dir / "mcp.json").write_text(json.dumps(config))

        results = project.scan(temp_dir, recursive=False)

        assert len(results) >= 1
        assert any(r.name == "project-server" for r in results)

    def test_scan_package_json_deps(self, temp_dir, package_json):
        """Test scanning package.json for MCP dependencies"""
        (temp_dir / "package.json").write_text(json.dumps(package_json))

        results = project.scan(temp_dir, recursive=False)

        # Should find MCP-related packages
        sources = [r.source for r in results]
        assert any("modelcontextprotocol" in s for s in sources) or any("mcp" in s.lower() for s in sources)

    def test_scan_recursive(self, temp_dir):
        """Test recursive scanning"""
        # Create nested structure
        subdir = temp_dir / "subproject"
        subdir.mkdir()

        config = {"mcpServers": {"nested-server": {"command": "npx", "args": ["test"]}}}
        (subdir / "mcp.json").write_text(json.dumps(config))

        results = project.scan(temp_dir, recursive=True)

        assert any(r.name == "nested-server" for r in results)

    def test_scan_skips_node_modules(self, temp_dir):
        """Test that node_modules is skipped"""
        node_modules = temp_dir / "node_modules" / "some-package"
        node_modules.mkdir(parents=True)

        # This should NOT be detected
        (node_modules / "package.json").write_text(json.dumps({
            "dependencies": {"@modelcontextprotocol/sdk": "^1.0.0"}
        }))

        results = project.scan(temp_dir, recursive=True)

        # Should not find the one in node_modules
        assert not any("some-package" in r.config_path for r in results)

    def test_scan_claude_desktop_config_in_project(self, temp_dir):
        """Test scanning claude_desktop_config.json in a project directory"""
        config = {
            "mcpServers": {
                "my-filesystem": {
                    "command": "npx",
                    "args": ["@anthropic/mcp-server-filesystem", "/home"]
                }
            }
        }
        (temp_dir / "claude_desktop_config.json").write_text(json.dumps(config))

        results = project.scan(temp_dir, recursive=False)

        assert any(r.name == "my-filesystem" for r in results)
        fs_result = next(r for r in results if r.name == "my-filesystem")
        assert "Claude Config" in fs_result.found_in

    def test_scan_claude_desktop_config_hyphen_variant(self, temp_dir):
        """Test scanning claude-desktop-config.json (hyphen variant)"""
        config = {
            "mcpServers": {
                "test-server": {
                    "command": "npx",
                    "args": ["@test/mcp-server"]
                }
            }
        }
        (temp_dir / "claude-desktop-config.json").write_text(json.dumps(config))

        results = project.scan(temp_dir, recursive=False)

        assert any(r.name == "test-server" for r in results)

    def test_scan_continue_config_in_project(self, temp_dir):
        """Test scanning continue_config.json with list-format mcpServers"""
        config = {
            "mcpServers": [
                {
                    "name": "docker-mcp",
                    "command": "docker",
                    "args": ["run", "mcp/docker"]
                }
            ]
        }
        (temp_dir / "continue_config.json").write_text(json.dumps(config))

        results = project.scan(temp_dir, recursive=False)

        assert any(r.name == "docker-mcp" for r in results)
        mcp_result = next(r for r in results if r.name == "docker-mcp")
        assert "Continue Config" in mcp_result.found_in

    def test_scan_continue_experimental_format(self, temp_dir):
        """Test scanning config with experimental.modelContextProtocolServers"""
        config = {
            "experimental": {
                "modelContextProtocolServers": [
                    {
                        "name": "legacy-server",
                        "command": "npx",
                        "args": ["@test/old-mcp"]
                    }
                ]
            }
        }
        (temp_dir / "continue_config.json").write_text(json.dumps(config))

        results = project.scan(temp_dir, recursive=False)

        assert any(r.name == "legacy-server" for r in results)

    def test_scan_mcp_manifest(self, temp_dir):
        """Test scanning mcp-manifest.json"""
        config = {
            "mcpServers": {
                "manifest-server": {
                    "command": "npx",
                    "args": ["@test/manifest-mcp"]
                }
            }
        }
        (temp_dir / "mcp-manifest.json").write_text(json.dumps(config))

        results = project.scan(temp_dir, recursive=False)

        assert any(r.name == "manifest-server" for r in results)

    def test_scan_env_file_secrets(self, temp_dir):
        """Test scanning .env file detects secrets"""
        env_content = "# Database config\nDB_HOST=localhost\nGITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\n"
        (temp_dir / ".env").write_text(env_content)

        results = project.scan(temp_dir, recursive=False)

        env_results = [r for r in results if r.server_type == "env-file"]
        assert len(env_results) == 1
        assert env_results[0].secrets
        assert any(s.type == "github_pat" for s in env_results[0].secrets)
        assert "secrets-detected" in env_results[0].risk_flags

    def test_scan_env_file_no_secrets(self, temp_dir):
        """Test scanning .env file with no secrets returns nothing"""
        env_content = "APP_NAME=my-app\nDEBUG=true\nPORT=3000\n"
        (temp_dir / ".env").write_text(env_content)

        results = project.scan(temp_dir, recursive=False)

        env_results = [r for r in results if r.server_type == "env-file"]
        assert len(env_results) == 0

    def test_scan_env_skips_node_modules(self, temp_dir):
        """Test that .env inside node_modules is skipped"""
        node_modules = temp_dir / "node_modules" / "some-pkg"
        node_modules.mkdir(parents=True)
        (node_modules / ".env").write_text("GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\n")

        results = project.scan(temp_dir, recursive=True)

        env_results = [r for r in results if r.server_type == "env-file"]
        assert len(env_results) == 0


class TestContinueScanner:
    """Tests for Continue extension scanner (new mcpServers format)"""

    def test_continue_new_dict_format(self, temp_dir):
        """Test Continue config with top-level mcpServers as dict"""
        config = {
            "models": [{"title": "Ollama", "provider": "ollama"}],
            "mcpServers": {
                "MCP_DOCKER": {
                    "command": "docker",
                    "args": ["run", "-i", "mcp/docker"]
                }
            }
        }
        config_path = temp_dir / "config.json"
        config_path.write_text(json.dumps(config))

        with patch.object(vscode, 'get_vscode_paths', return_value=[]),\
             patch.object(vscode, 'get_continue_paths', return_value=[config_path]):
            results = vscode.scan()

        assert len(results) == 1
        assert results[0].name == "MCP_DOCKER"
        assert results[0].found_in == "Continue"

    def test_continue_new_list_format(self, temp_dir):
        """Test Continue config with top-level mcpServers as list"""
        config = {
            "mcpServers": [
                {
                    "name": "my-mcp",
                    "command": "npx",
                    "args": ["@test/mcp-server"]
                }
            ]
        }
        config_path = temp_dir / "config.json"
        config_path.write_text(json.dumps(config))

        with patch.object(vscode, 'get_vscode_paths', return_value=[]),\
             patch.object(vscode, 'get_continue_paths', return_value=[config_path]):
            results = vscode.scan()

        assert len(results) == 1
        assert results[0].name == "my-mcp"
        assert results[0].found_in == "Continue"

    def test_continue_old_experimental_format(self, temp_dir):
        """Test Continue config with old experimental.modelContextProtocolServers"""
        config = {
            "experimental": {
                "modelContextProtocolServers": [
                    {
                        "name": "old-server",
                        "command": "npx",
                        "args": ["@test/old-mcp"]
                    }
                ]
            }
        }
        config_path = temp_dir / "config.json"
        config_path.write_text(json.dumps(config))

        with patch.object(vscode, 'get_vscode_paths', return_value=[]),\
             patch.object(vscode, 'get_continue_paths', return_value=[config_path]):
            results = vscode.scan()

        assert len(results) == 1
        assert results[0].name == "old-server"

    def test_continue_no_config(self, temp_dir):
        """Test Continue scanner when no config exists"""
        with patch.object(vscode, 'get_vscode_paths', return_value=[]),\
             patch.object(vscode, 'get_continue_paths', return_value=[temp_dir / "nonexistent.json"]):
            results = vscode.scan()

        assert len(results) == 0

    def test_continue_multiple_servers(self, temp_dir):
        """Test Continue config with multiple MCP servers"""
        config = {
            "mcpServers": {
                "docker-mcp": {
                    "command": "docker",
                    "args": ["run", "mcp/docker"]
                },
                "filesystem": {
                    "command": "npx",
                    "args": ["@anthropic/mcp-server-filesystem", "/home"]
                }
            }
        }
        config_path = temp_dir / "config.json"
        config_path.write_text(json.dumps(config))

        with patch.object(vscode, 'get_vscode_paths', return_value=[]),\
             patch.object(vscode, 'get_continue_paths', return_value=[config_path]):
            results = vscode.scan()

        assert len(results) == 2
        names = [r.name for r in results]
        assert "docker-mcp" in names
        assert "filesystem" in names


class TestDockerScanner:
    """Tests for Docker Compose MCP scanner"""

    def test_scan_docker_compose_mcp(self, temp_dir):
        """Test scanning Docker Compose with MCP service"""
        compose_content = """version: '3'
services:
  mcp-server:
    image: mcp-server-docker:latest
    ports:
      - "8080:8080"
"""
        (temp_dir / "docker-compose.yml").write_text(compose_content)

        results = docker.scan(temp_dir, recursive=False)

        assert len(results) >= 1
        assert any("mcp" in r.name.lower() for r in results)

    def test_scan_no_docker_compose(self, temp_dir):
        """Test scanning when no Docker Compose file exists"""
        results = docker.scan(temp_dir, recursive=False)

        assert len(results) == 0

    def test_scan_docker_compose_no_mcp(self, temp_dir):
        """Test scanning Docker Compose without MCP services"""
        compose_content = """version: '3'
services:
  web:
    image: nginx:latest
    ports:
      - "80:80"
"""
        (temp_dir / "docker-compose.yml").write_text(compose_content)

        results = docker.scan(temp_dir, recursive=False)

        assert len(results) == 0


class TestRiskDetection:
    """Tests for risk flag detection in scanners"""

    def test_filesystem_server_flags(self, temp_dir):
        """Test filesystem server gets correct flags"""
        config = {
            "mcpServers": {
                "filesystem": {
                    "command": "npx",
                    "args": ["@anthropic/mcp-server-filesystem", "/home/user"]
                }
            }
        }
        (temp_dir / "mcp.json").write_text(json.dumps(config))

        results = project.scan(temp_dir, recursive=False)
        fs_result = next((r for r in results if r.name == "filesystem"), None)

        assert fs_result is not None
        assert "filesystem-access" in fs_result.risk_flags

    def test_shell_server_flags(self, temp_dir):
        """Test shell server gets high risk flags"""
        config = {
            "mcpServers": {
                "shell": {
                    "command": "uvx",
                    "args": ["mcp-shell-tools"]
                }
            }
        }
        (temp_dir / "mcp.json").write_text(json.dumps(config))

        results = project.scan(temp_dir, recursive=False)
        shell_result = next((r for r in results if r.name == "shell"), None)

        assert shell_result is not None
        assert "shell-access" in shell_result.risk_flags
