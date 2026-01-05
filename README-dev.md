# MCP Audit

**Discover and audit MCP (Model Context Protocol) servers across your organization.**

MCP servers are plugins that give AI assistants special abilities - like reading files, accessing databases, or connecting to services. MCP Audit helps you find and assess these plugins for security risks.

---

## Two Ways to Use MCP Audit

| | **Web App** | **CLI Tool** |
|---|-------------|--------------|
| **What it scans** | GitHub repositories | Your local computer |
| **Installation** | None - runs in browser | Requires Python |
| **Best for** | Quick org-wide visibility | Deep local analysis |
| **Privacy** | Token stays in browser | Runs 100% locally |

---

## Quick Start

### Option 1: Web App (No Installation)

1. Open `webapp/index.html` in your browser
2. Enter a GitHub Personal Access Token ([create one here](https://github.com/settings/tokens/new?scopes=repo,read:org))
3. Select your organization and scan
4. Export results as JSON, CSV, or Markdown

### Option 2: CLI Tool

**Download from Web App:** Open the web app and click "Download CLI Tool" at the bottom of the page.

**Or install from source:**
```bash
# Navigate to the mcp-audit folder
cd /path/to/mcp-audit

# Install the CLI tool
pip install -e .

# Now you can run from anywhere:
mcp-audit scan

# View known MCP registry
mcp-audit registry

# Look up a specific MCP
mcp-audit registry lookup "@anthropic/mcp-server-filesystem"
```

> **Note**: The CLI requires Python 3.9+ and pip installed on your system.

---

## What It Finds

MCP Audit scans for configurations in:

- **Claude Desktop** - Anthropic's desktop app
- **Cursor** - AI-powered code editor
- **VS Code** - With Continue extension
- **Windsurf** - Codeium's editor
- **Zed** - Modern code editor
- **Project folders** - `.mcp/` directories, `mcp.json` files

---

## Understanding Results

### Risk Levels

| Level | Meaning |
|-------|---------|
| 🔴 **CRITICAL** | Full access to databases, cloud, payments |
| 🟠 **HIGH** | Write access to important systems |
| 🟡 **MEDIUM** | Read/write business data |
| 🟢 **LOW** | Read-only or limited access |

### Known vs Unknown MCPs

- ✅ **Known** - In our registry of 46+ verified MCP servers
- ❌ **Unknown** - Not in registry, may need security review

### Risk Flags

| Flag | What It Means |
|------|---------------|
| `filesystem-access` | Can read/write files |
| `database-access` | Can access databases |
| `shell-access` | Can run commands |
| `secrets-in-env` | Has passwords/keys in config |
| `unverified-source` | Not from trusted publisher |

---

## CLI Commands

### Scan for MCPs

```bash
# Basic scan
mcp-audit scan

# Verbose output
mcp-audit scan --verbose

# Scan specific folder
mcp-audit scan --path ./my-project

# Export to file
mcp-audit scan --format json --output results.json
```

### View MCP Registry

```bash
# List all known MCPs
mcp-audit registry

# Filter by risk level
mcp-audit registry --risk critical

# Look up specific MCP
mcp-audit registry lookup "stripe-mcp"

# View statistics
mcp-audit registry stats
```

### Trust & Policy

```bash
# Check trust scores (queries npm/GitHub)
mcp-audit scan --with-trust

# Validate against security policy
mcp-audit policy validate --policy policies/strict.yaml
```

---

## Example Output

```
MCP Audit - Local Scan

                              MCP Inventory
┏━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━┳━━━━━━━┓
┃ MCP Name   ┃ Source                      ┃ Found In       ┃ Known ┃ Risk  ┃
┡━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━╇━━━━━━━┩
│ filesystem │ @anthropic/mcp-server-files │ Claude Desktop │ Yes   │ HIGH  │
│ slack      │ @modelcontextprotocol/slack │ Claude Desktop │ Yes   │ MEDIUM│
│ my-tool    │ ./local/server.py           │ Cursor         │ No    │ -     │
└────────────┴─────────────────────────────┴────────────────┴───────┴───────┘

Summary
  Total MCPs found: 3
  Known MCPs: 2
  Unknown MCPs: 1
```

---

## For Organizations

### MDM Collection (Org-Wide Visibility)

Deploy collector scripts to gather MCP configs from all developer machines:

```bash
# macOS/Linux
./mdm-collectors/collect-macos.sh

# Windows
.\mdm-collectors\collect-windows.ps1

# Analyze collected configs
mcp-audit analyze /path/to/collected/
```

### CI/CD Integration

Add to your GitHub Actions workflow:

```yaml
- name: MCP Audit
  run: |
    pip install mcp-audit
    mcp-audit scan --path . --format json --output mcp-report.json
```

---

## Documentation

- 📖 **[User Guide](docs/USER_GUIDE.md)** - Detailed instructions for all features
- 🔒 **[Security Policies](policies/)** - Sample security policies (strict, permissive, enterprise)
- 🧪 **[Test Suite](tests/)** - 88 automated tests

---

## Privacy & Security

- **Web App**: Your GitHub token and code never leave your browser
- **CLI Tool**: Runs 100% locally on your machine
- **No telemetry**: We don't collect any data

---

## Installation & Development

### Installing the CLI Tool

```bash
# 1. Navigate to the mcp-audit folder
cd /path/to/mcp-audit

# 2. Install with pip
pip install -e .

# 3. Verify installation
mcp-audit --help
```

If `mcp-audit` is not found after installation, you may need to use the full path:
```bash
# Find where it was installed
pip show mcp-audit

# Or run directly with Python
python -m mcp_audit.cli --help
```

### Running the Web App

```bash
# Navigate to webapp folder and start a local server
cd /path/to/mcp-audit/webapp
python -m http.server 2000

# Open in browser
open http://localhost:2000
```

### Running Tests

```bash
cd /path/to/mcp-audit
pytest
```

---

## License

MIT License - see [LICENSE](LICENSE)

---

Built with Claude Code
