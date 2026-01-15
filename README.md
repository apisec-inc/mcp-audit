# MCP Audit

**APIsec MCP Audit shows you what your AI agents can touch - before they go live.**

As developers connect Claude, Cursor, and other AI assistants to databases, APIs, and internal services, they're granting these agents access to sensitive systems - often without security oversight. MCP Audit is a security scanner for AI-assisted development environments that reveals exactly what each agent can access: which databases it can query, which APIs it can call, which credentials it holds, and which AI models it uses. Scan developer AI agent configurations across your teams and generate AI-BOMs (AI Bill of Materials) for compliance and supply chain transparency. It's visibility and governance for the new attack surface created by AI-assisted development.

## Key Features

- **MCP Discovery** - Find all MCP servers across Claude Desktop, Cursor, VS Code, and project configs
- **Secrets Detection** - Detect exposed API keys, tokens, and passwords with provider-specific remediation
- **API Inventory** - Catalog all database, REST, SSE, and cloud endpoints MCPs connect to
- **AI Model Detection** - Discover which AI models are configured (OpenAI, Anthropic, Google, Mistral, Ollama)
- **AI-BOM Export** - Generate CycloneDX 1.6 AI Bill of Materials for compliance
- **Email Reports** - Get professional PDF security reports delivered to your inbox
- **Registry Verification** - Check MCPs against a curated registry of 50+ known servers
- **Risk Assessment** - Identify risky permissions, unverified sources, and security flags

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

**Try it now:** [https://apisec-inc.github.io/mcp-audit/](https://apisec-inc.github.io/mcp-audit/)

Or run locally:
1. Open `index.html` in your browser
2. Enter a GitHub Personal Access Token ([create one here](https://github.com/settings/tokens/new?scopes=repo,read:org))
3. Select your organization and scan
4. View secrets, API inventory, and export results

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
| `secrets-detected` | Exposed API keys/tokens found |
| `secrets-in-env` | Has passwords/keys in config |
| `unverified-source` | Not from trusted publisher |
| `remote-mcp` | Connects to remote SSE endpoint |

### Detected Secret Types

| Severity | Secret Types |
|----------|--------------|
| 🔴 **Critical** | AWS Access Keys, GitHub PATs, Stripe Live Keys, Database Credentials, Private Keys |
| 🟠 **High** | Slack Tokens, OpenAI Keys, Anthropic Keys, SendGrid Keys, Discord Tokens |
| 🟡 **Medium** | Slack Webhooks, Generic API Keys, Mailchimp Keys |

### API Endpoint Categories

| Category | Examples |
|----------|----------|
| 🗄️ **Database** | PostgreSQL, MySQL, MongoDB, Redis, SQLite |
| 🌐 **REST API** | Generic HTTP/HTTPS endpoints |
| 📡 **SSE** | GitHub MCP, Linear MCP, Asana MCP |
| ☁️ **SaaS** | Slack, GitHub, OpenAI, Anthropic APIs |
| 🏢 **Cloud** | AWS S3, Google Cloud, Azure |

### Detected AI Models

| Provider | Models |
|----------|--------|
| **OpenAI** | GPT-4, GPT-4 Turbo, GPT-3.5, o1, o3 series |
| **Anthropic** | Claude 3.5, Claude 3, Claude 2 |
| **Google** | Gemini Pro, Gemini Ultra, PaLM |
| **Meta** | Llama 2, Llama 3, Code Llama |
| **Mistral** | Mistral 7B, Mixtral 8x7B |
| **Local** | Ollama models |

---

## CLI Commands

### Scan for MCPs

```bash
# Basic scan (includes secrets + API detection)
mcp-audit scan

# Verbose output
mcp-audit scan --verbose

# Scan specific folder
mcp-audit scan --path ./my-project

# Export to file
mcp-audit scan --format json --output results.json

# Secrets only - show detected credentials
mcp-audit scan --secrets-only

# APIs only - show endpoint inventory
mcp-audit scan --apis-only

# AI models only - show model inventory
mcp-audit scan --models-only

# Skip secrets/APIs/models detection
mcp-audit scan --no-secrets
mcp-audit scan --no-apis
mcp-audit scan --no-models

# Email PDF report
mcp-audit scan --email user@company.com

# Export AI-BOM (CycloneDX 1.6)
mcp-audit scan --format cyclonedx --output ai-bom.json
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

════════════════════════════════════════════════════════════
⚠️  2 SECRET(S) DETECTED - IMMEDIATE ACTION REQUIRED
════════════════════════════════════════════════════════════

[CRITICAL] GitHub Personal Access Token
  Location: github-tools → env.GITHUB_TOKEN
  Value: ghp_********7890 (40 chars)
  Remediation:
    1. Go to https://github.com/settings/tokens and delete this token
    2. Create a new token with minimum required scopes
    3. Update GITHUB_TOKEN in your MCP config

[HIGH] Slack Token
  Location: slack → env.SLACK_BOT_TOKEN
  Value: xoxb********UvWx (57 chars)
  Remediation:
    1. Go to https://api.slack.com/apps and regenerate the bot token
    ...

════════════════════════════════════════════════════════════
📡 API INVENTORY - 4 endpoint(s) discovered
════════════════════════════════════════════════════════════

🗄️ DATABASE (2)
  • postgres-db → postgresql://****:****@db.example.com:5432/mydb
  • redis-cache → redis://localhost:6379

📡 SSE (2)
  • github-mcp → https://mcp.github.com/sse
  • linear-mcp → https://mcp.linear.app/sse

────────────────────────────────────────────────────────────
                              MCP Inventory
┏━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━┳━━━━━━━┓
┃ MCP Name   ┃ Source                      ┃ Found In       ┃ Known ┃ Risk  ┃
┡━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━╇━━━━━━━┩
│ filesystem │ @anthropic/mcp-server-files │ Claude Desktop │ Yes   │ HIGH  │
│ slack      │ @modelcontextprotocol/slack │ Claude Desktop │ Yes   │ MEDIUM│
│ postgres   │ @modelcontextprotocol/pg    │ Cursor         │ Yes   │ CRIT  │
└────────────┴─────────────────────────────┴────────────────┴───────┴───────┘
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
# Start a local server
cd /path/to/mcp-audit
python -m http.server 8080

# Open in browser
open http://localhost:8080
```

Or just open `index.html` directly in your browser.

### Running Tests

```bash
cd /path/to/mcp-audit
pytest
```

---

## License

MIT License - see [LICENSE](LICENSE)

---

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

Built by [APIsec](https://apisec.ai) with Claude Code
