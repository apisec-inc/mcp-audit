# APIsec MCP Audit v1.0.0

**Release Date:** January 14, 2026

---

## What's New in v1.0.0

MCP Audit v1.0 is the first major release, bringing professional PDF security reports delivered directly to your inbox. This release consolidates all features from the 0.1.x series into a production-ready security auditing tool for MCP configurations.

---

## Feature Highlights

### Email Report Delivery (NEW in v1.0)

Get professional PDF security audit reports delivered to your inbox with one command:

```bash
mcp-audit scan --email user@company.com
```

**Report Contents:**
- Executive summary with overall risk assessment
- Detected secrets with severity classification
- API endpoint inventory by category
- AI model inventory (AI-BOM)
- Provider-specific remediation guidance
- Actionable security recommendations

**Use Cases:**
- Share audit results with security teams
- Document compliance for audits
- Track MCP security posture over time

---

### Secrets Detection (v0.1.2)

Automatically detects exposed credentials in MCP configurations:

| Severity | Secret Types |
|----------|-------------|
| Critical | AWS Access Keys, GitHub PATs, Stripe Live Keys, Database connection strings, Private Keys |
| High | Slack Tokens, OpenAI/Anthropic API Keys, Google API Keys, SendGrid, Discord, NPM Tokens |
| Medium | Slack Webhooks, Google OAuth, Mailchimp Keys, Generic API Keys |

**Provider-Specific Remediation:**
Each finding includes direct links to rotation consoles (GitHub, Slack, AWS IAM, etc.) and step-by-step remediation instructions.

---

### API Inventory (v0.1.3)

Discovers and catalogs all API endpoints your MCPs connect to:

| Category | Examples |
|----------|----------|
| Database | PostgreSQL, MySQL, MongoDB, Redis, SQLite |
| REST API | HTTP/HTTPS endpoints |
| WebSocket | WS/WSS connections |
| SSE | GitHub MCP, Linear MCP, Asana MCP |
| SaaS | Slack, GitHub, OpenAI, Anthropic APIs |
| Cloud | AWS S3, Google Cloud, Azure |

**Security:** Credentials automatically masked in output.

---

### AI Model Detection & AI-BOM (v0.1.4)

Detects AI models configured in your MCPs and generates CycloneDX 1.6 AI Bill of Materials:

**Supported Providers:**
- OpenAI (GPT-4, GPT-4 Turbo, GPT-3.5, o1/o3 series)
- Anthropic (Claude 3.5, Claude 3, Claude 2)
- Google (Gemini Pro, Gemini Ultra, PaLM)
- Meta (Llama 2, Llama 3, Code Llama)
- Mistral (Mistral 7B, Mixtral 8x7B)
- Local (Ollama models)

**Export:** CycloneDX 1.6 JSON format for compliance and inventory tracking.

---

## CLI Commands

```bash
# Full scan with all features
mcp-audit scan

# Send PDF report via email
mcp-audit scan --email user@company.com

# Filter by feature
mcp-audit scan --secrets-only    # Only secrets
mcp-audit scan --apis-only       # Only API endpoints
mcp-audit scan --models-only     # Only AI models

# Skip specific detection
mcp-audit scan --no-secrets
mcp-audit scan --no-apis
mcp-audit scan --no-models

# Export formats
mcp-audit scan --output json
mcp-audit scan --output csv
mcp-audit scan --output markdown
mcp-audit scan --output cyclonedx   # AI-BOM

# Scan specific targets
mcp-audit scan --target claude      # Claude Desktop only
mcp-audit scan --target cursor      # Cursor IDE only
mcp-audit scan --path ./project     # Specific directory
```

---

## Web UI

Access the web-based scanner at: **https://apisec-inc.github.io/mcp-audit/**

Features:
- Drag-and-drop config file scanning
- Scan Claude Desktop configs directly
- Visual risk assessment dashboard
- Secrets, APIs, and Models inventory
- One-click email report delivery
- AI-BOM export

---

## Supported Platforms

**IDE Configurations:**
- Claude Desktop (macOS, Windows)
- Cursor IDE
- VS Code (MCP extensions)
- Windsurf
- Zed

**Project Files:**
- mcp.json
- .mcp/ directories
- package.json (MCP dependencies)
- requirements.txt (Python MCPs)
- docker-compose.yml (containerized MCPs)

---

## Installation

**CLI:**
```bash
# Clone and install
git clone https://github.com/apisec-inc/mcp-audit.git
cd mcp-audit
pip install -e .

# Verify installation
mcp-audit --version
# mcp-audit version 1.0.0
```

**Web UI:**
No installation required - visit https://apisec-inc.github.io/mcp-audit/

---

## Version History

| Version | Date | Highlights |
|---------|------|------------|
| 1.0.0 | Jan 14, 2026 | Email reports, PDF generation, lead capture backend |
| 0.1.4 | Jan 13, 2026 | AI model detection, AI-BOM (CycloneDX 1.6), UI redesign |
| 0.1.3 | Jan 5, 2026 | API inventory & endpoint discovery |
| 0.1.2 | Jan 5, 2026 | Secrets detection & provider-specific remediation |
| 0.1.1 | Dec 18, 2025 | Remote/hosted MCP support |
| 0.1.0 | Dec 11, 2025 | Initial release |

---

## Links

- **Web UI:** https://apisec-inc.github.io/mcp-audit/
- **GitHub:** https://github.com/apisec-inc/mcp-audit
- **Documentation:** https://github.com/apisec-inc/mcp-audit#readme
- **Security Issues:** security@apisec.ai

---

**Built by APIsec** | www.apisec.ai
