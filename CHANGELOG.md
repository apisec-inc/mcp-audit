# MCP Audit Changelog

All notable changes to MCP Audit are documented in this file.

---

## [1.0.0] - January 14, 2026

### Major Release - Email Reports & Lead Capture

MCP Audit v1.0 introduces professional PDF security reports delivered via email, providing security teams and developers with shareable audit documentation.

#### New Features

**Email Report Delivery**
- Professional PDF security reports sent directly to your inbox
- Executive summary with risk assessment and recommendations
- Detailed findings breakdown by category and severity
- APIsec branded reports suitable for compliance documentation

**Backend Infrastructure**
- Vercel serverless API for report generation
- React-PDF for professional report rendering
- Gmail SMTP integration for reliable delivery
- API key authentication for secure access

**CLI Integration**
```bash
mcp-audit scan --email user@company.com    # Send report via email
```

**Web UI Integration**
- "Get Report via Email" section after scan completion
- One-click report delivery to any email address

---

## [0.1.4] - January 13, 2026

### Model Detection & AI-BOM (AI Bill of Materials)

MCP Audit now detects AI models configured in your MCPs and generates an AI Bill of Materials (AI-BOM) for compliance and inventory tracking.

#### New Features

**AI Model Detection**
- Detects model configurations in environment variables (`*_MODEL`, `OPENAI_MODEL`, etc.)
- Identifies models in config fields (`model`, `modelId`, `llm`)
- Recognizes command-line model arguments

**Supported Model Providers**
| Provider | Models Detected |
|----------|----------------|
| OpenAI | GPT-4, GPT-4 Turbo, GPT-3.5, o1, o3 series |
| Anthropic | Claude 3.5, Claude 3, Claude 2 series |
| Google | Gemini Pro, Gemini Ultra, PaLM |
| Meta | Llama 2, Llama 3, Code Llama |
| Mistral | Mistral 7B, Mixtral 8x7B |
| Local | Ollama models |

**AI-BOM Export**
- JSON export includes `models_detected` section
- Markdown export includes AI Models table
- CSV export includes `models_count` column

**CLI Usage**
```bash
mcp-audit scan                   # Full scan with model detection
mcp-audit scan --models-only     # Only show detected models
mcp-audit scan --no-models       # Skip model detection
```

#### UI Improvements

**Color Redesign**
- New color scheme with improved visual hierarchy
- Risk levels clearly distinguished by color
- Better contrast for accessibility
- Modernized card and badge styling

---

## [0.1.3] - January 5, 2026

### API Inventory & Endpoint Discovery

MCP Audit automatically discovers and catalogs all API endpoints your MCPs are configured to access.

#### New Features

**API Extraction**
- Scans environment variables (`*_URL`, `*_ENDPOINT`, `*_API`, `*_HOST`)
- Parses config fields (`url`, `serverUrl`, `endpoint`, `baseUrl`, `uri`)
- Extracts endpoints from command arguments (connection strings)

**Detected Endpoint Categories**
| Category | Examples |
|----------|----------|
| Database | PostgreSQL, MySQL, MongoDB, Redis, SQLite |
| REST API | HTTP/HTTPS endpoints |
| WebSocket | WS/WSS connections |
| SSE | GitHub MCP, Linear MCP, Asana MCP endpoints |
| SaaS | Slack, GitHub, OpenAI, Anthropic APIs |
| Cloud | AWS S3, Google Cloud, Azure endpoints |

**Security Features**
- Credentials automatically masked in output (`postgresql://****:****@host`)
- Sensitive URL parameters redacted

**CLI Usage**
```bash
mcp-audit scan                 # Full scan with API inventory
mcp-audit scan --apis-only     # Only show API endpoints
mcp-audit scan --no-apis       # Skip API detection
```

**Sample Output**
```
📡 API INVENTORY - 9 endpoint(s) discovered

🗄️ DATABASE (4)
  • postgres-db → postgresql://****:****@db.example.com:5432/mydb
  • redis-cache → redis://localhost:6379

🌐 REST API (1)
  • custom-api → https://api.mycompany.com/v1

📡 SSE (2)
  • github-mcp → https://mcp.github.com/sse
  • linear-mcp → https://mcp.linear.app/sse
```

---

## [0.1.2] - January 5, 2026

### Secrets Detection & Provider-Specific Remediation

MCP Audit detects exposed secrets in configurations and provides provider-specific remediation guidance.

#### New Features

**Secrets Detection**
Automatically scans MCP environment variables for exposed credentials:

| Severity | Secret Types |
|----------|-------------|
| Critical | AWS Access Keys, GitHub PATs, Stripe Live Keys, PostgreSQL/MySQL/MongoDB connection strings, Private Keys |
| High | Slack Tokens, OpenAI API Keys, Anthropic API Keys, Google API Keys, SendGrid Keys, Discord Tokens, NPM Tokens |
| Medium | Slack Webhooks, Google OAuth, Mailchimp Keys, Generic API Keys/Passwords |

**Provider-Specific Remediation**
Each detected secret includes tailored remediation steps with direct links:
- **GitHub:** github.com/settings/tokens
- **Slack:** api.slack.com/apps
- **OpenAI:** platform.openai.com/api-keys
- **Anthropic:** console.anthropic.com/settings/keys
- **AWS:** IAM console instructions
- **Databases:** Password rotation + audit log review

All remediation includes: Remove from config, scrub Git history with BFG.

**CLI Usage**
```bash
mcp-audit scan                 # Full scan with secrets detection
mcp-audit scan --secrets-only  # Only show detected secrets
mcp-audit scan --no-secrets    # Skip secrets detection
```

---

## [0.1.1] - December 18, 2025

### Remote/Hosted MCP Support

MCP Audit correctly identifies remote MCPs connecting via URL endpoints.

#### Changes

- **Remote MCP Detection:** Parses `url`, `serverUrl`, `endpoint`, `uri` fields
- **Transport Detection:** Recognizes `sse`, `http`, `websocket` transport types
- **Registry Matching:** Matches remote MCPs by endpoint URL/domain
- **Name Matching:** Falls back to matching by MCP name
- **New Risk Flag:** `remote-mcp` flag for URL-based MCPs
- **Registry Update:** Added GitHub's official hosted MCP (`https://mcp.github.com`)

**Example**
```json
{
  "github": {
    "url": "https://mcp.github.com/sse"
  }
}
```

Output:
```
MCP Name: github
Source: https://mcp.github.com/sse
Type: remote
Known: Yes
Provider: GitHub
Verified: Yes
```

---

## [0.1.0] - December 11, 2025

### Initial Release

First public release of MCP Audit.

#### Features

**Local Scanning**
- Claude Desktop configuration
- Cursor IDE configuration
- VS Code MCP extensions
- Windsurf configuration
- Zed editor configuration

**Project Scanning**
- `mcp.json` files
- `.mcp/` directories
- `package.json` MCP dependencies
- `requirements.txt` MCP packages
- `docker-compose.yml` MCP services

**Registry**
- 50+ known MCPs with risk classifications
- Provider identification and verification status
- Trust scoring based on verification and risk flags

**Risk Detection**
- `secrets-in-env` - Hardcoded credentials
- `shell-access` - Command execution capability
- `database-access` - Database connectivity
- `filesystem-access` - File system permissions
- `local-binary` - Non-registry binaries

**Export Formats**
- JSON with full details
- CSV for spreadsheet analysis
- Markdown for documentation

**Policy Enforcement**
- YAML-based policy definitions
- Block/warn/allow rules
- CI/CD integration support

---

## How to Update

**CLI:**
```bash
git pull origin main && pip install -e .
```

**Web UI:**
Refresh https://apisec-inc.github.io/mcp-audit/

---

## Links

- **Documentation:** https://apisec-inc.github.io/mcp-audit/
- **GitHub:** https://github.com/apisec-inc/mcp-audit
- **Security Issues:** security@apisec.ai
