# MCP Audit Changelog

All notable changes to MCP Audit are documented in this file.

---

## [1.1.0] - 2026-05-12

### Major release — source-level vulnerability scanning

`mcp-audit` now reads MCP server **source code**, not just configurations. The new `source-scan` command catches the "Prompt In, Shell Out" attack chain: MCP servers that pipe LLM-controlled tool arguments into shell-spawning APIs without sanitization.

#### New: `mcp-audit source-scan <path>`

Scans an MCP server source tree for code-level vulnerabilities. Today the scanner catches:

- **JavaScript / TypeScript**: `child_process.exec`, `child_process.execSync`, and `util.promisify(child_process.exec)` aliases (the `execAsync` pattern) called with template literals or string concatenation.
- **Python**: `subprocess.run / Popen / call / check_call / check_output` with `shell=True`, `os.system`, and `os.popen` called with f-strings, `.format()`, `%`-formatting, or string concatenation.

Each finding includes file:line, the offending API, a confidence level (`high` for visible interpolation, `medium` for non-literal arguments), and a one-line fix hint. The full remediation guidance is in `mcp-audit explain shell-injection-in-source`.

Output formats:

- `--format table` (default, human-readable)
- `--format json` for CI integrations and `jq` pipelines
- `--format sarif` for upload to GitHub code-scanning, GitLab Advanced Security, etc.

CI gating:

```bash
mcp-audit source-scan ./my-mcp --exit-code   # fail on critical findings
```

The scanner is intentionally narrow — it only opens files that look like MCP server source (imports an MCP SDK: `@modelcontextprotocol/sdk`, `FastMCP`, `mcp.Server`). It will not flag shell-injection bugs in arbitrary Node or Python code; that is out of scope.

#### Updated: `mcp-audit scan` adds a `source-scan` nudge

When the regular `scan` command finds in-house or unverified MCP servers, the summary now suggests running `source-scan` against them. The inventory pass cannot see code-level vulnerabilities; the nudge closes that loop.

#### Updated: OWASP LLM Top 10 mapping

Adds **LLM05 — Improper Output Handling** to the mapping table. The new `shell-injection-in-source` risk flag maps under LLM05 because the vulnerability is exactly the LLM05 bug class: an LLM-derived value is passed to a downstream system (a shell) without sanitization.

#### New risk flag

`shell-injection-in-source` (CRITICAL severity). Full explanation, remediation steps, and the related-flag map are available via `mcp-audit explain shell-injection-in-source`.

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
- **Security Issues:** rajaram@apisec.ai
