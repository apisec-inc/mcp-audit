# MCP Audit - PR/FAQ

## Press Release

### APIsec Launches MCP Audit v1.1: From Inventory to Source-Level Vulnerability Scanning

**San Francisco, CA** – APIsec today announced MCP Audit v1.1, a free security scanner that now reads MCP server source code in addition to inventorying configurations. The headline addition is detection of the "Prompt In, Shell Out" attack chain — MCP servers that pipe LLM-controlled tool arguments into shell-spawning APIs, enabling command injection from anything that controls the LLM's input.

"In v1.0 we showed teams what their AI agents could access. In v1.1 we go one level deeper and read the MCP server's own code for the exact bug class attackers are already exploiting in the wild," said Rajaram Ramanathan, founder of APIsec. "If your in-house MCP server calls `child_process.exec` with a tool argument interpolated into the string, anything that can talk to the LLM can run shell commands on the host. We catch that in one command."

**Key Features:**

- **Source-Level Vulnerability Scanning (new in v1.1)** – `mcp-audit source-scan <path>` reads MCP server source code (JS/TS/Python) and flags shell-injection sinks: `child_process.exec`, `util.promisify(exec)`, `subprocess.run(shell=True)`, `os.system`, `os.popen`. Outputs table / JSON / SARIF for upload to GitHub code-scanning.
- **Secrets Detection** – Find exposed API keys, tokens, and passwords with provider-specific remediation guidance
- **API Inventory** – Discover all database, REST, SSE, SaaS, and cloud endpoints your AI agents connect to
- **AI Model Detection** – Identify which AI models (OpenAI, Anthropic, Google, Mistral, Ollama) are configured
- **AI-BOM Export** – Generate CycloneDX 1.6 AI Bill of Materials for compliance and supply chain transparency
- **Email Reports** – Get professional PDF security reports delivered to your inbox
- **50+ Known MCPs** – Registry of verified MCP servers with risk assessments

MCP Audit supports scanning Claude Desktop, Cursor, VS Code, Windsurf, Zed, and GitHub repositories. All scanning happens locally or in-browser – credentials never leave your machine.

**Available now:** https://apisec-inc.github.io/mcp-audit/

---

## Frequently Asked Questions

### General Questions

**Q: What is MCP Audit?**

A: MCP Audit is a free, open-source security scanner for AI-assisted development environments. It shows you what your AI agents can access – which databases they can query, which APIs they can call, which credentials they hold, and which AI models they use. Think of it as visibility and governance for the new attack surface created by AI-assisted development.

**Q: What is MCP (Model Context Protocol)?**

A: MCP is a standard protocol that allows AI assistants (like Claude, Cursor, GitHub Copilot) to connect with external tools and data sources. MCP servers are plugins that give AI assistants capabilities like reading files, querying databases, sending messages, or executing commands.

**Q: Why should I care about MCP security?**

A: MCP servers can have significant access to sensitive systems:
- **Database access** – Query and modify production databases
- **API access** – Connect to Slack, GitHub, cloud providers with stored credentials
- **Filesystem access** – Read/write files on developer machines
- **Shell access** – Execute arbitrary commands

Without visibility into what AI agents can access, you have a security blind spot in your development environment.

**Q: Who is this tool for?**

A: MCP Audit is designed for:
- **Security teams** – Get visibility into what AI agents across your organization can access
- **Compliance teams** – Generate AI-BOMs for EU AI Act and supply chain transparency
- **Engineering managers** – Understand what AI capabilities and models teams are using
- **Individual developers** – Check your own setup for exposed secrets and risky configurations

**Q: Is MCP Audit free?**

A: Yes, MCP Audit is completely free and open-source under the MIT license.

---

### Features

**Q: What secrets can MCP Audit detect?**

A: MCP Audit detects exposed credentials in AI agent configurations:

| Severity | Secret Types |
|----------|--------------|
| **Critical** | AWS Access Keys, GitHub PATs, Stripe Live Keys, Database Credentials, Private Keys |
| **High** | Slack Tokens, OpenAI Keys, Anthropic Keys, SendGrid Keys, Discord Tokens |
| **Medium** | Slack Webhooks, Generic API Keys, Mailchimp Keys |

Each detected secret includes provider-specific remediation with direct links to rotation consoles.

**Q: What API endpoints does MCP Audit discover?**

A: MCP Audit catalogs all endpoints your AI agents connect to:

| Category | Examples |
|----------|----------|
| **Database** | PostgreSQL, MySQL, MongoDB, Redis, SQLite |
| **REST API** | HTTP/HTTPS endpoints |
| **SSE** | GitHub MCP, Linear MCP, Asana MCP |
| **SaaS** | Slack, GitHub, OpenAI, Anthropic APIs |
| **Cloud** | AWS S3, Google Cloud, Azure |

Credentials in URLs are automatically masked for security.

**Q: What AI models does MCP Audit detect?**

A: MCP Audit identifies AI models configured in your agents:

| Provider | Models |
|----------|--------|
| **OpenAI** | GPT-4, GPT-4 Turbo, GPT-3.5, o1, o3 series |
| **Anthropic** | Claude 3.5, Claude 3, Claude 2 |
| **Google** | Gemini Pro, Gemini Ultra, PaLM |
| **Meta** | Llama 2, Llama 3, Code Llama |
| **Mistral** | Mistral 7B, Mixtral 8x7B |
| **Local** | Ollama models |

**Q: What is an AI-BOM?**

A: AI-BOM (AI Bill of Materials) is a machine-readable inventory of AI components in your environment, following the CycloneDX 1.6 specification. It's used for:
- **Compliance** – EU AI Act, supply chain transparency requirements
- **Inventory** – Track which AI models are deployed where
- **Risk Management** – Understand AI dependencies across your organization

---

### Privacy & Security

**Q: Is my data safe when using the web app?**

A: Yes. The web app runs entirely in your browser – your GitHub token and code never leave your machine. We don't have servers that process your scan data.

**Q: What about email reports?**

A: When you request an email report, only the scan summary (MCP counts, risk levels) is sent to our backend to generate the PDF. We do not store your scan details. The email address is captured for lead purposes.

**Q: Can I use this on private repositories?**

A: Yes. GitHub scanning happens in your browser using your token. Private repository contents are never sent to external servers.

**Q: Is the CLI tool safe to run on my machine?**

A: Yes. The CLI tool runs 100% locally and only sends data when you explicitly request an email report.

---

### CLI Tool

**Q: What does the CLI tool scan?**

A: The CLI scans MCP configurations in:
- **Claude Desktop** – Anthropic's desktop application
- **Cursor** – AI-powered code editor
- **VS Code** – With Continue extension
- **Windsurf** – Codeium's editor
- **Zed** – Modern code editor
- **Project folders** – .mcp/ directories and mcp.json files

**Q: What are the main CLI commands?**

```bash
# Full scan with secrets, APIs, and model detection
mcp-audit scan

# NEW in v1.1: source-level vulnerability scan against an MCP server tree
mcp-audit source-scan ./packages/my-mcp-server
mcp-audit source-scan ./packages/my-mcp-server --format sarif --output mcp.sarif
mcp-audit source-scan ./packages/my-mcp-server --exit-code   # CI gate on critical

# Get PDF report via email
mcp-audit scan --email user@company.com

# Export AI-BOM (CycloneDX 1.6)
mcp-audit scan --format cyclonedx --output ai-bom.json

# Secrets only
mcp-audit scan --secrets-only

# API endpoints only
mcp-audit scan --apis-only

# AI models only
mcp-audit scan --models-only

# View MCP registry
mcp-audit registry
mcp-audit registry --risk critical

# Explain a risk flag (including shell-injection-in-source, new in v1.1)
mcp-audit explain shell-injection-in-source
```

**Q: How do I install the CLI?**

```bash
pip install -e .
mcp-audit scan
```

Requires Python 3.9 or higher.

---

### Web App

**Q: How does the GitHub scanning work?**

A: The web app uses GitHub's API (authenticated with your personal access token) to:
1. List all repositories in your organization
2. Check each repo for MCP config files
3. Extract secrets, API endpoints, and model configurations
4. Match found MCPs against our known registry

All scanning happens in your browser.

**Q: What export formats are available?**

A:
- **JSON** – Full scan data
- **CSV** – Spreadsheet analysis
- **Markdown** – Documentation
- **CycloneDX** – AI-BOM for compliance

---

### Risk Assessment

**Q: How are risk levels determined?**

A: Risk levels are assigned based on the MCP's capabilities:

| Risk Level | Criteria |
|------------|----------|
| **Critical** | Database write, cloud infrastructure, payments, shell execution |
| **High** | Filesystem write, browser automation, email sending |
| **Medium** | API access, messaging (Slack, Discord), calendar |
| **Low** | Read-only access, search, memory/cache |

**Q: What does "Known" vs "Unknown" mean?**

A:
- **Known** – The MCP is in our curated registry of 50+ verified MCP servers
- **Unknown** – The MCP is not in our registry and requires manual review

---

### Enterprise

**Q: Can I deploy this internally?**

A: Yes. The web app is static HTML/CSS/JS and can be hosted on any internal web server. The CLI can be installed on any machine with Python.

**Q: How do I collect MCP configs from all developer machines?**

A: Use the MDM collector scripts included with the CLI:
- `collectors/collect-macos.sh` – For Mac computers
- `collectors/collect-windows.ps1` – For Windows computers

Deploy via your MDM solution (Jamf, Intune, etc.) to gather configs centrally.

**Q: Do you offer an enterprise version?**

A: Contact us at rajaram@apisec.ai for enterprise needs.

---

### Roadmap

**Q: What features are planned?**

A: Upcoming features include:
- GitLab, Bitbucket, Azure DevOps scanning
- Policy enforcement (block unapproved MCPs)
- Scheduled automated scans
- SIEM integration
- Runtime behavior monitoring

**Q: How can I request a feature?**

A: Open an issue on GitHub: https://github.com/apisec-inc/mcp-audit/issues

---

## Contact

- **Website**: https://apisec-inc.github.io/mcp-audit/
- **GitHub**: https://github.com/apisec-inc/mcp-audit
- **Email**: rajaram@apisec.ai
- **Company**: https://apisec.ai
