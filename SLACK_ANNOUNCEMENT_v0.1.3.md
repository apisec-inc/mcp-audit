## APIsec MCP Audit v0.1.3

**Release Date:** January 5, 2026

### What's New - API Inventory & Endpoint Discovery

MCP Audit now automatically discovers and catalogs all API endpoints that your MCPs are configured to access, giving you complete visibility into external service connections.

**Before:** You had to manually review each MCP config to understand what APIs and services it connects to.

**After:** A single scan reveals every database, API endpoint, and cloud service your MCPs access - grouped by category with credential masking.

### Feature: API Extraction & Inventory

Automatically scans MCP configurations for API endpoints in:
- Environment variables (`*_URL`, `*_ENDPOINT`, `*_API`)
- Config fields (`url`, `serverUrl`, `endpoint`, `baseUrl`)
- Command arguments (connection strings)

**Detected Endpoint Categories:**

| Category | Examples |
|----------|----------|
| Database | PostgreSQL, MySQL, MongoDB, Redis, SQLite |
| REST API | Generic HTTP/HTTPS endpoints |
| WebSocket | WS/WSS connections |
| SSE | GitHub MCP, Linear MCP, Asana MCP |
| SaaS | Slack, GitHub, OpenAI, Anthropic APIs |
| Cloud | AWS S3, Google Cloud, Azure |

**Security:** Credentials are automatically masked in output (`postgresql://****:****@host`)

### CLI Usage

```bash
mcp-audit scan                 # Full scan with API inventory
mcp-audit scan --apis-only     # Only show API endpoints
mcp-audit scan --no-apis       # Skip API detection
```

### Sample Output

```
📡 API INVENTORY - 9 endpoint(s) discovered

🗄️ DATABASE (4)
  • postgres-db → postgresql://****:****@db.example.com:5432/mydb
  • redis-cache → redis://localhost:6379
  • custom-api → mongodb+srv://****:****@cluster.mongodb.net/db

🌐 REST API (1)
  • custom-api → https://api.mycompany.com/v1

📡 SSE (2)
  • github-mcp → https://mcp.github.com/sse
  • linear-mcp → https://mcp.linear.app/sse

☁️ SAAS (1)
  • slack-bot → https://api.slack.com/api

🏢 CLOUD (1)
  • aws-service → https://my-bucket.s3.amazonaws.com
```

### Export Formats

API data is included in all export formats:
- **JSON:** `apis_detected` section with full details
- **Markdown:** API Endpoints table by category
- **CSV:** `apis_count` and `api_categories` columns

### How to Update

**CLI:** `git pull origin main && pip install -e .`

**Web UI:** Just refresh https://apisec-inc.github.io/mcp-audit/

### Coming in v0.1.4

- MDM/Enterprise collection scripts
- Aggregated fleet-wide reporting
- Policy enforcement rules
