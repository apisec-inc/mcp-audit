# APIsec MCP Audit v0.1.2

**Release Date:** January 5, 2025

## What's New - Secrets Detection & Provider-Specific Remediation

MCP Audit now detects exposed secrets (API keys, tokens, passwords) in your MCP configurations and provides **provider-specific remediation guidance** for each finding.

**Before:** Risk flags showed generic "secrets-in-env" with no actionable guidance.

**After:** Each detected secret shows exactly what it is, where to rotate it, and step-by-step remediation specific to that provider.

## Feature 1: Secrets Detection

Automatically scans MCP environment variables for exposed credentials:

### Supported Secret Types
- **Critical:** AWS Access Keys, GitHub PATs, Stripe Live Keys, PostgreSQL/MySQL/MongoDB connection strings, Private Keys
- **High:** Slack Tokens, OpenAI API Keys, Anthropic API Keys, Google API Keys, SendGrid Keys, Discord Tokens, NPM Tokens
- **Medium:** Slack Webhooks, Google OAuth, Mailchimp Keys, Generic API Keys/Passwords

### Detection Features
- Pattern-based detection with regex matching
- Context-aware detection (checks env var names for generic secrets)
- Placeholder filtering (skips `xxx`, `changeme`, `<your-api-key>`, etc.)
- Env var reference detection (skips `$VAR` and `${VAR}`)
- Masked values for safe display (e.g., `ghp_****7890`)

### CLI Flags
```bash
mcp-audit scan                 # Full scan with secrets detection
mcp-audit scan --secrets-only  # Only show detected secrets
mcp-audit scan --no-secrets    # Skip secrets detection
```

## Feature 2: Provider-Specific Remediation

Each detected secret now includes tailored remediation steps:

### GitHub Personal Access Token
```
1. Go to https://github.com/settings/tokens and delete this token
2. Create a new token with minimum required scopes
3. Update GITHUB_TOKEN in your MCP config
4. Remove hardcoded secret from config (use env vars instead)
5. If in Git: scrub history with BFG or git filter-branch
```

### Slack Token
```
1. Go to https://api.slack.com/apps and regenerate the bot token
2. Update SLACK_BOT_TOKEN in your MCP config
3. Remove hardcoded secret from config (use env vars instead)
4. If in Git: scrub history with BFG or git filter-branch
```

### OpenAI API Key
```
1. Go to https://platform.openai.com/api-keys and revoke this key
2. Create a new API key
3. Update OPENAI_API_KEY in your MCP config
4. Remove hardcoded secret from config (use env vars instead)
5. If in Git: scrub history with BFG or git filter-branch
```

### Database Credentials
```
1. Change database password in your database admin console
2. Update connection string in MCP config with new password
3. Review database access logs for unauthorized access
4. Remove hardcoded secret from config (use env vars instead)
5. If in Git: scrub history with BFG or git filter-branch
```

## Changes

### CLI
- **Secrets Alert Banner:** Shows prominently at top of scan output before MCP inventory
- **Provider-Specific Remediation:** Each secret type has tailored fix steps with rotation URLs
- **Secrets Column:** MCP inventory table now shows secrets count/severity per MCP
- **New Flags:** `--secrets-only` and `--no-secrets` for focused scanning
- **Export Support:** JSON, CSV, and Markdown exports include secrets data

### Web UI
- **Secrets Alert Banner:** Collapsible alert shows before results with severity breakdown
- **Provider-Specific Remediation:** Click to expand each secret for detailed fix steps
- **Secrets Summary:** Dashboard shows count of MCPs with detected secrets
- **Risk Flag:** MCPs with secrets get `secrets-detected` flag

### Bug Fixes
- Fixed `-y` flag appearing in Source column for npx commands
- Fixed OpenAI key pattern (now accepts variable length keys)
- Fixed severity sort order in remediation section

## Example

Config with exposed secrets:
```json
{
  "mcpServers": {
    "github-tools": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {
        "GITHUB_TOKEN": "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890"
      }
    }
  }
}
```

CLI Output:
```
════════════════════════════════════════════════════════════
⚠️  1 SECRET(S) DETECTED - IMMEDIATE ACTION REQUIRED
════════════════════════════════════════════════════════════

[CRITICAL] GitHub Personal Access Token
  Location: github-tools → env.GITHUB_TOKEN
  Value: ghp_********7890 (40 chars)
  Remediation:
    1. Go to https://github.com/settings/tokens and delete this token
    2. Create a new token with minimum required scopes
    3. Update GITHUB_TOKEN in your MCP config
    4. Remove hardcoded secret from config (use env vars instead)
    5. If in Git: scrub history with BFG or git filter-branch

────────────────────────────────────────────────────────────
Total: 1 secrets (1 critical, 0 high, 0 medium)
Rotate ALL exposed credentials before continuing.
────────────────────────────────────────────────────────────
```

## How to Update

### Option 1: Re-download from Website
1. Go to https://apisec-inc.github.io/mcp-audit/
2. Click "Local System Audit" tab
3. Download the CLI zip
4. Extract and reinstall:
```bash
cd mcp-audit-cli
pip install -e .
```

### Option 2: Update Existing Installation
If you cloned the repo:
```bash
cd mcp-audit
git pull origin main
pip install -e .
```

### Web UI
Just visit https://apisec-inc.github.io/mcp-audit/ - it auto-updates from GitHub Pages.

## Verify Update

Run a scan and check for secrets detection:
```bash
mcp-audit scan --secrets-only
```

If you have MCPs with environment variables containing API keys or tokens, you should see the secrets alert banner with provider-specific remediation.
