## APIsec MCP Audit v0.1.2

**Release Date:** January 5, 2026

### What's New - Secrets Detection & Provider-Specific Remediation

MCP Audit now detects exposed secrets (API keys, tokens, passwords) in your MCP configurations and provides **provider-specific remediation guidance** for each finding.

**Before:** Risk flags showed generic "secrets-in-env" with no actionable guidance.

**After:** Each detected secret shows exactly what it is, where to rotate it, and step-by-step remediation specific to that provider.

### Feature 1: Secrets Detection

Automatically scans MCP environment variables for exposed credentials:

**Supported Secret Types:**
- **Critical:** AWS Access Keys, GitHub PATs, Stripe Live Keys, PostgreSQL/MySQL/MongoDB connection strings, Private Keys
- **High:** Slack Tokens, OpenAI API Keys, Anthropic API Keys, Google API Keys, SendGrid Keys, Discord Tokens, NPM Tokens
- **Medium:** Slack Webhooks, Google OAuth, Mailchimp Keys, Generic API Keys/Passwords

**CLI Flags:**
```
mcp-audit scan                 # Full scan with secrets detection
mcp-audit scan --secrets-only  # Only show detected secrets
mcp-audit scan --no-secrets    # Skip secrets detection
```

### Feature 2: Provider-Specific Remediation

Each detected secret now includes tailored remediation steps with direct links to rotation consoles:

- **GitHub:** github.com/settings/tokens
- **Slack:** api.slack.com/apps
- **OpenAI:** platform.openai.com/api-keys
- **Anthropic:** console.anthropic.com/settings/keys
- **AWS:** IAM console instructions
- **Databases:** Change password + audit logs

All include common steps: Remove from config, scrub Git history with BFG.

### How to Update

**CLI:** `git pull origin main && pip install -e .`

**Web UI:** Just refresh https://apisec-inc.github.io/mcp-audit/
