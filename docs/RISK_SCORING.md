# MCP Audit Risk Scoring

This document explains how MCP Audit assigns risk levels and flags to discovered MCP configurations.

## Risk Levels

MCP Audit assigns one of four risk levels to each discovered MCP:

| Level | Meaning | Typical Triggers |
|-------|---------|------------------|
| **CRITICAL** | Full access to sensitive systems, immediate security concern | Database write, shell access, cloud admin, payment APIs |
| **HIGH** | Significant access that could cause damage if misused | Filesystem write, code execution, secrets detected |
| **MEDIUM** | Moderate access to business systems | API access, read-only database, SaaS integrations |
| **LOW** | Limited access, minimal risk | Read-only, memory/cache, verified low-privilege tools |

---

## Risk Flags

Risk flags identify specific security-relevant characteristics of an MCP configuration.

### Access-Based Flags

| Flag | Meaning | How It's Detected |
|------|---------|-------------------|
| `filesystem-access` | Can read/write files on the system | MCP name or args contain: `filesystem`, `fs`, `file`, `directory`, `path` AND references paths like `/`, `~`, `$HOME`, `.` |
| `database-access` | Can query or modify databases | MCP name or args contain: `postgres`, `mysql`, `sqlite`, `mongo`, `redis`, `database`, `db` |
| `shell-access` | Can execute shell commands | MCP name or args contain: `shell`, `exec`, `command`, `bash`, `terminal` |
| `network-access` | Can make HTTP/network requests | MCP name or args contain: `http`, `api`, `fetch`, `request`, `url` |

### Source-Based Flags

| Flag | Meaning | How It's Detected |
|------|---------|-------------------|
| `unverified-source` | NPM package not from trusted publisher | Package does not start with: `@anthropic/`, `@modelcontextprotocol/`, `@openai/` AND is unscoped (no `@`) |
| `local-binary` | Running a local script or binary | Command starts with `./` or `/` |
| `remote-mcp` | Connects to remote SSE/HTTP endpoint | Config contains `url`, `serverUrl`, `endpoint`, or `uri` field |

### Secret-Based Flags

| Flag | Meaning | How It's Detected |
|------|---------|-------------------|
| `secrets-in-env` | Configuration contains potential credentials | Environment variable names contain: `key`, `secret`, `token`, `password`, `credential`, `api_key` |
| `secrets-detected` | Actual secret patterns found in values | Values match patterns for: AWS keys, GitHub PATs, Slack tokens, OpenAI keys, database URLs, etc. |

---

## Risk Level Assignment Logic

Risk level is determined by combining flags and registry data:

### CRITICAL is assigned when ANY of:
- `database-access` flag present AND database has write capability
- `shell-access` flag present
- Registry risk level is "critical"
- Secrets detected with critical severity (AWS keys, database credentials, payment keys)
- MCP has cloud admin capabilities (AWS, GCP, Azure admin APIs)

### HIGH is assigned when ANY of:
- `filesystem-access` flag present
- `database-access` flag present (read-only)
- `unverified-source` AND (`network-access` OR `secrets-in-env`)
- Registry risk level is "high"
- Secrets detected with high severity (API keys, tokens)

### MEDIUM is assigned when ANY of:
- `network-access` flag present
- `remote-mcp` flag present
- `secrets-in-env` flag present (without detected secrets)
- `unverified-source` flag present (alone)
- Registry risk level is "medium"

### LOW is assigned when:
- None of the above conditions are met
- Registry risk level is "low"
- MCP is from verified source with limited capabilities

---

## Registry Verification

MCP Audit maintains a registry of 50+ known MCP servers with pre-assessed risk levels.

### Registry Fields

| Field | Description |
|-------|-------------|
| `provider` | Publisher (Anthropic, Model Context Protocol, Community, etc.) |
| `type` | `official`, `vendor`, or `community` |
| `verified` | Whether the package is from a verified publisher |
| `risk_level` | Pre-assessed risk level based on capabilities |
| `capabilities` | List of capabilities (file-read, database-write, etc.) |

### Known vs Unknown MCPs

| Status | Meaning | Implication |
|--------|---------|-------------|
| Known | Found in MCP Audit registry | Risk level informed by registry assessment |
| Unknown | Not in registry | Requires manual security review, may be custom/internal |

### Verified Publishers

The following NPM scopes are considered verified:
- `@anthropic/*` — Official Anthropic MCPs
- `@modelcontextprotocol/*` — Official MCP reference implementations
- `@openai/*` — Official OpenAI MCPs

Packages outside these scopes are flagged as `unverified-source` (not necessarily unsafe, but requires review).

---

## Secret Detection Patterns

MCP Audit detects exposed credentials using pattern matching:

### Critical Severity Secrets

| Secret Type | Pattern | Example |
|-------------|---------|---------|
| AWS Access Key | `AKIA[0-9A-Z]{16}` | `AKIAIOSFODNN7EXAMPLE` |
| AWS Secret Key | 40-char base64 after `aws_secret` | `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` |
| Database URL | `(postgres\|mysql\|mongodb)://.*:.*@` | `postgresql://user:pass@host/db` |
| Private Key | `-----BEGIN (RSA\|EC\|OPENSSH) PRIVATE KEY-----` | PEM-encoded keys |
| Stripe Live Key | `sk_live_[a-zA-Z0-9]{24,}` | `sk_live_abc123...` |

### High Severity Secrets

| Secret Type | Pattern | Example |
|-------------|---------|---------|
| GitHub PAT | `ghp_[a-zA-Z0-9]{36}` | `ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx` |
| GitHub OAuth | `gho_[a-zA-Z0-9]{36}` | `gho_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx` |
| Slack Bot Token | `xoxb-[0-9]{10,}-[a-zA-Z0-9]{24,}` | `xoxb-123456789012-abcdefghij...` |
| Slack User Token | `xoxp-[0-9]{10,}-[a-zA-Z0-9]{24,}` | `xoxp-123456789012-abcdefghij...` |
| OpenAI API Key | `sk-[a-zA-Z0-9]{48}` | `sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx` |
| Anthropic API Key | `sk-ant-[a-zA-Z0-9-]{40,}` | `sk-ant-api03-xxxx...` |
| SendGrid Key | `SG\.[a-zA-Z0-9]{22}\.[a-zA-Z0-9]{43}` | `SG.xxxxx.yyyyy` |
| Discord Token | `[MN][a-zA-Z0-9]{23,}\.[a-zA-Z0-9-_]{6}\.[a-zA-Z0-9-_]{27}` | Bot/user tokens |

### Medium Severity Secrets

| Secret Type | Pattern | Example |
|-------------|---------|---------|
| Slack Webhook | `https://hooks.slack.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+` | Webhook URLs |
| Generic API Key | `api[_-]?key.*[=:]["']?[a-zA-Z0-9]{16,}` | Various API keys |
| Mailchimp Key | `[a-f0-9]{32}-us[0-9]{1,2}` | `abc123...-us14` |

---

## Customizing Risk Assessment

### Using Policy Files (Future)

Create custom policies to override default risk assessment:

```yaml
# strict-policy.yaml
require_verified_source: true
max_risk_level: medium
denied_capabilities:
  - shell-access
  - filesystem-access
require_review:
  - database-access
  - unverified-source
```

Run with:
```bash
mcp-audit policy --policy strict-policy.yaml --input scan-results.json
```

### Allowlisting Internal MCPs

For internal/custom MCPs, add them to a local registry extension or use `allowed_sources` in policy:

```yaml
allowed_sources:
  - "@anthropic/*"
  - "@modelcontextprotocol/*"
  - "@mycompany/*"
  - "internal-*"
```

---

## Limitations

MCP Audit risk scoring has known limitations:

| Limitation | Implication |
|------------|-------------|
| Pattern-based detection | May miss obfuscated secrets or novel formats |
| Static analysis only | Cannot detect runtime behavior or actual API calls |
| Name-based capability inference | MCPs with misleading names may be misclassified |
| Registry coverage | Unknown MCPs require manual review |

Risk scores are advisory. Always perform manual security review for critical systems.

---

## Feedback

If you believe a risk level is incorrect or a pattern is missing, please:
1. Open an issue: https://github.com/apisec-inc/mcp-audit/issues
2. Include the MCP name, source, and suggested classification
