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

## OWASP LLM Top 10 (2025) Mapping

MCP Audit maps findings to the [OWASP LLM Top 10 (2025)](https://genai.owasp.org/llm-top-10/) framework to provide compliance-ready security context.

### Covered Categories

| OWASP ID | Name | MCP Audit Coverage |
|----------|------|-------------------|
| **LLM01** | Prompt Injection | Any MCP discovered provides attack surface visibility — each MCP represents potential prompt injection vectors through tools, APIs, and data sources |
| **LLM02** | Sensitive Information Disclosure | Secrets detected in MCP configs (API keys, tokens, passwords, connection strings) can be exposed through agent interactions |
| **LLM03** | Supply Chain Vulnerabilities | Unknown/unverified MCP sources and MCPs not in known registry represent supply chain risks |
| **LLM06** | Excessive Agency | MCPs with database access, shell access, filesystem access, or network access flags represent excessive agency risks |
| **LLM07** | System Prompt Leakage | Credentials or connection strings in configs that agents can access may leak through system prompts |
| **LLM09** | Overreliance | AI model inventory identifies all models in use (cloud vs. local), giving visibility into AI dependencies and vendor concentration risk |
| **LLM10** | Unbounded Consumption | API endpoints and AI models detected provide visibility into potential cost and resource consumption vectors |

### How Mappings Are Triggered

| OWASP ID | Trigger Condition |
|----------|-------------------|
| LLM01 | Any MCP found in scan |
| LLM02 | `secrets-detected` flag or secrets found in configuration |
| LLM03 | MCP not in known registry OR `unverified-source` flag |
| LLM06 | `database-access`, `shell-access`, `filesystem-access`, `network-access`, or `unsafe-command-allowlist` flag |
| LLM07 | `secrets-in-env` flag or secrets detected |
| LLM09 | AI model detected in MCP configuration |
| LLM10 | API endpoints or AI models detected |

### Output Formats with OWASP Data

All output formats include OWASP LLM mappings:

- **CLI**: Shows `OWASP LLM: LLM02 (Sensitive Information Disclosure)` for each finding
- **JSON**: Includes `owasp_llm` array on findings and `owasp_llm_coverage` summary
- **SARIF**: Adds `OWASP-LLM-*` tags for GitHub Security integration
- **Markdown**: Lists OWASP references in findings section

### Example JSON Output

```json
{
  "findings": [
    {
      "flag": "secrets-detected",
      "severity": "critical",
      "owasp_llm": [
        {"id": "LLM02", "name": "Sensitive Information Disclosure"},
        {"id": "LLM07", "name": "System Prompt Leakage"}
      ]
    }
  ],
  "owasp_llm_coverage": {
    "reference": "https://genai.owasp.org/llm-top-10/",
    "items": [
      {"id": "LLM01", "name": "Prompt Injection", "covered": true, "evidence": "5 MCP(s) discovered - attack surface mapped"},
      {"id": "LLM02", "name": "Sensitive Information Disclosure", "covered": true, "evidence": "3 secret(s) detected in MCP configs"}
    ]
  }
}
```

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

### Command Allowlist Flags

| Flag | Meaning | How It's Detected |
|------|---------|-------------------|
| `unsafe-command-allowlist` | Command allowlist can be bypassed via argument-level execution primitives in the allowlisted binary itself | An allowlist-style env var names a bare binary from the reference list in [`mcp_audit/data/allowlist_bypass_binaries.py`](../mcp_audit/data/allowlist_bypass_binaries.py) (`git`, `find`, `python`, `python3`, `perl`, `awk`, `gawk`, `sed`, `tar`, `npx`, `node`, `bash`, `sh`, `env`, `xargs`, `ssh`) |

Checking only argv[0] against an allowlist doesn't restrict execution if the allowlisted binary exposes its own way to run arbitrary commands — e.g. `git -c alias.x=!whoami x` or `find . -exec whoami \;` bypass an `ALLOW_COMMANDS=git`/`find` allowlist without any shell metacharacters. The reference binary list is intentionally extensible, new primitives can be added as they're discovered.

**Key matching.** The env var key is split on `_` and matched on whole tokens, not substrings:

- It must contain an allow token (`ALLOW`, `ALLOWED`, `ALLOWLIST`, `WHITELIST`, `PERMIT`, `PERMITTED`) **and** a subject token (`COMMAND(S)`, `CMD(S)`, `PATTERN(S)`, `BINARY/BINARIES`, `EXECUTABLE(S)`).
- It must **end** in a subject or list token, so a toggle like `ALLOW_COMMAND_LOGGING` does not qualify.
- Any deny token (`DISALLOW`, `DENY`, `BLOCK`, `FORBID`, `EXCLUDE`, `DENYLIST`, `BLOCKLIST`, `BLACKLIST`, `NO`, `NOT`, `NEVER`) disqualifies the key — a denylist such as `DISALLOW_COMMANDS=git` is the opposite of this risk.

Matches: `ALLOW_COMMANDS`, `ALLOWED_COMMANDS`, `ALLOW_PATTERNS`, `ALLOWED_PATTERNS`, `COMMAND_ALLOWLIST`, `ALLOWLIST_COMMANDS`, `MCP_ALLOW_COMMANDS`. Does not match: `DISALLOW_COMMANDS`, `DENY_COMMANDS`, `COMMAND_DENYLIST`, `ALLOW_COMMAND_LOGGING`, `GIT_COMMAND`.

**Value matching.** Entries are separated by `,`, `;`, `|`, or newline — *not* whitespace. Quotes and regex anchors (`^`, `$`) are stripped and path entries are reduced to their basename (`/usr/bin/find` → `find`). An entry that still carries arguments (`ALLOW_COMMANDS="git status"`) is a full-argument-vector allowlist — the pattern this flag's own remediation recommends — and is **not** flagged. Only bare binary names are.

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
- `unsafe-command-allowlist` flag present
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
