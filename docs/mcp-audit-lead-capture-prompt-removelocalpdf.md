# APIsec MCP Audit: Lead Capture Implementation Prompt

## Overview

Add lead capture functionality to the existing **APIsec MCP Audit** tool (CLI + Web UI). Users can optionally provide their email to receive a professional PDF report of their scan results. This is the primary mechanism for capturing leads from the open source tool.

**Product name:** APIsec MCP Audit (use this exact name consistently in all UI, CLI output, reports, and documentation)

**Existing features (already built):**
- Secrets Detection with rotation links
- API Inventory (Database, REST, SSE, cloud endpoints)
- Remediation guidance
- Export: JSON (for CI/CD), CSV (for spreadsheets)
- CLI flags: `--secrets-only`, `--apis-only`, `--remediation`, `--verbose`

**What's missing:**
- Lead capture (email collection)
- PDF report generation (server-side, via email only)
- Backend to receive and store leads

**Export strategy:**
| Format | Purpose | Lead Capture? |
|--------|---------|---------------|
| JSON | CI/CD pipelines, automation | ❌ No |
| CSV | Spreadsheets, data analysis | ❌ No |
| **PDF** | Executive reports, sharing with leadership | ✅ Yes (email required) |

---

## Design Principles

1. **Zero friction for users who don't want to share email** — Enter to skip, tool works fully without it
2. **Clear value exchange** — PDF report they can share with their team
3. **Privacy-first** — No secrets transmitted, only summary data, transparent about what's collected
4. **Works offline** — Core scan functionality never depends on backend

---

## Feature Requirements

### 1. CLI: Optional Email Prompt

After scan results display, show an optional prompt:

```
$ mcp-audit scan

[... scan results display as normal ...]

────────────────────────────────────────────────────────────────
📄 Get a PDF report to share with your team
   Email (press Enter to skip): raj@acme.com

✅ Report sent to raj@acme.com
   View online: https://apisec.ai/mcp-report/abc123
────────────────────────────────────────────────────────────────
```

**Behavior:**
- Prompt appears AFTER all scan results are displayed
- User can press Enter to skip (no email collected, no API call)
- If email provided:
  - Validate email format (basic regex)
  - POST scan summary + email to backend
  - Backend generates PDF + emails it
  - Show confirmation with link to online report

**Edge cases:**
- Network failure: "Couldn't send report. Check your connection and try again."
- Invalid email format: "Invalid email format. Press Enter to skip or try again: "
- Timeout: Fail silently after 5 seconds, don't block user

### 2. CLI: New Flags

```bash
# Skip the email prompt entirely (for CI/CD, privacy-conscious users)
mcp-audit scan --no-report

# Send report to specific email (non-interactive)
mcp-audit scan --email raj@acme.com

# Export for CI/CD pipelines
mcp-audit scan --format json -o results.json
```

**Flag details:**

| Flag | Behavior |
|------|----------|
| `--no-report` | Skip email prompt entirely. No network calls. |
| `--email <email>` | Non-interactive. Send PDF report to this email. No prompt. |
| `--format json` | Export raw results as JSON for CI/CD integration. |
| `--format csv` | Export raw results as CSV for spreadsheet analysis. |

**JSON export message (for CI/CD):**
```
$ mcp-audit scan --format json -o results.json

APIsec MCP Audit v0.1.3

Scanning...
Found 12 MCPs (2 critical, 3 high, 5 medium, 2 low)

✅ Results saved to results.json

────────────────────────────────────────────────────────────────
💡 CI/CD Integration Tip:
   Parse results.json to fail builds when critical risks are found.
   Example: jq '.summary.critical > 0' results.json

   Docs: https://apisec-inc.github.io/mcp-audit/ci-cd
────────────────────────────────────────────────────────────────
```

### 3. Web UI: Email Capture

Add email capture to the Web UI after scan results display:

```
┌─────────────────────────────────────────────────────────────────────┐
│                                                                     │
│  📄 Get a PDF Report                                                │
│                                                                     │
│  Receive a professional report to share with your security team.   │
│                                                                     │
│  ┌─────────────────────────────────────┐                           │
│  │ Email                               │  [Send Report]            │
│  └─────────────────────────────────────┘                           │
│                                                                     │
│  ─────────────────────────────────────────────────────────────────  │
│                                                                     │
│  Export raw data: [JSON] [CSV]                                      │
│                                                                     │
│  💡 Use JSON export for CI/CD pipeline integration                  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Behavior:**
- Section appears below scan results (after existing results table)
- "Send Report" button:
  - Validates email
  - POSTs to backend
  - Shows success: "✅ Report sent! Check your inbox."
  - Shows link to online report
- JSON/CSV buttons:
  - Download raw data directly
  - No email required
  - Clear message that these are for CI/CD / data analysis

**PDF is only available via email.** This is the value exchange for lead capture.

### 4. PDF Report Template

**Tool name:** APIsec MCP Audit (use this exact name consistently throughout the report)

**Design philosophy:**
- **Modern & Clean:** Generous whitespace, no visual clutter, breathing room between sections
- **Professional:** Suitable for sharing with C-suite, board members, auditors
- **Scannable:** Key findings visible in <5 seconds, details available for those who want them
- **Branded:** Consistent APIsec identity without being overly promotional

**Design requirements:**
- Modern, clean, minimalist design
- Professional enough to share with executives and security leadership
- Consistent APIsec branding (colors, logo)
- Clear visual hierarchy
- Easy to scan quickly
- Print-friendly (works in color and B&W)

**Design specifications:**

| Element | Specification |
|---------|---------------|
| **Primary color** | APIsec brand blue (#0066FF or from brand guidelines) |
| **Critical color** | Red (#DC2626) |
| **High color** | Orange (#EA580C) |
| **Medium color** | Yellow (#CA8A04) |
| **Low color** | Green (#16A34A) |
| **Font** | Inter, SF Pro, or system sans-serif |
| **Headings** | Bold, generous whitespace above |
| **Body text** | 11-12pt, comfortable line height (1.5) |
| **Page margins** | 0.75" all sides |
| **Max width** | Content constrained for readability |
| **Cards/Boxes** | Subtle borders (#E5E7EB), rounded corners (8px), light shadows |
| **Section spacing** | 24-32px between major sections |
| **Stat cards** | Large numbers (32-48pt), small labels (10pt), centered |

**Visual style notes:**
- NO heavy borders or boxes
- NO dense walls of text
- NO garish colors or gradients
- YES subtle shadows and rounded corners
- YES consistent spacing rhythm
- YES clear hierarchy (title → summary → details)
- YES metric cards with large numbers for quick scanning

**Report structure:**

```
┌─────────────────────────────────────────────────────────────────────┐
│                                                                     │
│  PAGE 1: COVER + EXECUTIVE SUMMARY                                  │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                                                             │   │
│  │  [APIsec Logo]                                              │   │
│  │                                                             │   │
│  │                                                             │   │
│  │         APIsec MCP Audit Report                             │   │
│  │                                                             │   │
│  │         ─────────────────────────                           │   │
│  │                                                             │   │
│  │         Target: acme-corp                                   │   │
│  │         Scan Type: GitHub Organization                      │   │
│  │         Date: January 11, 2026                              │   │
│  │                                                             │   │
│  │                                                             │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│                                                                     │
│  Executive Summary                                                  │
│  ──────────────────────────────────────────────────────────────    │
│                                                                     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌───────────┐  │
│  │     12      │  │      4      │  │      8      │  │     3     │  │
│  │   MCPs      │  │  Secrets    │  │   APIs      │  │ Unverified│  │
│  │ Discovered  │  │  Exposed    │  │ Discovered  │  │   MCPs    │  │
│  └─────────────┘  └─────────────┘  └─────────────┘  └───────────┘  │
│                                                                     │
│                                                                     │
│  Risk Distribution                                                  │
│  ──────────────────────────────────────────────────────────────    │
│                                                                     │
│  Critical  ████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  2       │
│  High      ████████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  3       │
│  Medium    ████████████████████░░░░░░░░░░░░░░░░░░░░░░░░░░  5       │
│  Low       ████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  2       │
│                                                                     │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  ⚠️  Immediate Actions Required                             │   │
│  │                                                             │   │
│  │  • 4 secrets require immediate rotation                     │   │
│  │  • 2 MCPs have shell command execution access               │   │
│  │  • 3 MCPs are from unverified sources                       │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                                                                     │
│  PAGE 2: SECRETS                                                    │
│                                                                     │
│  Exposed Secrets                                                    │
│  ──────────────────────────────────────────────────────────────    │
│                                                                     │
│  4 credentials detected in MCP configurations.                      │
│  Rotate immediately to prevent unauthorized access.                 │
│                                                                     │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  ● CRITICAL                                                 │   │
│  │                                                             │   │
│  │  Stripe Live Secret Key                                     │   │
│  │  Location: salesforce-mcp → STRIPE_KEY                      │   │
│  │  Rotate: dashboard.stripe.com/apikeys                       │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  ● CRITICAL                                                 │   │
│  │                                                             │   │
│  │  PostgreSQL Connection String                               │   │
│  │  Location: postgres-mcp → DATABASE_URL                      │   │
│  │  Rotate: Update database password and connection string     │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  ● HIGH                                                     │   │
│  │                                                             │   │
│  │  GitHub Personal Access Token                               │   │
│  │  Location: github-mcp → GITHUB_TOKEN                        │   │
│  │  Rotate: github.com/settings/tokens                         │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  ● HIGH                                                     │   │
│  │                                                             │   │
│  │  OpenAI API Key                                             │   │
│  │  Location: ai-tools-mcp → OPENAI_KEY                        │   │
│  │  Rotate: platform.openai.com/api-keys                       │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                                                                     │
│  PAGE 3: API INVENTORY                                              │
│                                                                     │
│  Discovered APIs                                                    │
│  ──────────────────────────────────────────────────────────────    │
│                                                                     │
│  8 API endpoints discovered across MCP configurations.              │
│  These APIs should be included in your security testing program.    │
│                                                                     │
│                                                                     │
│  SaaS APIs                                                          │
│  ─────────                                                          │
│                                                                     │
│  Endpoint                    Source MCP           Type              │
│  ──────────────────────────────────────────────────────────────    │
│  api.salesforce.com          salesforce-mcp       CRM               │
│  api.stripe.com              stripe-mcp           Payments          │
│  api.github.com              github-mcp           Version Control   │
│  api.slack.com               slack-mcp            Messaging         │
│  api.openai.com              ai-tools-mcp         AI/ML             │
│                                                                     │
│                                                                     │
│  Internal APIs                                                      │
│  ─────────────                                                      │
│                                                                     │
│  Endpoint                         Source MCP      Notes             │
│  ──────────────────────────────────────────────────────────────    │
│  inventory.internal.acme.com      inventory-mcp   Not in API catalog│
│  auth.internal.acme.com           auth-mcp        Authentication    │
│                                                                     │
│                                                                     │
│  Databases                                                          │
│  ─────────                                                          │
│                                                                     │
│  Type          Host              Source MCP       Access Level      │
│  ──────────────────────────────────────────────────────────────    │
│  PostgreSQL    db.acme.com       postgres-mcp     Read/Write        │
│                                                                     │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                                                                     │
│  PAGE 4: MCP INVENTORY                                              │
│                                                                     │
│  MCP Inventory                                                      │
│  ──────────────────────────────────────────────────────────────    │
│                                                                     │
│  12 Model Context Protocol servers discovered.                      │
│                                                                     │
│                                                                     │
│  ┌────────────────────────────────────────────────────────────┐    │
│  │ MCP Name        │ Risk     │ Verified │ Risk Flags         │    │
│  ├────────────────────────────────────────────────────────────┤    │
│  │ shell-executor  │ Critical │ No       │ shell-access       │    │
│  │ postgres-mcp    │ Critical │ Yes      │ database, secrets  │    │
│  │ filesystem      │ High     │ Yes      │ filesystem-access  │    │
│  │ salesforce-mcp  │ High     │ Yes      │ network, secrets   │    │
│  │ github-mcp      │ High     │ Yes      │ network, secrets   │    │
│  │ slack-mcp       │ Medium   │ Yes      │ network-access     │    │
│  │ ai-tools-mcp    │ Medium   │ No       │ network, secrets   │    │
│  │ inventory-mcp   │ Medium   │ No       │ network-access     │    │
│  │ auth-mcp        │ Medium   │ No       │ network-access     │    │
│  │ stripe-mcp      │ Medium   │ Yes      │ network-access     │    │
│  │ fetch-mcp       │ Low      │ Yes      │ network-access     │    │
│  │ time-mcp        │ Low      │ Yes      │ none               │    │
│  └────────────────────────────────────────────────────────────┘    │
│                                                                     │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                                                                     │
│  PAGE 5: REMEDIATION + NEXT STEPS                                   │
│                                                                     │
│  Remediation Priorities                                             │
│  ──────────────────────────────────────────────────────────────    │
│                                                                     │
│                                                                     │
│  1. Rotate Exposed Secrets                          IMMEDIATE       │
│     ─────────────────────────────────────────────────────────      │
│     4 credentials are exposed in MCP configuration files.           │
│     Rotate each credential using the links provided in the          │
│     Secrets section of this report.                                 │
│                                                                     │
│                                                                     │
│  2. Review Shell Access MCPs                        HIGH PRIORITY   │
│     ─────────────────────────────────────────────────────────      │
│     2 MCPs have shell command execution capability.                 │
│     Remove unless explicitly required for your workflow.            │
│     If required, restrict to specific allowed commands.             │
│                                                                     │
│                                                                     │
│  3. Verify Unknown MCPs                             MEDIUM          │
│     ─────────────────────────────────────────────────────────      │
│     3 MCPs are from unverified sources.                             │
│     Review source code or replace with official alternatives.       │
│                                                                     │
│                                                                     │
│  4. Test Discovered APIs                            RECOMMENDED     │
│     ─────────────────────────────────────────────────────────      │
│     8 APIs discovered. Include in your API security testing         │
│     program to check for BOLA, injection, and auth bypass.          │
│                                                                     │
│                                                                     │
│  ──────────────────────────────────────────────────────────────    │
│                                                                     │
│  Next Steps Checklist                                               │
│                                                                     │
│  ☐  Rotate all exposed credentials                                  │
│  ☐  Review and remove unnecessary shell-access MCPs                 │
│  ☐  Audit unverified MCPs or replace with verified versions         │
│  ☐  Add discovered APIs to security testing program                 │
│  ☐  Schedule follow-up scan in 30 days                              │
│                                                                     │
│                                                                     │
│  ──────────────────────────────────────────────────────────────    │
│                                                                     │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                                                             │   │
│  │  Test Your APIs for Vulnerabilities                         │   │
│  │                                                             │   │
│  │  APIsec automatically tests APIs for OWASP Top 10           │   │
│  │  vulnerabilities including BOLA, injection, and auth bypass.│   │
│  │                                                             │   │
│  │  → www.apisec.ai                                            │   │
│  │                                                             │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│                                                                     │
│  ──────────────────────────────────────────────────────────────    │
│                                                                     │
│  Generated by APIsec MCP Audit                                      │
│  https://apisec-inc.github.io/mcp-audit                             │
│                                                                     │
│  Questions? rajaram@apisec.ai                                       │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Implementation approach:**

| Method | Use Case | Technology |
|--------|----------|------------|
| **Server-side PDF** | Email delivery (only way to get PDF) | Puppeteer or Playwright (renders HTML template) |
| **Client-side JSON/CSV** | CI/CD, data analysis | Direct download, no backend |

**PDF is server-side only.** Users must provide email to receive PDF. This is the lead capture mechanism.

**HTML template requirements:**
- Create standalone HTML template (`report-template.html`)
- Inline all CSS (no external stylesheets)
- Use web-safe fonts with fallbacks (Inter via Google Fonts, fallback to system)
- Test rendering at different content lengths (1 MCP vs 50 MCPs)
- Include APIsec logo as base64 or hosted URL
- Use CSS `@media print` rules for clean printing
- Ensure tables don't break across pages awkwardly
- Use CSS Grid or Flexbox for stat cards layout
- Include subtle background colors for section differentiation
- Add page numbers in footer

**Reference designs (for visual inspiration):**
- Notion exports
- Linear changelogs
- Stripe documentation
- Vercel dashboards

The goal is a report that looks like it came from a well-funded, design-conscious company—not a generic security tool output.

### 5. Backend: Lead Capture Endpoint

Minimal backend to receive leads and send PDF reports.

**Endpoint:** `POST https://apisec.ai/api/mcp-leads`

**Request payload:**
```json
{
  "email": "raj@acme.com",
  "source": "cli",           // "cli" or "web"
  "scan_type": "github",     // "github" or "local"
  "target": "acme-corp",     // org name or "local-machine"
  "timestamp": "2026-01-11T10:30:00Z",
  "summary": {
    "total_mcps": 12,
    "risk_distribution": {
      "critical": 2,
      "high": 3,
      "medium": 5,
      "low": 2
    },
    "secrets_count": 4,
    "secrets_severity": {
      "critical": 2,
      "high": 2,
      "medium": 0
    },
    "apis_discovered": {
      "total": 8,
      "saas": 5,
      "internal": 2,
      "database": 1
    },
    "unverified_mcps": 3
  },
  "mcps": [
    {
      "name": "salesforce-mcp",
      "risk": "high",
      "risk_flags": ["network-access", "secrets"],
      "secrets_count": 1,
      "apis": ["api.salesforce.com"]
    }
    // ... other MCPs (summary only, no secret values)
  ]
}
```

**What is NOT sent:**
- Actual secret values (only counts)
- Full config file contents
- Source code
- Repository file paths

**Response:**
```json
{
  "success": true,
  "report_id": "abc123",
  "report_url": "https://apisec.ai/mcp-report/abc123",
  "message": "Report sent to raj@acme.com"
}
```

**Backend flow:**
1. Receive POST request
2. Validate email format
3. Store lead to database (Airtable/Supabase/Postgres)
4. Generate PDF from scan summary
5. Send email with PDF attachment
6. Return success response with report URL

**Backend stack (simple):**
- Vercel serverless function or Cloudflare Worker
- Supabase or Airtable for storage
- Resend or SendGrid for email
- weasyprint or Puppeteer for PDF generation

### 6. Privacy & Transparency

**CLI first-run notice:**
```
$ mcp-audit scan

APIsec MCP Audit v0.1.3
Privacy: All scanning happens locally. No data is sent unless you 
choose to receive a PDF report. Use --no-report to skip prompts.

Scanning...
```

**README section:**
```markdown
## Privacy

APIsec MCP Audit runs entirely on your machine. No code, configs, or secrets 
are transmitted to any server.

If you choose to receive a PDF report (optional), we collect:
- Your email address
- Scan summary (MCP count, risk levels, secret counts—NOT actual secret values)

This helps us understand usage and deliver your report. Your email is 
not shared with third parties.

To skip all prompts and network calls:
```bash
mcp-audit scan --no-report
```
```

**Data retention note:**
Add to backend: Store leads for [X] days/months. Provide unsubscribe mechanism.

---

## Files to Create/Modify

### CLI

| File | Changes |
|------|---------|
| `cli.py` | Add email prompt after scan, add `--no-report` and `--email` flags |
| `upload.py` (new) | API client to POST to backend |
| `output.py` | Update JSON export message with CI/CD tip |

### Web UI

| File | Changes |
|------|---------|
| `index.html` | Add email input + "Send Report" section, update export buttons (remove MD, add CI/CD tip for JSON) |
| `app.js` | Add email capture logic, backend POST |

### Backend (New)

| File | Purpose |
|------|---------|
| `api/mcp-leads.js` | Serverless function: receive POST, store lead, generate PDF, send email |
| `lib/pdf.js` | PDF generation from scan summary (server-side only) |
| `lib/email.js` | Send email with PDF attachment |
| `templates/report.html` | HTML template for PDF generation |

---

## Implementation Order

1. **CLI: `--no-report` flag** (15 min) — Let privacy-conscious users opt out immediately
2. **CLI: Email prompt** (30 min) — Basic prompt, validate email, show confirmation (mock backend)
3. **CLI: JSON export CI/CD message** (15 min) — Add helpful tip after JSON export
4. **Backend: Lead storage endpoint** (1-2 hrs) — POST to Supabase/Airtable
5. **PDF template** (2-3 hrs) — HTML template that looks professional
6. **Backend: PDF generation** (1-2 hrs) — Generate PDF server-side
7. **Backend: Email sending** (1 hr) — Send PDF as attachment
8. **CLI: Wire to real backend** (30 min) — Connect prompt to live endpoint
9. **Web UI: Email capture** (1 hr) — Add input + button + backend call
10. **Web UI: Update exports** (30 min) — Remove MD, add CI/CD tip for JSON
11. **Testing + polish** (1-2 hrs)

**Total estimate:** 10-14 hours (~2 days)

---

## Definition of Done

### CLI
- [ ] `--no-report` flag skips all prompts and network calls
- [ ] Email prompt appears after scan results
- [ ] Enter key skips prompt (no network call)
- [ ] Valid email triggers POST to backend
- [ ] Invalid email shows error, allows retry
- [ ] Network failure fails gracefully with helpful message
- [ ] `--email <email>` flag works for non-interactive use
- [ ] JSON export shows CI/CD integration tip
- [ ] No local PDF generation (PDF only via email)

### Web UI
- [ ] Email input + "Send Report" button appears below results
- [ ] Button validates email and POSTs to backend
- [ ] Success message shows with link to online report
- [ ] Loading state while sending
- [ ] JSON/CSV export buttons work
- [ ] Markdown export removed
- [ ] JSON export shows CI/CD tip
- [ ] No client-side PDF download (PDF only via email)

### Backend
- [ ] `POST /api/mcp-leads` receives and stores lead
- [ ] Email format validation
- [ ] PDF generated from scan summary (server-side)
- [ ] Email sent with PDF attachment
- [ ] Response includes report URL
- [ ] No secret values stored (only counts)

### Privacy
- [ ] README documents what data is collected
- [ ] First-run notice in CLI mentions privacy
- [ ] `--no-report` flag documented and works
- [ ] No secret values transmitted to backend

---

## Security Considerations

1. **Never transmit actual secret values** — Only counts and severity
2. **Validate email server-side** — Prevent injection attacks
3. **Rate limit the endpoint** — Prevent abuse (e.g., 10 requests/minute per IP)
4. **HTTPS only** — All backend calls over TLS
5. **Sanitize inputs** — Don't trust client-provided data for PDF generation
6. **No PII in logs** — Don't log full email addresses in production
