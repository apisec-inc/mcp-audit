# MCP Audit Backend

Serverless backend for PDF report generation and email delivery.

## Architecture

- **Runtime**: Vercel Serverless Functions
- **PDF Generation**: React-PDF (@react-pdf/renderer)
- **Email Delivery**: Gmail SMTP (via Nodemailer)

## API Endpoint

### POST /api/report

Generates a PDF security report and emails it to the specified address.

**Request Body:**
```json
{
  "email": "user@example.com",
  "source": "cli" | "web",
  "scan_type": "local",
  "timestamp": "2024-01-14T12:00:00Z",
  "summary": {
    "total_mcps": 10,
    "secrets_count": 3,
    "apis_count": 5,
    "models_count": 4,
    "risk_breakdown": {
      "critical": 1,
      "high": 2,
      "medium": 3,
      "low": 4
    }
  }
}
```

**Response:**
```json
{
  "success": true,
  "message": "Report sent successfully"
}
```

## Deployment

### Prerequisites

1. [Vercel account](https://vercel.com) (free)
2. Google Workspace email (@apisec.ai)
3. Gmail App Password

### Step 1: Create Gmail App Password

1. Go to https://myaccount.google.com/apppasswords
2. Sign in with your @apisec.ai account
3. Select app: "Mail"
4. Select device: "Other" → name it "MCP Audit"
5. Click "Generate"
6. **Copy the 16-character password** (shown only once)

> Note: If you don't see App Passwords, enable 2FA first at https://myaccount.google.com/security

### Step 2: Deploy to Vercel

1. Install Vercel CLI:
   ```bash
   npm install -g vercel
   ```

2. Navigate to backend folder:
   ```bash
   cd backend
   ```

3. Install dependencies:
   ```bash
   npm install
   ```

4. Login to Vercel:
   ```bash
   vercel login
   ```

5. Deploy (first time will prompt to link project):
   ```bash
   vercel
   ```

6. Add environment variables:
   ```bash
   vercel env add GMAIL_USER
   # Enter: audit@apisec.ai (or your sender email)

   vercel env add GMAIL_APP_PASSWORD
   # Enter: the 16-char app password from Step 1
   ```

7. Deploy to production:
   ```bash
   vercel --prod
   ```

### Step 3: Update Endpoint URL

After deploying, note your Vercel URL (e.g., `mcp-audit-backend.vercel.app`).

If different from `mcp-audit-api.vercel.app`, update:
- CLI: `mcp_audit/commands/scan.py` line ~904
- Web UI: `app.js` line ~2351

## Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `GMAIL_USER` | Sender email address | `audit@apisec.ai` |
| `GMAIL_APP_PASSWORD` | 16-char app password | `abcd efgh ijkl mnop` |

## Gmail Sending Limits

- Google Workspace: 2,000 emails/day
- Regular Gmail: 500 emails/day

## Local Development

```bash
npm run dev
```

This starts a local Vercel development server at `http://localhost:3000`.

For local testing, create a `.env` file:
```
GMAIL_USER=audit@apisec.ai
GMAIL_APP_PASSWORD=your-app-password
```

## Testing

```bash
curl -X POST http://localhost:3000/api/report \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "source": "test",
    "scan_type": "local",
    "summary": {
      "total_mcps": 5,
      "secrets_count": 2,
      "apis_count": 3,
      "models_count": 1,
      "risk_breakdown": {
        "critical": 1,
        "high": 1,
        "medium": 2,
        "low": 1
      }
    }
  }'
```

## File Structure

```
backend/
├── api/
│   └── report.ts      # Main API endpoint
├── lib/
│   ├── pdf.tsx        # React-PDF report template
│   └── email.ts       # Gmail/Nodemailer integration
├── package.json
├── tsconfig.json
├── vercel.json
└── README.md
```

## Troubleshooting

### "Invalid login" error
- Verify the App Password is correct (no spaces)
- Ensure 2FA is enabled on the Google account
- Check that "Less secure apps" is not blocking access

### Email not delivered
- Check spam folder
- Verify recipient email is valid
- Check Vercel function logs for errors
