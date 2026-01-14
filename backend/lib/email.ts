import nodemailer from 'nodemailer';

// Gmail SMTP configuration
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER,        // e.g., audit@apisec.ai
    pass: process.env.GMAIL_APP_PASSWORD  // 16-char app password
  }
});

interface SendReportOptions {
  to: string;
  pdfBuffer: Buffer;
  summary: {
    total_mcps: number;
    secrets_count: number;
    risk_breakdown: {
      critical: number;
      high: number;
      medium: number;
      low: number;
    };
  };
}

export async function sendReportEmail(options: SendReportOptions): Promise<{ success: boolean; error?: string }> {
  const { to, pdfBuffer, summary } = options;

  const hasSecrets = summary.secrets_count > 0;
  const hasCritical = summary.risk_breakdown.critical > 0;
  const totalIssues =
    summary.risk_breakdown.critical +
    summary.risk_breakdown.high +
    summary.risk_breakdown.medium +
    summary.risk_breakdown.low;

  // Build subject line based on findings
  let subject = 'Your MCP Security Audit Report';
  if (hasSecrets || hasCritical) {
    subject = `MCP Security Audit: ${summary.secrets_count} Secrets & ${totalIssues} Issues Found`;
  }

  // Email HTML body
  const htmlBody = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>MCP Security Audit Report</title>
</head>
<body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background-color: #f4f4f5;">
  <table width="100%" cellpadding="0" cellspacing="0" style="max-width: 600px; margin: 0 auto; background-color: #ffffff;">
    <!-- Header -->
    <tr>
      <td style="padding: 30px 40px; border-bottom: 3px solid #1E40AF;">
        <table width="100%" cellpadding="0" cellspacing="0">
          <tr>
            <td>
              <h1 style="margin: 0; font-size: 24px; color: #1E40AF; font-weight: bold;">APIsec</h1>
              <p style="margin: 5px 0 0 0; font-size: 12px; color: #6b7280;">MCP Security Audit</p>
            </td>
            <td style="text-align: right;">
              <a href="https://www.apisec.ai" style="font-size: 12px; color: #6b7280; text-decoration: none;">www.apisec.ai</a>
            </td>
          </tr>
        </table>
      </td>
    </tr>

    <!-- Main Content -->
    <tr>
      <td style="padding: 40px;">
        <h2 style="margin: 0 0 20px 0; font-size: 20px; color: #111827;">Your MCP Security Report is Ready</h2>

        <p style="margin: 0 0 25px 0; font-size: 14px; color: #374151; line-height: 1.6;">
          Thank you for using APIsec MCP Audit. Your security report is attached to this email as a PDF.
        </p>

        <!-- Summary Box -->
        <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #f9fafb; border-radius: 8px; margin-bottom: 25px;">
          <tr>
            <td style="padding: 20px;">
              <h3 style="margin: 0 0 15px 0; font-size: 14px; color: #374151; text-transform: uppercase; letter-spacing: 0.5px;">Scan Summary</h3>
              <table width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <td width="25%" style="padding: 10px; text-align: center;">
                    <div style="font-size: 28px; font-weight: bold; color: #111827;">${summary.total_mcps}</div>
                    <div style="font-size: 11px; color: #6b7280; text-transform: uppercase;">MCPs</div>
                  </td>
                  <td width="25%" style="padding: 10px; text-align: center; ${hasSecrets ? 'background-color: #fef2f2; border-radius: 6px;' : ''}">
                    <div style="font-size: 28px; font-weight: bold; color: ${hasSecrets ? '#dc2626' : '#111827'};">${summary.secrets_count}</div>
                    <div style="font-size: 11px; color: #6b7280; text-transform: uppercase;">Secrets</div>
                  </td>
                  <td width="25%" style="padding: 10px; text-align: center; ${hasCritical ? 'background-color: #fef2f2; border-radius: 6px;' : ''}">
                    <div style="font-size: 28px; font-weight: bold; color: ${hasCritical ? '#dc2626' : '#111827'};">${summary.risk_breakdown.critical}</div>
                    <div style="font-size: 11px; color: #6b7280; text-transform: uppercase;">Critical</div>
                  </td>
                  <td width="25%" style="padding: 10px; text-align: center;">
                    <div style="font-size: 28px; font-weight: bold; color: #111827;">${totalIssues}</div>
                    <div style="font-size: 11px; color: #6b7280; text-transform: uppercase;">Total Issues</div>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
        </table>

        ${hasSecrets || hasCritical ? `
        <!-- Alert Box -->
        <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #fef2f2; border-left: 4px solid #dc2626; border-radius: 0 8px 8px 0; margin-bottom: 25px;">
          <tr>
            <td style="padding: 15px 20px;">
              <p style="margin: 0; font-size: 14px; color: #991b1b; font-weight: 600;">Action Required</p>
              <p style="margin: 8px 0 0 0; font-size: 13px; color: #7f1d1d; line-height: 1.5;">
                ${hasSecrets ? `${summary.secrets_count} exposed credential(s) were detected. ` : ''}
                ${hasCritical ? `${summary.risk_breakdown.critical} critical security issue(s) need immediate attention. ` : ''}
                Please review the attached report for detailed remediation steps.
              </p>
            </td>
          </tr>
        </table>
        ` : ''}

        <p style="margin: 0 0 25px 0; font-size: 14px; color: #374151; line-height: 1.6;">
          The attached PDF contains detailed findings, risk assessments, and actionable recommendations for securing your MCP configurations.
        </p>

        <!-- CTA -->
        <table width="100%" cellpadding="0" cellspacing="0">
          <tr>
            <td style="text-align: center; padding: 20px 0;">
              <a href="https://www.apisec.ai" style="display: inline-block; padding: 14px 28px; background-color: #1E40AF; color: #ffffff; text-decoration: none; font-size: 14px; font-weight: 600; border-radius: 6px;">
                Learn More About APIsec
              </a>
            </td>
          </tr>
        </table>
      </td>
    </tr>

    <!-- Footer -->
    <tr>
      <td style="padding: 30px 40px; background-color: #f9fafb; border-top: 1px solid #e5e7eb;">
        <table width="100%" cellpadding="0" cellspacing="0">
          <tr>
            <td>
              <p style="margin: 0; font-size: 14px; font-weight: bold; color: #1E40AF;">APIsec Inc.</p>
              <p style="margin: 5px 0 0 0; font-size: 12px; color: #6b7280;">
                <a href="https://www.apisec.ai" style="color: #6b7280; text-decoration: none;">www.apisec.ai</a>
              </p>
            </td>
            <td style="text-align: right;">
              <p style="margin: 0; font-size: 11px; color: #9ca3af; line-height: 1.5;">
                This report was generated by<br>APIsec MCP Audit Tool
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>

  <!-- Sub-footer -->
  <table width="100%" cellpadding="0" cellspacing="0" style="max-width: 600px; margin: 0 auto;">
    <tr>
      <td style="padding: 20px 40px; text-align: center;">
        <p style="margin: 0; font-size: 11px; color: #9ca3af;">
          You received this email because you requested an MCP security audit report.
        </p>
      </td>
    </tr>
  </table>
</body>
</html>
  `;

  // Plain text fallback
  const textBody = `
APIsec MCP Security Audit Report
================================

Your MCP security report is attached to this email as a PDF.

SCAN SUMMARY
------------
MCPs Found: ${summary.total_mcps}
Secrets Exposed: ${summary.secrets_count}
Critical Issues: ${summary.risk_breakdown.critical}
High Issues: ${summary.risk_breakdown.high}
Medium Issues: ${summary.risk_breakdown.medium}
Low Issues: ${summary.risk_breakdown.low}

${hasSecrets || hasCritical ? `
ACTION REQUIRED
---------------
${hasSecrets ? `${summary.secrets_count} exposed credential(s) were detected. ` : ''}
${hasCritical ? `${summary.risk_breakdown.critical} critical security issue(s) need immediate attention. ` : ''}
Please review the attached report for detailed remediation steps.
` : ''}

The attached PDF contains detailed findings, risk assessments, and actionable recommendations for securing your MCP configurations.

---
APIsec Inc.
www.apisec.ai

This report was generated by APIsec MCP Audit Tool.
  `;

  try {
    const fromEmail = process.env.GMAIL_USER || 'audit@apisec.ai';

    await transporter.sendMail({
      from: `"APIsec MCP Audit" <${fromEmail}>`,
      to: to,
      subject: subject,
      text: textBody,
      html: htmlBody,
      attachments: [
        {
          filename: 'mcp-security-audit-report.pdf',
          content: pdfBuffer,
          contentType: 'application/pdf'
        }
      ]
    });

    return { success: true };
  } catch (err) {
    console.error('Email send error:', err);
    return { success: false, error: err instanceof Error ? err.message : 'Unknown error' };
  }
}
