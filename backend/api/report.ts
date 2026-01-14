import type { VercelRequest, VercelResponse } from '@vercel/node';
import { generatePDFReport, ScanSummary } from '../lib/pdf';
import { sendReportEmail } from '../lib/email';

// Validate email format
function isValidEmail(email: string): boolean {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(email);
}

// Sanitize and validate summary data
function validateSummary(summary: unknown): ScanSummary | null {
  if (!summary || typeof summary !== 'object') return null;

  const s = summary as Record<string, unknown>;

  return {
    total_mcps: typeof s.total_mcps === 'number' ? s.total_mcps : 0,
    secrets_count: typeof s.secrets_count === 'number' ? s.secrets_count : 0,
    apis_count: typeof s.apis_count === 'number' ? s.apis_count : 0,
    models_count: typeof s.models_count === 'number' ? s.models_count : 0,
    risk_breakdown: {
      critical: typeof (s.risk_breakdown as Record<string, unknown>)?.critical === 'number'
        ? (s.risk_breakdown as Record<string, number>).critical : 0,
      high: typeof (s.risk_breakdown as Record<string, unknown>)?.high === 'number'
        ? (s.risk_breakdown as Record<string, number>).high : 0,
      medium: typeof (s.risk_breakdown as Record<string, unknown>)?.medium === 'number'
        ? (s.risk_breakdown as Record<string, number>).medium : 0,
      low: typeof (s.risk_breakdown as Record<string, unknown>)?.low === 'number'
        ? (s.risk_breakdown as Record<string, number>).low : 0,
    },
    mcps: Array.isArray(s.mcps) ? s.mcps : undefined,
    findings: Array.isArray(s.findings) ? s.findings : undefined,
  };
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-API-Key');

  // Handle preflight
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  // Only allow POST
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  // Validate API key
  const apiKey = (req.headers['x-api-key'] as string || '').trim();
  const expectedKey = (process.env.MCP_AUDIT_API_KEY || '').trim();

  if (!apiKey || !expectedKey || apiKey !== expectedKey) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    const { email, source, scan_type, target, timestamp, summary } = req.body;

    // Validate required fields
    if (!email || typeof email !== 'string') {
      return res.status(400).json({ error: 'Email is required' });
    }

    if (!isValidEmail(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }

    // Validate summary
    const validatedSummary = validateSummary(summary);
    if (!validatedSummary) {
      return res.status(400).json({ error: 'Invalid summary data' });
    }

    // Use provided timestamp or generate new one
    const reportTimestamp = timestamp || new Date().toISOString();
    const scanType = scan_type || 'local';

    // Generate PDF
    console.log(`Generating PDF report for ${email}...`);
    const pdfBuffer = await generatePDFReport(validatedSummary, scanType, reportTimestamp);
    console.log(`PDF generated: ${pdfBuffer.length} bytes`);

    // Send email with PDF
    console.log(`Sending email to ${email}...`);
    const emailResult = await sendReportEmail({
      to: email,
      pdfBuffer,
      summary: validatedSummary,
    });

    if (!emailResult.success) {
      console.error('Email send failed:', emailResult.error);
      return res.status(500).json({
        error: 'Failed to send email',
        details: emailResult.error,
      });
    }

    console.log(`Report sent successfully to ${email}`);

    // Log for analytics (no PII stored server-side)
    console.log(JSON.stringify({
      event: 'report_sent',
      source: source || 'unknown',
      scan_type: scanType,
      mcps: validatedSummary.total_mcps,
      secrets: validatedSummary.secrets_count,
      timestamp: reportTimestamp,
    }));

    return res.status(200).json({
      success: true,
      message: 'Report sent successfully',
    });

  } catch (error) {
    console.error('Report generation error:', error);
    return res.status(500).json({
      error: 'Internal server error',
      details: error instanceof Error ? error.message : 'Unknown error',
    });
  }
}
