import React from 'react';
import {
  Document,
  Page,
  Text,
  View,
  StyleSheet,
  renderToBuffer,
  Link,
} from '@react-pdf/renderer';

// Color palette
const colors = {
  primary: '#1E40AF',      // APIsec blue
  primaryLight: '#3B82F6',
  danger: '#DC2626',
  warning: '#EA580C',
  success: '#16A34A',
  gray: '#6B7280',
  grayLight: '#F3F4F6',
  grayDark: '#374151',
  white: '#FFFFFF',
  black: '#111827',
};

// Professional styles
const styles = StyleSheet.create({
  page: {
    padding: 40,
    fontFamily: 'Helvetica',
    fontSize: 10,
    color: colors.black,
  },
  // Header
  header: {
    marginBottom: 30,
    borderBottomWidth: 2,
    borderBottomColor: colors.primary,
    paddingBottom: 20,
  },
  headerTop: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    marginBottom: 10,
  },
  logo: {
    fontSize: 24,
    fontFamily: 'Helvetica-Bold',
    color: colors.primary,
  },
  logoSub: {
    fontSize: 10,
    color: colors.gray,
    marginTop: 2,
  },
  reportTitle: {
    fontSize: 18,
    fontFamily: 'Helvetica-Bold',
    color: colors.black,
    marginTop: 15,
  },
  reportMeta: {
    fontSize: 9,
    color: colors.gray,
    marginTop: 5,
  },

  // Summary cards
  summarySection: {
    marginBottom: 25,
  },
  sectionTitle: {
    fontSize: 12,
    fontFamily: 'Helvetica-Bold',
    color: colors.grayDark,
    marginBottom: 12,
    textTransform: 'uppercase',
    letterSpacing: 0.5,
  },
  summaryGrid: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: 10,
  },
  summaryCard: {
    width: '23%',
    backgroundColor: colors.grayLight,
    padding: 12,
    borderRadius: 4,
  },
  summaryCardDanger: {
    backgroundColor: '#FEE2E2',
    borderLeftWidth: 3,
    borderLeftColor: colors.danger,
  },
  summaryCardWarning: {
    backgroundColor: '#FFF7ED',
    borderLeftWidth: 3,
    borderLeftColor: colors.warning,
  },
  summaryValue: {
    fontSize: 20,
    fontFamily: 'Helvetica-Bold',
    color: colors.black,
  },
  summaryLabel: {
    fontSize: 8,
    color: colors.gray,
    marginTop: 2,
    textTransform: 'uppercase',
  },

  // Risk breakdown
  riskSection: {
    marginBottom: 25,
  },
  riskRow: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 6,
    paddingVertical: 4,
  },
  riskLabel: {
    width: 80,
    fontSize: 9,
    fontFamily: 'Helvetica-Bold',
  },
  riskBar: {
    height: 8,
    borderRadius: 2,
    marginRight: 8,
  },
  riskCount: {
    fontSize: 9,
    color: colors.gray,
  },

  // Findings section
  findingsSection: {
    marginBottom: 25,
  },
  findingItem: {
    backgroundColor: colors.grayLight,
    padding: 10,
    marginBottom: 6,
    borderRadius: 4,
    borderLeftWidth: 3,
  },
  findingCritical: {
    borderLeftColor: colors.danger,
    backgroundColor: '#FEF2F2',
  },
  findingHigh: {
    borderLeftColor: colors.warning,
    backgroundColor: '#FFFBEB',
  },
  findingMedium: {
    borderLeftColor: '#F59E0B',
    backgroundColor: '#FFFBEB',
  },
  findingLow: {
    borderLeftColor: colors.primaryLight,
    backgroundColor: '#EFF6FF',
  },
  findingTitle: {
    fontSize: 9,
    fontFamily: 'Helvetica-Bold',
    color: colors.black,
    marginBottom: 2,
  },
  findingDesc: {
    fontSize: 8,
    color: colors.gray,
  },

  // Recommendations
  recsSection: {
    marginBottom: 25,
  },
  recItem: {
    flexDirection: 'row',
    marginBottom: 6,
    paddingLeft: 10,
  },
  recBullet: {
    width: 15,
    fontSize: 9,
    color: colors.primary,
  },
  recText: {
    flex: 1,
    fontSize: 9,
    color: colors.grayDark,
    lineHeight: 1.4,
  },

  // Footer
  footer: {
    position: 'absolute',
    bottom: 30,
    left: 40,
    right: 40,
    borderTopWidth: 1,
    borderTopColor: colors.grayLight,
    paddingTop: 15,
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  footerLeft: {
    flexDirection: 'column',
  },
  footerCompany: {
    fontSize: 10,
    fontFamily: 'Helvetica-Bold',
    color: colors.primary,
  },
  footerUrl: {
    fontSize: 8,
    color: colors.gray,
    marginTop: 2,
  },
  footerRight: {
    fontSize: 8,
    color: colors.gray,
    textAlign: 'right',
  },

  // Page number
  pageNumber: {
    position: 'absolute',
    bottom: 15,
    right: 40,
    fontSize: 8,
    color: colors.gray,
  },
});

interface ScanSummary {
  total_mcps: number;
  secrets_count: number;
  apis_count: number;
  models_count: number;
  risk_breakdown: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  mcps?: Array<{
    name: string;
    risk_level: string;
    source: string;
  }>;
  findings?: Array<{
    severity: string;
    title: string;
    description?: string;
  }>;
}

interface ReportProps {
  summary: ScanSummary;
  scanType: string;
  timestamp: string;
}

// Helper to format date
function formatDate(isoString: string): string {
  const date = new Date(isoString);
  return date.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

// Calculate risk bar width
function getRiskBarWidth(count: number, total: number): number {
  if (total === 0) return 0;
  return Math.min(Math.max((count / total) * 200, count > 0 ? 20 : 0), 200);
}

// Main Report Component
const MCPAuditReport: React.FC<ReportProps> = ({ summary, scanType, timestamp }) => {
  const totalRisk =
    summary.risk_breakdown.critical +
    summary.risk_breakdown.high +
    summary.risk_breakdown.medium +
    summary.risk_breakdown.low;

  const hasSecrets = summary.secrets_count > 0;
  const hasCritical = summary.risk_breakdown.critical > 0;

  return (
    <Document>
      <Page size="A4" style={styles.page}>
        {/* Header */}
        <View style={styles.header}>
          <View style={styles.headerTop}>
            <View>
              <Text style={styles.logo}>APIsec</Text>
              <Text style={styles.logoSub}>MCP Security Audit</Text>
            </View>
            <View style={{ alignItems: 'flex-end' }}>
              <Text style={{ fontSize: 8, color: colors.gray }}>www.apisec.ai</Text>
            </View>
          </View>
          <Text style={styles.reportTitle}>MCP Configuration Security Report</Text>
          <Text style={styles.reportMeta}>
            Scan Type: {scanType === 'local' ? 'Local Machine' : scanType} | Generated: {formatDate(timestamp)}
          </Text>
        </View>

        {/* Executive Summary */}
        <View style={styles.summarySection}>
          <Text style={styles.sectionTitle}>Executive Summary</Text>
          <View style={styles.summaryGrid}>
            <View style={styles.summaryCard}>
              <Text style={styles.summaryValue}>{summary.total_mcps}</Text>
              <Text style={styles.summaryLabel}>MCPs Found</Text>
            </View>
            <View style={hasSecrets ? [styles.summaryCard, styles.summaryCardDanger] : styles.summaryCard}>
              <Text style={styles.summaryValue}>{summary.secrets_count}</Text>
              <Text style={styles.summaryLabel}>Secrets Exposed</Text>
            </View>
            <View style={styles.summaryCard}>
              <Text style={styles.summaryValue}>{summary.apis_count}</Text>
              <Text style={styles.summaryLabel}>API Endpoints</Text>
            </View>
            <View style={styles.summaryCard}>
              <Text style={styles.summaryValue}>{summary.models_count}</Text>
              <Text style={styles.summaryLabel}>AI Models</Text>
            </View>
          </View>
        </View>

        {/* Risk Breakdown */}
        <View style={styles.riskSection}>
          <Text style={styles.sectionTitle}>Risk Assessment</Text>

          <View style={styles.riskRow}>
            <Text style={[styles.riskLabel, { color: colors.danger }]}>Critical</Text>
            <View style={[styles.riskBar, { width: getRiskBarWidth(summary.risk_breakdown.critical, totalRisk), backgroundColor: colors.danger }]} />
            <Text style={styles.riskCount}>{summary.risk_breakdown.critical} issues</Text>
          </View>

          <View style={styles.riskRow}>
            <Text style={[styles.riskLabel, { color: colors.warning }]}>High</Text>
            <View style={[styles.riskBar, { width: getRiskBarWidth(summary.risk_breakdown.high, totalRisk), backgroundColor: colors.warning }]} />
            <Text style={styles.riskCount}>{summary.risk_breakdown.high} issues</Text>
          </View>

          <View style={styles.riskRow}>
            <Text style={[styles.riskLabel, { color: '#F59E0B' }]}>Medium</Text>
            <View style={[styles.riskBar, { width: getRiskBarWidth(summary.risk_breakdown.medium, totalRisk), backgroundColor: '#F59E0B' }]} />
            <Text style={styles.riskCount}>{summary.risk_breakdown.medium} issues</Text>
          </View>

          <View style={styles.riskRow}>
            <Text style={[styles.riskLabel, { color: colors.primaryLight }]}>Low</Text>
            <View style={[styles.riskBar, { width: getRiskBarWidth(summary.risk_breakdown.low, totalRisk), backgroundColor: colors.primaryLight }]} />
            <Text style={styles.riskCount}>{summary.risk_breakdown.low} issues</Text>
          </View>
        </View>

        {/* Key Findings */}
        {(hasSecrets || hasCritical) && (
          <View style={styles.findingsSection}>
            <Text style={styles.sectionTitle}>Key Findings</Text>

            {hasSecrets && (
              <View style={[styles.findingItem, styles.findingCritical]}>
                <Text style={styles.findingTitle}>Exposed Secrets Detected</Text>
                <Text style={styles.findingDesc}>
                  {summary.secrets_count} credential(s) found in MCP configurations. These should be rotated immediately and moved to secure environment variables.
                </Text>
              </View>
            )}

            {hasCritical && (
              <View style={[styles.findingItem, styles.findingCritical]}>
                <Text style={styles.findingTitle}>Critical Security Issues</Text>
                <Text style={styles.findingDesc}>
                  {summary.risk_breakdown.critical} critical-risk MCP(s) detected with elevated privileges or known vulnerabilities.
                </Text>
              </View>
            )}

            {summary.risk_breakdown.high > 0 && (
              <View style={[styles.findingItem, styles.findingHigh]}>
                <Text style={styles.findingTitle}>High-Risk Configurations</Text>
                <Text style={styles.findingDesc}>
                  {summary.risk_breakdown.high} high-risk MCP(s) require attention due to sensitive data access or broad permissions.
                </Text>
              </View>
            )}
          </View>
        )}

        {/* Recommendations */}
        <View style={styles.recsSection}>
          <Text style={styles.sectionTitle}>Recommendations</Text>

          {hasSecrets && (
            <View style={styles.recItem}>
              <Text style={styles.recBullet}>1.</Text>
              <Text style={styles.recText}>
                Immediately rotate all exposed credentials and API keys. Use environment variables or a secrets manager instead of hardcoding values.
              </Text>
            </View>
          )}

          <View style={styles.recItem}>
            <Text style={styles.recBullet}>{hasSecrets ? '2.' : '1.'}</Text>
            <Text style={styles.recText}>
              Review MCP permissions and apply the principle of least privilege. Remove unnecessary access to filesystems, databases, and shell commands.
            </Text>
          </View>

          <View style={styles.recItem}>
            <Text style={styles.recBullet}>{hasSecrets ? '3.' : '2.'}</Text>
            <Text style={styles.recText}>
              Implement MCP allowlisting to ensure only approved and verified MCPs are used in your environment.
            </Text>
          </View>

          <View style={styles.recItem}>
            <Text style={styles.recBullet}>{hasSecrets ? '4.' : '3.'}</Text>
            <Text style={styles.recText}>
              Establish regular security audits for MCP configurations as part of your security review process.
            </Text>
          </View>
        </View>

        {/* Footer */}
        <View style={styles.footer}>
          <View style={styles.footerLeft}>
            <Text style={styles.footerCompany}>APIsec Inc.</Text>
            <Text style={styles.footerUrl}>www.apisec.ai</Text>
          </View>
          <View>
            <Text style={styles.footerRight}>
              This report was generated by APIsec MCP Audit.{'\n'}
              For enterprise security solutions, visit www.apisec.ai
            </Text>
          </View>
        </View>

        {/* Page number */}
        <Text style={styles.pageNumber} render={({ pageNumber, totalPages }) => `${pageNumber} / ${totalPages}`} fixed />
      </Page>
    </Document>
  );
};

// Export function to generate PDF buffer
export async function generatePDFReport(
  summary: ScanSummary,
  scanType: string,
  timestamp: string
): Promise<Buffer> {
  const buffer = await renderToBuffer(
    <MCPAuditReport summary={summary} scanType={scanType} timestamp={timestamp} />
  );
  return Buffer.from(buffer);
}

export type { ScanSummary, ReportProps };
