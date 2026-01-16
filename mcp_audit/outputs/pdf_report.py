"""
PDF Report Generation for MCP Audit

Generates professional PDF reports from scan results using HTML templates.
"""

from pathlib import Path
from datetime import datetime
from typing import Optional
import html


def generate_pdf(summary: dict, secrets: list, apis: list, results: list, output_path: Path):
    """
    Generate a PDF report from scan results.

    Args:
        summary: Scan summary dict with counts and risk distribution
        secrets: List of detected secrets (masked values only)
        apis: List of detected API endpoints
        results: List of ScanResult objects
        output_path: Path to save the PDF
    """
    # Generate HTML content
    html_content = _generate_html_report(summary, secrets, apis, results)

    # Try weasyprint first, fall back to basic HTML file
    try:
        from weasyprint import HTML
        HTML(string=html_content).write_pdf(str(output_path))
    except ImportError:
        # Fallback: save as HTML if weasyprint not available
        html_path = output_path.with_suffix('.html')
        html_path.write_text(html_content)
        raise ImportError(f"weasyprint not installed. HTML report saved to {html_path}")


def _generate_html_report(summary: dict, secrets: list, apis: list, results: list) -> str:
    """Generate HTML content for the PDF report"""

    # Get current date
    scan_date = datetime.now().strftime("%B %d, %Y")

    # Calculate stats
    total_mcps = summary.get("total_mcps", 0)
    secrets_count = summary.get("secrets_count", 0)
    apis_count = summary.get("apis_discovered", {}).get("total", 0)
    unverified_count = summary.get("unverified_mcps", 0)

    risk_dist = summary.get("risk_distribution", {})
    critical_count = risk_dist.get("critical", 0)
    high_count = risk_dist.get("high", 0)
    medium_count = risk_dist.get("medium", 0)
    low_count = risk_dist.get("low", 0)

    secrets_severity = summary.get("secrets_severity", {})

    # Generate sections
    secrets_html = _generate_secrets_section(secrets)
    apis_html = _generate_apis_section(apis)
    mcps_html = _generate_mcps_section(results)
    remediation_html = _generate_remediation_section(summary, secrets, results)

    # Build immediate actions
    immediate_actions = []
    if secrets_count > 0:
        immediate_actions.append(f"{secrets_count} secrets require immediate rotation")
    shell_mcps = [r for r in results if "shell-access" in r.risk_flags]
    if shell_mcps:
        immediate_actions.append(f"{len(shell_mcps)} MCPs have shell command execution access")
    if unverified_count > 0:
        immediate_actions.append(f"{unverified_count} MCPs are from unverified sources")

    immediate_actions_html = ""
    if immediate_actions:
        actions_list = "".join(f"<li>{html.escape(action)}</li>" for action in immediate_actions)
        immediate_actions_html = f"""
        <div class="alert-box">
            <div class="alert-title">Immediate Actions Required</div>
            <ul>{actions_list}</ul>
        </div>
        """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>APIsec MCP Audit Report</title>
    <style>
        {_get_report_css()}
    </style>
</head>
<body>
    <!-- Page 1: Cover + Executive Summary -->
    <div class="page">
        <div class="cover">
            <div class="logo">
                <svg width="120" height="40" viewBox="0 0 120 40" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <text x="0" y="30" font-family="Inter, system-ui, sans-serif" font-size="24" font-weight="700" fill="#0066FF">APIsec</text>
                </svg>
            </div>
            <h1 class="cover-title">APIsec MCP Audit Report</h1>
            <div class="cover-divider"></div>
            <div class="cover-meta">
                <p><strong>Scan Type:</strong> Local Machine</p>
                <p><strong>Date:</strong> {scan_date}</p>
            </div>
        </div>

        <section class="section">
            <h2>Executive Summary</h2>

            <div class="stat-cards">
                <div class="stat-card">
                    <div class="stat-value">{total_mcps}</div>
                    <div class="stat-label">MCPs Discovered</div>
                </div>
                <div class="stat-card {('danger' if secrets_count > 0 else '')}">
                    <div class="stat-value">{secrets_count}</div>
                    <div class="stat-label">Secrets Exposed</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{apis_count}</div>
                    <div class="stat-label">APIs Discovered</div>
                </div>
                <div class="stat-card {('warning' if unverified_count > 0 else '')}">
                    <div class="stat-value">{unverified_count}</div>
                    <div class="stat-label">Unverified MCPs</div>
                </div>
            </div>

            <h3>Risk Distribution</h3>
            <div class="risk-bars">
                <div class="risk-row">
                    <span class="risk-label">Critical</span>
                    <div class="risk-bar-container">
                        <div class="risk-bar critical" style="width: {_calc_percent(critical_count, total_mcps)}%"></div>
                    </div>
                    <span class="risk-count">{critical_count}</span>
                </div>
                <div class="risk-row">
                    <span class="risk-label">High</span>
                    <div class="risk-bar-container">
                        <div class="risk-bar high" style="width: {_calc_percent(high_count, total_mcps)}%"></div>
                    </div>
                    <span class="risk-count">{high_count}</span>
                </div>
                <div class="risk-row">
                    <span class="risk-label">Medium</span>
                    <div class="risk-bar-container">
                        <div class="risk-bar medium" style="width: {_calc_percent(medium_count, total_mcps)}%"></div>
                    </div>
                    <span class="risk-count">{medium_count}</span>
                </div>
                <div class="risk-row">
                    <span class="risk-label">Low</span>
                    <div class="risk-bar-container">
                        <div class="risk-bar low" style="width: {_calc_percent(low_count, total_mcps)}%"></div>
                    </div>
                    <span class="risk-count">{low_count}</span>
                </div>
            </div>

            {immediate_actions_html}
        </section>
    </div>

    <!-- Page 2: Secrets -->
    {secrets_html}

    <!-- Page 3: APIs -->
    {apis_html}

    <!-- Page 4: MCP Inventory -->
    {mcps_html}

    <!-- Page 5: Remediation -->
    {remediation_html}

    <!-- Footer -->
    <div class="footer">
        <div class="footer-content">
            <p>Generated by <strong>APIsec MCP Audit</strong></p>
            <p><a href="https://apisec-inc.github.io/mcp-audit">https://apisec-inc.github.io/mcp-audit</a></p>
            <p class="footer-contact">Questions? rajaram@apisec.ai</p>
        </div>
    </div>
</body>
</html>"""


def _generate_secrets_section(secrets: list) -> str:
    """Generate HTML for secrets section"""
    if not secrets:
        return """
        <div class="page">
            <section class="section">
                <h2>Exposed Secrets</h2>
                <p class="success-message">No exposed secrets detected in MCP configurations.</p>
            </section>
        </div>
        """

    secrets_items = ""
    for s in secrets:
        severity = s.get("severity", "medium").lower()
        severity_class = "critical" if severity == "critical" else ("high" if severity == "high" else "medium")
        severity_label = severity.upper()

        description = html.escape(s.get("description", "Unknown Secret"))
        mcp_name = html.escape(s.get("mcp_name", "unknown"))
        env_key = html.escape(s.get("env_key", ""))
        rotation_url = s.get("rotation_url", "")

        rotation_html = f'<a href="{html.escape(rotation_url)}">{html.escape(rotation_url)}</a>' if rotation_url else "Manual rotation required"

        secrets_items += f"""
        <div class="finding-card {severity_class}">
            <div class="finding-severity {severity_class}">{severity_label}</div>
            <div class="finding-content">
                <div class="finding-title">{description}</div>
                <div class="finding-detail"><strong>Location:</strong> {mcp_name} &rarr; {env_key}</div>
                <div class="finding-detail"><strong>Rotate:</strong> {rotation_html}</div>
            </div>
        </div>
        """

    return f"""
    <div class="page">
        <section class="section">
            <h2>Exposed Secrets</h2>
            <p class="section-intro">{len(secrets)} credentials detected in MCP configurations. Rotate immediately to prevent unauthorized access.</p>
            {secrets_items}
        </section>
    </div>
    """


def _generate_apis_section(apis: list) -> str:
    """Generate HTML for APIs section"""
    if not apis:
        return """
        <div class="page">
            <section class="section">
                <h2>Discovered APIs</h2>
                <p class="success-message">No API endpoints detected in MCP configurations.</p>
            </section>
        </div>
        """

    # Group by category
    categories = {}
    for api in apis:
        cat = api.get("category", "unknown")
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(api)

    category_names = {
        "database": "Databases",
        "saas": "SaaS APIs",
        "rest_api": "REST APIs",
        "sse": "SSE Endpoints",
        "websocket": "WebSocket",
        "cloud": "Cloud Services",
        "unknown": "Other"
    }

    apis_html = ""
    for cat, cat_apis in categories.items():
        cat_name = category_names.get(cat, cat.title())

        rows = ""
        for api in cat_apis:
            url = html.escape(api.get("url", ""))
            mcp_name = html.escape(api.get("mcp_name", ""))
            description = html.escape(api.get("description", ""))
            rows += f"""
            <tr>
                <td><code>{url}</code></td>
                <td>{mcp_name}</td>
                <td>{description}</td>
            </tr>
            """

        apis_html += f"""
        <h3>{cat_name}</h3>
        <table class="data-table">
            <thead>
                <tr>
                    <th>Endpoint</th>
                    <th>Source MCP</th>
                    <th>Type</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
        """

    return f"""
    <div class="page">
        <section class="section">
            <h2>Discovered APIs</h2>
            <p class="section-intro">{len(apis)} API endpoints discovered across MCP configurations. These APIs should be included in your security testing program.</p>
            {apis_html}
        </section>
    </div>
    """


def _generate_mcps_section(results: list) -> str:
    """Generate HTML for MCP inventory section"""
    if not results:
        return ""

    rows = ""
    for r in results:
        name = html.escape(r.name)
        risk = (r.registry_risk or "unknown").lower()
        risk_class = risk if risk in ["critical", "high", "medium", "low"] else ""
        verified = "Yes" if r.is_known else "No"
        verified_class = "success" if r.is_known else "danger"
        risk_flags = ", ".join(r.risk_flags) if r.risk_flags else "-"

        rows += f"""
        <tr>
            <td>{name}</td>
            <td class="{risk_class}">{risk.upper()}</td>
            <td class="{verified_class}">{verified}</td>
            <td>{html.escape(risk_flags)}</td>
        </tr>
        """

    return f"""
    <div class="page">
        <section class="section">
            <h2>MCP Inventory</h2>
            <p class="section-intro">{len(results)} Model Context Protocol servers discovered.</p>
            <table class="data-table">
                <thead>
                    <tr>
                        <th>MCP Name</th>
                        <th>Risk</th>
                        <th>Verified</th>
                        <th>Risk Flags</th>
                    </tr>
                </thead>
                <tbody>
                    {rows}
                </tbody>
            </table>
        </section>
    </div>
    """


def _generate_remediation_section(summary: dict, secrets: list, results: list) -> str:
    """Generate HTML for remediation section"""

    priorities = []

    # Priority 1: Secrets
    secrets_count = len(secrets)
    if secrets_count > 0:
        priorities.append({
            "title": "Rotate Exposed Secrets",
            "priority": "IMMEDIATE",
            "description": f"{secrets_count} credentials are exposed in MCP configuration files. Rotate each credential using the links provided in the Secrets section of this report."
        })

    # Priority 2: Shell access
    shell_mcps = [r for r in results if "shell-access" in r.risk_flags]
    if shell_mcps:
        priorities.append({
            "title": "Review Shell Access MCPs",
            "priority": "HIGH PRIORITY",
            "description": f"{len(shell_mcps)} MCPs have shell command execution capability. Remove unless explicitly required for your workflow. If required, restrict to specific allowed commands."
        })

    # Priority 3: Unverified MCPs
    unverified_mcps = [r for r in results if not r.is_known]
    if unverified_mcps:
        priorities.append({
            "title": "Verify Unknown MCPs",
            "priority": "MEDIUM",
            "description": f"{len(unverified_mcps)} MCPs are from unverified sources. Review source code or replace with official alternatives."
        })

    # Priority 4: API testing
    apis_count = summary.get("apis_discovered", {}).get("total", 0)
    if apis_count > 0:
        priorities.append({
            "title": "Test Discovered APIs",
            "priority": "RECOMMENDED",
            "description": f"{apis_count} APIs discovered. Include in your API security testing program to check for BOLA, injection, and auth bypass."
        })

    priorities_html = ""
    for i, p in enumerate(priorities, 1):
        priorities_html += f"""
        <div class="priority-item">
            <div class="priority-number">{i}</div>
            <div class="priority-content">
                <div class="priority-header">
                    <span class="priority-title">{html.escape(p['title'])}</span>
                    <span class="priority-badge">{html.escape(p['priority'])}</span>
                </div>
                <p>{html.escape(p['description'])}</p>
            </div>
        </div>
        """

    checklist_items = [
        "Rotate all exposed credentials",
        "Review and remove unnecessary shell-access MCPs",
        "Audit unverified MCPs or replace with verified versions",
        "Add discovered APIs to security testing program",
        "Schedule follow-up scan in 30 days"
    ]
    checklist_html = "".join(f'<div class="checklist-item"><span class="checkbox">☐</span> {html.escape(item)}</div>' for item in checklist_items)

    return f"""
    <div class="page">
        <section class="section">
            <h2>Remediation Priorities</h2>

            {priorities_html}

            <div class="checklist-section">
                <h3>Next Steps Checklist</h3>
                {checklist_html}
            </div>

            <div class="cta-box">
                <h3>Test Your APIs for Vulnerabilities</h3>
                <p>APIsec automatically tests APIs for OWASP Top 10 vulnerabilities including BOLA, injection, and auth bypass.</p>
                <p class="cta-link">&rarr; <a href="https://www.apisec.ai">www.apisec.ai</a></p>
            </div>
        </section>
    </div>
    """


def _calc_percent(count: int, total: int) -> int:
    """Calculate percentage for risk bars"""
    if total == 0:
        return 0
    return min(100, int((count / total) * 100))


def _get_report_css() -> str:
    """Return CSS styles for the PDF report"""
    return """
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            font-size: 11pt;
            line-height: 1.6;
            color: #1f2937;
            background: white;
        }

        .page {
            padding: 0.75in;
            page-break-after: always;
        }

        .page:last-of-type {
            page-break-after: avoid;
        }

        /* Cover */
        .cover {
            text-align: center;
            padding: 2in 0 1in;
        }

        .logo {
            margin-bottom: 2rem;
        }

        .cover-title {
            font-size: 28pt;
            font-weight: 700;
            color: #111827;
            margin-bottom: 1rem;
        }

        .cover-divider {
            width: 60px;
            height: 4px;
            background: #0066FF;
            margin: 1.5rem auto;
            border-radius: 2px;
        }

        .cover-meta {
            color: #6b7280;
            font-size: 12pt;
        }

        .cover-meta p {
            margin: 0.5rem 0;
        }

        /* Sections */
        .section {
            margin-bottom: 2rem;
        }

        h2 {
            font-size: 18pt;
            font-weight: 700;
            color: #111827;
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 2px solid #e5e7eb;
        }

        h3 {
            font-size: 14pt;
            font-weight: 600;
            color: #374151;
            margin: 1.5rem 0 0.75rem;
        }

        .section-intro {
            color: #6b7280;
            margin-bottom: 1.5rem;
        }

        /* Stat Cards */
        .stat-cards {
            display: flex;
            gap: 1rem;
            margin-bottom: 2rem;
        }

        .stat-card {
            flex: 1;
            background: #f9fafb;
            border: 1px solid #e5e7eb;
            border-radius: 8px;
            padding: 1rem;
            text-align: center;
        }

        .stat-card.danger {
            background: #fef2f2;
            border-color: #fecaca;
        }

        .stat-card.warning {
            background: #fffbeb;
            border-color: #fde68a;
        }

        .stat-value {
            font-size: 32pt;
            font-weight: 700;
            color: #111827;
        }

        .stat-card.danger .stat-value {
            color: #dc2626;
        }

        .stat-card.warning .stat-value {
            color: #d97706;
        }

        .stat-label {
            font-size: 10pt;
            color: #6b7280;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        /* Risk Bars */
        .risk-bars {
            margin: 1rem 0;
        }

        .risk-row {
            display: flex;
            align-items: center;
            margin-bottom: 0.5rem;
        }

        .risk-label {
            width: 80px;
            font-size: 10pt;
            color: #6b7280;
        }

        .risk-bar-container {
            flex: 1;
            height: 20px;
            background: #f3f4f6;
            border-radius: 4px;
            margin: 0 1rem;
        }

        .risk-bar {
            height: 100%;
            border-radius: 4px;
            min-width: 4px;
        }

        .risk-bar.critical { background: #dc2626; }
        .risk-bar.high { background: #ea580c; }
        .risk-bar.medium { background: #ca8a04; }
        .risk-bar.low { background: #16a34a; }

        .risk-count {
            width: 30px;
            text-align: right;
            font-weight: 600;
        }

        /* Alert Box */
        .alert-box {
            background: #fef2f2;
            border: 1px solid #fecaca;
            border-radius: 8px;
            padding: 1rem 1.25rem;
            margin-top: 1.5rem;
        }

        .alert-title {
            font-weight: 600;
            color: #dc2626;
            margin-bottom: 0.5rem;
        }

        .alert-box ul {
            margin: 0;
            padding-left: 1.25rem;
            color: #7f1d1d;
        }

        .alert-box li {
            margin: 0.25rem 0;
        }

        /* Finding Cards */
        .finding-card {
            display: flex;
            gap: 1rem;
            border: 1px solid #e5e7eb;
            border-radius: 8px;
            padding: 1rem;
            margin-bottom: 1rem;
            background: #f9fafb;
        }

        .finding-card.critical {
            background: #fef2f2;
            border-color: #fecaca;
        }

        .finding-card.high {
            background: #fff7ed;
            border-color: #fed7aa;
        }

        .finding-card.medium {
            background: #fefce8;
            border-color: #fef08a;
        }

        .finding-severity {
            font-size: 9pt;
            font-weight: 700;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            height: fit-content;
        }

        .finding-severity.critical {
            background: #dc2626;
            color: white;
        }

        .finding-severity.high {
            background: #ea580c;
            color: white;
        }

        .finding-severity.medium {
            background: #ca8a04;
            color: white;
        }

        .finding-content {
            flex: 1;
        }

        .finding-title {
            font-weight: 600;
            margin-bottom: 0.5rem;
        }

        .finding-detail {
            font-size: 10pt;
            color: #4b5563;
            margin: 0.25rem 0;
        }

        .finding-detail a {
            color: #0066FF;
        }

        /* Data Tables */
        .data-table {
            width: 100%;
            border-collapse: collapse;
            margin: 1rem 0;
            font-size: 10pt;
        }

        .data-table th,
        .data-table td {
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid #e5e7eb;
        }

        .data-table th {
            background: #f9fafb;
            font-weight: 600;
            color: #374151;
        }

        .data-table code {
            background: #f3f4f6;
            padding: 0.125rem 0.375rem;
            border-radius: 4px;
            font-size: 9pt;
        }

        .data-table .critical { color: #dc2626; font-weight: 600; }
        .data-table .high { color: #ea580c; font-weight: 600; }
        .data-table .medium { color: #ca8a04; font-weight: 600; }
        .data-table .low { color: #16a34a; font-weight: 600; }
        .data-table .success { color: #16a34a; }
        .data-table .danger { color: #dc2626; }

        /* Priority Items */
        .priority-item {
            display: flex;
            gap: 1rem;
            margin-bottom: 1.5rem;
        }

        .priority-number {
            width: 32px;
            height: 32px;
            background: #0066FF;
            color: white;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 700;
            flex-shrink: 0;
        }

        .priority-content {
            flex: 1;
        }

        .priority-header {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            margin-bottom: 0.5rem;
        }

        .priority-title {
            font-weight: 600;
            font-size: 12pt;
        }

        .priority-badge {
            font-size: 9pt;
            font-weight: 600;
            padding: 0.125rem 0.5rem;
            background: #f3f4f6;
            border-radius: 4px;
            color: #6b7280;
        }

        .priority-content p {
            color: #4b5563;
            font-size: 10pt;
        }

        /* Checklist */
        .checklist-section {
            margin-top: 2rem;
            padding-top: 1.5rem;
            border-top: 1px solid #e5e7eb;
        }

        .checklist-item {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            margin: 0.5rem 0;
            font-size: 10pt;
        }

        .checkbox {
            font-size: 14pt;
        }

        /* CTA Box */
        .cta-box {
            background: linear-gradient(135deg, #eff6ff 0%, #dbeafe 100%);
            border: 1px solid #bfdbfe;
            border-radius: 8px;
            padding: 1.5rem;
            margin-top: 2rem;
            text-align: center;
        }

        .cta-box h3 {
            margin: 0 0 0.5rem;
            color: #1e40af;
        }

        .cta-box p {
            color: #3b82f6;
            margin: 0.5rem 0;
        }

        .cta-link {
            font-weight: 600;
        }

        .cta-link a {
            color: #1d4ed8;
        }

        /* Footer */
        .footer {
            padding: 1rem 0.75in;
            border-top: 1px solid #e5e7eb;
            text-align: center;
        }

        .footer-content p {
            margin: 0.25rem 0;
            font-size: 10pt;
            color: #6b7280;
        }

        .footer-content a {
            color: #0066FF;
        }

        .footer-contact {
            margin-top: 0.5rem !important;
        }

        /* Success message */
        .success-message {
            background: #f0fdf4;
            border: 1px solid #bbf7d0;
            color: #166534;
            padding: 1rem;
            border-radius: 8px;
            text-align: center;
        }

        /* Print styles */
        @media print {
            .page {
                page-break-after: always;
            }

            body {
                print-color-adjust: exact;
                -webkit-print-color-adjust: exact;
            }
        }
    """
