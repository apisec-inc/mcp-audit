"""
Output formatters for MCP Audit results
"""

import json
from datetime import datetime
from typing import Optional

from mcp_audit.models import ScanResult, CollectedConfig
from mcp_audit.data.risk_definitions import get_risk_flag_info, get_severity_for_flag


def format_results(results: list[ScanResult], format: str) -> str:
    """Format scan results in requested format"""
    if format == "json":
        return _to_json(results)
    elif format == "markdown":
        return _to_markdown(results)
    elif format == "csv":
        return _to_csv(results)
    elif format == "cyclonedx":
        from mcp_audit.outputs.cyclonedx import generate_cyclonedx_bom
        return generate_cyclonedx_bom(results, format="json")
    elif format == "cyclonedx-xml":
        from mcp_audit.outputs.cyclonedx import generate_cyclonedx_bom
        return generate_cyclonedx_bom(results, format="xml")
    else:
        # Table format is handled separately with rich
        return _to_json(results)


def format_aggregated(
    mcps: dict, 
    configs: list[CollectedConfig], 
    format: str
) -> str:
    """Format aggregated results from collected configs"""
    if format == "json":
        return _aggregated_to_json(mcps, configs)
    elif format == "markdown":
        return _aggregated_to_markdown(mcps, configs)
    elif format == "csv":
        return _aggregated_to_csv(mcps, configs)
    else:
        return _aggregated_to_json(mcps, configs)


def _to_json(results: list[ScanResult]) -> str:
    """Convert results to JSON"""
    # Build findings from risk flags
    findings = _build_findings(results)

    # Collect secrets (always masked)
    secrets_data = _build_secrets_summary(results)

    # Collect APIs
    apis_data = _build_apis_summary(results)

    # Collect AI models
    models_data = _build_models_summary(results)

    data = {
        "scan_time": datetime.now().isoformat(),
        "total_mcps": len(results),
        "mcps": [r.to_dict() for r in results],
        "findings": findings,
    }

    # Add secrets section if any detected
    if secrets_data["total"] > 0:
        data["secrets_detected"] = secrets_data

    # Add APIs section if any detected
    if apis_data["total"] > 0:
        data["apis_detected"] = apis_data

    # Add AI models section if any detected
    if models_data["total"] > 0:
        data["ai_models"] = models_data

    return json.dumps(data, indent=2)


def _build_secrets_summary(results: list[ScanResult]) -> dict:
    """Build secrets summary from results"""
    all_secrets = []
    for r in results:
        for s in r.secrets:
            secret_dict = s.to_dict() if hasattr(s, 'to_dict') else s
            secret_dict["source_mcp"] = r.name
            all_secrets.append(secret_dict)

    critical = sum(1 for s in all_secrets if s.get("severity") == "critical")
    high = sum(1 for s in all_secrets if s.get("severity") == "high")
    medium = sum(1 for s in all_secrets if s.get("severity") == "medium")

    return {
        "total": len(all_secrets),
        "critical": critical,
        "high": high,
        "medium": medium,
        "items": all_secrets,
    }


def _build_apis_summary(results: list[ScanResult]) -> dict:
    """Build API endpoints summary from results"""
    all_apis = []
    for r in results:
        for a in r.apis:
            api_dict = a.to_dict() if hasattr(a, 'to_dict') else a
            api_dict["source_mcp"] = r.name
            all_apis.append(api_dict)

    # Count by category
    categories = {}
    for a in all_apis:
        cat = a.get("category", "unknown")
        categories[cat] = categories.get(cat, 0) + 1

    return {
        "total": len(all_apis),
        "by_category": categories,
        "items": all_apis,
    }


def _build_models_summary(results: list[ScanResult]) -> dict:
    """Build AI models summary from results"""
    all_models = []
    for r in results:
        if r.model:
            model_dict = r.model.copy() if isinstance(r.model, dict) else {}
            model_dict["source_mcp"] = r.name
            all_models.append(model_dict)

    # Count by provider
    by_provider = {}
    for m in all_models:
        provider = m.get("provider", "Unknown")
        by_provider[provider] = by_provider.get(provider, 0) + 1

    # Count by hosting
    by_hosting = {"cloud": 0, "local": 0, "unknown": 0}
    for m in all_models:
        hosting = m.get("hosting", "unknown")
        if hosting in by_hosting:
            by_hosting[hosting] += 1

    return {
        "total": len(all_models),
        "by_provider": by_provider,
        "by_hosting": by_hosting,
        "items": all_models,
    }


def _build_findings(results: list[ScanResult]) -> list[dict]:
    """Build findings list from results' risk flags"""
    flag_to_mcps: dict[str, list[str]] = {}
    for r in results:
        for flag in r.risk_flags:
            if flag not in flag_to_mcps:
                flag_to_mcps[flag] = []
            flag_to_mcps[flag].append(r.name)

    findings = []
    for flag, mcps in flag_to_mcps.items():
        info = get_risk_flag_info(flag)
        findings.append({
            "flag": flag,
            "severity": get_severity_for_flag(flag),
            "affected_mcps": mcps,
            "explanation": info.get("explanation", ""),
            "remediation": info.get("remediation", ""),
        })

    # Sort by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
    findings.sort(key=lambda x: severity_order.get(x["severity"], 4))

    return findings


def _to_markdown(results: list[ScanResult]) -> str:
    """Convert results to Markdown"""
    lines = [
        "# MCP Audit Report",
        "",
        f"**Scan Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"**Total MCPs Found:** {len(results)}",
        "",
    ]

    # Secrets section (first, if any)
    secrets_data = _build_secrets_summary(results)
    if secrets_data["total"] > 0:
        lines.extend([
            "## ⚠️ Secrets Detected",
            "",
            f"**{secrets_data['total']} secrets found - immediate rotation required**",
            "",
        ])

        # Group by severity
        for severity in ["critical", "high", "medium"]:
            severity_secrets = [s for s in secrets_data["items"] if s.get("severity") == severity]
            if severity_secrets:
                lines.extend([
                    f"### {severity.title()}",
                    "",
                    "| Type | Location | Masked Value | Rotate At |",
                    "|------|----------|--------------|-----------|",
                ])
                for s in severity_secrets:
                    rotate_link = f"[Rotate]({s['rotation_url']})" if s.get("rotation_url") else "Manual rotation"
                    lines.append(f"| {s['description']} | {s['source_mcp']} → {s['env_key']} | `{s['value_masked']}` | {rotate_link} |")
                lines.append("")

    # APIs section (after secrets, before MCP inventory)
    apis_data = _build_apis_summary(results)
    if apis_data["total"] > 0:
        lines.extend([
            "## 📡 API Endpoints Detected",
            "",
            f"**{apis_data['total']} API endpoint(s) discovered**",
            "",
            "| Category | MCP | URL | Source |",
            "|----------|-----|-----|--------|",
        ])

        # Category display names
        category_names = {
            "database": "🗄️ Database",
            "rest_api": "🌐 REST API",
            "websocket": "🔌 WebSocket",
            "sse": "📡 SSE",
            "saas": "☁️ SaaS",
            "cloud": "🏢 Cloud",
            "unknown": "❓ Other",
        }

        for api in apis_data["items"]:
            cat = api.get("category", "unknown")
            cat_name = category_names.get(cat, cat)
            mcp_name = api.get("source_mcp", "unknown")
            url = api.get("url", "unknown")
            source = f"{api.get('source', '')} → {api.get('source_key', '')}"
            lines.append(f"| {cat_name} | {mcp_name} | `{url}` | {source} |")

        lines.append("")

    # MCP Inventory
    lines.extend([
        "## MCP Inventory",
        "",
        "| MCP Name | Source | Found In | Type | Risk Flags |",
        "|----------|--------|----------|------|------------|",
    ])

    for r in results:
        risk_flags = ", ".join(r.risk_flags) if r.risk_flags else "-"
        lines.append(f"| {r.name} | {r.source} | {r.found_in} | {r.server_type} | {risk_flags} |")

    # Findings & Remediation section
    findings = _build_findings(results)
    if findings:
        lines.extend([
            "",
            "## Findings & Remediation",
            "",
        ])

        for finding in findings:
            severity = finding["severity"].upper()
            flag = finding["flag"]
            mcps = ", ".join(finding["affected_mcps"])

            lines.append(f"### [{severity}] {flag}")
            lines.append("")
            lines.append(f"**Affected MCPs:** {mcps}")
            lines.append("")
            lines.append(f"**Why:** {finding['explanation']}")
            lines.append("")
            lines.append(f"**Fix:** {finding['remediation']}")
            lines.append("")

    return "\n".join(lines)


def _to_csv(results: list[ScanResult]) -> str:
    """Convert results to CSV"""
    lines = ["name,source,found_in,server_type,risk_flags,secrets_count,secrets_severity,apis_count,api_categories,config_path"]

    for r in results:
        risk_flags = "|".join(r.risk_flags)
        # Escape commas in fields
        source = f'"{r.source}"' if "," in r.source else r.source
        config_path = f'"{r.config_path}"' if "," in r.config_path else r.config_path

        # Secrets info
        secrets_count = len(r.secrets)
        if secrets_count > 0:
            severities = [s.severity if hasattr(s, 'severity') else s.get('severity', 'unknown') for s in r.secrets]
            if 'critical' in severities:
                secrets_severity = 'critical'
            elif 'high' in severities:
                secrets_severity = 'high'
            else:
                secrets_severity = 'medium'
        else:
            secrets_severity = ''

        # APIs info
        apis_count = len(r.apis)
        if apis_count > 0:
            categories = set()
            for a in r.apis:
                cat = a.category if hasattr(a, 'category') else a.get('category', 'unknown')
                categories.add(cat)
            api_categories = "|".join(sorted(categories))
        else:
            api_categories = ''

        lines.append(f"{r.name},{source},{r.found_in},{r.server_type},{risk_flags},{secrets_count},{secrets_severity},{apis_count},{api_categories},{config_path}")

    return "\n".join(lines)


def _aggregated_to_json(mcps: dict, configs: list[CollectedConfig]) -> str:
    """Convert aggregated results to JSON"""
    data = {
        "scan_time": datetime.now().isoformat(),
        "machines_reporting": len(configs),
        "unique_mcps": len(mcps),
        "mcps": [
            {
                "name": name,
                "source": info["source"],
                "server_type": info["server_type"],
                "machine_count": len(info["machines"]),
                "machines": info["machines"],
                "risk_flags": list(info["risk_flags"]),
            }
            for name, info in mcps.items()
        ],
        "by_machine": [c.to_dict() for c in configs],
    }
    return json.dumps(data, indent=2)


def _aggregated_to_markdown(mcps: dict, configs: list[CollectedConfig]) -> str:
    """Convert aggregated results to Markdown"""
    lines = [
        "# MCP Audit Report - Aggregated",
        "",
        f"**Scan Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"**Machines Reporting:** {len(configs)}",
        f"**Unique MCPs:** {len(mcps)}",
        "",
        "## MCP Inventory",
        "",
        "| MCP Name | Source | Machines | Type | Risk Flags |",
        "|----------|--------|----------|------|------------|",
    ]
    
    for name, info in sorted(mcps.items(), key=lambda x: len(x[1]["machines"]), reverse=True):
        risk_flags = ", ".join(info["risk_flags"]) if info["risk_flags"] else "-"
        lines.append(
            f"| {name} | {info['source'][:40]} | {len(info['machines'])} | "
            f"{info['server_type']} | {risk_flags} |"
        )
    
    # Machine summary
    lines.extend([
        "",
        "## By Machine",
        "",
    ])
    
    for config in configs:
        mcp_names = ", ".join([m.name for m in config.mcps[:5]])
        if len(config.mcps) > 5:
            mcp_names += f" (+{len(config.mcps) - 5} more)"
        lines.append(f"- **{config.machine_id}**: {len(config.mcps)} MCPs - {mcp_names}")
    
    return "\n".join(lines)


def _aggregated_to_csv(mcps: dict, configs: list[CollectedConfig]) -> str:
    """Convert aggregated results to CSV"""
    lines = ["name,source,server_type,machine_count,risk_flags"]
    
    for name, info in mcps.items():
        risk_flags = "|".join(info["risk_flags"])
        source = f'"{info["source"]}"' if "," in info["source"] else info["source"]
        lines.append(f"{name},{source},{info['server_type']},{len(info['machines'])},{risk_flags}")
    
    return "\n".join(lines)
