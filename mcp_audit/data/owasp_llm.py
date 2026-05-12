"""
OWASP LLM Top 10 (2025) Mapping for MCP Audit

Reference: https://genai.owasp.org/llm-top-10/
"""

from typing import List, Dict, Set

# OWASP LLM Top 10 (2025) Definitions
OWASP_LLM_TOP_10 = {
    "LLM01": {
        "name": "Prompt Injection",
        "description": "Manipulating LLM behavior through crafted prompts via external inputs",
        "mcp_relevance": "MCP discovery provides attack surface visibility - each MCP represents potential prompt injection vectors through tools, APIs, and data sources",
    },
    "LLM02": {
        "name": "Sensitive Information Disclosure",
        "description": "Unintended exposure of sensitive data through LLM responses",
        "mcp_relevance": "Secrets detected in MCP configs (API keys, tokens, passwords, connection strings) can be exposed through agent interactions",
    },
    "LLM03": {
        "name": "Supply Chain Vulnerabilities",
        "description": "Risks from third-party components, models, or data",
        "mcp_relevance": "Unknown/unverified MCP sources and MCPs not in known registry represent supply chain risks",
    },
    "LLM05": {
        "name": "Improper Output Handling",
        "description": "Insufficient validation, sanitization, or handling of LLM outputs before they are passed downstream to other systems",
        "mcp_relevance": "MCP server source code that pipes LLM-controlled tool arguments into shell/SQL/eval calls without sanitization — e.g., child_process.exec(`gh ${args.repo}`) is exploitable because the LLM (or an attacker controlling its input) can inject shell metacharacters into ${args.repo}",
    },
    "LLM06": {
        "name": "Excessive Agency",
        "description": "LLM systems granted excessive permissions or autonomy",
        "mcp_relevance": "MCPs with database access, shell access, filesystem access, or API access flags represent excessive agency risks",
    },
    "LLM07": {
        "name": "System Prompt Leakage",
        "description": "Exposure of system prompts or sensitive configurations",
        "mcp_relevance": "Credentials or connection strings in configs that agents can access may leak through system prompts",
    },
    "LLM09": {
        "name": "Overreliance",
        "description": "Excessive dependence on LLM outputs without validation",
        "mcp_relevance": "AI model inventory identifies all models in use, giving visibility into AI dependencies and vendor concentration risk",
    },
    "LLM10": {
        "name": "Unbounded Consumption",
        "description": "Uncontrolled resource usage leading to DoS or excessive costs",
        "mcp_relevance": "API endpoints and AI models detected provide visibility into potential cost and resource consumption vectors",
    },
}

# Mapping conditions - what triggers each OWASP LLM category
OWASP_LLM_TRIGGERS = {
    "LLM01": {
        "conditions": ["any_mcp_found"],
        "description": "Any MCP discovered provides attack surface visibility",
    },
    "LLM02": {
        "conditions": ["secrets_detected"],
        "description": "Secrets detected in MCP configurations",
    },
    "LLM03": {
        "conditions": ["unverified-source", "unknown_mcp"],
        "description": "Unknown or unverified MCP sources",
    },
    "LLM05": {
        "conditions": ["shell-injection-in-source"],
        "description": "MCP server source code passes LLM-controlled arguments into shell calls without sanitization (command injection)",
    },
    "LLM06": {
        "conditions": ["database-access", "shell-access", "filesystem-access", "network-access"],
        "description": "MCPs with powerful access capabilities",
    },
    "LLM07": {
        "conditions": ["secrets-in-env", "secrets_detected"],
        "description": "Credentials in configs accessible to agents",
    },
    "LLM09": {
        "conditions": ["ai_model_detected"],
        "description": "AI models detected in configuration",
    },
    "LLM10": {
        "conditions": ["api_endpoint_detected", "ai_model_detected"],
        "description": "API endpoints or AI models detected",
    },
}


def get_owasp_llm_for_finding(finding_type: str, risk_flags: List[str] = None,
                               has_secrets: bool = False, has_apis: bool = False,
                               has_models: bool = False, is_known: bool = True) -> List[Dict]:
    """
    Get OWASP LLM Top 10 mappings for a finding.

    Args:
        finding_type: Type of finding (e.g., 'mcp_discovered', 'secret_detected', 'risk_flag')
        risk_flags: List of risk flags present
        has_secrets: Whether secrets were detected
        has_apis: Whether API endpoints were detected
        has_models: Whether AI models were detected
        is_known: Whether MCP is in known registry

    Returns:
        List of OWASP LLM mappings with id, name, and relevance
    """
    risk_flags = risk_flags or []
    mappings = []
    seen = set()

    # LLM01 - Any MCP found = attack surface visibility
    if finding_type in ("mcp_discovered", "any"):
        if "LLM01" not in seen:
            mappings.append({
                "id": "LLM01",
                "name": OWASP_LLM_TOP_10["LLM01"]["name"],
                "relevance": OWASP_LLM_TOP_10["LLM01"]["mcp_relevance"],
            })
            seen.add("LLM01")

    # LLM02 - Secrets detected
    if has_secrets or "secrets-detected" in risk_flags:
        if "LLM02" not in seen:
            mappings.append({
                "id": "LLM02",
                "name": OWASP_LLM_TOP_10["LLM02"]["name"],
                "relevance": OWASP_LLM_TOP_10["LLM02"]["mcp_relevance"],
            })
            seen.add("LLM02")

    # LLM03 - Supply chain (unverified or unknown)
    if not is_known or "unverified-source" in risk_flags:
        if "LLM03" not in seen:
            mappings.append({
                "id": "LLM03",
                "name": OWASP_LLM_TOP_10["LLM03"]["name"],
                "relevance": OWASP_LLM_TOP_10["LLM03"]["mcp_relevance"],
            })
            seen.add("LLM03")

    # LLM06 - Excessive agency (dangerous access flags)
    agency_flags = {"database-access", "shell-access", "filesystem-access", "network-access"}
    if agency_flags.intersection(set(risk_flags)):
        if "LLM06" not in seen:
            mappings.append({
                "id": "LLM06",
                "name": OWASP_LLM_TOP_10["LLM06"]["name"],
                "relevance": OWASP_LLM_TOP_10["LLM06"]["mcp_relevance"],
            })
            seen.add("LLM06")

    # LLM07 - System prompt leakage (secrets in env)
    if "secrets-in-env" in risk_flags or has_secrets:
        if "LLM07" not in seen:
            mappings.append({
                "id": "LLM07",
                "name": OWASP_LLM_TOP_10["LLM07"]["name"],
                "relevance": OWASP_LLM_TOP_10["LLM07"]["mcp_relevance"],
            })
            seen.add("LLM07")

    # LLM09 - Overreliance (AI models detected)
    if has_models:
        if "LLM09" not in seen:
            mappings.append({
                "id": "LLM09",
                "name": OWASP_LLM_TOP_10["LLM09"]["name"],
                "relevance": OWASP_LLM_TOP_10["LLM09"]["mcp_relevance"],
            })
            seen.add("LLM09")

    # LLM10 - Unbounded consumption (APIs or models)
    if has_apis or has_models:
        if "LLM10" not in seen:
            mappings.append({
                "id": "LLM10",
                "name": OWASP_LLM_TOP_10["LLM10"]["name"],
                "relevance": OWASP_LLM_TOP_10["LLM10"]["mcp_relevance"],
            })
            seen.add("LLM10")

    return mappings


def get_owasp_llm_for_secret(secret_type: str) -> List[Dict]:
    """Get OWASP LLM mappings for a detected secret."""
    return [
        {
            "id": "LLM02",
            "name": OWASP_LLM_TOP_10["LLM02"]["name"],
            "relevance": "Exposed credential can be disclosed through LLM interactions",
        },
        {
            "id": "LLM07",
            "name": OWASP_LLM_TOP_10["LLM07"]["name"],
            "relevance": "Credential in config may leak through system prompt exposure",
        },
    ]


def get_owasp_llm_for_risk_flag(flag: str) -> List[Dict]:
    """Get OWASP LLM mappings for a specific risk flag."""
    mappings = []

    flag_to_owasp = {
        "database-access": ["LLM06"],
        "shell-access": ["LLM06"],
        "filesystem-access": ["LLM06"],
        "network-access": ["LLM06"],
        "secrets-in-env": ["LLM02", "LLM07"],
        "secrets-detected": ["LLM02", "LLM07"],
        "unverified-source": ["LLM03"],
        "local-binary": ["LLM03"],
        "remote-mcp": ["LLM03", "LLM10"],
    }

    owasp_ids = flag_to_owasp.get(flag, [])
    for owasp_id in owasp_ids:
        if owasp_id in OWASP_LLM_TOP_10:
            mappings.append({
                "id": owasp_id,
                "name": OWASP_LLM_TOP_10[owasp_id]["name"],
                "relevance": OWASP_LLM_TOP_10[owasp_id]["mcp_relevance"],
            })

    return mappings


def get_scan_owasp_coverage(results) -> Dict:
    """
    Get OWASP LLM Top 10 coverage summary for a scan.

    Returns dict with covered risks and their evidence.
    """
    coverage = {}

    # Check what we found
    has_mcps = len(results) > 0
    has_secrets = any(r.secrets for r in results)
    has_apis = any(r.apis for r in results)
    has_models = any(r.model for r in results)
    has_unknown = any(not r.is_known for r in results)

    # Collect all risk flags
    all_flags = set()
    for r in results:
        all_flags.update(r.risk_flags)

    # LLM01 - Attack surface visibility
    if has_mcps:
        coverage["LLM01"] = {
            "name": OWASP_LLM_TOP_10["LLM01"]["name"],
            "covered": True,
            "evidence": f"{len(results)} MCP(s) discovered - attack surface mapped",
        }

    # LLM02 - Sensitive info disclosure
    if has_secrets or "secrets-detected" in all_flags:
        secret_count = sum(len(r.secrets) for r in results)
        coverage["LLM02"] = {
            "name": OWASP_LLM_TOP_10["LLM02"]["name"],
            "covered": True,
            "evidence": f"{secret_count} secret(s) detected in MCP configs",
        }

    # LLM03 - Supply chain
    if has_unknown or "unverified-source" in all_flags:
        unknown_count = sum(1 for r in results if not r.is_known)
        coverage["LLM03"] = {
            "name": OWASP_LLM_TOP_10["LLM03"]["name"],
            "covered": True,
            "evidence": f"{unknown_count} unknown/unverified MCP source(s)",
        }

    # LLM06 - Excessive agency
    agency_flags = {"database-access", "shell-access", "filesystem-access", "network-access"}
    found_agency = agency_flags.intersection(all_flags)
    if found_agency:
        coverage["LLM06"] = {
            "name": OWASP_LLM_TOP_10["LLM06"]["name"],
            "covered": True,
            "evidence": f"Agency risks: {', '.join(found_agency)}",
        }

    # LLM07 - System prompt leakage
    if "secrets-in-env" in all_flags or has_secrets:
        coverage["LLM07"] = {
            "name": OWASP_LLM_TOP_10["LLM07"]["name"],
            "covered": True,
            "evidence": "Credentials in configs may leak via system prompts",
        }

    # LLM09 - Overreliance
    if has_models:
        model_count = sum(1 for r in results if r.model)
        coverage["LLM09"] = {
            "name": OWASP_LLM_TOP_10["LLM09"]["name"],
            "covered": True,
            "evidence": f"{model_count} AI model(s) identified for dependency tracking",
        }

    # LLM10 - Unbounded consumption
    if has_apis or has_models:
        api_count = sum(len(r.apis) for r in results)
        model_count = sum(1 for r in results if r.model)
        evidence_parts = []
        if api_count:
            evidence_parts.append(f"{api_count} API endpoint(s)")
        if model_count:
            evidence_parts.append(f"{model_count} AI model(s)")
        coverage["LLM10"] = {
            "name": OWASP_LLM_TOP_10["LLM10"]["name"],
            "covered": True,
            "evidence": f"Resource vectors identified: {', '.join(evidence_parts)}",
        }

    return coverage
