"""
CycloneDX 1.6 AI-BOM Export for MCP Audit

Generates CycloneDX Software Bill of Materials with AI/ML model components
following the CycloneDX 1.6 specification for AI transparency.
"""

import json
import uuid
from datetime import datetime
from typing import Optional

from mcp_audit.models import ScanResult


def generate_cyclonedx_bom(
    results: list[ScanResult],
    format: str = "json",
    include_mcps: bool = True,
) -> str:
    """
    Generate CycloneDX 1.6 AI-BOM from scan results.

    Args:
        results: List of ScanResult objects from scanning
        format: Output format ("json" or "xml")
        include_mcps: Whether to include MCP components (not just AI models)

    Returns:
        CycloneDX BOM as JSON or XML string
    """
    # Collect AI models from results
    models = []
    for r in results:
        if r.model:
            model_info = r.model.copy() if isinstance(r.model, dict) else {}
            model_info["mcp_name"] = r.name
            model_info["mcp_source"] = r.source
            models.append(model_info)

    # Build BOM structure
    bom = _build_bom_structure(results, models, include_mcps)

    if format == "xml":
        return _to_xml(bom)
    else:
        return json.dumps(bom, indent=2)


def _build_bom_structure(
    results: list[ScanResult],
    models: list[dict],
    include_mcps: bool,
) -> dict:
    """Build the CycloneDX 1.6 BOM data structure."""
    serial_number = f"urn:uuid:{uuid.uuid4()}"
    timestamp = datetime.utcnow().isoformat() + "Z"

    bom = {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": serial_number,
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "mcp-audit",
                        "publisher": "APIsec",
                        "version": "1.0.0",
                        "description": "MCP configuration security audit tool",
                        "externalReferences": [
                            {
                                "type": "website",
                                "url": "https://github.com/apisec-inc/mcp-audit"
                            }
                        ]
                    }
                ]
            },
            "component": {
                "type": "application",
                "name": "mcp-environment",
                "description": "MCP-enabled AI development environment",
            }
        },
        "components": [],
    }

    # Add AI model components
    for model in models:
        component = _model_to_component(model)
        bom["components"].append(component)

    # Add MCP components if requested
    if include_mcps:
        for r in results:
            mcp_component = _mcp_to_component(r)
            bom["components"].append(mcp_component)

    # Add dependencies section (models depend on their MCPs)
    bom["dependencies"] = _build_dependencies(results, models)

    return bom


def _model_to_component(model: dict) -> dict:
    """Convert a detected AI model to a CycloneDX component."""
    model_id = model.get("model_id", "unknown")
    model_name = model.get("model_name", model_id)
    provider = model.get("provider", "Unknown")
    hosting = model.get("hosting", "unknown")
    source = model.get("source", "")
    mcp_name = model.get("mcp_name", "")

    # Generate stable bom-ref
    bom_ref = f"model:{provider.lower().replace(' ', '-')}:{model_id}"

    component = {
        "type": "machine-learning-model",
        "bom-ref": bom_ref,
        "name": model_name,
        "version": _extract_version(model_id),
        "supplier": {
            "name": provider,
        },
        "description": f"AI model used by {mcp_name} MCP",
        "properties": [
            {
                "name": "hosting",
                "value": hosting,
            },
            {
                "name": "source",
                "value": source,
            },
            {
                "name": "mcp",
                "value": mcp_name,
            },
        ],
    }

    # Add model card for AI transparency (CycloneDX 1.6 feature)
    component["modelCard"] = {
        "modelArchitecture": _infer_architecture(model_name, provider),
        "modelParameters": {
            "task": _infer_task(model_name),
        },
        "considerations": {
            "environmentalConsiderations": {
                "energyConsumption": _get_energy_class(hosting, model_name),
            },
        },
    }

    # Add external references for cloud models
    if hosting == "cloud":
        api_url = _get_provider_api_url(provider)
        if api_url:
            component["externalReferences"] = [
                {
                    "type": "distribution",
                    "url": api_url,
                    "comment": f"{provider} API endpoint",
                }
            ]

    return component


def _mcp_to_component(result: ScanResult) -> dict:
    """Convert an MCP to a CycloneDX component."""
    bom_ref = f"mcp:{result.name}"

    component = {
        "type": "application",
        "bom-ref": bom_ref,
        "name": result.name,
        "supplier": {
            "name": result.provider or "Unknown",
        },
        "description": f"Model Context Protocol server ({result.server_type})",
        "properties": [
            {
                "name": "source",
                "value": result.source,
            },
            {
                "name": "server_type",
                "value": result.server_type,
            },
            {
                "name": "found_in",
                "value": result.found_in,
            },
        ],
    }

    # Add registry info if known
    if result.is_known:
        component["properties"].extend([
            {
                "name": "registry_known",
                "value": "true",
            },
            {
                "name": "registry_risk",
                "value": result.registry_risk or "unknown",
            },
            {
                "name": "verified",
                "value": str(result.verified).lower(),
            },
        ])

    # Add risk flags
    if result.risk_flags:
        component["properties"].append({
            "name": "risk_flags",
            "value": ",".join(result.risk_flags),
        })

    # Add capabilities
    if result.capabilities:
        component["properties"].append({
            "name": "capabilities",
            "value": ",".join(result.capabilities),
        })

    # Add external references for APIs
    if result.apis:
        component["externalReferences"] = []
        for api in result.apis:
            api_dict = api.to_dict() if hasattr(api, 'to_dict') else api
            component["externalReferences"].append({
                "type": "other",
                "url": api_dict.get("url", "unknown"),
                "comment": api_dict.get("description", "API endpoint"),
            })

    return component


def _build_dependencies(results: list[ScanResult], models: list[dict]) -> list[dict]:
    """Build dependency relationships between models and MCPs."""
    dependencies = []

    # Models depend on their MCPs
    for model in models:
        mcp_name = model.get("mcp_name", "")
        model_id = model.get("model_id", "unknown")
        provider = model.get("provider", "Unknown")

        model_ref = f"model:{provider.lower().replace(' ', '-')}:{model_id}"
        mcp_ref = f"mcp:{mcp_name}"

        dependencies.append({
            "ref": model_ref,
            "dependsOn": [mcp_ref],
        })

    # MCPs that use AI models
    for r in results:
        if r.model:
            model_id = r.model.get("model_id", "unknown")
            provider = r.model.get("provider", "Unknown")
            model_ref = f"model:{provider.lower().replace(' ', '-')}:{model_id}"

            dependencies.append({
                "ref": f"mcp:{r.name}",
                "provides": [model_ref],
            })

    return dependencies


def _extract_version(model_id: str) -> str:
    """Extract version from model ID string."""
    if not model_id:
        return "unknown"

    # Common patterns: gpt-4o-2024-08-06, claude-3-5-sonnet-20241022
    parts = model_id.split("-")

    # Look for date pattern (YYYYMMDD or YYYY-MM-DD)
    for part in parts:
        if len(part) == 8 and part.isdigit():
            return f"{part[:4]}-{part[4:6]}-{part[6:]}"

    # Look for version number pattern
    for i, part in enumerate(parts):
        if part.replace(".", "").isdigit() and "." in part:
            return part

    return "latest"


def _infer_architecture(model_name: str, provider: str) -> str:
    """Infer model architecture from name and provider."""
    name_lower = model_name.lower()

    if "llama" in name_lower:
        return "Llama Transformer"
    elif "mistral" in name_lower or "mixtral" in name_lower:
        return "Mistral/Mixtral Architecture"
    elif "gpt" in name_lower or provider == "OpenAI":
        return "GPT Transformer"
    elif "claude" in name_lower or provider == "Anthropic":
        return "Constitutional AI"
    elif "gemini" in name_lower or "gemma" in name_lower:
        return "Gemini/Gemma Architecture"
    elif "qwen" in name_lower:
        return "Qwen Architecture"
    elif "phi" in name_lower:
        return "Phi Architecture"
    else:
        return "Transformer"


def _infer_task(model_name: str) -> str:
    """Infer model task from name."""
    name_lower = model_name.lower()

    if "code" in name_lower or "coder" in name_lower:
        return "code-generation"
    elif "embed" in name_lower:
        return "text-embedding"
    elif "vision" in name_lower or "image" in name_lower:
        return "image-understanding"
    else:
        return "text-generation"


def _get_energy_class(hosting: str, model_name: str) -> str:
    """Estimate energy consumption class."""
    if hosting == "local":
        return "variable-local"
    elif "mini" in model_name.lower() or "small" in model_name.lower():
        return "low"
    elif "large" in model_name.lower() or "ultra" in model_name.lower():
        return "high"
    else:
        return "medium"


def _get_provider_api_url(provider: str) -> Optional[str]:
    """Get API documentation URL for provider."""
    urls = {
        "OpenAI": "https://api.openai.com",
        "Anthropic": "https://api.anthropic.com",
        "Google": "https://generativelanguage.googleapis.com",
        "Mistral AI": "https://api.mistral.ai",
        "Cohere": "https://api.cohere.ai",
        "Azure OpenAI": "https://azure.openai.com",
        "AWS Bedrock": "https://bedrock.amazonaws.com",
        "Together AI": "https://api.together.xyz",
        "Groq": "https://api.groq.com",
        "DeepSeek": "https://api.deepseek.com",
        "Fireworks AI": "https://api.fireworks.ai",
    }
    return urls.get(provider)


def _to_xml(bom: dict) -> str:
    """Convert BOM dict to CycloneDX XML format."""
    # Simplified XML generation - for production use cyclonedx-python-lib
    xml_lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<bom xmlns="http://cyclonedx.org/schema/bom/1.6"',
        f'     serialNumber="{bom["serialNumber"]}"',
        f'     version="{bom["version"]}">',
    ]

    # Metadata
    xml_lines.append("  <metadata>")
    xml_lines.append(f'    <timestamp>{bom["metadata"]["timestamp"]}</timestamp>')
    xml_lines.append("    <tools>")
    for tool in bom["metadata"]["tools"]["components"]:
        xml_lines.append(f'      <tool ref="{tool["name"]}">')
        xml_lines.append(f'        <name>{tool["name"]}</name>')
        xml_lines.append(f'        <version>{tool["version"]}</version>')
        xml_lines.append("      </tool>")
    xml_lines.append("    </tools>")
    xml_lines.append("  </metadata>")

    # Components
    xml_lines.append("  <components>")
    for comp in bom["components"]:
        xml_lines.append(f'    <component type="{comp["type"]}" bom-ref="{comp["bom-ref"]}">')
        xml_lines.append(f'      <name>{_xml_escape(comp["name"])}</name>')
        if comp.get("version"):
            xml_lines.append(f'      <version>{comp["version"]}</version>')
        if comp.get("supplier"):
            xml_lines.append(f'      <supplier><name>{_xml_escape(comp["supplier"]["name"])}</name></supplier>')
        if comp.get("description"):
            xml_lines.append(f'      <description>{_xml_escape(comp["description"])}</description>')

        # Properties
        if comp.get("properties"):
            xml_lines.append("      <properties>")
            for prop in comp["properties"]:
                xml_lines.append(f'        <property name="{prop["name"]}">{_xml_escape(prop["value"])}</property>')
            xml_lines.append("      </properties>")

        xml_lines.append("    </component>")
    xml_lines.append("  </components>")

    # Dependencies
    if bom.get("dependencies"):
        xml_lines.append("  <dependencies>")
        for dep in bom["dependencies"]:
            xml_lines.append(f'    <dependency ref="{dep["ref"]}">')
            if dep.get("dependsOn"):
                for d in dep["dependsOn"]:
                    xml_lines.append(f'      <dependency ref="{d}"/>')
            xml_lines.append("    </dependency>")
        xml_lines.append("  </dependencies>")

    xml_lines.append("</bom>")
    return "\n".join(xml_lines)


def _xml_escape(text: str) -> str:
    """Escape special XML characters."""
    if not text:
        return ""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )
