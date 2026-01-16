# APIsec MCP Audit: Model Detection & AI-BOM Export

## Overview

Add two features to APIsec MCP Audit:

1. **Model Detection** — Identify which AI models are configured in each MCP
2. **AI-BOM Export** — Export scan results in CycloneDX format for compliance/automation

These features position APIsec MCP Audit as an "AI Bill of Materials" tool.

---

## Feature 1: Model Detection

### What It Does

Parse MCP configuration environment variables to identify which AI models are being used.

### Current Output

```
┌─────────────────┬───────────┬─────────────────────────────┐
│ MCP Name        │ Risk      │ APIs Discovered             │
├─────────────────┼───────────┼─────────────────────────────┤
│ openai-mcp      │ Medium    │ api.openai.com              │
│ anthropic-mcp   │ Medium    │ api.anthropic.com           │
│ local-llm       │ Medium    │ localhost:11434             │
└─────────────────┴───────────┴─────────────────────────────┘
```

### With Model Detection

```
┌─────────────────┬───────────┬─────────────────────────────┬─────────────────────┐
│ MCP Name        │ Risk      │ APIs Discovered             │ AI Model            │
├─────────────────┼───────────┼─────────────────────────────┼─────────────────────┤
│ openai-mcp      │ Medium    │ api.openai.com              │ GPT-4o              │
│ anthropic-mcp   │ Medium    │ api.anthropic.com           │ Claude 3.5 Sonnet   │
│ local-llm       │ Medium    │ localhost:11434             │ Llama 3 70B         │
│ bedrock-mcp     │ Medium    │ bedrock.us-east-1.aws...    │ Claude 3 (Bedrock)  │
│ azure-openai    │ Medium    │ acme.openai.azure.com       │ GPT-4 (Azure)       │
└─────────────────┴───────────┴─────────────────────────────┴─────────────────────┘
```

### New Summary Section

Add an "AI Models Summary" section to scan output:

```
AI Models Summary
─────────────────────────────────────────────────────────────────
Total Models: 5

By Provider:
  OpenAI      ██████████████████  2 (GPT-4o, GPT-4)
  Anthropic   █████████████████   2 (Claude 3.5 Sonnet, Claude 3)
  Meta        █████████           1 (Llama 3 70B)

By Hosting:
  Cloud API   ████████████████████████  4
  Local       ██████                    1

Model Inventory:
  • GPT-4o (OpenAI) — openai-mcp
  • GPT-4 (Azure OpenAI) — azure-openai-mcp
  • Claude 3.5 Sonnet (Anthropic) — anthropic-mcp
  • Claude 3 (AWS Bedrock) — bedrock-mcp
  • Llama 3 70B (Local) — local-llm
─────────────────────────────────────────────────────────────────
```

---

### Implementation

#### Environment Variable Patterns to Match

```python
MODEL_ENV_PATTERNS = [
    # Exact matches (case-insensitive)
    'MODEL',
    'MODEL_NAME',
    'MODEL_ID',
    'LLM_MODEL',
    'AI_MODEL',
    
    # Provider-specific
    'OPENAI_MODEL',
    'OPENAI_MODEL_NAME',
    'ANTHROPIC_MODEL',
    'CLAUDE_MODEL',
    'BEDROCK_MODEL_ID',
    'AZURE_OPENAI_DEPLOYMENT',
    'AZURE_DEPLOYMENT_NAME',
    'OLLAMA_MODEL',
    'TOGETHER_MODEL',
    'GROQ_MODEL',
    'MISTRAL_MODEL',
    'COHERE_MODEL',
    
    # Local model paths
    'MODEL_PATH',
    'GGUF_MODEL',
    'LLAMA_MODEL_PATH',
]
```

#### Model Identification Patterns

```python
MODEL_IDENTIFIERS = {
    # OpenAI Models
    'gpt-4o': {'name': 'GPT-4o', 'provider': 'OpenAI', 'hosting': 'cloud'},
    'gpt-4o-mini': {'name': 'GPT-4o Mini', 'provider': 'OpenAI', 'hosting': 'cloud'},
    'gpt-4-turbo': {'name': 'GPT-4 Turbo', 'provider': 'OpenAI', 'hosting': 'cloud'},
    'gpt-4': {'name': 'GPT-4', 'provider': 'OpenAI', 'hosting': 'cloud'},
    'gpt-3.5-turbo': {'name': 'GPT-3.5 Turbo', 'provider': 'OpenAI', 'hosting': 'cloud'},
    'o1': {'name': 'o1', 'provider': 'OpenAI', 'hosting': 'cloud'},
    'o1-mini': {'name': 'o1 Mini', 'provider': 'OpenAI', 'hosting': 'cloud'},
    'o1-preview': {'name': 'o1 Preview', 'provider': 'OpenAI', 'hosting': 'cloud'},
    
    # Anthropic Models
    'claude-3-5-sonnet': {'name': 'Claude 3.5 Sonnet', 'provider': 'Anthropic', 'hosting': 'cloud'},
    'claude-3-5-haiku': {'name': 'Claude 3.5 Haiku', 'provider': 'Anthropic', 'hosting': 'cloud'},
    'claude-3-opus': {'name': 'Claude 3 Opus', 'provider': 'Anthropic', 'hosting': 'cloud'},
    'claude-3-sonnet': {'name': 'Claude 3 Sonnet', 'provider': 'Anthropic', 'hosting': 'cloud'},
    'claude-3-haiku': {'name': 'Claude 3 Haiku', 'provider': 'Anthropic', 'hosting': 'cloud'},
    
    # Meta Llama Models
    'llama-3': {'name': 'Llama 3', 'provider': 'Meta', 'hosting': 'local'},
    'llama-3.1': {'name': 'Llama 3.1', 'provider': 'Meta', 'hosting': 'local'},
    'llama-3.2': {'name': 'Llama 3.2', 'provider': 'Meta', 'hosting': 'local'},
    'llama-2': {'name': 'Llama 2', 'provider': 'Meta', 'hosting': 'local'},
    'codellama': {'name': 'Code Llama', 'provider': 'Meta', 'hosting': 'local'},
    
    # Mistral Models
    'mistral': {'name': 'Mistral', 'provider': 'Mistral AI', 'hosting': 'cloud'},
    'mistral-large': {'name': 'Mistral Large', 'provider': 'Mistral AI', 'hosting': 'cloud'},
    'mistral-medium': {'name': 'Mistral Medium', 'provider': 'Mistral AI', 'hosting': 'cloud'},
    'mistral-small': {'name': 'Mistral Small', 'provider': 'Mistral AI', 'hosting': 'cloud'},
    'mixtral': {'name': 'Mixtral', 'provider': 'Mistral AI', 'hosting': 'local'},
    'codestral': {'name': 'Codestral', 'provider': 'Mistral AI', 'hosting': 'cloud'},
    
    # Google Models
    'gemini-pro': {'name': 'Gemini Pro', 'provider': 'Google', 'hosting': 'cloud'},
    'gemini-ultra': {'name': 'Gemini Ultra', 'provider': 'Google', 'hosting': 'cloud'},
    'gemini-1.5-pro': {'name': 'Gemini 1.5 Pro', 'provider': 'Google', 'hosting': 'cloud'},
    'gemini-1.5-flash': {'name': 'Gemini 1.5 Flash', 'provider': 'Google', 'hosting': 'cloud'},
    'gemma': {'name': 'Gemma', 'provider': 'Google', 'hosting': 'local'},
    
    # Cohere Models
    'command': {'name': 'Command', 'provider': 'Cohere', 'hosting': 'cloud'},
    'command-r': {'name': 'Command R', 'provider': 'Cohere', 'hosting': 'cloud'},
    'command-r-plus': {'name': 'Command R+', 'provider': 'Cohere', 'hosting': 'cloud'},
    
    # Other Local Models
    'phi-3': {'name': 'Phi-3', 'provider': 'Microsoft', 'hosting': 'local'},
    'phi-2': {'name': 'Phi-2', 'provider': 'Microsoft', 'hosting': 'local'},
    'qwen': {'name': 'Qwen', 'provider': 'Alibaba', 'hosting': 'local'},
    'deepseek': {'name': 'DeepSeek', 'provider': 'DeepSeek', 'hosting': 'local'},
    'yi': {'name': 'Yi', 'provider': '01.AI', 'hosting': 'local'},
    'falcon': {'name': 'Falcon', 'provider': 'TII', 'hosting': 'local'},
    'vicuna': {'name': 'Vicuna', 'provider': 'LMSYS', 'hosting': 'local'},
    'openchat': {'name': 'OpenChat', 'provider': 'OpenChat', 'hosting': 'local'},
    'neural-chat': {'name': 'Neural Chat', 'provider': 'Intel', 'hosting': 'local'},
    'starling': {'name': 'Starling', 'provider': 'Berkeley', 'hosting': 'local'},
    'zephyr': {'name': 'Zephyr', 'provider': 'HuggingFace', 'hosting': 'local'},
}
```

#### Cloud Provider Detection

Infer hosting from API endpoint:

```python
CLOUD_PROVIDERS = {
    'api.openai.com': {'provider': 'OpenAI', 'hosting': 'cloud'},
    'api.anthropic.com': {'provider': 'Anthropic', 'hosting': 'cloud'},
    'openai.azure.com': {'provider': 'Azure OpenAI', 'hosting': 'cloud'},
    'bedrock': {'provider': 'AWS Bedrock', 'hosting': 'cloud'},
    'aiplatform.googleapis.com': {'provider': 'Google Vertex AI', 'hosting': 'cloud'},
    'api.mistral.ai': {'provider': 'Mistral AI', 'hosting': 'cloud'},
    'api.cohere.ai': {'provider': 'Cohere', 'hosting': 'cloud'},
    'api.together.xyz': {'provider': 'Together AI', 'hosting': 'cloud'},
    'api.groq.com': {'provider': 'Groq', 'hosting': 'cloud'},
    'localhost': {'provider': 'Local', 'hosting': 'local'},
    '127.0.0.1': {'provider': 'Local', 'hosting': 'local'},
    '0.0.0.0': {'provider': 'Local', 'hosting': 'local'},
}
```

#### Detection Logic

```python
def detect_model(mcp_config):
    """
    Detect AI model from MCP configuration.
    
    Returns:
        {
            'model_id': 'gpt-4o',
            'model_name': 'GPT-4o',
            'provider': 'OpenAI',
            'hosting': 'cloud',  # 'cloud' or 'local'
            'source': 'env:OPENAI_MODEL'  # where we found it
        }
    """
    
    env_vars = mcp_config.get('env', {})
    
    # 1. Check explicit model env vars
    for env_key, env_value in env_vars.items():
        if any(pattern in env_key.upper() for pattern in MODEL_ENV_PATTERNS):
            model_info = identify_model(env_value)
            if model_info:
                model_info['source'] = f'env:{env_key}'
                return model_info
    
    # 2. Infer from API endpoint
    # (If we found api.anthropic.com but no model specified, assume Claude)
    
    # 3. Check for local model paths
    for env_key, env_value in env_vars.items():
        if 'PATH' in env_key.upper() and is_model_path(env_value):
            model_info = identify_model_from_path(env_value)
            if model_info:
                model_info['source'] = f'path:{env_key}'
                return model_info
    
    return None


def identify_model(model_string):
    """
    Match a model string to known models.
    Handles variations like 'gpt-4o-2024-08-06' → 'gpt-4o'
    """
    model_lower = model_string.lower()
    
    # Try exact match first
    if model_lower in MODEL_IDENTIFIERS:
        return MODEL_IDENTIFIERS[model_lower].copy()
    
    # Try prefix match (for versioned models like 'gpt-4o-2024-08-06')
    for pattern, info in MODEL_IDENTIFIERS.items():
        if model_lower.startswith(pattern):
            result = info.copy()
            result['model_id'] = model_string  # Keep original ID
            return result
    
    # Try fuzzy match
    for pattern, info in MODEL_IDENTIFIERS.items():
        if pattern in model_lower:
            result = info.copy()
            result['model_id'] = model_string
            return result
    
    # Unknown model
    return {
        'model_id': model_string,
        'model_name': model_string,
        'provider': 'Unknown',
        'hosting': 'unknown'
    }
```

---

### CLI Output

#### New Flag

```bash
# Show AI models summary
mcp-audit scan --models

# Include models in JSON export
mcp-audit scan --format json  # Models included by default
```

#### Output Format

```
$ mcp-audit scan

APIsec MCP Audit v0.2.0

Scanning /Users/raj/.cursor, /Users/raj/Library/Application Support/Claude...

Found 8 MCPs

MCP Inventory
─────────────────────────────────────────────────────────────────
┌─────────────────┬───────────┬─────────────────────┬─────────────────────┐
│ MCP Name        │ Risk      │ AI Model            │ APIs                │
├─────────────────┼───────────┼─────────────────────┼─────────────────────┤
│ openai-mcp      │ Medium    │ GPT-4o (OpenAI)     │ api.openai.com      │
│ anthropic-mcp   │ Medium    │ Claude 3.5 Sonnet   │ api.anthropic.com   │
│ local-llm       │ Low       │ Llama 3 70B (Local) │ localhost:11434     │
│ postgres-mcp    │ Critical  │ —                   │ db.acme.com         │
│ filesystem      │ High      │ —                   │ —                   │
└─────────────────┴───────────┴─────────────────────┴─────────────────────┘

AI Models Summary
─────────────────────────────────────────────────────────────────
3 AI models detected across 3 MCPs

By Provider:                      By Hosting:
  OpenAI        1                   Cloud    2
  Anthropic     1                   Local    1
  Meta          1                   

Model Details:
  • GPT-4o — OpenAI (Cloud) — openai-mcp
  • Claude 3.5 Sonnet — Anthropic (Cloud) — anthropic-mcp
  • Llama 3 70B — Meta (Local) — local-llm
─────────────────────────────────────────────────────────────────

[... rest of scan output: Secrets, APIs, Remediation ...]
```

---

### Web UI Updates

Add "AI Models" tab/section to results:

```
┌─────────────────────────────────────────────────────────────────────┐
│                                                                     │
│  [Overview] [MCPs] [Secrets] [APIs] [AI Models]                    │
│                                                                     │
│  AI Models                                                          │
│  ─────────────────────────────────────────────────────────────────  │
│                                                                     │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐           │
│  │       3       │  │       2       │  │       1       │           │
│  │    Models     │  │     Cloud     │  │     Local     │           │
│  └───────────────┘  └───────────────┘  └───────────────┘           │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ Model                │ Provider   │ Hosting │ Used By       │   │
│  ├─────────────────────────────────────────────────────────────┤   │
│  │ GPT-4o               │ OpenAI     │ Cloud   │ openai-mcp    │   │
│  │ Claude 3.5 Sonnet    │ Anthropic  │ Cloud   │ anthropic-mcp │   │
│  │ Llama 3 70B          │ Meta       │ Local   │ local-llm     │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

### Data Structure

Add to scan results:

```json
{
  "summary": {
    "total_mcps": 8,
    "critical": 1,
    "high": 2,
    "medium": 3,
    "low": 2,
    "secrets_found": 4,
    "apis_discovered": 5,
    "models_detected": 3
  },
  "models": {
    "total": 3,
    "by_provider": {
      "OpenAI": 1,
      "Anthropic": 1,
      "Meta": 1
    },
    "by_hosting": {
      "cloud": 2,
      "local": 1
    },
    "inventory": [
      {
        "model_id": "gpt-4o",
        "model_name": "GPT-4o",
        "provider": "OpenAI",
        "hosting": "cloud",
        "source": "env:OPENAI_MODEL",
        "mcp": "openai-mcp"
      },
      {
        "model_id": "claude-3-5-sonnet-20241022",
        "model_name": "Claude 3.5 Sonnet",
        "provider": "Anthropic",
        "hosting": "cloud",
        "source": "env:ANTHROPIC_MODEL",
        "mcp": "anthropic-mcp"
      },
      {
        "model_id": "llama-3-70b",
        "model_name": "Llama 3 70B",
        "provider": "Meta",
        "hosting": "local",
        "source": "path:MODEL_PATH",
        "mcp": "local-llm"
      }
    ]
  },
  "mcps": [
    {
      "name": "openai-mcp",
      "risk": "medium",
      "model": {
        "model_id": "gpt-4o",
        "model_name": "GPT-4o",
        "provider": "OpenAI",
        "hosting": "cloud"
      },
      "apis": ["api.openai.com"],
      "secrets": []
    }
  ]
}
```

---

## Feature 2: AI-BOM Export (CycloneDX)

### What It Does

Export scan results in CycloneDX format — the industry standard for Software Bill of Materials (SBOM). This enables:

- Import into GRC/compliance platforms
- Integration with security dashboards
- Audit evidence for compliance
- Automation and CI/CD pipelines

---

### CycloneDX Format

CycloneDX is an OWASP standard. Version 1.6 added support for ML/AI components.

**File extension:** `.cdx.json` (JSON) or `.cdx.xml` (XML)

**Recommendation:** Support JSON format only (simpler, more common in modern tooling).

---

### Output Schema

```json
{
  "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "timestamp": "2026-01-13T10:30:00Z",
    "tools": {
      "components": [
        {
          "type": "application",
          "name": "APIsec MCP Audit",
          "version": "0.2.0",
          "supplier": {
            "name": "APIsec",
            "url": ["https://www.apisec.ai"]
          }
        }
      ]
    },
    "component": {
      "type": "application",
      "name": "AI Development Environment",
      "description": "AI tools and integrations inventory"
    }
  },
  "components": [
    {
      "type": "machine-learning-model",
      "bom-ref": "model-gpt-4o",
      "name": "GPT-4o",
      "version": "2024-08-06",
      "supplier": {
        "name": "OpenAI",
        "url": ["https://openai.com"]
      },
      "properties": [
        {"name": "apisec:hosting", "value": "cloud"},
        {"name": "apisec:api_endpoint", "value": "api.openai.com"},
        {"name": "apisec:mcp_source", "value": "openai-mcp"}
      ]
    },
    {
      "type": "machine-learning-model",
      "bom-ref": "model-claude-3-5-sonnet",
      "name": "Claude 3.5 Sonnet",
      "version": "20241022",
      "supplier": {
        "name": "Anthropic",
        "url": ["https://anthropic.com"]
      },
      "properties": [
        {"name": "apisec:hosting", "value": "cloud"},
        {"name": "apisec:api_endpoint", "value": "api.anthropic.com"},
        {"name": "apisec:mcp_source", "value": "anthropic-mcp"}
      ]
    },
    {
      "type": "machine-learning-model",
      "bom-ref": "model-llama-3-70b",
      "name": "Llama 3 70B",
      "supplier": {
        "name": "Meta",
        "url": ["https://llama.meta.com"]
      },
      "properties": [
        {"name": "apisec:hosting", "value": "local"},
        {"name": "apisec:model_path", "value": "/models/llama-3-70b"},
        {"name": "apisec:mcp_source", "value": "local-llm"}
      ]
    },
    {
      "type": "platform",
      "bom-ref": "mcp-openai-mcp",
      "name": "openai-mcp",
      "description": "MCP integration for OpenAI API",
      "properties": [
        {"name": "apisec:type", "value": "mcp"},
        {"name": "apisec:risk", "value": "medium"},
        {"name": "apisec:verified", "value": "true"},
        {"name": "apisec:permissions", "value": "network-access"}
      ]
    },
    {
      "type": "platform",
      "bom-ref": "mcp-postgres-mcp",
      "name": "postgres-mcp",
      "description": "MCP integration for PostgreSQL database",
      "properties": [
        {"name": "apisec:type", "value": "mcp"},
        {"name": "apisec:risk", "value": "critical"},
        {"name": "apisec:verified", "value": "true"},
        {"name": "apisec:permissions", "value": "database-access"},
        {"name": "apisec:secrets_detected", "value": "1"}
      ]
    }
  ],
  "services": [
    {
      "bom-ref": "service-openai-api",
      "name": "OpenAI API",
      "endpoints": ["https://api.openai.com/v1"],
      "provider": {
        "name": "OpenAI"
      }
    },
    {
      "bom-ref": "service-anthropic-api",
      "name": "Anthropic API",
      "endpoints": ["https://api.anthropic.com/v1"],
      "provider": {
        "name": "Anthropic"
      }
    },
    {
      "bom-ref": "service-internal-db",
      "name": "PostgreSQL Database",
      "endpoints": ["postgres://db.acme.com:5432"],
      "properties": [
        {"name": "apisec:type", "value": "database"},
        {"name": "apisec:internal", "value": "true"}
      ]
    }
  ],
  "dependencies": [
    {
      "ref": "mcp-openai-mcp",
      "dependsOn": ["model-gpt-4o", "service-openai-api"]
    },
    {
      "ref": "mcp-anthropic-mcp",
      "dependsOn": ["model-claude-3-5-sonnet", "service-anthropic-api"]
    },
    {
      "ref": "mcp-postgres-mcp",
      "dependsOn": ["service-internal-db"]
    }
  ],
  "vulnerabilities": [
    {
      "bom-ref": "vuln-secret-1",
      "id": "APISEC-SECRET-001",
      "description": "Exposed credential in MCP configuration",
      "detail": "PostgreSQL connection string detected in postgres-mcp configuration",
      "recommendation": "Move credential to secure secrets manager. Rotate immediately.",
      "ratings": [
        {
          "severity": "critical",
          "method": "other",
          "vector": "Configuration file contains database credentials"
        }
      ],
      "affects": [
        {
          "ref": "mcp-postgres-mcp"
        }
      ]
    }
  ]
}
```

---

### CLI Usage

```bash
# Export as CycloneDX AI-BOM
mcp-audit scan --format cyclonedx -o ai-bom.cdx.json

# Or use shorthand
mcp-audit scan --format bom -o ai-bom.cdx.json

# Export all formats at once
mcp-audit scan --format all -o results
# Creates: results.json, results.csv, results.cdx.json
```

**Output message:**

```
$ mcp-audit scan --format cyclonedx -o ai-bom.cdx.json

APIsec MCP Audit v0.2.0

Scanning...
Found 8 MCPs, 3 AI models, 5 APIs

✅ AI-BOM saved to ai-bom.cdx.json (CycloneDX 1.6)

────────────────────────────────────────────────────────────────
💡 Import this file into your GRC platform or SBOM dashboard
   for continuous AI supply chain visibility.
   
   CycloneDX spec: https://cyclonedx.org
────────────────────────────────────────────────────────────────
```

---

### Web UI

Add CycloneDX to export options:

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
│  Export raw data:                                                   │
│  [JSON] [CSV] [CycloneDX]                                          │
│                                                                     │
│  💡 Use JSON for CI/CD • CycloneDX for compliance/GRC platforms    │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

### Implementation Notes

#### File Naming

```
# CycloneDX convention
ai-bom.cdx.json     # JSON format
ai-bom.cdx.xml      # XML format (not implementing)
```

#### Validation

Optionally validate output against CycloneDX schema:
- Schema URL: `http://cyclonedx.org/schema/bom-1.6.schema.json`
- Validation library: `cyclonedx-python-lib`

#### What Goes in Each Section

| CycloneDX Section | What We Put There |
|-------------------|-------------------|
| `metadata` | Tool info, timestamp, scan target |
| `components` | MCPs + AI Models (as machine-learning-model type) |
| `services` | Discovered APIs (external services) |
| `dependencies` | Which MCPs use which models/APIs |
| `vulnerabilities` | Detected secrets (as findings) |

---

## Files to Create/Modify

### For Model Detection

| File | Changes |
|------|---------|
| `models.py` (new) | Model detection logic, patterns, identification |
| `scanner.py` | Integrate model detection into scan pipeline |
| `output.py` | Add AI Models Summary section to CLI output |
| `index.html` | Add AI Models tab/section to Web UI |
| `app.js` | Handle model data display |

### For AI-BOM Export

| File | Changes |
|------|---------|
| `cyclonedx.py` (new) | CycloneDX export generation |
| `cli.py` | Add `--format cyclonedx` and `--format bom` flags |
| `index.html` | Add CycloneDX export button |
| `app.js` | Handle CycloneDX download |

---

## Implementation Order

1. **Model Detection: Patterns & Identification** (2-3 hrs)
   - Create `models.py` with pattern matching
   - Test against sample configs

2. **Model Detection: Integration** (1-2 hrs)
   - Add model detection to scan pipeline
   - Add model field to MCP results

3. **Model Detection: CLI Output** (1 hr)
   - Add AI Models Summary section
   - Add model column to MCP table

4. **Model Detection: Web UI** (1-2 hrs)
   - Add AI Models tab/section
   - Display model inventory

5. **AI-BOM: CycloneDX Export** (2-3 hrs)
   - Create `cyclonedx.py` with schema generation
   - Map scan results to CycloneDX structure

6. **AI-BOM: CLI Integration** (30 min)
   - Add `--format cyclonedx` flag
   - Output file with `.cdx.json` extension

7. **AI-BOM: Web UI** (30 min)
   - Add CycloneDX button to export options

8. **Testing** (1-2 hrs)
   - Test model detection across various configs
   - Validate CycloneDX output against schema

**Total estimate:** 10-14 hours (~2 days)

---

## Definition of Done

### Model Detection
- [ ] Detects models from env vars (MODEL, OPENAI_MODEL, etc.)
- [ ] Identifies model name, provider, hosting type
- [ ] Handles versioned model IDs (gpt-4o-2024-08-06 → GPT-4o)
- [ ] Falls back to "Unknown" for unrecognized models
- [ ] AI Models Summary section in CLI output
- [ ] AI Models tab/section in Web UI
- [ ] Model included in JSON export
- [ ] Model included in PDF report

### AI-BOM Export
- [ ] `--format cyclonedx` flag works
- [ ] Output is valid CycloneDX 1.6 JSON
- [ ] Includes: metadata, components (MCPs + models), services (APIs), dependencies, vulnerabilities (secrets)
- [ ] Web UI has CycloneDX export button
- [ ] Helpful message about GRC/compliance use

---

## Positioning

With these features, the tool becomes:

> **APIsec MCP Audit: Build your AI-BOM**
> 
> Discover every MCP, the AI models they use, the APIs they call, and the secrets they expose. Export as CycloneDX for compliance.

This positions it as an **AI supply chain security tool**, not just an MCP scanner.
