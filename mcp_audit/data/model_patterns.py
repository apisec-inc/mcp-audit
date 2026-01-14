"""
AI Model Detection Patterns for MCP Audit

Detects AI models from MCP configuration environment variables and infers
provider/hosting information.
"""

from typing import Optional
from dataclasses import dataclass


@dataclass
class DetectedModel:
    """Represents a detected AI model"""
    model_id: str           # Original model string (e.g., "gpt-4o-2024-08-06")
    model_name: str         # Display name (e.g., "GPT-4o")
    provider: str           # Provider (e.g., "OpenAI", "Anthropic")
    hosting: str            # "cloud" or "local"
    source: str             # Where found (e.g., "env:OPENAI_MODEL")
    mcp_name: str = ""      # Which MCP uses this model

    def to_dict(self) -> dict:
        return {
            "model_id": self.model_id,
            "model_name": self.model_name,
            "provider": self.provider,
            "hosting": self.hosting,
            "source": self.source,
            "mcp_name": self.mcp_name,
        }


# Environment variable patterns that typically contain model names
MODEL_ENV_PATTERNS = [
    # Exact matches (case-insensitive)
    "MODEL",
    "MODEL_NAME",
    "MODEL_ID",
    "LLM_MODEL",
    "AI_MODEL",

    # Provider-specific
    "OPENAI_MODEL",
    "OPENAI_MODEL_NAME",
    "ANTHROPIC_MODEL",
    "CLAUDE_MODEL",
    "BEDROCK_MODEL_ID",
    "BEDROCK_MODEL",
    "AZURE_OPENAI_DEPLOYMENT",
    "AZURE_DEPLOYMENT_NAME",
    "AZURE_DEPLOYMENT",
    "OLLAMA_MODEL",
    "TOGETHER_MODEL",
    "GROQ_MODEL",
    "MISTRAL_MODEL",
    "COHERE_MODEL",
    "GOOGLE_MODEL",
    "GEMINI_MODEL",
    "VERTEX_MODEL",

    # Local model paths
    "MODEL_PATH",
    "GGUF_MODEL",
    "LLAMA_MODEL_PATH",
    "LLAMA_MODEL",
]

# Known model identifiers and their metadata
MODEL_IDENTIFIERS = {
    # OpenAI Models
    "gpt-4o": {"name": "GPT-4o", "provider": "OpenAI", "hosting": "cloud"},
    "gpt-4o-mini": {"name": "GPT-4o Mini", "provider": "OpenAI", "hosting": "cloud"},
    "gpt-4-turbo": {"name": "GPT-4 Turbo", "provider": "OpenAI", "hosting": "cloud"},
    "gpt-4": {"name": "GPT-4", "provider": "OpenAI", "hosting": "cloud"},
    "gpt-3.5-turbo": {"name": "GPT-3.5 Turbo", "provider": "OpenAI", "hosting": "cloud"},
    "gpt-3.5": {"name": "GPT-3.5", "provider": "OpenAI", "hosting": "cloud"},
    "o1": {"name": "o1", "provider": "OpenAI", "hosting": "cloud"},
    "o1-mini": {"name": "o1 Mini", "provider": "OpenAI", "hosting": "cloud"},
    "o1-preview": {"name": "o1 Preview", "provider": "OpenAI", "hosting": "cloud"},
    "o3-mini": {"name": "o3 Mini", "provider": "OpenAI", "hosting": "cloud"},
    "chatgpt": {"name": "ChatGPT", "provider": "OpenAI", "hosting": "cloud"},

    # Anthropic Models
    "claude-3-5-sonnet": {"name": "Claude 3.5 Sonnet", "provider": "Anthropic", "hosting": "cloud"},
    "claude-3.5-sonnet": {"name": "Claude 3.5 Sonnet", "provider": "Anthropic", "hosting": "cloud"},
    "claude-3-5-haiku": {"name": "Claude 3.5 Haiku", "provider": "Anthropic", "hosting": "cloud"},
    "claude-3.5-haiku": {"name": "Claude 3.5 Haiku", "provider": "Anthropic", "hosting": "cloud"},
    "claude-3-opus": {"name": "Claude 3 Opus", "provider": "Anthropic", "hosting": "cloud"},
    "claude-3-sonnet": {"name": "Claude 3 Sonnet", "provider": "Anthropic", "hosting": "cloud"},
    "claude-3-haiku": {"name": "Claude 3 Haiku", "provider": "Anthropic", "hosting": "cloud"},
    "claude-2": {"name": "Claude 2", "provider": "Anthropic", "hosting": "cloud"},
    "claude-instant": {"name": "Claude Instant", "provider": "Anthropic", "hosting": "cloud"},
    "claude": {"name": "Claude", "provider": "Anthropic", "hosting": "cloud"},

    # Meta Llama Models
    "llama-3.3": {"name": "Llama 3.3", "provider": "Meta", "hosting": "local"},
    "llama-3.2": {"name": "Llama 3.2", "provider": "Meta", "hosting": "local"},
    "llama-3.1": {"name": "Llama 3.1", "provider": "Meta", "hosting": "local"},
    "llama-3": {"name": "Llama 3", "provider": "Meta", "hosting": "local"},
    "llama3": {"name": "Llama 3", "provider": "Meta", "hosting": "local"},
    "llama-2": {"name": "Llama 2", "provider": "Meta", "hosting": "local"},
    "llama2": {"name": "Llama 2", "provider": "Meta", "hosting": "local"},
    "llama": {"name": "Llama", "provider": "Meta", "hosting": "local"},
    "codellama": {"name": "Code Llama", "provider": "Meta", "hosting": "local"},
    "code-llama": {"name": "Code Llama", "provider": "Meta", "hosting": "local"},

    # Mistral Models
    "mistral-large": {"name": "Mistral Large", "provider": "Mistral AI", "hosting": "cloud"},
    "mistral-medium": {"name": "Mistral Medium", "provider": "Mistral AI", "hosting": "cloud"},
    "mistral-small": {"name": "Mistral Small", "provider": "Mistral AI", "hosting": "cloud"},
    "mistral": {"name": "Mistral", "provider": "Mistral AI", "hosting": "local"},
    "mixtral": {"name": "Mixtral", "provider": "Mistral AI", "hosting": "local"},
    "codestral": {"name": "Codestral", "provider": "Mistral AI", "hosting": "cloud"},
    "pixtral": {"name": "Pixtral", "provider": "Mistral AI", "hosting": "cloud"},

    # Google Models
    "gemini-2.0": {"name": "Gemini 2.0", "provider": "Google", "hosting": "cloud"},
    "gemini-1.5-pro": {"name": "Gemini 1.5 Pro", "provider": "Google", "hosting": "cloud"},
    "gemini-1.5-flash": {"name": "Gemini 1.5 Flash", "provider": "Google", "hosting": "cloud"},
    "gemini-pro": {"name": "Gemini Pro", "provider": "Google", "hosting": "cloud"},
    "gemini-ultra": {"name": "Gemini Ultra", "provider": "Google", "hosting": "cloud"},
    "gemini": {"name": "Gemini", "provider": "Google", "hosting": "cloud"},
    "gemma-2": {"name": "Gemma 2", "provider": "Google", "hosting": "local"},
    "gemma": {"name": "Gemma", "provider": "Google", "hosting": "local"},
    "palm": {"name": "PaLM", "provider": "Google", "hosting": "cloud"},

    # Cohere Models
    "command-r-plus": {"name": "Command R+", "provider": "Cohere", "hosting": "cloud"},
    "command-r": {"name": "Command R", "provider": "Cohere", "hosting": "cloud"},
    "command": {"name": "Command", "provider": "Cohere", "hosting": "cloud"},
    "coral": {"name": "Coral", "provider": "Cohere", "hosting": "cloud"},

    # Microsoft Models
    "phi-4": {"name": "Phi-4", "provider": "Microsoft", "hosting": "local"},
    "phi-3": {"name": "Phi-3", "provider": "Microsoft", "hosting": "local"},
    "phi-2": {"name": "Phi-2", "provider": "Microsoft", "hosting": "local"},
    "phi": {"name": "Phi", "provider": "Microsoft", "hosting": "local"},

    # Other Cloud Models
    "deepseek-v3": {"name": "DeepSeek V3", "provider": "DeepSeek", "hosting": "cloud"},
    "deepseek-r1": {"name": "DeepSeek R1", "provider": "DeepSeek", "hosting": "cloud"},
    "deepseek": {"name": "DeepSeek", "provider": "DeepSeek", "hosting": "local"},
    "qwen-2.5": {"name": "Qwen 2.5", "provider": "Alibaba", "hosting": "local"},
    "qwen-2": {"name": "Qwen 2", "provider": "Alibaba", "hosting": "local"},
    "qwen": {"name": "Qwen", "provider": "Alibaba", "hosting": "local"},
    "yi-1.5": {"name": "Yi 1.5", "provider": "01.AI", "hosting": "local"},
    "yi": {"name": "Yi", "provider": "01.AI", "hosting": "local"},

    # Other Local Models
    "falcon": {"name": "Falcon", "provider": "TII", "hosting": "local"},
    "vicuna": {"name": "Vicuna", "provider": "LMSYS", "hosting": "local"},
    "openchat": {"name": "OpenChat", "provider": "OpenChat", "hosting": "local"},
    "neural-chat": {"name": "Neural Chat", "provider": "Intel", "hosting": "local"},
    "starling": {"name": "Starling", "provider": "Berkeley", "hosting": "local"},
    "zephyr": {"name": "Zephyr", "provider": "HuggingFace", "hosting": "local"},
    "solar": {"name": "Solar", "provider": "Upstage", "hosting": "local"},
    "nous-hermes": {"name": "Nous Hermes", "provider": "Nous Research", "hosting": "local"},
    "dolphin": {"name": "Dolphin", "provider": "Cognitive Computations", "hosting": "local"},
    "orca": {"name": "Orca", "provider": "Microsoft", "hosting": "local"},
    "wizard": {"name": "WizardLM", "provider": "WizardLM", "hosting": "local"},
    "starcoder": {"name": "StarCoder", "provider": "BigCode", "hosting": "local"},
    "codegen": {"name": "CodeGen", "provider": "Salesforce", "hosting": "local"},
}

# Cloud provider detection from API endpoints
CLOUD_PROVIDERS = {
    "api.openai.com": {"provider": "OpenAI", "hosting": "cloud"},
    "openai.azure.com": {"provider": "Azure OpenAI", "hosting": "cloud"},
    "api.anthropic.com": {"provider": "Anthropic", "hosting": "cloud"},
    "bedrock": {"provider": "AWS Bedrock", "hosting": "cloud"},
    "amazonaws.com": {"provider": "AWS", "hosting": "cloud"},
    "aiplatform.googleapis.com": {"provider": "Google Vertex AI", "hosting": "cloud"},
    "generativelanguage.googleapis.com": {"provider": "Google AI", "hosting": "cloud"},
    "api.mistral.ai": {"provider": "Mistral AI", "hosting": "cloud"},
    "api.cohere.ai": {"provider": "Cohere", "hosting": "cloud"},
    "api.together.xyz": {"provider": "Together AI", "hosting": "cloud"},
    "api.groq.com": {"provider": "Groq", "hosting": "cloud"},
    "api.deepseek.com": {"provider": "DeepSeek", "hosting": "cloud"},
    "api.fireworks.ai": {"provider": "Fireworks AI", "hosting": "cloud"},
    "api.replicate.com": {"provider": "Replicate", "hosting": "cloud"},
    "api.perplexity.ai": {"provider": "Perplexity", "hosting": "cloud"},
    "localhost": {"provider": "Local", "hosting": "local"},
    "127.0.0.1": {"provider": "Local", "hosting": "local"},
    "0.0.0.0": {"provider": "Local", "hosting": "local"},
}


def detect_model_from_config(env_vars: dict, apis: list = None, mcp_name: str = "") -> Optional[DetectedModel]:
    """
    Detect AI model from MCP configuration.

    Args:
        env_vars: Dictionary of environment variables from MCP config
        apis: List of detected API endpoints
        mcp_name: Name of the MCP

    Returns:
        DetectedModel if found, None otherwise
    """
    if not env_vars:
        return None

    # 1. Check explicit model env vars
    for env_key, env_value in env_vars.items():
        if not env_value or not isinstance(env_value, str):
            continue

        env_key_upper = env_key.upper()

        # Check if this env var matches model patterns
        for pattern in MODEL_ENV_PATTERNS:
            if pattern in env_key_upper or env_key_upper.endswith("_MODEL") or env_key_upper.endswith("_MODEL_ID"):
                model_info = identify_model(env_value)
                if model_info:
                    return DetectedModel(
                        model_id=env_value,
                        model_name=model_info["name"],
                        provider=model_info["provider"],
                        hosting=model_info["hosting"],
                        source=f"env:{env_key}",
                        mcp_name=mcp_name,
                    )
                break

    # 2. Infer from API endpoint if no explicit model found
    if apis:
        for api in apis:
            api_url = api.get("url", "") if isinstance(api, dict) else str(api)
            for endpoint_pattern, provider_info in CLOUD_PROVIDERS.items():
                if endpoint_pattern in api_url.lower():
                    # We found a known AI provider API but no model specified
                    # Return with provider info but unknown model
                    return DetectedModel(
                        model_id="unknown",
                        model_name=f"Unknown ({provider_info['provider']})",
                        provider=provider_info["provider"],
                        hosting=provider_info["hosting"],
                        source=f"api:{api_url}",
                        mcp_name=mcp_name,
                    )

    return None


def identify_model(model_string: str) -> Optional[dict]:
    """
    Match a model string to known models.
    Handles variations like 'gpt-4o-2024-08-06' → 'gpt-4o'

    Args:
        model_string: The model identifier string

    Returns:
        Dict with name, provider, hosting or None
    """
    if not model_string:
        return None

    model_lower = model_string.lower().strip()

    # Try exact match first
    if model_lower in MODEL_IDENTIFIERS:
        return MODEL_IDENTIFIERS[model_lower].copy()

    # Try prefix match (for versioned models like 'gpt-4o-2024-08-06')
    for pattern, info in MODEL_IDENTIFIERS.items():
        if model_lower.startswith(pattern):
            return info.copy()

    # Try contains match (for models like 'anthropic.claude-3-5-sonnet-20241022-v2:0')
    for pattern, info in MODEL_IDENTIFIERS.items():
        if pattern in model_lower:
            return info.copy()

    # Check for common patterns in unknown models
    if any(x in model_lower for x in ["llama", "lama"]):
        return {"name": model_string, "provider": "Meta", "hosting": "local"}
    if "mistral" in model_lower or "mixtral" in model_lower:
        return {"name": model_string, "provider": "Mistral AI", "hosting": "local"}
    if "claude" in model_lower:
        return {"name": model_string, "provider": "Anthropic", "hosting": "cloud"}
    if "gpt" in model_lower:
        return {"name": model_string, "provider": "OpenAI", "hosting": "cloud"}
    if "gemini" in model_lower or "gemma" in model_lower:
        return {"name": model_string, "provider": "Google", "hosting": "cloud"}
    if "qwen" in model_lower:
        return {"name": model_string, "provider": "Alibaba", "hosting": "local"}
    if "deepseek" in model_lower:
        return {"name": model_string, "provider": "DeepSeek", "hosting": "local"}

    # Unknown model - return generic info
    return {
        "name": model_string,
        "provider": "Unknown",
        "hosting": "unknown",
    }


def infer_provider_from_endpoint(endpoint: str) -> Optional[dict]:
    """
    Infer AI provider from API endpoint URL.

    Args:
        endpoint: API endpoint URL

    Returns:
        Dict with provider and hosting info or None
    """
    if not endpoint:
        return None

    endpoint_lower = endpoint.lower()

    for pattern, info in CLOUD_PROVIDERS.items():
        if pattern in endpoint_lower:
            return info.copy()

    return None
