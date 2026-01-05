"""
Secret detection patterns for MCP configurations.

This module contains regex patterns for detecting exposed secrets,
along with metadata for classification and remediation guidance.
"""

import re

# Patterns to skip - common placeholders that aren't real secrets
PLACEHOLDER_PATTERNS = [
    r"^xxx+$",
    r"^your[_-]?(api[_-]?key|token|secret|password).*$",
    r"^changeme$",
    r"^replace[_-]?me$",
    r"^todo$",
    r"^fixme$",
    r"^example$",
    r"^test$",
    r"^dummy$",
    r"^fake$",
    r"^\*+$",
    r"^<.*>$",      # <your-api-key>
    r"^\[.*\]$",    # [your-api-key]
    r"^\{.*\}$",    # {your-api-key}
    r"^sk_test_",   # Stripe test keys are lower risk
    r"^pk_test_",   # Stripe test public keys
]

# Secret detection patterns
SECRET_PATTERNS = {
    # AWS
    "aws_access_key": {
        "pattern": r"AKIA[0-9A-Z]{16}",
        "description": "AWS Access Key ID",
        "severity": "critical",
        "rotation_url": "https://console.aws.amazon.com/iam/home#/security_credentials"
    },
    "aws_secret_key": {
        "pattern": r"(?<![A-Za-z0-9/+=])[0-9a-zA-Z/+]{40}(?![A-Za-z0-9/+=])",
        "context_keys": ["AWS_SECRET", "SECRET_KEY", "SECRET_ACCESS"],
        "description": "AWS Secret Access Key",
        "severity": "critical",
        "rotation_url": "https://console.aws.amazon.com/iam/home#/security_credentials",
        "requires_context": True
    },

    # GitHub
    "github_pat": {
        "pattern": r"ghp_[0-9a-zA-Z]{36}",
        "description": "GitHub Personal Access Token",
        "severity": "critical",
        "rotation_url": "https://github.com/settings/tokens"
    },
    "github_oauth": {
        "pattern": r"gho_[0-9a-zA-Z]{36}",
        "description": "GitHub OAuth Access Token",
        "severity": "critical",
        "rotation_url": "https://github.com/settings/tokens"
    },
    "github_app": {
        "pattern": r"gh[us]_[0-9a-zA-Z]{36}",
        "description": "GitHub App Token",
        "severity": "critical",
        "rotation_url": "https://github.com/settings/apps"
    },

    # Stripe
    "stripe_live": {
        "pattern": r"sk_live_[0-9a-zA-Z]{24,}",
        "description": "Stripe Live Secret Key",
        "severity": "critical",
        "rotation_url": "https://dashboard.stripe.com/apikeys"
    },
    "stripe_restricted": {
        "pattern": r"rk_live_[0-9a-zA-Z]{24,}",
        "description": "Stripe Restricted API Key",
        "severity": "high",
        "rotation_url": "https://dashboard.stripe.com/apikeys"
    },

    # Slack
    "slack_token": {
        "pattern": r"xox[baprs]-[0-9a-zA-Z-]{10,}",
        "description": "Slack Token",
        "severity": "high",
        "rotation_url": "https://api.slack.com/apps"
    },
    "slack_webhook": {
        "pattern": r"https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9a-zA-Z]+",
        "description": "Slack Webhook URL",
        "severity": "medium",
        "rotation_url": "https://api.slack.com/apps"
    },

    # OpenAI
    "openai_key": {
        "pattern": r"sk-[0-9a-zA-Z]{48}",
        "description": "OpenAI API Key",
        "severity": "high",
        "rotation_url": "https://platform.openai.com/api-keys"
    },
    "openai_project_key": {
        "pattern": r"sk-proj-[0-9a-zA-Z_-]{40,}",
        "description": "OpenAI Project API Key",
        "severity": "high",
        "rotation_url": "https://platform.openai.com/api-keys"
    },

    # Anthropic
    "anthropic_key": {
        "pattern": r"sk-ant-[0-9a-zA-Z-]{40,}",
        "description": "Anthropic API Key",
        "severity": "high",
        "rotation_url": "https://console.anthropic.com/settings/keys"
    },

    # Google
    "google_api_key": {
        "pattern": r"AIza[0-9A-Za-z-_]{35}",
        "description": "Google API Key",
        "severity": "high",
        "rotation_url": "https://console.cloud.google.com/apis/credentials"
    },
    "google_oauth": {
        "pattern": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
        "description": "Google OAuth Client ID",
        "severity": "medium",
        "rotation_url": "https://console.cloud.google.com/apis/credentials"
    },

    # Salesforce
    "salesforce_token": {
        "pattern": r"[0-9A-Za-z]{24,}",
        "context_keys": ["SF_ACCESS_TOKEN", "SALESFORCE_TOKEN", "SFDC_TOKEN", "SF_TOKEN"],
        "description": "Salesforce Access Token",
        "severity": "high",
        "rotation_url": "https://help.salesforce.com/s/articleView?id=sf.user_security_token.htm",
        "requires_context": True
    },

    # Database connection strings
    "postgres_conn": {
        "pattern": r"postgres(?:ql)?://[^:]+:[^@]+@[^/]+/\w+",
        "description": "PostgreSQL Connection String with Credentials",
        "severity": "critical",
        "rotation_url": None
    },
    "mysql_conn": {
        "pattern": r"mysql://[^:]+:[^@]+@[^/]+/\w+",
        "description": "MySQL Connection String with Credentials",
        "severity": "critical",
        "rotation_url": None
    },
    "mongodb_conn": {
        "pattern": r"mongodb(?:\+srv)?://[^:]+:[^@]+@",
        "description": "MongoDB Connection String with Credentials",
        "severity": "critical",
        "rotation_url": None
    },
    "redis_conn": {
        "pattern": r"redis://[^:]+:[^@]+@",
        "description": "Redis Connection String with Credentials",
        "severity": "high",
        "rotation_url": None
    },

    # Private keys
    "private_key": {
        "pattern": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
        "description": "Private Key",
        "severity": "critical",
        "rotation_url": None
    },

    # SendGrid
    "sendgrid_key": {
        "pattern": r"SG\.[0-9A-Za-z-_]{22}\.[0-9A-Za-z-_]{43}",
        "description": "SendGrid API Key",
        "severity": "high",
        "rotation_url": "https://app.sendgrid.com/settings/api_keys"
    },

    # Twilio
    "twilio_key": {
        "pattern": r"SK[0-9a-fA-F]{32}",
        "description": "Twilio API Key",
        "severity": "high",
        "rotation_url": "https://www.twilio.com/console/project/api-keys"
    },

    # Mailchimp
    "mailchimp_key": {
        "pattern": r"[0-9a-f]{32}-us[0-9]{1,2}",
        "description": "Mailchimp API Key",
        "severity": "medium",
        "rotation_url": "https://admin.mailchimp.com/account/api/"
    },

    # Discord
    "discord_token": {
        "pattern": r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}",
        "description": "Discord Bot Token",
        "severity": "high",
        "rotation_url": "https://discord.com/developers/applications"
    },
    "discord_webhook": {
        "pattern": r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+",
        "description": "Discord Webhook URL",
        "severity": "medium",
        "rotation_url": None
    },

    # NPM
    "npm_token": {
        "pattern": r"npm_[A-Za-z0-9]{36}",
        "description": "NPM Access Token",
        "severity": "high",
        "rotation_url": "https://www.npmjs.com/settings/tokens"
    },

    # PyPI
    "pypi_token": {
        "pattern": r"pypi-[A-Za-z0-9_-]{50,}",
        "description": "PyPI API Token",
        "severity": "high",
        "rotation_url": "https://pypi.org/manage/account/token/"
    },

    # Heroku
    "heroku_key": {
        "pattern": r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        "context_keys": ["HEROKU_API_KEY", "HEROKU_TOKEN"],
        "description": "Heroku API Key",
        "severity": "high",
        "rotation_url": "https://dashboard.heroku.com/account",
        "requires_context": True
    },

    # Generic patterns (lower confidence, need context)
    "generic_api_key": {
        "pattern": r"[0-9a-zA-Z]{32,}",
        "context_keys": ["API_KEY", "APIKEY", "API_SECRET", "SECRET_KEY", "ACCESS_KEY"],
        "description": "Potential API Key",
        "severity": "medium",
        "requires_context": True
    },
    "generic_password": {
        "pattern": r".{8,}",
        "context_keys": ["PASSWORD", "PASSWD", "PWD", "DB_PASS", "DB_PASSWORD"],
        "description": "Password",
        "severity": "high",
        "requires_context": True
    },
    "generic_token": {
        "pattern": r"[0-9a-zA-Z_-]{20,}",
        "context_keys": ["TOKEN", "AUTH_TOKEN", "ACCESS_TOKEN", "BEARER", "JWT"],
        "description": "Authentication Token",
        "severity": "high",
        "requires_context": True
    },
}


def is_placeholder(value: str) -> bool:
    """Check if a value is a common placeholder that shouldn't be flagged."""
    value_lower = value.lower().strip()
    for pattern in PLACEHOLDER_PATTERNS:
        if re.match(pattern, value_lower, re.IGNORECASE):
            return True
    return False


def mask_secret(value: str) -> str:
    """
    Mask a secret value for safe display.
    Shows first 4 and last 4 characters only.
    """
    if len(value) <= 12:
        return value[:2] + "*" * (len(value) - 4) + value[-2:] if len(value) > 4 else "*" * len(value)
    return value[:4] + "*" * 8 + value[-4:]


def detect_secrets(env_dict: dict, config_path: str = None, mcp_name: str = None) -> list:
    """
    Detect secrets in MCP environment variables.

    Args:
        env_dict: Dictionary of environment variables from MCP config
        config_path: Path to the config file (for reporting)
        mcp_name: Name of the MCP server (for reporting)

    Returns:
        List of detected secrets with metadata
    """
    secrets = []

    if not env_dict or not isinstance(env_dict, dict):
        return secrets

    for key, value in env_dict.items():
        if not isinstance(value, str):
            continue

        # Skip empty or very short values
        if len(value) < 8:
            continue

        # Skip placeholders
        if is_placeholder(value):
            continue

        # Skip environment variable references
        if value.startswith("$") or value.startswith("${"):
            continue

        for secret_type, config in SECRET_PATTERNS.items():
            pattern = config["pattern"]
            context_keys = config.get("context_keys", [])
            requires_context = config.get("requires_context", False)

            # Check if pattern matches
            try:
                match = re.search(pattern, value)
            except re.error:
                continue

            if not match:
                continue

            # For generic patterns, require key context
            if requires_context:
                key_upper = key.upper()
                key_matches_context = any(
                    ctx.upper() in key_upper
                    for ctx in context_keys
                )
                if not key_matches_context:
                    continue

            # Calculate confidence
            confidence = "high"
            if requires_context:
                confidence = "medium"
            if secret_type.startswith("generic_"):
                confidence = "medium"

            secrets.append({
                "type": secret_type,
                "description": config["description"],
                "severity": config["severity"],
                "env_key": key,
                "value_masked": mask_secret(value),
                "value_length": len(value),
                "confidence": confidence,
                "rotation_url": config.get("rotation_url"),
                "config_path": config_path,
                "mcp_name": mcp_name
            })

            # Don't double-count same value with multiple patterns
            break

    return secrets
