"""
Risk level and risk flag definitions with remediation guidance.
All content is static and bundled with the tool.
"""

RISK_LEVELS = {
    "critical": {
        "definition": "MCP has capabilities that could lead to full system compromise if exploited.",
        "criteria": "Shell/command execution, root filesystem write access, or admin-level cloud credentials.",
        "remediation": "Remove unless absolutely required. If required, isolate in sandboxed environment and restrict to specific users.",
        "color": "red"
    },
    "high": {
        "definition": "MCP can access or modify sensitive data or systems.",
        "criteria": "Database access, cloud API access, filesystem write access, or credentials in config.",
        "remediation": "Restrict permissions to minimum required. Rotate any exposed credentials. Review access regularly.",
        "color": "orange"
    },
    "medium": {
        "definition": "MCP has elevated access but limited blast radius.",
        "criteria": "Third-party SaaS API access, read-only filesystem access, or network access.",
        "remediation": "Verify MCP is from trusted source. Ensure credentials are scoped to minimum required permissions.",
        "color": "yellow"
    },
    "low": {
        "definition": "MCP has minimal system access.",
        "criteria": "Read-only access to non-sensitive data or public APIs.",
        "remediation": "Verify MCP is from trusted source. No immediate action required.",
        "color": "green"
    },
    "unknown": {
        "definition": "Risk level could not be determined.",
        "criteria": "MCP not found in registry or insufficient information to assess.",
        "remediation": "Review MCP source code and capabilities manually before use.",
        "color": "gray"
    }
}

RISK_FLAGS = {
    "shell-access": {
        "explanation": "This MCP can execute shell commands on the host system. An attacker exploiting prompt injection could run arbitrary commands.",
        "remediation": "Remove shell access MCP unless absolutely required. If needed, restrict to specific allowed commands using a wrapper.",
        "severity": "critical",
        "detailed_steps": [
            "Remove shell access MCP unless absolutely required for your workflow.",
            "If shell access is required, create a wrapper that restricts execution to a specific allowlist of commands.",
            "Run the MCP in an isolated container or sandbox environment.",
            "Monitor and log all shell commands executed through the MCP."
        ],
        "related": ["filesystem-write", "admin-credentials"]
    },
    "filesystem-access": {
        "explanation": "This MCP can read and/or write files on the host system. Could leak sensitive files or modify system configuration.",
        "remediation": "Restrict to specific directories. Use read-only mode if writes are not required. Never allow access to home directory or system paths.",
        "severity": "high",
        "detailed_steps": [
            "Restrict filesystem access to specific directories only.",
            "Use read-only mode if write access is not required.",
            "Never allow access to home directory (~), system paths (/etc, /usr), or sensitive directories (.ssh, .aws).",
            "Consider using a sandboxed directory for MCP file operations."
        ],
        "related": ["filesystem-write", "shell-access"]
    },
    "filesystem-write": {
        "explanation": "This MCP can write files to the host system. Could be used to modify configs, drop malware, or corrupt data.",
        "remediation": "Remove write access unless absolutely required. Restrict to a specific sandboxed directory.",
        "severity": "critical",
        "detailed_steps": [
            "Remove filesystem write access unless absolutely required.",
            "Restrict write access to a specific sandboxed directory.",
            "Implement file type restrictions (e.g., only allow .txt, .json).",
            "Monitor for unexpected file creation or modification."
        ],
        "related": ["filesystem-access", "shell-access"]
    },
    "database-access": {
        "explanation": "This MCP can query or modify database contents. Could leak sensitive data or corrupt records.",
        "remediation": "Use read-only database credentials. Restrict to specific tables/schemas. Never use admin credentials.",
        "severity": "high",
        "detailed_steps": [
            "Use read-only database credentials if writes are not required.",
            "Restrict access to specific tables or schemas only.",
            "Never use admin or superuser credentials.",
            "Create a dedicated database user with minimum required permissions.",
            "Enable query logging for audit purposes."
        ],
        "related": ["secrets-detected", "admin-credentials"]
    },
    "network-access": {
        "explanation": "This MCP can make outbound network requests. Could be used for SSRF attacks or data exfiltration.",
        "remediation": "Restrict to specific allowed domains/IPs. Monitor outbound traffic for anomalies.",
        "severity": "medium",
        "detailed_steps": [
            "Restrict network access to specific allowed domains or IP addresses.",
            "Use a proxy or firewall to monitor and filter outbound requests.",
            "Block access to internal network ranges (10.x.x.x, 192.168.x.x, etc.).",
            "Monitor for unusual data transfer patterns."
        ],
        "related": ["secrets-detected"]
    },
    "secrets-detected": {
        "explanation": "API keys, tokens, or passwords are visible in the MCP configuration file.",
        "remediation": "Immediately rotate the exposed credential. Move secrets to environment variables or a secrets manager. Never commit credentials to config files.",
        "severity": "critical",
        "detailed_steps": [
            "IMMEDIATELY rotate the exposed credential.",
            "Move secrets to environment variables or a secrets manager.",
            "Update the MCP configuration to reference environment variables.",
            "Never commit credentials to configuration files.",
            "Review git history for any previously committed secrets."
        ],
        "related": ["admin-credentials"]
    },
    "secrets-in-env": {
        "explanation": "Environment variables in config appear to contain sensitive credentials.",
        "remediation": "Rotate credentials if exposed. Use a secrets manager instead of plain environment variables where possible.",
        "severity": "high",
        "detailed_steps": [
            "Verify that environment variables are not logged or exposed.",
            "Consider using a secrets manager for sensitive credentials.",
            "Ensure config files with env references are not committed to version control.",
            "Rotate any credentials that may have been exposed."
        ],
        "related": ["secrets-detected"]
    },
    "unverified-source": {
        "explanation": "This MCP is not from a known/verified publisher. Its behavior and security posture are unknown.",
        "remediation": "Review the MCP source code before use. Prefer official or verified MCPs when available. If custom, ensure security review.",
        "severity": "medium",
        "detailed_steps": [
            "Review the MCP source code before deployment.",
            "Check for known vulnerabilities or security issues.",
            "Prefer official or verified MCPs from trusted publishers.",
            "If using a custom MCP, ensure it undergoes security review.",
            "Consider running unverified MCPs in an isolated environment."
        ],
        "related": ["local-binary"]
    },
    "local-binary": {
        "explanation": "This MCP runs a local binary or script. Its behavior is determined by the local file, which may have been modified.",
        "remediation": "Verify the integrity of the local binary. Use checksums or signatures where possible. Ensure the binary has not been tampered with.",
        "severity": "medium",
        "detailed_steps": [
            "Verify the integrity of the local binary using checksums.",
            "Ensure the binary has not been modified since deployment.",
            "Store binaries in a protected directory with restricted write access.",
            "Consider code-signing for internal MCP binaries.",
            "Review the source code if available."
        ],
        "related": ["unverified-source"]
    },
    "inferred-capability": {
        "explanation": "This capability was detected from code patterns, not explicitly declared. Actual behavior may differ.",
        "remediation": "Review MCP source code to confirm actual capabilities. Treat inferred capabilities as potential risks.",
        "severity": "low",
        "detailed_steps": [
            "Review the MCP source code to confirm actual capabilities.",
            "Test the MCP in a sandbox to verify behavior.",
            "Treat inferred capabilities as potential risks until confirmed."
        ],
        "related": []
    },
    "admin-credentials": {
        "explanation": "MCP is configured with admin-level credentials, granting excessive permissions.",
        "remediation": "Replace with scoped credentials that have minimum required permissions. Create a dedicated service account.",
        "severity": "critical",
        "detailed_steps": [
            "Create a dedicated service account with minimum required permissions.",
            "Replace admin credentials with scoped credentials.",
            "Document the specific permissions required by the MCP.",
            "Implement credential rotation on a regular schedule.",
            "Enable audit logging for the service account."
        ],
        "related": ["secrets-detected", "database-access"]
    },
    "duplicate-capability": {
        "explanation": "Multiple MCPs provide the same capability, expanding attack surface unnecessarily.",
        "remediation": "Remove duplicate MCPs. Consolidate to a single, trusted MCP for each capability.",
        "severity": "low",
        "detailed_steps": [
            "Identify all MCPs providing the same capability.",
            "Choose the most trusted and well-maintained MCP.",
            "Remove duplicate MCPs to reduce attack surface.",
            "Document which MCP is approved for each capability."
        ],
        "related": []
    },
    "remote-mcp": {
        "explanation": "This MCP connects to a remote server via URL. Network availability and server security affect reliability.",
        "remediation": "Verify the remote server is trusted and secure. Use HTTPS only. Consider fallback behavior if server is unavailable.",
        "severity": "medium",
        "detailed_steps": [
            "Verify the remote server is from a trusted source.",
            "Ensure HTTPS is used for all connections.",
            "Validate SSL/TLS certificates.",
            "Consider what happens if the remote server is unavailable.",
            "Monitor for unexpected changes in server behavior."
        ],
        "related": ["network-access"]
    }
}


def get_risk_level_info(level: str) -> dict:
    """Get information about a risk level."""
    return RISK_LEVELS.get(level.lower(), RISK_LEVELS["unknown"])


def get_risk_flag_info(flag: str) -> dict:
    """Get information about a risk flag."""
    return RISK_FLAGS.get(flag, {
        "explanation": f"Unknown risk flag: {flag}",
        "remediation": "Review MCP configuration and capabilities manually.",
        "severity": "unknown",
        "detailed_steps": [],
        "related": []
    })


def get_severity_for_flag(flag: str) -> str:
    """Get the severity level for a risk flag."""
    info = RISK_FLAGS.get(flag, {})
    return info.get("severity", "unknown")


def get_all_flags() -> list[str]:
    """Get list of all known risk flags."""
    return list(RISK_FLAGS.keys())


def get_flags_by_severity(severity: str) -> list[str]:
    """Get all flags of a specific severity."""
    return [flag for flag, info in RISK_FLAGS.items() if info.get("severity") == severity]
