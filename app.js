/**
 * MCP Audit - GitHub Organization Scanner
 *
 * All scanning happens in the browser. No PII is collected.
 * Anonymous usage analytics are sent to help improve the product.
 */

// Analytics endpoint
const ANALYTICS_URL = 'https://script.google.com/macros/s/AKfycbxJ9-VwHe4455XkRElauSC8pWx65q-1OgKWQJNZnafBkfFjbvmOM6qvp07RMwUm0Qml/exec';

// Send analytics event (fire and forget, non-blocking)
function trackEvent(eventData) {
    try {
        // Use GET with query params (more reliable with Google Apps Script CORS)
        const params = new URLSearchParams(eventData).toString();
        fetch(`${ANALYTICS_URL}?${params}`, {
            method: 'GET',
            mode: 'no-cors'
        }).catch(() => {}); // Silently ignore errors
    } catch (e) {
        // Ignore analytics errors - don't affect user experience
    }
}

// State
let githubToken = '';
let scanResults = [];
let isDemoMode = false;

// DOM Elements
const connectSection = document.getElementById('connect-section');
const orgSection = document.getElementById('org-section');
const progressSection = document.getElementById('progress-section');
const resultsSection = document.getElementById('results-section');
const noResultsSection = document.getElementById('no-results-section');
const sourceTiles = document.getElementById('source-tiles');
const githubSection = document.getElementById('github-section');

const tokenInput = document.getElementById('github-token');
const connectBtn = document.getElementById('connect-btn');
const connectStatus = document.getElementById('connect-status');

const orgSelect = document.getElementById('org-select');
const scanBtn = document.getElementById('scan-btn');

const progressFill = document.getElementById('progress-fill');
const progressText = document.getElementById('progress-text');
const scanLog = document.getElementById('scan-log');

const summary = document.getElementById('summary');
const resultsBody = document.getElementById('results-body');

// MCP Detection Patterns
const MCP_SEARCH_PATTERNS = [
    { query: 'filename:mcp.json', type: 'config' },
    { query: 'filename:mcp.yaml', type: 'config' },
    { query: 'path:.mcp', type: 'config' },
    { query: '"mcpServers" extension:json', type: 'config' },
    { query: '@modelcontextprotocol filename:package.json', type: 'dependency' },
    { query: '"mcp-server" filename:package.json', type: 'dependency' },
    { query: '@anthropic/mcp filename:package.json', type: 'dependency' },
    { query: 'fastmcp filename:requirements.txt', type: 'dependency' },
    { query: 'modelcontextprotocol filename:requirements.txt', type: 'dependency' },
];

const VERIFIED_PUBLISHERS = [
    '@anthropic/',
    '@modelcontextprotocol/',
    '@openai/',
];

// Known MCP Registry for client-side matching (with descriptions)
const KNOWN_MCPS = {
    // Official Anthropic MCPs
    "@anthropic/mcp-server-filesystem": { provider: "Anthropic", type: "official", risk_level: "high", verified: true, description: "Read and write files on the local filesystem" },
    "@anthropic/mcp-server-git": { provider: "Anthropic", type: "official", risk_level: "medium", verified: true, description: "Git repository operations (clone, commit, push, pull)" },
    "@anthropic/mcp-server-github": { provider: "Anthropic", type: "official", risk_level: "medium", verified: true, description: "GitHub API access for repos, issues, and PRs" },
    "@anthropic/mcp-server-memory": { provider: "Anthropic", type: "official", risk_level: "low", verified: true, description: "Persistent memory storage for AI conversations" },
    "@anthropic/mcp-server-puppeteer": { provider: "Anthropic", type: "official", risk_level: "high", verified: true, description: "Browser automation and web scraping via Puppeteer" },
    "@anthropic/mcp-server-fetch": { provider: "Anthropic", type: "official", risk_level: "medium", verified: true, description: "Fetch and retrieve content from URLs" },
    "@anthropic/mcp-server-sqlite": { provider: "Anthropic", type: "official", risk_level: "high", verified: true, description: "SQLite database read/write operations" },
    "@anthropic/mcp-server-postgres": { provider: "Anthropic", type: "official", risk_level: "critical", verified: true, description: "PostgreSQL database access and query execution" },
    "@anthropic/mcp-server-slack": { provider: "Anthropic", type: "official", risk_level: "medium", verified: true, description: "Slack messaging - read/write messages and channels" },
    "@anthropic/mcp-server-google-drive": { provider: "Anthropic", type: "official", risk_level: "high", verified: true, description: "Google Drive file access and management" },
    "@anthropic/mcp-server-brave-search": { provider: "Anthropic", type: "official", risk_level: "low", verified: true, description: "Web search via Brave Search API" },
    "@anthropic/mcp-server-everart": { provider: "Anthropic", type: "official", risk_level: "low", verified: true, description: "AI image generation capabilities" },
    "@anthropic/mcp-server-sequential-thinking": { provider: "Anthropic", type: "official", risk_level: "low", verified: true, description: "Enhanced reasoning and step-by-step thinking" },
    "@anthropic/mcp-server-aws-kb-retrieval": { provider: "Anthropic", type: "official", risk_level: "medium", verified: true, description: "AWS Knowledge Base retrieval for RAG" },
    // ModelContextProtocol official
    "@modelcontextprotocol/server-filesystem": { provider: "MCP", type: "official", risk_level: "high", verified: true, description: "Read and write files on the local filesystem" },
    "@modelcontextprotocol/server-github": { provider: "MCP", type: "official", risk_level: "medium", verified: true, description: "GitHub API access for repos, issues, and PRs" },
    "@modelcontextprotocol/server-slack": { provider: "MCP", type: "official", risk_level: "medium", verified: true, description: "Slack messaging - read/write messages and channels" },
    "@modelcontextprotocol/server-postgres": { provider: "MCP", type: "official", risk_level: "critical", verified: true, description: "PostgreSQL database access and query execution" },
    "@modelcontextprotocol/server-memory": { provider: "MCP", type: "official", risk_level: "low", verified: true, description: "Persistent memory storage for AI conversations" },
    "@modelcontextprotocol/server-puppeteer": { provider: "MCP", type: "official", risk_level: "high", verified: true, description: "Browser automation and web scraping via Puppeteer" },
    "@modelcontextprotocol/server-brave-search": { provider: "MCP", type: "official", risk_level: "low", verified: true, description: "Web search via Brave Search API" },
    "@modelcontextprotocol/server-google-maps": { provider: "MCP", type: "official", risk_level: "low", verified: true, description: "Google Maps location and directions API" },
    "@modelcontextprotocol/server-fetch": { provider: "MCP", type: "official", risk_level: "medium", verified: true, description: "Fetch and retrieve content from URLs" },
    "@modelcontextprotocol/sdk": { provider: "MCP", type: "official", risk_level: "low", verified: true, description: "Core SDK for building MCP servers" },
    // Vendor MCPs
    "@stripe/mcp-server": { provider: "Stripe", type: "vendor", risk_level: "critical", verified: true, description: "Stripe payment processing and financial operations" },
    "@supabase/mcp-server": { provider: "Supabase", type: "vendor", risk_level: "high", verified: true, description: "Supabase database and auth operations" },
    "@cloudflare/mcp-server": { provider: "Cloudflare", type: "vendor", risk_level: "medium", verified: true, description: "Cloudflare CDN and edge services management" },
    "@sentry/mcp-server": { provider: "Sentry", type: "vendor", risk_level: "medium", verified: true, description: "Sentry error tracking and monitoring" },
    "@datadog/mcp-server": { provider: "Datadog", type: "vendor", risk_level: "medium", verified: true, description: "Datadog monitoring and observability" },
    "@atlassian/mcp-server-jira": { provider: "Atlassian", type: "vendor", risk_level: "medium", verified: true, description: "Jira issue tracking and project management" },
    "@atlassian/mcp-server-confluence": { provider: "Atlassian", type: "vendor", risk_level: "medium", verified: true, description: "Confluence wiki and documentation access" },
    "@vercel/mcp-server": { provider: "Vercel", type: "vendor", risk_level: "medium", verified: true, description: "Vercel deployment and hosting management" },
    "@linear/mcp-server": { provider: "Linear", type: "vendor", risk_level: "medium", verified: true, description: "Linear issue tracking and project management" },
    "@notion/mcp-server": { provider: "Notion", type: "vendor", risk_level: "medium", verified: true, description: "Notion workspace and page management" },
    "@asana/mcp-server": { provider: "Asana", type: "vendor", risk_level: "medium", verified: true, description: "Asana task and project management" },
    // Community MCPs
    "mcp-server-kubernetes": { provider: "Community", type: "community", risk_level: "critical", verified: false, description: "Kubernetes cluster management and deployments" },
    "mcp-server-docker": { provider: "Community", type: "community", risk_level: "critical", verified: false, description: "Docker container management and orchestration" },
    "mcp-server-shell": { provider: "Community", type: "community", risk_level: "critical", verified: false, description: "Execute shell commands on the host system" },
    "mcp-server-mysql": { provider: "Community", type: "community", risk_level: "critical", verified: false, description: "MySQL database access and query execution" },
    "mcp-server-mongodb": { provider: "Community", type: "community", risk_level: "critical", verified: false, description: "MongoDB database access and operations" },
    "mcp-server-redis": { provider: "Community", type: "community", risk_level: "high", verified: false, description: "Redis cache and data store operations" },
    "mcp-server-elasticsearch": { provider: "Community", type: "community", risk_level: "high", verified: false, description: "Elasticsearch search and analytics" },
    "mcp-server-aws": { provider: "Community", type: "community", risk_level: "critical", verified: false, description: "AWS cloud services management" },
    "mcp-server-azure": { provider: "Community", type: "community", risk_level: "critical", verified: false, description: "Azure cloud services management" },
    "mcp-server-gcp": { provider: "Community", type: "community", risk_level: "critical", verified: false, description: "Google Cloud Platform services management" },
    "mcp-server-terraform": { provider: "Community", type: "community", risk_level: "critical", verified: false, description: "Infrastructure as Code deployments" },
    "fastmcp": { provider: "Community", type: "community", risk_level: "medium", verified: false, description: "Python framework for building MCP servers" },
    "mcp-server-http": { provider: "Community", type: "community", risk_level: "high", verified: false, description: "HTTP client for external API requests" },
    "mcp-server-graphql": { provider: "Community", type: "community", risk_level: "high", verified: false, description: "GraphQL API query execution" },
    "mcp-server-openapi": { provider: "Community", type: "community", risk_level: "medium", verified: false, description: "OpenAPI/Swagger spec integration" },
    "mcp-server-browser": { provider: "Community", type: "community", risk_level: "high", verified: false, description: "Browser automation and control" },
    "mcp-server-playwright": { provider: "Community", type: "community", risk_level: "high", verified: false, description: "Browser automation via Playwright" },
    "mcp-server-email": { provider: "Community", type: "community", risk_level: "high", verified: false, description: "Email sending and inbox access" },
    "mcp-server-calendar": { provider: "Community", type: "community", risk_level: "medium", verified: false, description: "Calendar event management" },
    "mcp-server-twitter": { provider: "Community", type: "community", risk_level: "medium", verified: false, description: "Twitter/X API access and posting" },
    "mcp-server-discord": { provider: "Community", type: "community", risk_level: "medium", verified: false, description: "Discord bot and messaging" },
    "mcp-server-llm": { provider: "Community", type: "community", risk_level: "medium", verified: false, description: "LLM/AI model API access" },
    "mcp-server-vector-db": { provider: "Community", type: "community", risk_level: "high", verified: false, description: "Vector database for embeddings" },
    "mcp-server-pinecone": { provider: "Community", type: "community", risk_level: "high", verified: false, description: "Pinecone vector database access" },
    "mcp-server-weaviate": { provider: "Community", type: "community", risk_level: "high", verified: false, description: "Weaviate vector database access" },
    "mcp-server-github": { provider: "Community", type: "community", risk_level: "medium", verified: false, description: "GitHub API access (community version)" },
    "mcp-shell-tools": { provider: "Community", type: "community", risk_level: "critical", verified: false, description: "Shell command execution tools" },
    "modelcontextprotocol": { provider: "MCP", type: "official", risk_level: "low", verified: true, description: "Core MCP Python library" },
};

// Risk Level Definitions for tooltips and remediation
const RISK_LEVELS = {
    "critical": {
        definition: "MCP has capabilities that could lead to full system compromise if exploited.",
        criteria: "Shell/command execution, root filesystem write access, or admin-level cloud credentials.",
        remediation: "Remove unless absolutely required. If required, isolate in sandboxed environment.",
    },
    "high": {
        definition: "MCP can access or modify sensitive data or systems.",
        criteria: "Database access, cloud API access, filesystem write access, or credentials in config.",
        remediation: "Restrict permissions to minimum required. Rotate any exposed credentials.",
    },
    "medium": {
        definition: "MCP has elevated access but limited blast radius.",
        criteria: "Third-party SaaS API access, read-only filesystem access, or network access.",
        remediation: "Verify MCP is from trusted source. Ensure credentials are scoped appropriately.",
    },
    "low": {
        definition: "MCP has minimal system access.",
        criteria: "Read-only access to non-sensitive data or public APIs.",
        remediation: "Verify MCP is from trusted source. No immediate action required.",
    },
    "unknown": {
        definition: "Risk level could not be determined.",
        criteria: "MCP not found in registry or insufficient information to assess.",
        remediation: "Review MCP source code and capabilities manually before use.",
    }
};

// Risk Flag Definitions for tooltips and remediation
const RISK_FLAGS = {
    "shell-access": {
        explanation: "This MCP can execute shell commands on the host system. An attacker exploiting prompt injection could run arbitrary commands.",
        remediation: "Remove shell access MCP unless absolutely required. If needed, restrict to specific allowed commands.",
        severity: "critical"
    },
    "filesystem-access": {
        explanation: "This MCP can read and/or write files on the host system. Could leak sensitive files or modify system configuration.",
        remediation: "Restrict to specific directories. Use read-only mode if writes not required.",
        severity: "high"
    },
    "database-access": {
        explanation: "This MCP can query or modify database contents. Could leak sensitive data or corrupt records.",
        remediation: "Use read-only credentials. Restrict to specific tables/schemas. Never use admin credentials.",
        severity: "high"
    },
    "network-access": {
        explanation: "This MCP can make outbound network requests. Could be used for data exfiltration.",
        remediation: "Restrict to specific allowed domains/IPs. Monitor outbound traffic.",
        severity: "medium"
    },
    "secrets-detected": {
        explanation: "API keys, tokens, or passwords are visible in the MCP configuration file.",
        remediation: "IMMEDIATELY rotate the exposed credential. Move secrets to environment variables.",
        severity: "critical"
    },
    "secrets-in-env": {
        explanation: "Environment variables in config appear to contain sensitive credentials.",
        remediation: "Rotate credentials if exposed. Use a secrets manager where possible.",
        severity: "high"
    },
    "unverified-source": {
        explanation: "This MCP is not from a known/verified publisher. Its behavior and security posture are unknown.",
        remediation: "Review the MCP source code before use. Prefer official or verified MCPs.",
        severity: "medium"
    },
    "local-binary": {
        explanation: "This MCP runs a local binary or script. Its behavior is determined by the local file.",
        remediation: "Verify the integrity of the local binary. Ensure it has not been tampered with.",
        severity: "medium"
    },
    "dependency-only": {
        explanation: "This MCP was found as a dependency, not as an active configuration.",
        remediation: "Verify the MCP is intentionally included and properly configured.",
        severity: "low"
    }
};

// Secret detection patterns for exposed credentials
const SECRET_PATTERNS = {
    // AWS
    aws_access_key: {
        pattern: /AKIA[0-9A-Z]{16}/,
        description: "AWS Access Key ID",
        severity: "critical",
        rotation_url: "https://console.aws.amazon.com/iam/home#/security_credentials"
    },
    // GitHub
    github_pat: {
        pattern: /ghp_[0-9a-zA-Z]{36}/,
        description: "GitHub Personal Access Token",
        severity: "critical",
        rotation_url: "https://github.com/settings/tokens"
    },
    github_oauth: {
        pattern: /gho_[0-9a-zA-Z]{36}/,
        description: "GitHub OAuth Access Token",
        severity: "critical",
        rotation_url: "https://github.com/settings/tokens"
    },
    // Stripe
    stripe_live: {
        pattern: /sk_live_[0-9a-zA-Z]{24,}/,
        description: "Stripe Live Secret Key",
        severity: "critical",
        rotation_url: "https://dashboard.stripe.com/apikeys"
    },
    // Slack
    slack_token: {
        pattern: /xox[baprs]-[0-9a-zA-Z-]{10,}/,
        description: "Slack Token",
        severity: "high",
        rotation_url: "https://api.slack.com/apps"
    },
    // OpenAI
    openai_key: {
        pattern: /sk-[0-9a-zA-Z]{20,}/,
        description: "OpenAI API Key",
        severity: "high",
        rotation_url: "https://platform.openai.com/api-keys"
    },
    openai_project_key: {
        pattern: /sk-proj-[0-9a-zA-Z_-]{20,}/,
        description: "OpenAI Project API Key",
        severity: "high",
        rotation_url: "https://platform.openai.com/api-keys"
    },
    // Anthropic
    anthropic_key: {
        pattern: /sk-ant-[0-9a-zA-Z-]{40,}/,
        description: "Anthropic API Key",
        severity: "high",
        rotation_url: "https://console.anthropic.com/settings/keys"
    },
    // Google
    google_api_key: {
        pattern: /AIza[0-9A-Za-z-_]{35}/,
        description: "Google API Key",
        severity: "high",
        rotation_url: "https://console.cloud.google.com/apis/credentials"
    },
    // Database connection strings
    postgres_conn: {
        pattern: /postgres(ql)?:\/\/[^:]+:[^@]+@[^/]+\/\w+/,
        description: "PostgreSQL Connection String with Credentials",
        severity: "critical",
        rotation_url: null
    },
    mongodb_conn: {
        pattern: /mongodb(\+srv)?:\/\/[^:]+:[^@]+@/,
        description: "MongoDB Connection String with Credentials",
        severity: "critical",
        rotation_url: null
    },
    // Private keys
    private_key: {
        pattern: /-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/,
        description: "Private Key",
        severity: "critical",
        rotation_url: null
    },
    // SendGrid
    sendgrid_key: {
        pattern: /SG\.[0-9A-Za-z-_]{22}\.[0-9A-Za-z-_]{43}/,
        description: "SendGrid API Key",
        severity: "high",
        rotation_url: "https://app.sendgrid.com/settings/api_keys"
    },
    // Discord
    discord_token: {
        pattern: /[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}/,
        description: "Discord Bot Token",
        severity: "high",
        rotation_url: "https://discord.com/developers/applications"
    },
    // NPM
    npm_token: {
        pattern: /npm_[A-Za-z0-9]{36}/,
        description: "NPM Access Token",
        severity: "high",
        rotation_url: "https://www.npmjs.com/settings/tokens"
    }
};

// API endpoint detection patterns
const API_PATTERNS = {
    // Databases
    postgresql: {
        pattern: /postgres(ql)?:\/\/[^\s"']+/i,
        category: "database",
        description: "PostgreSQL Database"
    },
    mysql: {
        pattern: /mysql:\/\/[^\s"']+/i,
        category: "database",
        description: "MySQL Database"
    },
    mongodb: {
        pattern: /mongodb(\+srv)?:\/\/[^\s"']+/i,
        category: "database",
        description: "MongoDB Database"
    },
    redis: {
        pattern: /redis:\/\/[^\s"']+/i,
        category: "database",
        description: "Redis Cache"
    },
    sqlite: {
        pattern: /sqlite:(?:\/\/)?[^\s"']+/i,
        category: "database",
        description: "SQLite Database"
    },
    // WebSocket
    websocket: {
        pattern: /wss?:\/\/[^\s"']+/i,
        category: "websocket",
        description: "WebSocket Connection"
    },
    // Known SaaS/MCP endpoints
    slack_api: {
        pattern: /https?:\/\/(?:api\.)?slack\.com[^\s"']*/i,
        category: "saas",
        description: "Slack API"
    },
    github_api: {
        pattern: /https?:\/\/(?:api\.)?github\.com[^\s"']*/i,
        category: "saas",
        description: "GitHub API"
    },
    github_mcp: {
        pattern: /https?:\/\/mcp\.github\.com[^\s"']*/i,
        category: "sse",
        description: "GitHub MCP (SSE)"
    },
    linear_mcp: {
        pattern: /https?:\/\/mcp\.linear\.app[^\s"']*/i,
        category: "sse",
        description: "Linear MCP (SSE)"
    },
    asana_mcp: {
        pattern: /https?:\/\/mcp\.asana\.com[^\s"']*/i,
        category: "sse",
        description: "Asana MCP (SSE)"
    },
    openai_api: {
        pattern: /https?:\/\/api\.openai\.com[^\s"']*/i,
        category: "saas",
        description: "OpenAI API"
    },
    anthropic_api: {
        pattern: /https?:\/\/api\.anthropic\.com[^\s"']*/i,
        category: "saas",
        description: "Anthropic API"
    },
    // Cloud providers
    aws_s3: {
        pattern: /https?:\/\/[^\/]*\.s3\.amazonaws\.com[^\s"']*/i,
        category: "cloud",
        description: "AWS S3"
    },
    aws_api: {
        pattern: /https?:\/\/[^\/]*\.amazonaws\.com[^\s"']*/i,
        category: "cloud",
        description: "AWS API"
    },
    gcp_api: {
        pattern: /https?:\/\/[^\/]*\.googleapis\.com[^\s"']*/i,
        category: "cloud",
        description: "Google Cloud API"
    },
    azure_api: {
        pattern: /https?:\/\/[^\/]*\.azure\.com[^\s"']*/i,
        category: "cloud",
        description: "Azure API"
    },
    // Generic SSE (contains /sse path)
    sse_endpoint: {
        pattern: /https?:\/\/[^\s"']+\/sse[^\s"']*/i,
        category: "sse",
        description: "SSE Endpoint"
    }
};

// URL fields in config to check
const CONFIG_URL_FIELDS = ['url', 'serverUrl', 'endpoint', 'baseUrl', 'uri', 'host', 'server', 'apiUrl', 'apiEndpoint'];

// Environment variable patterns for URLs
const ENV_URL_PATTERNS = ['_URL', '_ENDPOINT', '_HOST', '_API', '_URI', '_SERVER', '_BASE'];

// Category display info
const API_CATEGORY_INFO = {
    database: { name: "Database", icon: "🗄️", color: "#17a2b8" },
    rest_api: { name: "REST API", icon: "🌐", color: "#007bff" },
    websocket: { name: "WebSocket", icon: "🔌", color: "#6f42c1" },
    sse: { name: "SSE", icon: "📡", color: "#ffc107" },
    saas: { name: "SaaS", icon: "☁️", color: "#28a745" },
    cloud: { name: "Cloud", icon: "🏢", color: "#6c757d" },
    unknown: { name: "Other", icon: "❓", color: "#adb5bd" }
};

// AI Model detection patterns
const MODEL_ENV_PATTERNS = [
    'MODEL', 'MODEL_NAME', 'MODEL_ID', 'LLM_MODEL', 'AI_MODEL',
    'OPENAI_MODEL', 'ANTHROPIC_MODEL', 'CLAUDE_MODEL', 'BEDROCK_MODEL_ID',
    'AZURE_OPENAI_DEPLOYMENT', 'AZURE_DEPLOYMENT', 'OLLAMA_MODEL',
    'TOGETHER_MODEL', 'GROQ_MODEL', 'MISTRAL_MODEL', 'GEMINI_MODEL'
];

// Known model identifiers
const MODEL_IDENTIFIERS = {
    // OpenAI
    'gpt-4o': { name: 'GPT-4o', provider: 'OpenAI', hosting: 'cloud' },
    'gpt-4o-mini': { name: 'GPT-4o Mini', provider: 'OpenAI', hosting: 'cloud' },
    'gpt-4-turbo': { name: 'GPT-4 Turbo', provider: 'OpenAI', hosting: 'cloud' },
    'gpt-4': { name: 'GPT-4', provider: 'OpenAI', hosting: 'cloud' },
    'gpt-3.5-turbo': { name: 'GPT-3.5 Turbo', provider: 'OpenAI', hosting: 'cloud' },
    'o1': { name: 'o1', provider: 'OpenAI', hosting: 'cloud' },
    'o1-mini': { name: 'o1 Mini', provider: 'OpenAI', hosting: 'cloud' },
    'o3-mini': { name: 'o3 Mini', provider: 'OpenAI', hosting: 'cloud' },
    // Anthropic
    'claude-3-5-sonnet': { name: 'Claude 3.5 Sonnet', provider: 'Anthropic', hosting: 'cloud' },
    'claude-3.5-sonnet': { name: 'Claude 3.5 Sonnet', provider: 'Anthropic', hosting: 'cloud' },
    'claude-3-5-haiku': { name: 'Claude 3.5 Haiku', provider: 'Anthropic', hosting: 'cloud' },
    'claude-3-opus': { name: 'Claude 3 Opus', provider: 'Anthropic', hosting: 'cloud' },
    'claude-3-sonnet': { name: 'Claude 3 Sonnet', provider: 'Anthropic', hosting: 'cloud' },
    'claude-3-haiku': { name: 'Claude 3 Haiku', provider: 'Anthropic', hosting: 'cloud' },
    // Meta Llama
    'llama-3.3': { name: 'Llama 3.3', provider: 'Meta', hosting: 'local' },
    'llama-3.2': { name: 'Llama 3.2', provider: 'Meta', hosting: 'local' },
    'llama-3.1': { name: 'Llama 3.1', provider: 'Meta', hosting: 'local' },
    'llama-3': { name: 'Llama 3', provider: 'Meta', hosting: 'local' },
    'llama3': { name: 'Llama 3', provider: 'Meta', hosting: 'local' },
    'codellama': { name: 'Code Llama', provider: 'Meta', hosting: 'local' },
    // Mistral
    'mistral-large': { name: 'Mistral Large', provider: 'Mistral AI', hosting: 'cloud' },
    'mistral': { name: 'Mistral', provider: 'Mistral AI', hosting: 'local' },
    'mixtral': { name: 'Mixtral', provider: 'Mistral AI', hosting: 'local' },
    'codestral': { name: 'Codestral', provider: 'Mistral AI', hosting: 'cloud' },
    // Google
    'gemini-2.0': { name: 'Gemini 2.0', provider: 'Google', hosting: 'cloud' },
    'gemini-1.5-pro': { name: 'Gemini 1.5 Pro', provider: 'Google', hosting: 'cloud' },
    'gemini-1.5-flash': { name: 'Gemini 1.5 Flash', provider: 'Google', hosting: 'cloud' },
    'gemini-pro': { name: 'Gemini Pro', provider: 'Google', hosting: 'cloud' },
    'gemma-2': { name: 'Gemma 2', provider: 'Google', hosting: 'local' },
    'gemma': { name: 'Gemma', provider: 'Google', hosting: 'local' },
    // Others
    'deepseek-v3': { name: 'DeepSeek V3', provider: 'DeepSeek', hosting: 'cloud' },
    'deepseek-r1': { name: 'DeepSeek R1', provider: 'DeepSeek', hosting: 'cloud' },
    'deepseek': { name: 'DeepSeek', provider: 'DeepSeek', hosting: 'local' },
    'qwen-2.5': { name: 'Qwen 2.5', provider: 'Alibaba', hosting: 'local' },
    'qwen': { name: 'Qwen', provider: 'Alibaba', hosting: 'local' },
    'phi-4': { name: 'Phi-4', provider: 'Microsoft', hosting: 'local' },
    'phi-3': { name: 'Phi-3', provider: 'Microsoft', hosting: 'local' },
};

// Provider display info for AI models
const MODEL_PROVIDER_INFO = {
    'OpenAI': { icon: '🤖', color: '#10a37f' },
    'Anthropic': { icon: '🧠', color: '#d4a27f' },
    'Google': { icon: '🔷', color: '#4285f4' },
    'Meta': { icon: '🦙', color: '#0668e1' },
    'Mistral AI': { icon: '🌬️', color: '#ff7000' },
    'DeepSeek': { icon: '🔍', color: '#1e90ff' },
    'Alibaba': { icon: '☁️', color: '#ff6a00' },
    'Microsoft': { icon: '🪟', color: '#00a4ef' },
    'Unknown': { icon: '❓', color: '#6c757d' },
};

// Placeholder patterns to skip (not real secrets)
const PLACEHOLDER_PATTERNS = [
    /^xxx+$/i,
    /^your[_-]?(api[_-]?key|token|secret|password)/i,
    /^changeme$/i,
    /^replace[_-]?me$/i,
    /^todo$/i,
    /^example$/i,
    /^test$/i,
    /^dummy$/i,
    /^fake$/i,
    /^\*+$/,
    /^<.*>$/,      // <your-api-key>
    /^\[.*\]$/,    // [your-api-key]
    /^\{.*\}$/,    // {your-api-key}
    /^sk_test_/,   // Stripe test keys
    /^pk_test_/,   // Stripe test public keys
];

// Mask a secret value for safe display
function maskSecret(value) {
    if (!value || value.length <= 12) {
        return value ? value.slice(0, 2) + '*'.repeat(Math.max(0, value.length - 4)) + value.slice(-2) : '****';
    }
    return value.slice(0, 4) + '********' + value.slice(-4);
}

// Check if a value is a placeholder
function isPlaceholder(value) {
    if (!value) return true;
    const valueLower = value.toLowerCase().trim();
    return PLACEHOLDER_PATTERNS.some(pattern => pattern.test(valueLower));
}

// Detect secrets in environment variables
function detectSecrets(env, mcpName) {
    const secrets = [];
    if (!env || typeof env !== 'object') return secrets;

    for (const [key, value] of Object.entries(env)) {
        if (typeof value !== 'string' || value.length < 8) continue;
        if (isPlaceholder(value)) continue;
        if (value.startsWith('$') || value.startsWith('${')) continue; // Env var reference

        for (const [type, config] of Object.entries(SECRET_PATTERNS)) {
            if (config.pattern.test(value)) {
                secrets.push({
                    type,
                    description: config.description,
                    severity: config.severity,
                    env_key: key,
                    value_masked: maskSecret(value),
                    value_length: value.length,
                    rotation_url: config.rotation_url,
                    mcp_name: mcpName
                });
                break; // Don't double-count
            }
        }

        // Generic detection for context-based secrets
        const genericPatterns = [
            { keys: ['API_KEY', 'APIKEY', 'API_SECRET'], desc: 'Potential API Key' },
            { keys: ['PASSWORD', 'PASSWD', 'PWD', 'DB_PASS'], desc: 'Password' },
            { keys: ['TOKEN', 'AUTH_TOKEN', 'ACCESS_TOKEN', 'BEARER'], desc: 'Authentication Token' },
        ];

        for (const gp of genericPatterns) {
            const keyUpper = key.toUpperCase();
            if (gp.keys.some(k => keyUpper.includes(k)) && value.length >= 16) {
                // Check if not already detected
                if (!secrets.find(s => s.env_key === key)) {
                    secrets.push({
                        type: 'generic',
                        description: gp.desc,
                        severity: 'medium',
                        env_key: key,
                        value_masked: maskSecret(value),
                        value_length: value.length,
                        rotation_url: null,
                        mcp_name: mcpName,
                        confidence: 'medium'
                    });
                }
                break;
            }
        }
    }

    return secrets;
}

// Mask credentials in URL for safe display
function maskUrlCredentials(url) {
    if (!url) return url;
    // Pattern to match credentials in URL: protocol://user:pass@host
    return url.replace(/:\/\/([^:@]+):([^@]+)@/g, '://****:****@');
}

// Classify a URL and return category and description
function classifyUrl(url) {
    const urlLower = url.toLowerCase();

    // Check specific patterns first
    for (const [name, config] of Object.entries(API_PATTERNS)) {
        if (config.pattern.test(url)) {
            return { category: config.category, description: config.description };
        }
    }

    // Generic HTTP/HTTPS
    if (urlLower.startsWith('http://') || urlLower.startsWith('https://')) {
        return { category: 'rest_api', description: 'HTTP API Endpoint' };
    }

    return { category: 'unknown', description: 'Unknown Endpoint' };
}

// Detect API endpoints from MCP configuration
function detectApis(rawConfig, args, mcpName) {
    const apis = [];
    const seenUrls = new Set();

    if (!rawConfig) return apis;

    const env = rawConfig.env || {};

    // 1. Check environment variables for URLs
    for (const [key, value] of Object.entries(env)) {
        if (typeof value !== 'string' || value.length < 8) continue;
        if (value.startsWith('$') || value.startsWith('${')) continue; // Env var reference

        // Check if key suggests it's a URL
        const keyUpper = key.toUpperCase();
        const isUrlKey = ENV_URL_PATTERNS.some(p => keyUpper.includes(p));

        // Extract URLs from the value
        const urls = extractUrls(value);
        for (const url of urls) {
            if (seenUrls.has(url)) continue;
            seenUrls.add(url);

            const { category, description } = classifyUrl(url);
            apis.push({
                url: url,
                maskedUrl: maskUrlCredentials(url),
                category: category,
                description: description,
                source: 'env_var',
                sourceKey: key,
                mcpName: mcpName
            });
        }
    }

    // 2. Check config fields for URLs
    for (const field of CONFIG_URL_FIELDS) {
        const value = rawConfig[field];
        if (!value || typeof value !== 'string') continue;

        const urls = extractUrls(value);
        for (const url of urls) {
            if (seenUrls.has(url)) continue;
            seenUrls.add(url);

            const { category, description } = classifyUrl(url);
            apis.push({
                url: url,
                maskedUrl: maskUrlCredentials(url),
                category: category,
                description: description,
                source: 'config_field',
                sourceKey: field,
                mcpName: mcpName
            });
        }
    }

    // 3. Check command args for URLs
    if (args && Array.isArray(args)) {
        for (let i = 0; i < args.length; i++) {
            const arg = args[i];
            if (typeof arg !== 'string' || arg.length < 8) continue;

            const urls = extractUrls(arg);
            for (const url of urls) {
                if (seenUrls.has(url)) continue;
                seenUrls.add(url);

                const { category, description } = classifyUrl(url);
                apis.push({
                    url: url,
                    maskedUrl: maskUrlCredentials(url),
                    category: category,
                    description: description,
                    source: 'args',
                    sourceKey: `args[${i}]`,
                    mcpName: mcpName
                });
            }
        }
    }

    return apis;
}

// Identify a model string and return its metadata
function identifyModel(modelString) {
    if (!modelString) return null;
    const modelLower = modelString.toLowerCase().trim();

    // Try exact match first
    if (MODEL_IDENTIFIERS[modelLower]) {
        return { ...MODEL_IDENTIFIERS[modelLower] };
    }

    // Try prefix match (for versioned models like 'gpt-4o-2024-08-06')
    for (const [pattern, info] of Object.entries(MODEL_IDENTIFIERS)) {
        if (modelLower.startsWith(pattern)) {
            return { ...info };
        }
    }

    // Try contains match (for models like 'anthropic.claude-3-5-sonnet-20241022-v2:0')
    for (const [pattern, info] of Object.entries(MODEL_IDENTIFIERS)) {
        if (modelLower.includes(pattern)) {
            return { ...info };
        }
    }

    // Infer from common patterns
    if (modelLower.includes('llama')) {
        return { name: modelString, provider: 'Meta', hosting: 'local' };
    }
    if (modelLower.includes('mistral') || modelLower.includes('mixtral')) {
        return { name: modelString, provider: 'Mistral AI', hosting: 'local' };
    }
    if (modelLower.includes('claude')) {
        return { name: modelString, provider: 'Anthropic', hosting: 'cloud' };
    }
    if (modelLower.includes('gpt')) {
        return { name: modelString, provider: 'OpenAI', hosting: 'cloud' };
    }
    if (modelLower.includes('gemini') || modelLower.includes('gemma')) {
        return { name: modelString, provider: 'Google', hosting: 'cloud' };
    }
    if (modelLower.includes('qwen')) {
        return { name: modelString, provider: 'Alibaba', hosting: 'local' };
    }
    if (modelLower.includes('deepseek')) {
        return { name: modelString, provider: 'DeepSeek', hosting: 'local' };
    }

    // Unknown model
    return {
        name: modelString,
        provider: 'Unknown',
        hosting: 'unknown'
    };
}

// Detect AI model from MCP configuration
function detectModel(rawConfig, mcpName) {
    if (!rawConfig) return null;

    const env = rawConfig.env || {};

    // Check environment variables for model names
    for (const [key, value] of Object.entries(env)) {
        if (typeof value !== 'string' || !value) continue;
        if (value.startsWith('$') || value.startsWith('${')) continue;

        const keyUpper = key.toUpperCase();

        // Check if this env var matches model patterns
        const isModelKey = MODEL_ENV_PATTERNS.some(p =>
            keyUpper.includes(p) || keyUpper.endsWith('_MODEL') || keyUpper.endsWith('_MODEL_ID')
        );

        if (isModelKey) {
            const modelInfo = identifyModel(value);
            if (modelInfo) {
                return {
                    modelId: value,
                    modelName: modelInfo.name,
                    provider: modelInfo.provider,
                    hosting: modelInfo.hosting,
                    source: `env:${key}`,
                    mcpName: mcpName
                };
            }
        }
    }

    return null;
}

// Extract all URLs from a text string
function extractUrls(text) {
    const urls = [];

    // Check specific patterns first
    for (const [name, config] of Object.entries(API_PATTERNS)) {
        const matches = text.match(new RegExp(config.pattern.source, 'gi'));
        if (matches) {
            for (const m of matches) {
                if (!urls.includes(m)) urls.push(m);
            }
        }
    }

    // Generic HTTP/HTTPS
    const httpMatches = text.match(/https?:\/\/[^\s"']+/gi);
    if (httpMatches) {
        for (const m of httpMatches) {
            if (!urls.includes(m)) urls.push(m);
        }
    }

    return urls;
}

// Heuristic risk calculation for unknown MCPs
function calculateHeuristicRisk(name, source, config) {
    let riskScore = 0;
    const riskFactors = [];
    const nameLower = (name || '').toLowerCase();
    const sourceLower = (source || '').toLowerCase();
    const env = config?.env || {};
    const command = config?.command || '';
    const args = config?.args || [];

    // Check for high-risk keywords in name/source
    const criticalKeywords = ['shell', 'exec', 'command', 'bash', 'terminal', 'kubernetes', 'k8s', 'docker', 'terraform', 'aws', 'azure', 'gcp', 'admin'];
    const highKeywords = ['filesystem', 'file', 'database', 'postgres', 'mysql', 'mongo', 'redis', 'email', 'browser', 'puppeteer', 'playwright'];
    const mediumKeywords = ['slack', 'discord', 'github', 'api', 'http', 'fetch', 'calendar', 'twitter'];

    for (const kw of criticalKeywords) {
        if (nameLower.includes(kw) || sourceLower.includes(kw)) {
            riskScore += 40;
            riskFactors.push(`contains "${kw}"`);
            break;
        }
    }
    for (const kw of highKeywords) {
        if (nameLower.includes(kw) || sourceLower.includes(kw)) {
            riskScore += 25;
            riskFactors.push(`contains "${kw}"`);
            break;
        }
    }
    for (const kw of mediumKeywords) {
        if (nameLower.includes(kw) || sourceLower.includes(kw)) {
            riskScore += 15;
            riskFactors.push(`contains "${kw}"`);
            break;
        }
    }

    // Check for secrets in environment variables
    const secretPatterns = ['password', 'secret', 'token', 'key', 'credential', 'api_key', 'apikey', 'auth'];
    for (const envKey of Object.keys(env)) {
        const keyLower = envKey.toLowerCase();
        for (const pattern of secretPatterns) {
            if (keyLower.includes(pattern)) {
                riskScore += 15;
                riskFactors.push(`secret in env: ${envKey}`);
                break;
            }
        }
    }

    // Check command type
    if (command.startsWith('./') || command.startsWith('/')) {
        riskScore += 20;
        riskFactors.push('local script');
    }
    if (['bash', 'sh', 'zsh', 'cmd', 'powershell'].includes(command)) {
        riskScore += 35;
        riskFactors.push('shell command');
    }
    if (command === 'docker') {
        riskScore += 25;
        riskFactors.push('docker container');
    }

    // Check if unverified (not from known publisher)
    const verifiedPrefixes = ['@anthropic/', '@modelcontextprotocol/', '@stripe/', '@supabase/', '@cloudflare/', '@atlassian/', '@vercel/'];
    const isVerified = verifiedPrefixes.some(p => sourceLower.includes(p.toLowerCase()));
    if (!isVerified) {
        riskScore += 10;
        riskFactors.push('unverified publisher');
    }

    // Determine risk level from score
    let riskLevel;
    if (riskScore >= 50) riskLevel = 'critical';
    else if (riskScore >= 35) riskLevel = 'high';
    else if (riskScore >= 20) riskLevel = 'medium';
    else riskLevel = 'low';

    return { riskLevel, riskScore, riskFactors };
}

// Generate description for unknown MCPs based on heuristics
function generateDescription(name, source, config) {
    const nameLower = (name || '').toLowerCase();
    const sourceLower = (source || '').toLowerCase();
    const command = config?.command || '';

    // Try to infer from name/source
    if (nameLower.includes('filesystem') || nameLower.includes('file')) return 'File system access (inferred)';
    if (nameLower.includes('shell') || nameLower.includes('exec') || nameLower.includes('command')) return 'Shell/command execution (inferred)';
    if (nameLower.includes('postgres') || nameLower.includes('mysql') || nameLower.includes('database') || nameLower.includes('db')) return 'Database access (inferred)';
    if (nameLower.includes('slack')) return 'Slack messaging integration (inferred)';
    if (nameLower.includes('github')) return 'GitHub API integration (inferred)';
    if (nameLower.includes('docker')) return 'Docker container management (inferred)';
    if (nameLower.includes('kubernetes') || nameLower.includes('k8s')) return 'Kubernetes cluster management (inferred)';
    if (nameLower.includes('email') || nameLower.includes('mail')) return 'Email operations (inferred)';
    if (nameLower.includes('browser') || nameLower.includes('puppeteer') || nameLower.includes('playwright')) return 'Browser automation (inferred)';
    if (nameLower.includes('api') || nameLower.includes('http') || nameLower.includes('fetch')) return 'HTTP/API requests (inferred)';
    if (nameLower.includes('memory') || nameLower.includes('cache')) return 'Memory/cache storage (inferred)';
    if (nameLower.includes('search')) return 'Search functionality (inferred)';

    // Check command type
    if (command.startsWith('./') || command.startsWith('/')) return 'Local custom script';
    if (command === 'docker') return 'Docker-based MCP server';

    return 'Unknown MCP server';
}

// Look up MCP in known registry
function lookupMcp(source) {
    const sourceLower = source.toLowerCase();

    for (const [pkg, info] of Object.entries(KNOWN_MCPS)) {
        if (sourceLower.includes(pkg.toLowerCase())) {
            return { package: pkg, ...info };
        }
    }

    return null;
}

// ============================================
// Demo Mode Functions
// ============================================

// Load demo mode data and display results
async function loadDemoMode() {
    isDemoMode = true;

    // Track demo mode usage
    trackEvent({ event: 'demo_mode', source: 'button' });

    // Hide connect section and show progress
    connectSection?.classList.add('hidden');
    progressSection?.classList.remove('hidden');
    updateProgress(10, 'Loading demo results...');

    try {
        const response = await fetch('demo-data.json');
        if (!response.ok) {
            throw new Error('Failed to load demo data');
        }

        updateProgress(50, 'Processing demo data...');
        const demoData = await response.json();

        updateProgress(80, 'Preparing display...');

        // Transform demo MCPs to scanResults format
        scanResults = transformDemoData(demoData);

        // Store demo metadata for display
        window.demoOrg = demoData.org;
        window.demoSummary = demoData.summary;
        window.demoSecrets = demoData.secrets;
        window.demoApis = demoData.apis;
        window.demoModels = demoData.models;

        updateProgress(100, 'Complete!');

        // Small delay for UX
        await new Promise(resolve => setTimeout(resolve, 300));

        // Display results with demo banner
        displayDemoResults();

    } catch (error) {
        console.error('Demo mode error:', error);
        progressSection?.classList.add('hidden');
        connectSection?.classList.remove('hidden');
        alert('Failed to load demo data. Please try again.');
    }
}

// Transform demo data MCPs to scanResults format
function transformDemoData(demoData) {
    return demoData.mcps.map(mcp => {
        // Find any secrets for this MCP
        const mcpSecrets = (demoData.secrets || []).filter(s => s.mcp_name === mcp.name);

        // Find any APIs for this MCP
        const mcpApis = (demoData.apis || []).filter(a => a.mcp_name === mcp.name);

        // Find any models for this MCP
        const mcpModel = (demoData.models || []).find(m => m.mcp_name === mcp.name);

        return {
            name: mcp.name,
            source: mcp.source,
            repository: mcp.found_in,
            filePath: 'mcp.json',
            type: mcp.source.startsWith('@') ? 'npm' : 'unknown',
            sourceType: 'config',
            riskFlags: mcp.risk_flags || [],
            isKnown: mcp.is_known,
            provider: mcp.is_known ? 'MCP' : 'Unknown',
            mcpType: mcp.is_known ? 'official' : 'unknown',
            registryRisk: mcp.risk,
            verified: mcp.is_known,
            description: generateDescriptionFromRiskFlags(mcp.name, mcp.risk_flags),
            heuristicRisk: null,
            rawConfig: {
                env: {},
                args: []
            },
            // Pre-attached secrets/apis/model for demo
            secrets: mcpSecrets,
            apis: mcpApis,
            model: mcpModel || null
        };
    });
}

// Generate description based on risk flags
function generateDescriptionFromRiskFlags(name, riskFlags) {
    if (riskFlags.includes('shell-access')) return 'Execute shell commands on the host system';
    if (riskFlags.includes('database-access')) return 'Database access and query execution';
    if (riskFlags.includes('filesystem-access')) return 'Read and write files on the local filesystem';
    if (riskFlags.includes('network-access')) return 'Make outbound network requests';
    if (riskFlags.includes('remote-mcp')) return 'Remote/hosted MCP server';
    if (riskFlags.includes('local-binary')) return 'Local binary or script execution';
    return `${name} MCP integration`;
}

// Display results for demo mode (with pre-calculated secrets/apis/models)
function displayDemoResults() {
    progressSection?.classList.add('hidden');

    if (scanResults.length === 0) {
        noResultsSection?.classList.remove('hidden');
        return;
    }

    resultsSection?.classList.remove('hidden');

    // Show demo banner first
    showDemoBanner();

    // Collect all pre-calculated secrets, APIs, models from demo data
    const allSecrets = window.demoSecrets || [];
    const allApis = window.demoApis || [];
    const allModels = window.demoModels || [];

    // Summary from demo data - SHOW FIRST
    const demoSummary = window.demoSummary || {};
    const totalMcps = demoSummary.total_mcps || scanResults.length;
    const uniqueRepos = demoSummary.repositories_scanned || new Set(scanResults.map(r => r.repository)).size;
    const knownMcps = demoSummary.known_mcps || scanResults.filter(r => r.isKnown).length;
    const unknownMcps = demoSummary.unknown_mcps || (totalMcps - knownMcps);
    const criticalRisk = demoSummary.critical_risk || scanResults.filter(r => r.registryRisk === 'critical').length;
    const withSecrets = demoSummary.secrets_detected || allSecrets.length;

    summary.innerHTML = `
        <div class="summary-item">
            <div class="value">${totalMcps}</div>
            <div class="label">MCPs Found</div>
        </div>
        <div class="summary-item">
            <div class="value">${uniqueRepos}</div>
            <div class="label">Repositories</div>
        </div>
        <div class="summary-item ${knownMcps > 0 ? 'success' : ''}">
            <div class="value">${knownMcps}</div>
            <div class="label">Known MCPs</div>
        </div>
        <div class="summary-item ${unknownMcps > 0 ? 'warning' : ''}">
            <div class="value">${unknownMcps}</div>
            <div class="label">Unknown MCPs</div>
        </div>
        <div class="summary-item ${criticalRisk > 0 ? 'danger' : ''}">
            <div class="value">${criticalRisk}</div>
            <div class="label">Critical Risk</div>
        </div>
        <div class="summary-item ${withSecrets > 0 ? 'danger' : ''}">
            <div class="value">${withSecrets}</div>
            <div class="label">Secrets Detected</div>
        </div>
    `;

    // Update table banner title with count
    const tableBannerTitle = document.getElementById('table-banner-title');
    if (tableBannerTitle) {
        tableBannerTitle.textContent = `MCP DISCOVERY RESULTS - ${totalMcps} server(s) found`;
    }

    // Display MCP table - SECOND
    displayDemoMcpTable();

    // Expand the MCP Discovery Results table by default
    const tableDetail = document.getElementById('table-detail');
    const tableToggleIcon = document.getElementById('table-toggle-icon');
    if (tableDetail) {
        tableDetail.classList.add('expanded');
    }
    if (tableToggleIcon) {
        tableToggleIcon.textContent = '▼';
    }

    // Now display secrets/APIs/models AFTER the table
    // Create a container for these sections after the table-banner
    const tableBanner = document.getElementById('table-banner');
    const reportSection = document.getElementById('report-section');

    // Display secrets alert - insert after table
    if (allSecrets.length > 0) {
        displaySecretsAlertAfterTable(allSecrets, tableBanner);
    }

    // Display APIs inventory - insert after secrets (or after table)
    if (allApis.length > 0) {
        displayApisInventoryAfterTable(allApis, tableBanner);
    }

    // Display AI Models inventory - insert after APIs (or after table)
    if (allModels.length > 0) {
        displayModelsInventoryAfterTable(allModels, tableBanner);
    }

    // Show export/report section
    showReportSection();
}

// Display secrets alert AFTER the table (for demo mode)
function displaySecretsAlertAfterTable(secrets, afterElement) {
    if (!secrets || secrets.length === 0) return;

    // Count by severity
    const critical = secrets.filter(s => s.severity === 'critical').length;
    const high = secrets.filter(s => s.severity === 'high').length;
    const medium = secrets.filter(s => s.severity === 'medium').length;

    // Remove existing if any
    const existing = document.getElementById('secrets-alert');
    if (existing) existing.remove();

    const alertDiv = document.createElement('div');
    alertDiv.id = 'secrets-alert';
    alertDiv.className = 'secrets-alert';

    // Sort by severity
    const severityOrder = { critical: 0, high: 1, medium: 2 };
    const sortedSecrets = [...secrets].sort((a, b) =>
        (severityOrder[a.severity] || 2) - (severityOrder[b.severity] || 2)
    );

    const secretsHtml = sortedSecrets.map(s => {
        const severityClass = s.severity === 'critical' ? 'danger' : (s.severity === 'high' ? 'warning' : 'info');
        const remediation = getSecretRemediation(s);

        return `
            <div class="secret-item ${severityClass}">
                <div class="secret-header">
                    <span class="badge ${severityClass}">${s.severity.toUpperCase()}</span>
                    <strong>${escapeHtml(s.description)}</strong>
                </div>
                <div class="secret-details">
                    <p><strong>Location:</strong> ${escapeHtml(s.mcp_name)} → <code>${escapeHtml(s.env_key)}</code></p>
                    <p><strong>Value:</strong> <code>${escapeHtml(s.value_masked)}</code> (${s.value_length} chars)</p>
                    <p><strong>Remediation:</strong></p>
                    <ol class="remediation-steps">
                        ${remediation.map(step => `<li>${step}</li>`).join('')}
                    </ol>
                </div>
            </div>
        `;
    }).join('');

    const summaryParts = [];
    if (critical) summaryParts.push(`<span class="text-danger">${critical} critical</span>`);
    if (high) summaryParts.push(`<span class="text-warning">${high} high</span>`);
    if (medium) summaryParts.push(`<span class="text-info">${medium} medium</span>`);

    alertDiv.innerHTML = `
        <div class="secrets-alert-header" onclick="toggleSecretsDetail()">
            <div class="secrets-alert-title">
                <span class="alert-icon">⚠️</span>
                <strong>${secrets.length} SECRET(S) DETECTED - IMMEDIATE ACTION REQUIRED</strong>
            </div>
            <span class="toggle-icon">▶</span>
        </div>
        <div class="secrets-alert-summary">
            ${summaryParts.join(' • ')}
            <span class="text-muted"> - Rotate ALL exposed credentials before continuing</span>
        </div>
        <div id="secrets-detail" class="secrets-detail">
            ${secretsHtml}
        </div>
    `;

    // Insert after the table banner
    if (afterElement && afterElement.parentNode) {
        afterElement.parentNode.insertBefore(alertDiv, afterElement.nextSibling);
    }
}

// Display APIs inventory AFTER the table (for demo mode)
function displayApisInventoryAfterTable(apis, afterElement) {
    if (!apis || apis.length === 0) return;

    // Group by category
    const byCategory = {};
    for (const api of apis) {
        const cat = api.category || 'unknown';
        if (!byCategory[cat]) byCategory[cat] = [];
        byCategory[cat].push(api);
    }

    // Remove existing if any
    const existing = document.getElementById('apis-inventory');
    if (existing) existing.remove();

    const inventoryDiv = document.createElement('div');
    inventoryDiv.id = 'apis-inventory';
    inventoryDiv.className = 'apis-inventory';

    // Category order and info
    const categoryOrder = ['database', 'rest_api', 'websocket', 'sse', 'saas', 'cloud', 'unknown'];

    let categoriesHtml = '';
    for (const cat of categoryOrder) {
        if (!byCategory[cat]) continue;
        const catApis = byCategory[cat];
        const info = API_CATEGORY_INFO[cat] || API_CATEGORY_INFO.unknown;

        const apisHtml = catApis.map(api => `
            <div class="api-item">
                <span class="api-mcp">${escapeHtml(api.mcpName)}</span>
                <span class="api-arrow">→</span>
                <code class="api-url">${escapeHtml(api.maskedUrl)}</code>
                <span class="api-source">(${escapeHtml(api.source)}: ${escapeHtml(api.sourceKey)})</span>
            </div>
        `).join('');

        categoriesHtml += `
            <div class="api-category">
                <div class="api-category-header">
                    <span class="api-icon">${info.icon}</span>
                    <strong>${info.name.toUpperCase()}</strong>
                    <span class="api-count">(${catApis.length})</span>
                </div>
                <div class="api-items">
                    ${apisHtml}
                </div>
            </div>
        `;
    }

    inventoryDiv.innerHTML = `
        <div class="apis-inventory-header" onclick="toggleApisInventory()">
            <div class="apis-inventory-title">
                <span class="inventory-icon">🔗</span>
                <strong>ENDPOINTS DISCOVERED - ${apis.length} connection(s)</strong>
            </div>
            <span class="toggle-icon">▶</span>
        </div>
        <div id="apis-detail" class="apis-detail">
            ${categoriesHtml}
        </div>
    `;

    // Insert after secrets alert (or after table if no secrets)
    const secretsAlert = document.getElementById('secrets-alert');
    const insertAfter = secretsAlert || afterElement;
    if (insertAfter && insertAfter.parentNode) {
        insertAfter.parentNode.insertBefore(inventoryDiv, insertAfter.nextSibling);
    }
}

// Display Models inventory AFTER the table (for demo mode)
function displayModelsInventoryAfterTable(models, afterElement) {
    if (!models || models.length === 0) return;

    // Group by provider
    const byProvider = {};
    for (const model of models) {
        const provider = model.provider || 'Unknown';
        if (!byProvider[provider]) byProvider[provider] = [];
        byProvider[provider].push(model);
    }

    // Remove existing if any
    const existing = document.getElementById('models-inventory');
    if (existing) existing.remove();

    const inventoryDiv = document.createElement('div');
    inventoryDiv.id = 'models-inventory';
    inventoryDiv.className = 'models-inventory';

    // Sort providers by count
    const sortedProviders = Object.entries(byProvider).sort((a, b) => b[1].length - a[1].length);

    let providersHtml = '';
    for (const [provider, providerModels] of sortedProviders) {
        const info = MODEL_PROVIDER_INFO[provider] || MODEL_PROVIDER_INFO.Unknown;
        const barWidth = Math.min(providerModels.length * 4, 20);

        const modelsHtml = providerModels.map(model => `
            <div class="model-item">
                <span class="model-name">${escapeHtml(model.modelName)}</span>
                <span class="model-hosting ${model.hosting}">${model.hosting === 'cloud' ? '☁️ Cloud' : model.hosting === 'local' ? '🏠 Local' : '❓ Unknown'}</span>
                <span class="model-mcp">(${escapeHtml(model.mcpName)})</span>
            </div>
        `).join('');

        providersHtml += `
            <div class="model-provider">
                <div class="model-provider-header">
                    <span class="model-icon">${info.icon}</span>
                    <strong>${escapeHtml(provider)}</strong>
                    <span class="model-bar" style="width: ${barWidth * 10}px; background: ${info.color}"></span>
                    <span class="model-count">${providerModels.length}</span>
                </div>
                <div class="model-items">
                    ${modelsHtml}
                </div>
            </div>
        `;
    }

    inventoryDiv.innerHTML = `
        <div class="models-inventory-header" onclick="toggleModelsInventory()">
            <div class="models-inventory-title">
                <span class="inventory-icon">🤖</span>
                <strong>AI MODELS - ${models.length} model(s) detected</strong>
            </div>
            <span class="toggle-icon">▶</span>
        </div>
        <div id="models-detail" class="models-detail">
            ${providersHtml}
        </div>
    `;

    // Insert after APIs inventory (or after secrets, or after table)
    const apisInventory = document.getElementById('apis-inventory');
    const secretsAlert = document.getElementById('secrets-alert');
    const insertAfter = apisInventory || secretsAlert || afterElement;
    if (insertAfter && insertAfter.parentNode) {
        insertAfter.parentNode.insertBefore(inventoryDiv, insertAfter.nextSibling);
    }
}

// Display MCP table for demo mode (matches original displayResults format)
function displayDemoMcpTable() {
    // Sort results by risk level (critical -> high -> medium -> low -> unknown)
    const riskOrder = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4 };
    const sortedResults = [...scanResults].sort((a, b) => {
        const riskA = riskOrder[a.registryRisk] ?? 4;
        const riskB = riskOrder[b.registryRisk] ?? 4;
        return riskA - riskB;
    });

    // Table with description and risk columns (same structure as original)
    resultsBody.innerHTML = sortedResults.map(r => {
        // Build risk indicator
        const riskBadge = getRegistryRiskBadge(r.registryRisk || 'unknown');

        // Get description
        const description = r.description || 'Unknown MCP server';

        // Build risk flags HTML
        const riskFlagsHtml = (r.riskFlags && r.riskFlags.length > 0)
            ? r.riskFlags.map(f => `<span class="risk-flag ${getRiskLevel(f)} has-tooltip" title="${escapeHtml(getRiskFlagTooltip(f))}">${f}</span>`).join(' ')
            : '<span class="text-muted">-</span>';

        return `
            <tr>
                <td class="name-cell">${escapeHtml(r.name)}</td>
                <td class="description-cell">${escapeHtml(description)}</td>
                <td><code>${escapeHtml(r.source)}</code></td>
                <td>
                    <span title="${escapeHtml(r.repository)}">
                        ${escapeHtml(r.repository.split('/')[1] || r.repository)}
                    </span>
                </td>
                <td>${r.isKnown ? '<span class="badge success">Yes</span>' : '<span class="badge danger">No</span>'}</td>
                <td>${riskBadge}</td>
                <td>${riskFlagsHtml}</td>
            </tr>
        `;
    }).join('');
}

// Show demo banner at the top of results
function showDemoBanner() {
    // Remove existing banner if any
    const existingBanner = document.getElementById('demo-banner');
    if (existingBanner) {
        existingBanner.remove();
    }

    const banner = document.createElement('div');
    banner.id = 'demo-banner';
    banner.className = 'demo-banner';
    banner.innerHTML = `
        <div class="demo-banner-content">
            <span class="demo-badge">DEMO MODE</span>
            <span>Viewing sample results for <strong>${window.demoOrg || 'acme-corp'}</strong>.
            <a href="index.html" class="demo-exit-link">Connect your GitHub</a> to scan your own repos.</span>
        </div>
    `;

    // Insert at the top of results section
    if (resultsSection) {
        resultsSection.insertBefore(banner, resultsSection.firstChild);
    }
}

// Check for demo mode URL parameter
function checkDemoUrlParam() {
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.get('demo') === 'true') {
        loadDemoMode();
    }
}

// Event Listeners - Initialize when DOM is ready
function initializeEventListeners() {
    // Track page view on load
    trackEvent({ event: 'page_view' });

    // Tab navigation
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.preventDefault();
            const tabId = btn.dataset.tab;

            if (!tabId) return;

            // Track tab click
            trackEvent({ event: 'tab_click', source: tabId });

            // Update tab buttons
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');

            // Update tab content
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            const tabContent = document.getElementById(tabId);
            if (tabContent) {
                tabContent.classList.add('active');
            }
        });
    });

    // Source tile click (GitHub)
    document.querySelectorAll('.source-tile.available').forEach(tile => {
        tile.addEventListener('click', () => {
            const source = tile.dataset.source;
            // Track source click
            trackEvent({ event: 'source_click', source: source });
            if (source === 'github') {
                document.getElementById('source-tiles').classList.add('hidden');
                document.getElementById('github-section').classList.remove('hidden');
            }
        });
    });

    // Back to tiles button
    document.getElementById('back-to-tiles')?.addEventListener('click', () => {
        document.getElementById('github-section').classList.add('hidden');
        document.getElementById('source-tiles').classList.remove('hidden');
        // Reset GitHub state
        resetGitHubState();
    });

    // CLI download tracking
    document.querySelector('.download-btn')?.addEventListener('click', () => {
        trackEvent({ event: 'cli_download', source: 'local-audit-tab' });
    });

    connectBtn?.addEventListener('click', handleConnect);
    scanBtn?.addEventListener('click', handleScan);
    orgSelect?.addEventListener('change', () => {
        scanBtn.disabled = !orgSelect.value;
    });

    document.getElementById('export-json-btn')?.addEventListener('click', () => exportResults('json'));
    document.getElementById('export-csv-btn')?.addEventListener('click', () => exportResults('csv'));
    document.getElementById('export-md-btn')?.addEventListener('click', () => exportResults('markdown'));
    document.getElementById('scan-again-btn')?.addEventListener('click', resetToOrgSelect);
    document.getElementById('scan-again-btn-2')?.addEventListener('click', resetToOrgSelect);

    // Demo button click handler
    document.getElementById('demo-btn')?.addEventListener('click', () => {
        loadDemoMode();
    });

    // Check for ?demo=true URL parameter on page load
    checkDemoUrlParam();
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeEventListeners);
} else {
    initializeEventListeners();
}

// Reset GitHub state
function resetGitHubState() {
    githubToken = '';
    scanResults = [];
    tokenInput.value = '';
    connectStatus.classList.add('hidden');
    orgSection.classList.add('hidden');
    progressSection.classList.add('hidden');
    resultsSection.classList.add('hidden');
    noResultsSection.classList.add('hidden');
    connectSection.classList.remove('hidden');
}

// GitHub API Helper
async function githubApi(endpoint, options = {}) {
    const response = await fetch(`https://api.github.com${endpoint}`, {
        ...options,
        headers: {
            'Authorization': `Bearer ${githubToken}`,
            'Accept': 'application/vnd.github.v3+json',
            ...options.headers,
        },
    });
    
    if (!response.ok) {
        const error = await response.json().catch(() => ({}));
        throw new Error(error.message || `GitHub API error: ${response.status}`);
    }
    
    return response.json();
}

// Connect to GitHub
async function handleConnect() {
    const token = tokenInput.value.trim();
    
    if (!token) {
        showStatus(connectStatus, 'Please enter a GitHub token', 'error');
        return;
    }
    
    connectBtn.disabled = true;
    connectBtn.textContent = 'Connecting...';
    
    try {
        githubToken = token;
        
        // Verify token and get user
        const user = await githubApi('/user');
        
        // Get organizations
        const orgs = await githubApi('/user/orgs');
        
        // Also add user's personal repos as an option
        const options = [
            { login: user.login, type: 'user', name: `${user.login} (Personal)` },
            ...orgs.map(org => ({ login: org.login, type: 'org', name: org.login })),
        ];
        
        // Populate org select
        orgSelect.innerHTML = '<option value="">Select an organization...</option>';
        options.forEach(opt => {
            const option = document.createElement('option');
            option.value = JSON.stringify({ login: opt.login, type: opt.type });
            option.textContent = opt.name;
            orgSelect.appendChild(option);
        });
        
        showStatus(connectStatus, `Connected as ${user.login}`, 'success');
        
        // Show org section
        orgSection.classList.remove('hidden');
        
    } catch (error) {
        showStatus(connectStatus, `Connection failed: ${error.message}`, 'error');
    } finally {
        connectBtn.disabled = false;
        connectBtn.textContent = 'Connect to GitHub';
    }
}

// Known MCP config file paths to check directly
const DIRECT_CHECK_PATHS = [
    { path: 'mcp.json', type: 'config' },
    { path: '.mcp/config.json', type: 'config' },
    { path: '.mcp/mcp.json', type: 'config' },
    { path: 'package.json', type: 'dependency' },
    { path: 'requirements.txt', type: 'dependency' },
];

// Scan Organization
async function handleScan() {
    const selected = JSON.parse(orgSelect.value);
    if (!selected) return;

    scanResults = [];

    // Show progress section
    orgSection.classList.add('hidden');
    progressSection.classList.remove('hidden');
    resultsSection.classList.add('hidden');
    noResultsSection.classList.add('hidden');

    scanLog.innerHTML = '';
    updateProgress(0, 'Starting scan...');

    try {
        const { login, type } = selected;

        // Track scan started
        trackEvent({ event: 'scan_started', source: 'github' });

        log(`Scanning ${type === 'org' ? 'organization' : 'user'}: ${login}`);

        // Phase 1: Direct repo scan (works for new repos not yet indexed)
        log('Phase 1: Direct repository scan...');
        updateProgress(5, 'Fetching repositories...');

        const repos = await fetchAllRepos(login, type);
        log(`Found ${repos.length} repositories`);

        let repoCount = 0;
        for (const repo of repos) {
            repoCount++;
            const repoProgress = 5 + (repoCount / repos.length) * 45; // 5-50%
            updateProgress(repoProgress, `Checking ${repo.name}...`);

            for (const check of DIRECT_CHECK_PATHS) {
                try {
                    const content = await githubApi(`/repos/${repo.full_name}/contents/${check.path}`);
                    if (content && content.content) {
                        const fileContent = atob(content.content);
                        const item = {
                            repository: { full_name: repo.full_name },
                            path: check.path,
                        };
                        const mcps = extractMcps(fileContent, item, check.type);
                        for (const mcp of mcps) {
                            const exists = scanResults.find(r =>
                                r.name === mcp.name && r.repository === mcp.repository
                            );
                            if (!exists) {
                                scanResults.push(mcp);
                                log(`  Found MCP: ${mcp.name} in ${repo.name}`, 'success');
                            }
                        }
                    }
                } catch (e) {
                    // File doesn't exist, that's fine
                }
            }

            // Small delay to avoid rate limits
            if (repoCount % 10 === 0) {
                await sleep(500);
            }
        }

        // Phase 2: GitHub code search (for files we might have missed)
        log('Phase 2: GitHub code search (for indexed repos)...');
        const totalPatterns = MCP_SEARCH_PATTERNS.length;

        for (let i = 0; i < totalPatterns; i++) {
            const pattern = MCP_SEARCH_PATTERNS[i];
            const progress = 50 + ((i + 1) / totalPatterns) * 45; // 50-95%

            updateProgress(progress, `Searching: ${pattern.query}`);
            log(`Searching: ${pattern.query}`);

            try {
                const query = type === 'org'
                    ? `org:${login} ${pattern.query}`
                    : `user:${login} ${pattern.query}`;

                const results = await githubApi(`/search/code?q=${encodeURIComponent(query)}&per_page=100`);

                if (results.items && results.items.length > 0) {
                    log(`  Found ${results.items.length} result(s)`, 'success');

                    for (const item of results.items) {
                        await processSearchResult(item, pattern.type);
                    }
                }

                // Rate limit handling - wait between searches
                await sleep(1000);

            } catch (error) {
                log(`  Error: ${error.message}`, 'warning');
            }
        }

        updateProgress(100, 'Scan complete!');
        log('Scan complete!', 'success');

        // Track scan completed with results
        const knownCount = scanResults.filter(r => r.isKnown).length;
        const unknownCount = scanResults.length - knownCount;
        trackEvent({
            event: 'scan_completed',
            source: 'github',
            mcps_found: scanResults.length,
            known_mcps: knownCount,
            unknown_mcps: unknownCount
        });

        // Show results
        await sleep(500);
        displayResults();

    } catch (error) {
        log(`Scan failed: ${error.message}`, 'error');
        updateProgress(0, 'Scan failed');
        trackEvent({ event: 'scan_error', source: 'github' });
    }
}

// Fetch all repos for a user or org
async function fetchAllRepos(login, type) {
    const repos = [];
    let page = 1;
    const perPage = 100;

    while (true) {
        const endpoint = type === 'org'
            ? `/orgs/${login}/repos?per_page=${perPage}&page=${page}`
            : `/users/${login}/repos?per_page=${perPage}&page=${page}`;

        const pageRepos = await githubApi(endpoint);

        if (!pageRepos || pageRepos.length === 0) break;

        repos.push(...pageRepos);

        if (pageRepos.length < perPage) break;
        page++;
    }

    return repos;
}

// Process a search result
async function processSearchResult(item, type) {
    try {
        // Fetch file content
        const content = await githubApi(`/repos/${item.repository.full_name}/contents/${item.path}`);
        
        let fileContent;
        if (content.encoding === 'base64') {
            fileContent = atob(content.content);
        } else {
            fileContent = content.content;
        }
        
        // Parse and extract MCPs
        const mcps = extractMcps(fileContent, item, type);
        
        for (const mcp of mcps) {
            // Check if already found (dedupe)
            const exists = scanResults.find(r => 
                r.name === mcp.name && r.repository === mcp.repository
            );
            
            if (!exists) {
                scanResults.push(mcp);
            }
        }
        
    } catch (error) {
        // Silently skip files we can't read
    }
}

// Extract MCP info from file content
function extractMcps(content, item, type) {
    const mcps = [];
    const repo = item.repository.full_name;
    const filePath = item.path;
    
    try {
        if (type === 'config') {
            // Parse as JSON config
            const config = JSON.parse(content);
            
            // Look for mcpServers
            const servers = config.mcpServers || config.servers || {};
            
            for (const [name, serverConfig] of Object.entries(servers)) {
                mcps.push(createMcpEntry(name, serverConfig, repo, filePath, 'config'));
            }
            
        } else if (type === 'dependency') {
            // Parse package.json or requirements.txt
            if (filePath.endsWith('package.json')) {
                const pkg = JSON.parse(content);
                const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };
                
                for (const [name, version] of Object.entries(allDeps)) {
                    if (isMcpPackage(name)) {
                        const registryMatch = lookupMcp(name);
                        const heuristic = !registryMatch ? calculateHeuristicRisk(name, name, {}) : null;
                        mcps.push({
                            name: name,
                            source: `${name}@${version}`,
                            repository: repo,
                            filePath: filePath,
                            type: 'npm',
                            sourceType: 'dependency',
                            riskFlags: identifyRisks(name, name, {}),
                            // Registry info
                            isKnown: !!registryMatch,
                            provider: registryMatch?.provider || 'Unknown',
                            mcpType: registryMatch?.type || 'unknown',
                            registryRisk: registryMatch?.risk_level || heuristic?.riskLevel || 'unknown',
                            verified: registryMatch?.verified || false,
                            description: registryMatch?.description || generateDescription(name, name, {}),
                            heuristicRisk: heuristic,
                        });
                    }
                }
                
            } else if (filePath.endsWith('requirements.txt')) {
                const lines = content.split('\n');
                for (const line of lines) {
                    const pkg = line.split('==')[0].split('>=')[0].trim();
                    if (isMcpPackage(pkg)) {
                        const registryMatch = lookupMcp(pkg);
                        const heuristic = !registryMatch ? calculateHeuristicRisk(pkg, pkg, {}) : null;
                        mcps.push({
                            name: pkg,
                            source: line.trim(),
                            repository: repo,
                            filePath: filePath,
                            type: 'python',
                            sourceType: 'dependency',
                            riskFlags: ['dependency-only'],
                            // Registry info
                            isKnown: !!registryMatch,
                            provider: registryMatch?.provider || 'Unknown',
                            mcpType: registryMatch?.type || 'unknown',
                            registryRisk: registryMatch?.risk_level || heuristic?.riskLevel || 'unknown',
                            verified: registryMatch?.verified || false,
                            description: registryMatch?.description || generateDescription(pkg, pkg, {}),
                            heuristicRisk: heuristic,
                        });
                    }
                }
            }
        }
    } catch (error) {
        // Skip unparseable files
    }
    
    return mcps;
}

// Create MCP entry from config
function createMcpEntry(name, config, repo, filePath, sourceType) {
    const command = config.command || '';
    const args = config.args || [];

    let source = command;
    let type = 'unknown';

    if (command === 'npx' && args.length > 0) {
        // Skip -y flag if present and get the actual package name
        let pkgIndex = 0;
        while (pkgIndex < args.length && args[pkgIndex].startsWith('-')) {
            pkgIndex++;
        }
        source = pkgIndex < args.length ? args[pkgIndex] : args[0];
        type = 'npm';
    } else if (command === 'node' && args.length > 0) {
        source = args[0];
        type = 'node';
    } else if (['python', 'python3', 'uvx', 'uv'].includes(command)) {
        // Skip flags for python commands too
        let pkgIndex = 0;
        while (pkgIndex < args.length && args[pkgIndex].startsWith('-')) {
            pkgIndex++;
        }
        source = pkgIndex < args.length ? args[pkgIndex] : command;
        type = 'python';
    } else if (command === 'docker') {
        type = 'docker';
    } else if (command.startsWith('/') || command.startsWith('./')) {
        type = 'local';
    }

    // Look up in registry
    const registryMatch = lookupMcp(source);

    // Calculate heuristic risk for unknown MCPs
    const heuristic = !registryMatch ? calculateHeuristicRisk(name, source, config) : null;

    return {
        name: name,
        source: source,
        repository: repo,
        filePath: filePath,
        type: type,
        sourceType: sourceType,
        riskFlags: identifyRisks(name, source, config),
        // Registry info
        isKnown: !!registryMatch,
        provider: registryMatch?.provider || 'Unknown',
        mcpType: registryMatch?.type || 'unknown',
        registryRisk: registryMatch?.risk_level || heuristic?.riskLevel || 'unknown',
        verified: registryMatch?.verified || false,
        description: registryMatch?.description || generateDescription(name, source, config),
        heuristicRisk: heuristic,
        // Store raw config for secrets detection
        rawConfig: config,
    };
}

// Check if package name is MCP-related
function isMcpPackage(name) {
    const patterns = [
        '@modelcontextprotocol/',
        '@anthropic/mcp',
        'mcp-server',
        'fastmcp',
        'modelcontextprotocol',
    ];
    return patterns.some(p => name.toLowerCase().includes(p.toLowerCase()));
}

// Identify risk flags
function identifyRisks(name, source, config) {
    const risks = [];
    const nameLower = name.toLowerCase();
    const sourceLower = source.toLowerCase();
    
    // Filesystem access
    if (['filesystem', 'fs', 'file', 'directory'].some(k => nameLower.includes(k))) {
        risks.push('filesystem-access');
    }
    
    // Database access
    if (['postgres', 'mysql', 'sqlite', 'mongo', 'redis', 'database'].some(k => nameLower.includes(k))) {
        risks.push('database-access');
    }
    
    // Shell access
    if (['shell', 'exec', 'command', 'bash', 'terminal'].some(k => nameLower.includes(k))) {
        risks.push('shell-access');
    }
    
    // Check for unverified source
    if (!VERIFIED_PUBLISHERS.some(v => sourceLower.includes(v.toLowerCase()))) {
        if (!sourceLower.startsWith('@')) {
            risks.push('unverified-source');
        }
    }
    
    return risks;
}

// Display results
function displayResults() {
    progressSection.classList.add('hidden');

    if (scanResults.length === 0) {
        noResultsSection.classList.remove('hidden');
        return;
    }

    resultsSection.classList.remove('hidden');

    // Detect secrets in all scan results (detection first, display later)
    const allSecrets = [];
    for (const r of scanResults) {
        const env = r.rawConfig?.env || {};
        const secrets = detectSecrets(env, r.name);
        r.secrets = secrets;
        allSecrets.push(...secrets);

        // Add secrets-detected risk flag if secrets found
        if (secrets.length > 0 && !r.riskFlags.includes('secrets-detected')) {
            r.riskFlags.push('secrets-detected');
        }
    }

    // Detect API endpoints in all scan results (detection first, display later)
    const allApis = [];
    for (const r of scanResults) {
        const args = r.rawConfig?.args || [];
        const apis = detectApis(r.rawConfig, args, r.name);
        r.apis = apis;
        allApis.push(...apis);
    }

    // Detect AI models in all scan results (detection first, display later)
    const allModels = [];
    for (const r of scanResults) {
        const model = detectModel(r.rawConfig, r.name);
        if (model) {
            r.model = model;
            allModels.push(model);
        }
    }

    // === DISPLAY ORDER: Summary Cards -> MCP Table -> Secrets -> APIs -> Models -> Export ===

    // 1. Summary Cards (FIRST)
    const totalMcps = scanResults.length;
    const uniqueRepos = new Set(scanResults.map(r => r.repository)).size;
    const withRisks = scanResults.filter(r => r.riskFlags.length > 0).length;
    const knownMcps = scanResults.filter(r => r.isKnown).length;
    const unknownMcps = totalMcps - knownMcps;
    const criticalRisk = scanResults.filter(r => r.registryRisk === 'critical').length;
    const withSecrets = scanResults.filter(r => r.secrets && r.secrets.length > 0).length;

    summary.innerHTML = `
        <div class="summary-item">
            <div class="value">${totalMcps}</div>
            <div class="label">MCPs Found</div>
        </div>
        <div class="summary-item">
            <div class="value">${uniqueRepos}</div>
            <div class="label">Repositories</div>
        </div>
        <div class="summary-item ${knownMcps > 0 ? 'success' : ''}">
            <div class="value">${knownMcps}</div>
            <div class="label">Known MCPs</div>
        </div>
        <div class="summary-item ${unknownMcps > 0 ? 'warning' : ''}">
            <div class="value">${unknownMcps}</div>
            <div class="label">Unknown MCPs</div>
        </div>
        <div class="summary-item ${criticalRisk > 0 ? 'danger' : ''}">
            <div class="value">${criticalRisk}</div>
            <div class="label">Critical Risk</div>
        </div>
        <div class="summary-item ${withRisks > 0 ? 'warning' : ''}">
            <div class="value">${withRisks}</div>
            <div class="label">With Risk Flags</div>
        </div>
        ${withSecrets > 0 ? `
        <div class="summary-item danger">
            <div class="value">${withSecrets}</div>
            <div class="label">With Secrets</div>
        </div>
        ` : ''}
        ${allModels.length > 0 ? `
        <div class="summary-item">
            <div class="value">${allModels.length}</div>
            <div class="label">AI Models</div>
        </div>
        ` : ''}
    `;

    // 2. MCP Discovery Results Table (SECOND - expanded by default)
    const tableBannerTitle = document.getElementById('table-banner-title');
    if (tableBannerTitle) {
        tableBannerTitle.textContent = `MCP DISCOVERY RESULTS - ${totalMcps} server(s) found`;
    }

    // Sort results by risk level (critical -> high -> medium -> low -> unknown)
    const riskOrder = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4 };
    const sortedResults = [...scanResults].sort((a, b) => {
        const riskA = riskOrder[a.registryRisk] ?? 4;
        const riskB = riskOrder[b.registryRisk] ?? 4;
        return riskA - riskB;
    });

    // Table with description and risk columns
    resultsBody.innerHTML = sortedResults.map(r => {
        // Build risk indicator - show if heuristic was used
        const riskBadge = getRegistryRiskBadge(r.registryRisk);
        const riskIndicator = r.heuristicRisk
            ? `${riskBadge}<br><span class="badge secondary" title="Calculated via heuristics based on name, config, and env vars">inferred</span>`
            : riskBadge;

        // Get description - from registry or generated
        const description = r.description || 'Unknown MCP server';

        return `
            <tr>
                <td class="name-cell">${escapeHtml(r.name)}</td>
                <td class="description-cell">${escapeHtml(description)}</td>
                <td><code>${escapeHtml(r.source)}</code></td>
                <td>
                    <a href="https://github.com/${r.repository}/blob/main/${r.filePath}" target="_blank" title="${escapeHtml(r.repository)}">
                        ${escapeHtml(r.repository.split('/')[1] || r.repository)}
                    </a>
                </td>
                <td>${r.isKnown ? '<span class="badge success">Yes</span>' : '<span class="badge danger">No</span>'}</td>
                <td>${riskIndicator}</td>
                <td>${r.riskFlags.length > 0 ? r.riskFlags.map(f => `<span class="risk-flag ${getRiskLevel(f)} has-tooltip" title="${escapeHtml(getRiskFlagTooltip(f))}">${f}</span>`).join(' ') : '<span class="text-muted">-</span>'}</td>
            </tr>
        `;
    }).join('');

    // Expand the MCP Discovery Results table by default
    const tableDetail = document.getElementById('table-detail');
    const tableToggleIcon = document.getElementById('table-toggle-icon');
    if (tableDetail) {
        tableDetail.classList.add('expanded');
    }
    if (tableToggleIcon) {
        tableToggleIcon.textContent = '▼';
    }

    // 3. Now display Secrets, APIs, Models AFTER the table
    const tableBanner = document.getElementById('table-banner');

    // Display secrets alert - insert after table
    if (allSecrets.length > 0) {
        displaySecretsAlertAfterTable(allSecrets, tableBanner);
    }

    // Display APIs inventory - insert after secrets (or after table)
    if (allApis.length > 0) {
        displayApisInventoryAfterTable(allApis, tableBanner);
    }

    // Display AI Models inventory - insert after APIs (or after table)
    if (allModels.length > 0) {
        displayModelsInventoryAfterTable(allModels, tableBanner);
    }

    // Display remediation section
    displayRemediationSection(scanResults);

    // Show report section for PDF/email option
    showReportSection();
}

// Get badge for registry risk level with tooltip
function getRegistryRiskBadge(risk) {
    const styles = {
        critical: 'danger',
        high: 'warning',
        medium: 'info',
        low: 'success',
        unknown: 'secondary',
    };
    const tooltip = getRiskLevelTooltip(risk);
    return `<span class="badge ${styles[risk] || 'secondary'} has-tooltip" title="${escapeHtml(tooltip)}">${risk.toUpperCase()}</span>`;
}

// Get risk level for styling
function getRiskLevel(flag) {
    const flagInfo = RISK_FLAGS[flag];
    if (flagInfo && flagInfo.severity) {
        return flagInfo.severity;
    }
    return 'unknown';
}

// Get tooltip text for a risk flag
function getRiskFlagTooltip(flag) {
    const flagInfo = RISK_FLAGS[flag];
    if (flagInfo) {
        return `${flagInfo.explanation}\n\nFix: ${flagInfo.remediation}`;
    }
    return flag;
}

// Get tooltip text for a risk level
function getRiskLevelTooltip(level) {
    const levelInfo = RISK_LEVELS[level?.toLowerCase()];
    if (levelInfo) {
        return `${levelInfo.definition}\n\nCriteria: ${levelInfo.criteria}\n\nRemediation: ${levelInfo.remediation}`;
    }
    return level;
}

// Export results
function exportResults(format) {
    let content, filename, mimeType;

    if (format === 'json') {
        content = JSON.stringify({
            scan_time: new Date().toISOString(),
            total_mcps: scanResults.length,
            known_mcps: scanResults.filter(r => r.isKnown).length,
            unknown_mcps: scanResults.filter(r => !r.isKnown).length,
            mcps: scanResults,
        }, null, 2);
        filename = 'mcp-audit-results.json';
        mimeType = 'application/json';

    } else if (format === 'csv') {
        const headers = 'name,source,repository,file_path,type,is_known,provider,registry_risk,risk_flags';
        const rows = scanResults.map(r =>
            `"${r.name}","${r.source}","${r.repository}","${r.filePath}","${r.type}","${r.isKnown}","${r.provider}","${r.registryRisk}","${r.riskFlags.join('|')}"`
        );
        content = [headers, ...rows].join('\n');
        filename = 'mcp-audit-results.csv';
        mimeType = 'text/csv';

    } else if (format === 'markdown') {
        const knownCount = scanResults.filter(r => r.isKnown).length;
        const unknownCount = scanResults.filter(r => !r.isKnown).length;
        content = `# MCP Audit Report

**Scan Time:** ${new Date().toLocaleString()}
**Total MCPs Found:** ${scanResults.length}
**Known MCPs:** ${knownCount}
**Unknown MCPs:** ${unknownCount}

## MCP Inventory

| MCP Name | Source | Repository | Type | Known | Provider | Reg Risk | Risk Flags |
|----------|--------|------------|------|-------|----------|----------|------------|
${scanResults.map(r =>
    `| ${r.name} | ${r.source} | ${r.repository} | ${r.type} | ${r.isKnown ? 'Yes' : 'No'} | ${r.provider} | ${r.registryRisk} | ${r.riskFlags.join(', ') || '-'} |`
).join('\n')}
`;
        filename = 'mcp-audit-results.md';
        mimeType = 'text/markdown';
    }

    // Track export
    trackEvent({
        event: 'export',
        export_format: format,
        mcps_found: scanResults.length
    });

    // Download
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
}

// Reset to org selection
function resetToOrgSelect() {
    progressSection.classList.add('hidden');
    resultsSection.classList.add('hidden');
    noResultsSection.classList.add('hidden');
    connectSection.classList.remove('hidden');
    orgSection.classList.remove('hidden');
    scanResults = [];
}

// Utility functions
function showStatus(element, message, type) {
    element.textContent = message;
    element.className = `status ${type}`;
    element.classList.remove('hidden');
}

function updateProgress(percent, text) {
    progressFill.style.width = `${percent}%`;
    progressText.textContent = text;
}

function log(message, type = '') {
    const entry = document.createElement('div');
    entry.className = `log-entry ${type}`;
    entry.textContent = `> ${message}`;
    scanLog.appendChild(entry);
    scanLog.scrollTop = scanLog.scrollHeight;
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Build findings for remediation section
function buildFindings(results) {
    const flagToMcps = {};
    for (const r of results) {
        for (const flag of r.riskFlags) {
            if (!flagToMcps[flag]) {
                flagToMcps[flag] = [];
            }
            flagToMcps[flag].push(r.name);
        }
    }

    const findings = [];
    for (const [flag, mcps] of Object.entries(flagToMcps)) {
        const flagInfo = RISK_FLAGS[flag] || {};
        findings.push({
            flag,
            severity: flagInfo.severity || 'unknown',
            mcps,
            explanation: flagInfo.explanation || 'Unknown risk flag',
            remediation: flagInfo.remediation || 'Review manually',
        });
    }

    // Sort by severity: critical first, then high, medium, low, unknown
    // Note: Using explicit check because 0 is falsy in JavaScript
    const severityOrder = { critical: 1, high: 2, medium: 3, low: 4, unknown: 5 };
    findings.sort((a, b) => {
        const orderA = severityOrder[a.severity] || 5;
        const orderB = severityOrder[b.severity] || 5;
        return orderA - orderB;
    });

    return findings;
}

// Get specific remediation steps for a secret type
function getSecretRemediation(secret) {
    const steps = [];
    const type = secret.type;
    const url = secret.rotation_url;

    // Step 1: Rotate - specific to each provider
    switch (type) {
        case 'github_pat':
        case 'github_oauth':
            steps.push(`<a href="${url}" target="_blank" class="rotate-link">Go to GitHub Settings → Tokens</a> and delete this token, then create a new one`);
            steps.push('Update your MCP config with the new token');
            break;
        case 'slack_token':
            steps.push(`<a href="${url}" target="_blank" class="rotate-link">Go to Slack API → Your Apps</a> and regenerate the bot token`);
            steps.push('Update SLACK_BOT_TOKEN in your MCP config');
            break;
        case 'openai_key':
        case 'openai_project_key':
            steps.push(`<a href="${url}" target="_blank" class="rotate-link">Go to OpenAI API Keys</a> and revoke this key, then create a new one`);
            steps.push('Update OPENAI_API_KEY in your MCP config');
            break;
        case 'anthropic_key':
            steps.push(`<a href="${url}" target="_blank" class="rotate-link">Go to Anthropic Console → API Keys</a> and delete this key, then create a new one`);
            steps.push('Update ANTHROPIC_API_KEY in your MCP config');
            break;
        case 'aws_access_key':
            steps.push(`<a href="${url}" target="_blank" class="rotate-link">Go to AWS IAM Console</a> and deactivate/delete this access key`);
            steps.push('Create new access key and update AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY');
            break;
        case 'stripe_live':
            steps.push(`<a href="${url}" target="_blank" class="rotate-link">Go to Stripe Dashboard → API Keys</a> and roll the secret key`);
            steps.push('Update your MCP config with the new key (CRITICAL: This is a LIVE key!)');
            break;
        case 'postgres_conn':
        case 'mongodb_conn':
            steps.push('Change the database password immediately in your database admin console');
            steps.push('Update the connection string in your MCP config with the new password');
            steps.push('Review database access logs for unauthorized access');
            break;
        case 'private_key':
            steps.push('Generate a new key pair and replace the compromised private key');
            steps.push('Update any systems that use the corresponding public key');
            steps.push('Revoke certificates associated with the old key');
            break;
        case 'sendgrid_key':
            steps.push(`<a href="${url}" target="_blank" class="rotate-link">Go to SendGrid → API Keys</a> and delete this key`);
            steps.push('Create a new API key with minimum required permissions');
            break;
        case 'discord_token':
            steps.push(`<a href="${url}" target="_blank" class="rotate-link">Go to Discord Developer Portal</a> and regenerate the bot token`);
            steps.push('Update your MCP config with the new token');
            break;
        case 'npm_token':
            steps.push(`<a href="${url}" target="_blank" class="rotate-link">Go to npmjs.com → Access Tokens</a> and delete this token`);
            steps.push('Create a new token with appropriate permissions');
            break;
        case 'google_api_key':
            steps.push(`<a href="${url}" target="_blank" class="rotate-link">Go to Google Cloud Console → Credentials</a>`);
            steps.push('Delete the compromised key and create a new one with API restrictions');
            break;
        default:
            // Generic secret
            if (url) {
                steps.push(`<a href="${url}" target="_blank" class="rotate-link">Rotate this credential</a>`);
            } else {
                steps.push('Rotate this credential through your provider\'s console');
            }
            steps.push('Update your MCP configuration with the new value');
    }

    // Common final steps for all secrets in Git repos
    steps.push('Remove the secret from the config file (use environment variables instead)');
    steps.push('Scrub from Git history: <code>git filter-branch</code> or <a href="https://rtyley.github.io/bfg-repo-cleaner/" target="_blank">BFG Repo-Cleaner</a>');

    return steps;
}

// Display secrets alert banner
function displaySecretsAlert(secrets) {
    if (!secrets || secrets.length === 0) return;

    // Count by severity
    const critical = secrets.filter(s => s.severity === 'critical').length;
    const high = secrets.filter(s => s.severity === 'high').length;
    const medium = secrets.filter(s => s.severity === 'medium').length;

    // Create or get secrets alert container
    let alertDiv = document.getElementById('secrets-alert');
    if (!alertDiv) {
        alertDiv = document.createElement('div');
        alertDiv.id = 'secrets-alert';
        alertDiv.className = 'secrets-alert';
        // Insert before summary
        const summaryEl = document.getElementById('summary');
        if (summaryEl) {
            summaryEl.parentNode.insertBefore(alertDiv, summaryEl);
        }
    }

    // Sort by severity
    const severityOrder = { critical: 0, high: 1, medium: 2 };
    const sortedSecrets = [...secrets].sort((a, b) =>
        (severityOrder[a.severity] || 2) - (severityOrder[b.severity] || 2)
    );

    const secretsHtml = sortedSecrets.map(s => {
        const severityClass = s.severity === 'critical' ? 'danger' : (s.severity === 'high' ? 'warning' : 'info');

        // Build specific remediation based on secret type
        const remediation = getSecretRemediation(s);

        return `
            <div class="secret-item ${severityClass}">
                <div class="secret-header">
                    <span class="badge ${severityClass}">${s.severity.toUpperCase()}</span>
                    <strong>${escapeHtml(s.description)}</strong>
                </div>
                <div class="secret-details">
                    <p><strong>Location:</strong> ${escapeHtml(s.mcp_name)} → <code>${escapeHtml(s.env_key)}</code></p>
                    <p><strong>Value:</strong> <code>${escapeHtml(s.value_masked)}</code> (${s.value_length} chars)</p>
                    <p><strong>Remediation:</strong></p>
                    <ol class="remediation-steps">
                        ${remediation.map(step => `<li>${step}</li>`).join('')}
                    </ol>
                </div>
            </div>
        `;
    }).join('');

    const summaryParts = [];
    if (critical) summaryParts.push(`<span class="text-danger">${critical} critical</span>`);
    if (high) summaryParts.push(`<span class="text-warning">${high} high</span>`);
    if (medium) summaryParts.push(`<span class="text-info">${medium} medium</span>`);

    alertDiv.innerHTML = `
        <div class="secrets-alert-header" onclick="toggleSecretsDetail()">
            <div class="secrets-alert-title">
                <span class="alert-icon">⚠️</span>
                <strong>${secrets.length} SECRET(S) DETECTED - IMMEDIATE ACTION REQUIRED</strong>
            </div>
            <span class="toggle-icon">▶</span>
        </div>
        <div class="secrets-alert-summary">
            ${summaryParts.join(' • ')}
            <span class="text-muted"> - Rotate ALL exposed credentials before continuing</span>
        </div>
        <div id="secrets-detail" class="secrets-detail">
            ${secretsHtml}
        </div>
    `;
}

// Toggle secrets detail visibility
function toggleSecretsDetail() {
    const detail = document.getElementById('secrets-detail');
    const icon = document.querySelector('.secrets-alert .toggle-icon');
    if (detail) {
        detail.classList.toggle('expanded');
        if (icon) {
            icon.textContent = detail.classList.contains('expanded') ? '▼' : '▶';
        }
    }
}

// Display APIs inventory
function displayApisInventory(apis) {
    if (!apis || apis.length === 0) return;

    // Group by category
    const byCategory = {};
    for (const api of apis) {
        const cat = api.category || 'unknown';
        if (!byCategory[cat]) byCategory[cat] = [];
        byCategory[cat].push(api);
    }

    // Create or get API inventory container
    let inventoryDiv = document.getElementById('apis-inventory');
    if (!inventoryDiv) {
        inventoryDiv = document.createElement('div');
        inventoryDiv.id = 'apis-inventory';
        inventoryDiv.className = 'apis-inventory';
        // Insert after secrets alert (if exists) or before summary
        const secretsAlert = document.getElementById('secrets-alert');
        const summaryEl = document.getElementById('summary');
        if (secretsAlert && secretsAlert.parentNode) {
            secretsAlert.parentNode.insertBefore(inventoryDiv, secretsAlert.nextSibling);
        } else if (summaryEl && summaryEl.parentNode) {
            summaryEl.parentNode.insertBefore(inventoryDiv, summaryEl);
        }
    }

    // Category order
    const categoryOrder = ['database', 'rest_api', 'websocket', 'sse', 'saas', 'cloud', 'unknown'];

    let categoriesHtml = '';
    for (const cat of categoryOrder) {
        if (!byCategory[cat]) continue;
        const catApis = byCategory[cat];
        const info = API_CATEGORY_INFO[cat] || API_CATEGORY_INFO.unknown;

        const apisHtml = catApis.map(api => `
            <div class="api-item">
                <span class="api-mcp">${escapeHtml(api.mcpName)}</span>
                <span class="api-arrow">→</span>
                <code class="api-url">${escapeHtml(api.maskedUrl)}</code>
                <span class="api-source">(${escapeHtml(api.source)}: ${escapeHtml(api.sourceKey)})</span>
            </div>
        `).join('');

        categoriesHtml += `
            <div class="api-category">
                <div class="api-category-header">
                    <span class="api-icon">${info.icon}</span>
                    <strong>${info.name.toUpperCase()}</strong>
                    <span class="api-count">(${catApis.length})</span>
                </div>
                <div class="api-items">
                    ${apisHtml}
                </div>
            </div>
        `;
    }

    inventoryDiv.innerHTML = `
        <div class="apis-inventory-header" onclick="toggleApisInventory()">
            <div class="apis-inventory-title">
                <span class="inventory-icon">📡</span>
                <strong>ENDPOINTS DISCOVERED - ${apis.length} connection(s)</strong>
            </div>
            <span class="toggle-icon">▶</span>
        </div>
        <div id="apis-detail" class="apis-detail">
            ${categoriesHtml}
        </div>
    `;
}

// Toggle APIs inventory visibility
function toggleApisInventory() {
    const detail = document.getElementById('apis-detail');
    const icon = document.querySelector('.apis-inventory .toggle-icon');
    if (detail) {
        detail.classList.toggle('expanded');
        if (icon) {
            icon.textContent = detail.classList.contains('expanded') ? '▼' : '▶';
        }
    }
}

// Display AI Models inventory
function displayModelsInventory(models) {
    if (!models || models.length === 0) return;

    // Group by provider
    const byProvider = {};
    for (const model of models) {
        const provider = model.provider || 'Unknown';
        if (!byProvider[provider]) byProvider[provider] = [];
        byProvider[provider].push(model);
    }

    // Count by hosting
    const byHosting = { cloud: 0, local: 0, unknown: 0 };
    for (const model of models) {
        const hosting = model.hosting || 'unknown';
        if (hosting in byHosting) byHosting[hosting]++;
    }

    // Create or get models inventory container
    let inventoryDiv = document.getElementById('models-inventory');
    if (!inventoryDiv) {
        inventoryDiv = document.createElement('div');
        inventoryDiv.id = 'models-inventory';
        inventoryDiv.className = 'models-inventory';
        // Insert after APIs inventory (if exists) or after secrets alert or before summary
        const apisInventory = document.getElementById('apis-inventory');
        const secretsAlert = document.getElementById('secrets-alert');
        const summaryEl = document.getElementById('summary');
        if (apisInventory && apisInventory.parentNode) {
            apisInventory.parentNode.insertBefore(inventoryDiv, apisInventory.nextSibling);
        } else if (secretsAlert && secretsAlert.parentNode) {
            secretsAlert.parentNode.insertBefore(inventoryDiv, secretsAlert.nextSibling);
        } else if (summaryEl && summaryEl.parentNode) {
            summaryEl.parentNode.insertBefore(inventoryDiv, summaryEl);
        }
    }

    // Sort providers by count
    const sortedProviders = Object.entries(byProvider).sort((a, b) => b[1].length - a[1].length);

    let providersHtml = '';
    for (const [provider, providerModels] of sortedProviders) {
        const info = MODEL_PROVIDER_INFO[provider] || MODEL_PROVIDER_INFO.Unknown;
        const barWidth = Math.min(providerModels.length * 4, 20);

        const modelsHtml = providerModels.map(model => `
            <div class="model-item">
                <span class="model-name">${escapeHtml(model.modelName)}</span>
                <span class="model-hosting ${model.hosting}">${model.hosting === 'cloud' ? '☁️ Cloud' : model.hosting === 'local' ? '🏠 Local' : '❓ Unknown'}</span>
                <span class="model-mcp">(${escapeHtml(model.mcpName)})</span>
            </div>
        `).join('');

        providersHtml += `
            <div class="model-provider">
                <div class="model-provider-header">
                    <span class="model-icon">${info.icon}</span>
                    <strong>${escapeHtml(provider)}</strong>
                    <span class="model-bar" style="width: ${barWidth * 10}px; background: ${info.color}"></span>
                    <span class="model-count">${providerModels.length}</span>
                </div>
                <div class="model-items">
                    ${modelsHtml}
                </div>
            </div>
        `;
    }

    // Hosting summary
    const hostingHtml = `
        <div class="model-hosting-summary">
            <span class="hosting-label">By Hosting:</span>
            ${byHosting.cloud > 0 ? `<span class="hosting-badge cloud">☁️ Cloud: ${byHosting.cloud}</span>` : ''}
            ${byHosting.local > 0 ? `<span class="hosting-badge local">🏠 Local: ${byHosting.local}</span>` : ''}
        </div>
    `;

    inventoryDiv.innerHTML = `
        <div class="models-inventory-header" onclick="toggleModelsInventory()">
            <div class="models-inventory-title">
                <span class="inventory-icon">🤖</span>
                <strong>AI MODELS - ${models.length} model(s) detected</strong>
            </div>
            <span class="toggle-icon">▶</span>
        </div>
        <div id="models-detail" class="models-detail">
            ${hostingHtml}
            ${providersHtml}
        </div>
    `;
}

// Toggle Models inventory visibility
function toggleModelsInventory() {
    const detail = document.getElementById('models-detail');
    const icon = document.querySelector('.models-inventory .toggle-icon');
    if (detail) {
        detail.classList.toggle('expanded');
        if (icon) {
            icon.textContent = detail.classList.contains('expanded') ? '▼' : '▶';
        }
    }
}

// Display remediation section
function displayRemediationSection(results) {
    const remediationDiv = document.getElementById('remediation-section');
    if (!remediationDiv) return;

    const findings = buildFindings(results);

    if (findings.length === 0) {
        remediationDiv.innerHTML = `
            <div class="findings-banner">
                <div class="findings-banner-header">
                    <div class="findings-banner-title">
                        <span class="inventory-icon">🔍</span>
                        <strong>FINDINGS & REMEDIATION</strong>
                    </div>
                </div>
                <div class="findings-detail expanded">
                    <p class="success-message" style="padding: 1rem 1.25rem;">✓ No risk flags detected. All MCPs appear safe.</p>
                </div>
            </div>
        `;
        remediationDiv.classList.remove('hidden');
        return;
    }

    const findingsHtml = findings.map(f => {
        const badgeClass = f.severity === 'critical' ? 'danger' : (f.severity === 'high' ? 'warning' : (f.severity === 'medium' ? 'info' : 'secondary'));
        return `
            <div class="finding-item">
                <div class="finding-header">
                    <span class="badge ${badgeClass}">${f.severity.toUpperCase()}</span>
                    <strong>${f.flag}</strong>
                    <span class="mcp-count">(${f.mcps.length} MCP${f.mcps.length > 1 ? 's' : ''} affected)</span>
                </div>
                <div class="finding-body">
                    <p><strong>Why:</strong> ${escapeHtml(f.explanation)}</p>
                    <p><strong>Fix:</strong> ${escapeHtml(f.remediation)}</p>
                    <p><strong>MCPs:</strong> ${f.mcps.map(m => escapeHtml(m)).join(', ')}</p>
                </div>
            </div>
        `;
    }).join('');

    const criticalCount = findings.filter(f => f.severity === 'critical').length;
    const highCount = findings.filter(f => f.severity === 'high').length;
    const countText = criticalCount > 0 ? `${criticalCount} critical, ${highCount} high` : `${findings.length} finding(s)`;

    remediationDiv.innerHTML = `
        <div class="findings-banner">
            <div class="findings-banner-header" onclick="toggleRemediation()">
                <div class="findings-banner-title">
                    <span class="inventory-icon">🔍</span>
                    <strong>FINDINGS & REMEDIATION - ${countText}</strong>
                </div>
                <span class="toggle-icon" id="findings-toggle-icon">▶</span>
            </div>
            <div class="findings-detail">
                ${findingsHtml}
            </div>
        </div>
    `;
    remediationDiv.classList.remove('hidden');
}

// Toggle remediation section visibility
function toggleRemediation() {
    const content = document.querySelector('.findings-detail');
    const icon = document.getElementById('findings-toggle-icon');
    if (content && icon) {
        content.classList.toggle('expanded');
        icon.textContent = content.classList.contains('expanded') ? '▼' : '▶';
    }
}

// Toggle export section visibility
function toggleExportSection() {
    const detail = document.getElementById('export-detail');
    const icon = document.getElementById('export-toggle-icon');
    if (detail && icon) {
        detail.classList.toggle('expanded');
        icon.textContent = detail.classList.contains('expanded') ? '▼' : '▶';
    }
}

// Toggle table section visibility
function toggleTableSection() {
    const detail = document.getElementById('table-detail');
    const icon = document.getElementById('table-toggle-icon');
    if (detail && icon) {
        detail.classList.toggle('expanded');
        icon.textContent = detail.classList.contains('expanded') ? '▼' : '▶';
    }
}

// Initialize tooltips with smart positioning
function initTooltips() {
    let tooltipEl = null;

    document.addEventListener('mouseover', (e) => {
        const target = e.target.closest('.has-tooltip');
        if (!target) return;

        const text = target.getAttribute('title');
        if (!text) return;

        // Store and remove title to prevent default tooltip
        target.setAttribute('data-tooltip', text);
        target.removeAttribute('title');

        // Create tooltip element
        tooltipEl = document.createElement('div');
        tooltipEl.className = 'tooltip-popup';
        tooltipEl.textContent = text;
        document.body.appendChild(tooltipEl);

        // Position tooltip
        const rect = target.getBoundingClientRect();
        const tooltipRect = tooltipEl.getBoundingClientRect();

        let top, left;
        const padding = 8;

        // Check if there's room above
        if (rect.top > tooltipRect.height + padding + 12) {
            // Show above
            top = rect.top - tooltipRect.height - padding;
            tooltipEl.classList.add('above');
        } else {
            // Show below
            top = rect.bottom + padding;
            tooltipEl.classList.add('below');
        }

        // Center horizontally, but keep within viewport
        left = rect.left + (rect.width / 2) - (tooltipRect.width / 2);
        left = Math.max(padding, Math.min(left, window.innerWidth - tooltipRect.width - padding));

        tooltipEl.style.top = `${top}px`;
        tooltipEl.style.left = `${left}px`;
    });

    document.addEventListener('mouseout', (e) => {
        const target = e.target.closest('.has-tooltip');
        if (!target) return;

        // Restore title
        const text = target.getAttribute('data-tooltip');
        if (text) {
            target.setAttribute('title', text);
            target.removeAttribute('data-tooltip');
        }

        // Remove tooltip
        if (tooltipEl) {
            tooltipEl.remove();
            tooltipEl = null;
        }
    });
}

// Initialize tooltips when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initTooltips);
} else {
    initTooltips();
}

// ============================================
// PDF Report Functions
// ============================================

// Backend endpoint for report generation
const REPORT_API_URL = 'https://mcp-audit-api.vercel.app/api/report';
const REPORT_API_KEY = 'a85eeddadf75ea8ff5dea73b3e823a6ce804fddd0d7f7d8dd8147c5d112b5c52';

// Validate email format
function validateEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
}

// Build scan summary for sending (no actual secret values)
function buildScanSummary() {
    const totalMcps = scanResults.length;
    const criticalRisk = scanResults.filter(r => r.registryRisk === 'critical').length;
    const highRisk = scanResults.filter(r => r.registryRisk === 'high').length;
    const mediumRisk = scanResults.filter(r => r.registryRisk === 'medium').length;
    const lowRisk = scanResults.filter(r => r.registryRisk === 'low').length;

    // Count secrets and APIs
    const allSecrets = scanResults.flatMap(r => r.secrets || []);
    const allApis = scanResults.flatMap(r => r.apis || []);
    const allModels = scanResults.filter(r => r.model).length;

    // Return structure matching backend API expectations
    return {
        total_mcps: totalMcps,
        secrets_count: allSecrets.length,
        apis_count: allApis.length,
        models_count: allModels,
        risk_breakdown: {
            critical: criticalRisk,
            high: highRisk,
            medium: mediumRisk,
            low: lowRisk
        },
        // MCP list (names only, no secrets)
        mcps: scanResults.map(r => ({
            name: r.name,
            source: r.source,
            risk_level: r.registryRisk
        }))
    };
}

// Send report to email via backend
async function sendReportToEmail(email) {
    const statusEl = document.getElementById('report-status');
    const sendBtn = document.getElementById('send-report-btn');
    const emailInput = document.getElementById('report-email');

    // Validate email
    if (!validateEmail(email)) {
        statusEl.className = 'report-status error';
        statusEl.textContent = 'Please enter a valid email address.';
        emailInput.classList.add('error');
        return false;
    }

    emailInput.classList.remove('error');

    // Show loading state
    sendBtn.classList.add('loading');
    sendBtn.disabled = true;
    statusEl.className = 'report-status loading';
    statusEl.textContent = 'Sending report...';

    try {
        const summary = buildScanSummary();

        const response = await fetch(REPORT_API_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-API-Key': REPORT_API_KEY
            },
            body: JSON.stringify({
                email: email,
                source: 'web',
                scan_type: 'local',
                timestamp: new Date().toISOString(),
                summary: summary
            })
        });

        if (response.ok) {
            statusEl.className = 'report-status success';
            statusEl.textContent = 'Report sent! Check your inbox shortly.';
            trackEvent({ event: 'report_sent', source: 'web_app', method: 'email' });
            return true;
        } else {
            throw new Error('Failed to send report');
        }
    } catch (error) {
        statusEl.className = 'report-status error';
        statusEl.textContent = 'Failed to send report. Please try again.';
        console.error('Report send error:', error);
        return false;
    } finally {
        sendBtn.classList.remove('loading');
        sendBtn.disabled = false;
    }
}

// Export results as JSON (for CI/CD)
function exportResultsJson() {
    const data = {
        scan_time: new Date().toISOString(),
        source: 'web_app',
        mcps: scanResults.map(r => ({
            name: r.name,
            source: r.source,
            repository: r.repository,
            is_known: r.isKnown,
            registry_risk: r.registryRisk,
            risk_flags: r.riskFlags,
            secrets_count: (r.secrets || []).length,
            apis_count: (r.apis || []).length
        })),
        summary: buildScanSummary()
    };

    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `mcp-audit-${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);

    trackEvent({ event: 'export_json', source: 'web_app' });
}

// Export results as CSV (for spreadsheets)
function exportResultsCsv() {
    const headers = ['Name', 'Source', 'Repository', 'Known', 'Risk Level', 'Risk Flags', 'Secrets Count', 'APIs Count'];
    const rows = scanResults.map(r => [
        r.name,
        r.source,
        r.repository,
        r.isKnown ? 'Yes' : 'No',
        r.registryRisk || 'unknown',
        (r.riskFlags || []).join('; '),
        (r.secrets || []).length,
        (r.apis || []).length
    ]);

    const csvContent = [headers, ...rows]
        .map(row => row.map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(','))
        .join('\n');

    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `mcp-audit-${new Date().toISOString().split('T')[0]}.csv`;
    a.click();
    URL.revokeObjectURL(url);

    trackEvent({ event: 'export_csv', source: 'web_app' });
}

// Export results as CycloneDX AI-BOM (for supply chain security)
function exportResultsCycloneDX() {
    const serialNumber = `urn:uuid:${crypto.randomUUID()}`;
    const timestamp = new Date().toISOString();

    // Collect AI models
    const modelComponents = [];
    const mcpComponents = [];
    const dependencies = [];

    for (const r of scanResults) {
        const mcpRef = `mcp:${r.name}`;

        // Add MCP component
        mcpComponents.push({
            type: "application",
            "bom-ref": mcpRef,
            name: r.name,
            supplier: { name: r.provider || "Unknown" },
            description: r.description || `MCP server (${r.sourceType || 'unknown'})`,
            properties: [
                { name: "source", value: r.source },
                { name: "server_type", value: r.sourceType || "unknown" },
                { name: "found_in", value: r.repository || "unknown" },
                { name: "registry_known", value: String(r.isKnown) },
                { name: "registry_risk", value: r.registryRisk || "unknown" },
                { name: "risk_flags", value: (r.riskFlags || []).join(",") }
            ]
        });

        // Add model if detected
        if (r.model) {
            const modelRef = `model:${r.model.provider.toLowerCase().replace(/ /g, '-')}:${r.model.modelId}`;

            modelComponents.push({
                type: "machine-learning-model",
                "bom-ref": modelRef,
                name: r.model.modelName,
                version: extractModelVersion(r.model.modelId),
                supplier: { name: r.model.provider },
                description: `AI model used by ${r.name} MCP`,
                properties: [
                    { name: "hosting", value: r.model.hosting },
                    { name: "source", value: r.model.source },
                    { name: "mcp", value: r.name }
                ],
                modelCard: {
                    modelArchitecture: inferModelArchitecture(r.model.modelName, r.model.provider),
                    modelParameters: {
                        task: inferModelTask(r.model.modelName)
                    }
                }
            });

            dependencies.push({
                ref: modelRef,
                dependsOn: [mcpRef]
            });
        }
    }

    const bom = {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        bomFormat: "CycloneDX",
        specVersion: "1.6",
        serialNumber: serialNumber,
        version: 1,
        metadata: {
            timestamp: timestamp,
            tools: {
                components: [{
                    type: "application",
                    name: "mcp-audit",
                    publisher: "APIsec",
                    version: "1.0.0",
                    description: "MCP configuration security audit tool"
                }]
            },
            component: {
                type: "application",
                name: "mcp-environment",
                description: "MCP-enabled AI development environment"
            }
        },
        components: [...modelComponents, ...mcpComponents],
        dependencies: dependencies
    };

    const jsonString = JSON.stringify(bom, null, 2);
    const blob = new Blob([jsonString], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `mcp-audit-ai-bom-${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);

    trackEvent({ event: 'export_cyclonedx', source: 'web_app' });
}

// Helper: Extract version from model ID
function extractModelVersion(modelId) {
    if (!modelId) return "latest";
    const parts = modelId.split("-");
    for (const part of parts) {
        if (part.length === 8 && /^\d+$/.test(part)) {
            return `${part.slice(0,4)}-${part.slice(4,6)}-${part.slice(6)}`;
        }
    }
    return "latest";
}

// Helper: Infer model architecture
function inferModelArchitecture(modelName, provider) {
    const name = (modelName || '').toLowerCase();
    if (name.includes('llama')) return "Llama Transformer";
    if (name.includes('mistral') || name.includes('mixtral')) return "Mistral Architecture";
    if (name.includes('gpt') || provider === 'OpenAI') return "GPT Transformer";
    if (name.includes('claude') || provider === 'Anthropic') return "Constitutional AI";
    if (name.includes('gemini') || name.includes('gemma')) return "Gemini Architecture";
    return "Transformer";
}

// Helper: Infer model task
function inferModelTask(modelName) {
    const name = (modelName || '').toLowerCase();
    if (name.includes('code')) return "code-generation";
    if (name.includes('embed')) return "text-embedding";
    if (name.includes('vision') || name.includes('image')) return "image-understanding";
    return "text-generation";
}

// Show the report section when results are available
function showReportSection() {
    const reportSection = document.getElementById('report-section');
    if (reportSection && scanResults.length > 0) {
        reportSection.style.display = 'block';
    }
}

// Hide the report section
function hideReportSection() {
    const reportSection = document.getElementById('report-section');
    if (reportSection) {
        reportSection.style.display = 'none';
    }
}

// Initialize report section event listeners
function initReportSection() {
    const sendBtn = document.getElementById('send-report-btn');
    const emailInput = document.getElementById('report-email');
    const exportJsonBtn = document.getElementById('export-json-btn');
    const exportCsvBtn = document.getElementById('export-csv-btn');

    if (sendBtn) {
        sendBtn.addEventListener('click', () => {
            const email = emailInput?.value?.trim() || '';
            sendReportToEmail(email);
        });
    }

    // Export buttons in report section
    if (exportJsonBtn) {
        exportJsonBtn.addEventListener('click', () => {
            exportResultsJson();
        });
    }

    if (exportCsvBtn) {
        exportCsvBtn.addEventListener('click', () => {
            exportResultsCsv();
        });
    }

    const exportCycloneDxBtn = document.getElementById('export-cyclonedx-btn');
    if (exportCycloneDxBtn) {
        exportCycloneDxBtn.addEventListener('click', () => {
            exportResultsCycloneDX();
        });
    }

    // Clear error state on input
    if (emailInput) {
        emailInput.addEventListener('input', () => {
            emailInput.classList.remove('error');
            const statusEl = document.getElementById('report-status');
            if (statusEl && statusEl.classList.contains('error')) {
                statusEl.className = 'report-status';
            }
        });

        // Allow Enter key to submit
        emailInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                const email = emailInput.value?.trim() || '';
                sendReportToEmail(email);
            }
        });
    }

    // Initially hide report section
    hideReportSection();
}

// Initialize report section when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initReportSection);
} else {
    initReportSection();
}

// Copy checksum to clipboard
function copyChecksum() {
    const checksum = document.getElementById('cli-checksum')?.textContent;
    if (checksum) {
        navigator.clipboard.writeText(checksum).then(() => {
            const btn = document.querySelector('.copy-btn');
            if (btn) {
                const originalText = btn.textContent;
                btn.textContent = 'Copied!';
                setTimeout(() => {
                    btn.textContent = originalText;
                }, 2000);
            }
        });
    }
}
