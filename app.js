/**
 * MCP Audit - GitHub Organization Scanner
 *
 * All scanning happens in the browser. No PII is collected.
 * Anonymous usage analytics are sent to help improve the product.
 */

// Analytics endpoint
const ANALYTICS_URL = 'https://script.google.com/a/macros/apisec.ai/s/AKfycbxJ9-VwHe4455XkRElauSC8pWx65q-1OgKWQJNZnafBkfFjbvmOM6qvp07RMwUm0Qml/exec';

// Send analytics event (fire and forget, non-blocking)
function trackEvent(eventData) {
    try {
        fetch(ANALYTICS_URL, {
            method: 'POST',
            mode: 'no-cors', // Required for Google Apps Script
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(eventData)
        }).catch(() => {}); // Silently ignore errors
    } catch (e) {
        // Ignore analytics errors - don't affect user experience
    }
}

// State
let githubToken = '';
let scanResults = [];

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
        trackEvent({ event: 'scan_started', source: 'github', org_name: login });

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
            org_name: login,
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
        source = args[0];
        type = 'npm';
    } else if (command === 'node' && args.length > 0) {
        source = args[0];
        type = 'node';
    } else if (['python', 'python3', 'uvx', 'uv'].includes(command)) {
        source = args.length > 0 ? args[0] : command;
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

    // Summary
    const totalMcps = scanResults.length;
    const uniqueRepos = new Set(scanResults.map(r => r.repository)).size;
    const withRisks = scanResults.filter(r => r.riskFlags.length > 0).length;
    const knownMcps = scanResults.filter(r => r.isKnown).length;
    const unknownMcps = totalMcps - knownMcps;
    const criticalRisk = scanResults.filter(r => r.registryRisk === 'critical').length;

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
    `;

    // Table with description and risk columns
    resultsBody.innerHTML = scanResults.map(r => {
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
                <td>${r.riskFlags.length > 0 ? r.riskFlags.map(f => `<span class="risk-flag ${getRiskLevel(f)}">${f}</span>`).join(' ') : '<span class="text-muted">-</span>'}</td>
            </tr>
        `;
    }).join('');
}

// Get badge for registry risk level
function getRegistryRiskBadge(risk) {
    const styles = {
        critical: 'danger',
        high: 'warning',
        medium: 'info',
        low: 'success',
        unknown: 'secondary',
    };
    return `<span class="badge ${styles[risk] || 'secondary'}">${risk.toUpperCase()}</span>`;
}

// Get risk level for styling
function getRiskLevel(flag) {
    const high = ['shell-access', 'unverified-source'];
    const medium = ['filesystem-access', 'database-access'];
    
    if (high.includes(flag)) return 'high';
    if (medium.includes(flag)) return 'medium';
    return 'low';
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
