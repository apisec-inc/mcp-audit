# `mcp-audit source-scan`

Scan an MCP server's source code for code-level vulnerabilities the server author may have introduced. Distinct from `mcp-audit scan`, which inventories MCP **configurations** across your machine.

```bash
mcp-audit source-scan ./packages/my-mcp-server
```

## What it catches today

### Shell injection ("Prompt In, Shell Out")

An MCP server that pipes an LLM-controlled tool argument into a shell-spawning API without sanitization. An attacker that controls the LLM's input — including indirect attackers via prompt injection — can inject shell metacharacters into the command and execute arbitrary code on the host running the MCP server.

**JavaScript / TypeScript sinks:**

```js
// Flagged: template literal with interpolation
child_process.exec(`gh issue list --repo ${args.repo}`)

// Flagged: string concatenation
child_process.execSync("git checkout " + branchName)

// Flagged: util.promisify(exec) alias — the classic execAsync pattern
const execAsync = util.promisify(child_process.exec);
await execAsync(`tail ${args.file}`)
```

**Python sinks:**

```python
# Flagged: f-string into subprocess with shell=True
subprocess.run(f"tail -n 100 /var/log/{service}.log", shell=True)

# Flagged: concatenation into os.system
os.system("du -sh " + path)

# Flagged: f-string into os.popen
os.popen(f"ps aux | grep {filter_term}")
```

**Safe patterns (not flagged):**

```js
// SAFE: execFile passes args as an array — no shell involved
execFile("gh", ["issue", "list", "--repo", `${args.owner}/${args.repo}`])

// SAFE: spawn with an array
spawn("git", ["checkout", branchName])
```

```python
# SAFE: argument list, no shell
subprocess.run(["tail", "-n", "100", f"/var/log/{service}.log"])
```

## Confidence and severity

Each finding carries a `confidence` field:

- **`high`** — the dangerous API is called with a template literal, f-string, concatenation, or `%`/`format()`. Interpolation is visibly happening. Severity is **CRITICAL**.
- **`medium`** — the dangerous API is called with a non-literal argument that the scanner can't classify (a function call, a spread). Could still be safe; an analyst should review. Severity is **HIGH**.

Pure literal calls (`exec("ls -la")`) are not flagged — nothing is being interpolated.

## Output formats

```bash
# Human-readable table (default)
mcp-audit source-scan ./my-mcp

# JSON for CI integrations / jq pipelines
mcp-audit source-scan ./my-mcp --format json --output findings.json

# SARIF 2.1.0 for upload to GitHub code-scanning, GitLab Advanced Security, etc.
mcp-audit source-scan ./my-mcp --format sarif --output findings.sarif
```

## CI gating

```bash
# Exits non-zero if any critical findings are detected
mcp-audit source-scan ./my-mcp --exit-code
```

Drop into a GitHub Actions workflow:

```yaml
- name: MCP source-scan
  run: |
    pip install mcp-audit
    mcp-audit source-scan ./packages/my-mcp --exit-code

# Or upload findings to GitHub code-scanning:
- name: MCP source-scan (SARIF)
  run: mcp-audit source-scan ./packages/my-mcp --format sarif --output mcp.sarif
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: mcp.sarif }
```

## What the scanner does NOT do

By design, this is a narrow, focused scanner:

- **It only opens files that look like MCP server source.** The gate is "this file (or one of its siblings) imports an MCP SDK." A random Node project in your tree is silently skipped. The cost is missing MCP servers that don't import any recognisable SDK symbol; we accept that miss to keep false-positive noise low.
- **It does not do dataflow analysis.** It reports the sink (the `exec` call) and the visible interpolation, but it does not trace whether the interpolated value actually originates from a tool argument. The risk flag's confidence levels reflect this — `high` means "interpolation is visible," not "tainted data is confirmed."
- **It does not find every shell-injection bug ever written.** Out of scope: shell injection via `eval`, `vm.runInThisContext`, SSH/RPC tunnels, downstream services that themselves call shells, regex-sanitization that's incorrect but not flagged as concatenation. These are real risks; they're just not what this tool addresses today.

## Remediation

The structural fix is to keep the shell out of the loop entirely:

| Don't | Do |
| --- | --- |
| `child_process.exec(\`cmd ${arg}\`)` | `execFile("cmd", [arg])` |
| `child_process.execSync("cmd " + arg)` | `spawnSync("cmd", [arg])` |
| `subprocess.run(f"cmd {arg}", shell=True)` | `subprocess.run(["cmd", arg])` |
| `os.system("cmd " + arg)` | `subprocess.run(["cmd", arg])` |

Regex-based sanitization or escaping is a brittle second line of defence — the moment a contributor adds a new edge case, you're back where you started. The structural fix is to pass arguments as an array so no shell parser is ever invoked.

Run `mcp-audit explain shell-injection-in-source` for the full guidance, including allowlist patterns and test cases.
