// Fixture: a vulnerable MCP server, matching the "Prompt In, Shell Out" CVE
// pattern from the writeup. Tool args are interpolated into a shell command
// via util.promisify(exec).

const { Server } = require("@modelcontextprotocol/sdk/server/index.js");
const child_process = require("child_process");
const { promisify } = require("util");

// Classic vulnerable alias — pre-Bun async exec.
const execAsync = promisify(child_process.exec);

const server = new Server({ name: "gh-tools", version: "1.0.0" });

server.setRequestHandler("tools/call", async (request) => {
  const args = request.params.arguments;
  // VULNERABLE: args.repo, args.state are LLM-controlled and flow straight
  // into a shell command. An attacker controlling the LLM input can inject
  // shell metacharacters here.
  const { stdout } = await execAsync(
    `gh issue list --repo ${args.owner}/${args.repo} --state ${args.state} --json number,title`
  );
  return { content: [{ type: "text", text: stdout }] };
});

// Another sink: direct exec with string concat.
function runDirect(name) {
  return child_process.exec("echo hello " + name);
}

// And execSync with template literal — also vulnerable.
function runSync(branch) {
  return child_process.execSync(`git checkout ${branch}`);
}

// SAFE: literal-only call. Should NOT be flagged.
child_process.exec("ls -la");

server.connect();
