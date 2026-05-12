// Fixture: the SAFE form of the vulnerable_mcp_js server. Same purpose,
// but uses execFile so no shell parser is involved.

const { Server } = require("@modelcontextprotocol/sdk/server/index.js");
const { execFile } = require("child_process");
const { promisify } = require("util");

const execFileAsync = promisify(execFile);

const server = new Server({ name: "gh-tools", version: "1.0.0" });

server.setRequestHandler("tools/call", async (request) => {
  const args = request.params.arguments;
  // SAFE: arguments are an array — execFile does not invoke a shell.
  const { stdout } = await execFileAsync("gh", [
    "issue", "list",
    "--repo", `${args.owner}/${args.repo}`,  // string interpolation here is fine
    "--state", args.state,                    // because it never reaches a shell
    "--json", "number,title",
  ]);
  return { content: [{ type: "text", text: stdout }] };
});

server.connect();
