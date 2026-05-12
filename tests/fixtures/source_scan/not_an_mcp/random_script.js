// Not an MCP server — just a random Node script with an exec call.
// The scanner should leave this alone because no MCP SDK is referenced.
const { exec } = require("child_process");

function runShell(name) {
  return exec(`echo hello ${name}`);
}
