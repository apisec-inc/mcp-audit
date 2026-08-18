"""
Argument-injection-prone binaries for command-allowlist bypass detection.

Many MCP servers implement a "command allowlist" by checking only argv[0]
(the binary name) against a list like ALLOW_COMMANDS=git, without inspecting
the rest of argv. That's not a real restriction if the allowlisted binary
itself exposes an argument or config-driven way to run arbitrary commands.

This list is intentionally not closed — add entries as new primitives surface.
"""

# Binary name (as it would appear in argv[0]) -> one-line description of its
# argument/config-level execution primitive.
ARG_INJECTION_PRONE_BINARIES = {
    "git": "git -c alias.<x>=!<cmd> defines a shell alias; -c core.fsmonitor=<cmd> or "
    "-c diff.external=<cmd> also execute arbitrary commands",
    "find": "-exec/-execdir runs an arbitrary command on matched files",
    "python": "-c '<code>' executes arbitrary Python, including os.system()/subprocess calls",
    "python3": "-c '<code>' executes arbitrary Python, including os.system()/subprocess calls",
    "perl": "-e '<code>' executes arbitrary Perl, including system()/exec()",
    "awk": 'system("<cmd>") inside a BEGIN block executes an arbitrary command',
    "gawk": 'system("<cmd>") inside a BEGIN block executes an arbitrary command',
    "sed": "GNU sed's e command/flag (s/.../cmd/e or e cmd) executes an arbitrary shell command",
    "tar": "--checkpoint-action=exec=<cmd> or --to-command=<cmd> executes an arbitrary command",
    "npx": "-c '<script>' runs an arbitrary shell command via the underlying package runner",
    "node": "-e '<code>' executes arbitrary JavaScript, including child_process calls",
    "bash": "-c '<cmd>' runs an arbitrary command string; allowlisting a shell voids the allowlist",
    "sh": "-c '<cmd>' runs an arbitrary command string; allowlisting a shell voids the allowlist",
    "env": "env <cmd> execs an arbitrary binary, so the argv[0] check only ever sees env",
    "xargs": "xargs <cmd> execs an arbitrary command with input-supplied arguments",
    "ssh": "-o ProxyCommand=<cmd>, and -o PermitLocalCommand=yes -o LocalCommand=<cmd>, "
    "execute arbitrary commands on the local host",
}

# Allowlist-style env var keys are recognized by splitting the key on "_" and
# matching whole tokens — NOT by substring. Substring matching is what makes
# DISALLOW_COMMANDS (a denylist) look like an allowlist, since "DISALLOW"
# contains "ALLOW".
_DENY_TOKENS = {
    "DISALLOW",
    "DISALLOWED",
    "DENY",
    "DENIED",
    "BLOCK",
    "BLOCKED",
    "FORBID",
    "FORBIDDEN",
    "EXCLUDE",
    "EXCLUDED",
    "DENYLIST",
    "BLOCKLIST",
    "BLACKLIST",
    "NO",
    "NOT",
    "NEVER",
}

_ALLOW_TOKENS = {"ALLOW", "ALLOWED", "ALLOWLIST", "WHITELIST", "PERMIT", "PERMITTED"}

_SUBJECT_TOKENS = {
    "COMMAND",
    "COMMANDS",
    "CMD",
    "CMDS",
    "PATTERN",
    "PATTERNS",
    "BINARY",
    "BINARIES",
    "EXECUTABLE",
    "EXECUTABLES",
}

# A key must END in one of these, so that a toggle like ALLOW_COMMAND_LOGGING
# (which ends in LOGGING) is not mistaken for a list of allowed commands.
_LIST_TAIL_TOKENS = {"ALLOWLIST", "WHITELIST", "LIST", "ALLOWED", "ALLOW"}

# Characters that separate entries in an allowlist value. Whitespace is
# deliberately NOT a separator: an entry with arguments (e.g. "git status") is
# a full-argument-vector allowlist, which is the safe pattern, not a bare
# binary-name allowlist.
_VALUE_SEPARATORS = [",", ";", "|", "\n"]


def is_allowlist_env_key(key: str) -> bool:
    """Check whether an env var key looks like a command-allowlist declaration."""
    tokens = [t for t in key.upper().replace("-", "_").split("_") if t]
    if not tokens:
        return False

    # A deny-style key (DISALLOW_COMMANDS, COMMAND_DENYLIST, NO_ALLOW_COMMANDS)
    # describes the opposite of this risk.
    if any(t in _DENY_TOKENS for t in tokens):
        return False

    if not any(t in _ALLOW_TOKENS for t in tokens):
        return False
    if not any(t in _SUBJECT_TOKENS for t in tokens):
        return False

    return tokens[-1] in _SUBJECT_TOKENS or tokens[-1] in _LIST_TAIL_TOKENS


def _split_entries(value: str) -> list[str]:
    """Split an allowlist value into individual entries."""
    entries = [value]
    for sep in _VALUE_SEPARATORS:
        next_entries = []
        for e in entries:
            next_entries.extend(e.split(sep))
        entries = next_entries
    return [e.strip() for e in entries if e.strip()]


def _normalize_entry(entry: str) -> str:
    """
    Reduce an allowlist entry to the bare binary name it allows.

    Returns "" for entries that don't name a bare binary — notably entries that
    carry arguments ("git status"), which are full-argument-vector allowlists
    and are not bypassable by argv[0] alone.
    """
    entry = entry.strip().strip("\"'")
    # ALLOW_PATTERNS values are often anchored regexes (^git$).
    entry = entry.lstrip("^").rstrip("$").strip()
    if not entry or any(c.isspace() for c in entry):
        return ""
    return entry.replace("\\", "/").rsplit("/", 1)[-1].lower()


def detect_unsafe_command_allowlist(env: dict) -> list[str]:
    """
    Scan env vars for allowlist-style keys whose values reference a binary
    known to have argument-level execution primitives.

    Returns a sorted list of matched binary names (empty if none found).
    """
    if not env:
        return []

    matched = set()
    for key, value in env.items():
        if not is_allowlist_env_key(key):
            continue
        if isinstance(value, (list, tuple)):
            value = ",".join(str(v) for v in value)
        if not isinstance(value, str):
            continue
        for entry in _split_entries(value):
            binary = _normalize_entry(entry)
            if binary in ARG_INJECTION_PRONE_BINARIES:
                matched.add(binary)

    return sorted(matched)


def get_reason(binary: str) -> str:
    """Get the one-line execution-primitive description for a binary."""
    return ARG_INJECTION_PRONE_BINARIES.get(binary.lower(), "")
