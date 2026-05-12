"""Source-code scanner for MCP server vulnerabilities.

The other scanners under this package look at MCP *configurations* (which
servers are connected to which client, what env vars are set, what tools
they advertise). This scanner looks at the MCP server's own **source code**
and flags vulnerability patterns the server author may have introduced.

Today this catches the "Prompt In, Shell Out" attack chain: an MCP server
that pipes LLM-controlled tool arguments into ``child_process.exec`` (or a
``util.promisify(exec)`` aliased ``execAsync``, or Python's
``subprocess.run(shell=True)`` / ``os.system``) without sanitization. The
LLM (or anyone controlling its input) can inject shell metacharacters into
the command and run arbitrary code on the host that runs the MCP server.

The scanner is intentionally narrow:

* It only opens files that look like they belong to an MCP server. The
  heuristic is "the file or one of its sibling files imports an MCP SDK"
  (``@modelcontextprotocol/sdk``, ``FastMCP``, ``mcp.Server``). Random
  Node / Python projects in the tree are skipped to keep false positives
  low. The cost is that we may miss MCP servers written without any
  recognisable SDK import; we accept that miss to keep the signal strong.
* Findings are emitted with a ``confidence`` field:
    * ``high``: the dangerous API is called with a template literal, f-string,
      or string concatenation — i.e., interpolation is visibly happening.
    * ``medium``: called with a non-literal argument that is not visibly
      interpolated (could still be safe; the analyst should double-check).
  Pure literal calls (``exec("ls -la")``) are not flagged because nothing
  is being interpolated.
* Walks the tree, but skips ``node_modules``, ``venv``, ``__pycache__``,
  ``dist``, ``build`` to avoid scanning vendored code we don't own.

Design constraint: no AST. Regex-based on each line, scoped to one source
file at a time. We accept the false-negative rate in exchange for keeping
the scanner zero-dependency and fast enough to run in CI.
"""
from __future__ import annotations

import re
from pathlib import Path

from mcp_audit.models import SourceFinding

# ---------------------------------------------------------------------------
# Where we look
# ---------------------------------------------------------------------------

# Files we'll inspect when looking for vulnerable patterns.
SOURCE_EXTENSIONS = frozenset([".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".tsx", ".jsx", ".py"])

# Directories to skip — vendored code, build artifacts, virtualenvs. We
# intentionally do NOT use a fancy gitignore parser here: the failure mode
# for missing a skip dir is "noisy scan", not "missed bug", and we want the
# tool to behave the same whether the repo is git-tracked or not.
SKIP_DIRS = frozenset([
    "node_modules", ".git", "venv", ".venv", "env",
    "__pycache__", "dist", "build", ".next", ".nuxt",
    ".pytest_cache", ".mypy_cache", ".tox", "coverage", ".turbo",
])

# Signals that a file (or one of its siblings) is an MCP server. We don't
# require these on the same line as the vulnerability — they just gate the
# file as "MCP-shaped" before we bother regexing for sinks.
MCP_SIGNALS_JS = (
    "@modelcontextprotocol/sdk",
    "@modelcontextprotocol/server",
    "mcp.server.Server",
    "Server.connect",  # SDK pattern: server = new Server(...); server.connect(transport)
)
MCP_SIGNALS_PY = (
    "from mcp",                # `from mcp.server import Server`, etc.
    "import mcp",
    "FastMCP",                 # `from mcp.server.fastmcp import FastMCP`
    "modelcontextprotocol",
)

# Per-file read cap so we don't tarpit on a 500 MB minified bundle that
# somehow escaped the skip-dir filter.
MAX_FILE_BYTES = 2_000_000  # 2 MB

# Per-scan caps so we don't tarpit on a deliberately huge tree.
MAX_FILES = 50_000
MAX_FINDINGS = 500


# ---------------------------------------------------------------------------
# Sink patterns: JavaScript / TypeScript
# ---------------------------------------------------------------------------

# Each tuple: (api_label, compiled_regex, captures_arg)
# The regex anchors on the call site; the ``captures_arg`` group (when present)
# captures the first argument so we can classify it (literal / interpolation /
# non-literal identifier).

# Direct usage: `child_process.exec("...")`, `exec("...")` (when imported destructured),
# `execSync(...)`, `cp.exec(...)`, `child_process.execSync(...)`. We anchor only on
# the call opening (through the ``(``) so the multi-line arg extractor in
# ``_first_arg_from`` can pick up template literals that span lines.
# ``(?!Async)`` keeps us from misfiring on ``execAsync``, ``execFile``, etc. —
# those are handled by the alias path (vulnerable) or skipped (safe).
_JS_DIRECT_EXEC_RE = re.compile(
    r"\b(?:child_process\.)?(exec(?!File)(?:Sync)?)(?!Async)\s*\(",
)

# Promisified `execAsync` style: `const execAsync = promisify(exec)` or
# `util.promisify(child_process.exec)`. We flag the *call sites* of any
# identifier that was bound via promisify(exec)-like initialiser. To avoid
# a full data-flow pass, we collect identifier names bound by
# `promisify(exec)` / `promisify(child_process.exec)` in a first pass, then
# look for those identifier names followed by `(`.
_JS_PROMISIFY_BIND_RE = re.compile(
    r"\b(?:const|let|var)\s+([A-Za-z_]\w*)\s*=\s*(?:util\.)?promisify\s*\(\s*(?:child_process\.)?exec(?:Sync)?\s*\)",
)

# Heuristic: spawn/execFile are SAFE alternatives, do NOT flag them. We
# deliberately do not include them in the sink list. Documented here so
# someone reading this file doesn't add them by mistake.


# ---------------------------------------------------------------------------
# Sink patterns: Python
# ---------------------------------------------------------------------------

# `subprocess.run(..., shell=True)` / `subprocess.Popen(..., shell=True)` /
# `subprocess.call(..., shell=True)` / `subprocess.check_output(..., shell=True)`.
# Match the API name; check the call body for `shell=True`.
_PY_SUBPROCESS_CALL_RE = re.compile(
    r"\b(?:subprocess\.)?(?P<api>run|Popen|call|check_call|check_output)\s*\(",
)
_PY_SHELL_TRUE_RE = re.compile(r"\bshell\s*=\s*True\b")

# `os.system("...")` always invokes a shell, no flag needed.
_PY_OS_SYSTEM_RE = re.compile(r"\bos\.system\s*\(\s*(?P<arg>[^,)]+)")

# `os.popen(...)` invokes a shell too.
_PY_OS_POPEN_RE = re.compile(r"\bos\.popen\s*\(\s*(?P<arg>[^,)]+)")


# ---------------------------------------------------------------------------
# Argument classification
# ---------------------------------------------------------------------------

# An argument is "interpolated" (high confidence) if it's a JS template
# literal with ${...}, a Python f-string with {...}, or a string-concat
# expression using `+`.
_JS_TEMPLATE_INTERP_RE = re.compile(r"`[^`]*\$\{")
_JS_STRING_CONCAT_RE = re.compile(r"['\"][^'\"]*['\"]\s*\+|\+\s*['\"]")
_PY_FSTRING_INTERP_RE = re.compile(r"""[fF]['"][^'"]*\{""")
_PY_STRING_PERCENT_RE = re.compile(r"""['"][^'"]*%[sd]""")  # printf-style
_PY_STRING_FORMAT_RE = re.compile(r"""['"]\.format\s*\(""")


def _classify_arg_js(arg: str) -> tuple[str, bool]:
    """Return (confidence, should_flag) for a JS exec-call first arg.

    * ``high`` + flag: visible interpolation (`` `gh ${repo}` `` or `"gh " + repo`).
    * ``medium`` + flag: bareword identifier that isn't a string literal.
    * neither: pure string literal (no interpolation) — safe, don't flag.
    """
    a = arg.strip()
    if not a:
        return ("medium", False)
    # Pure literal: a string that doesn't contain ${ or +. Safe.
    if (a.startswith("'") and a.endswith("'") and "${" not in a) or (
        a.startswith('"') and a.endswith('"') and "${" not in a
    ):
        return ("high", False)
    # Visible interpolation.
    if _JS_TEMPLATE_INTERP_RE.search(a) or _JS_STRING_CONCAT_RE.search(a):
        return ("high", True)
    # Pure backtick string with no ${ is also safe.
    if a.startswith("`") and "${" not in a:
        return ("high", False)
    # Anything else: a variable, a function call, an array spread — flag it
    # at medium confidence so the analyst takes a look.
    return ("medium", True)


def _classify_arg_py(arg: str) -> tuple[str, bool]:
    """Return (confidence, should_flag) for a Python first arg."""
    a = arg.strip()
    if not a:
        return ("medium", False)
    # Pure literal string?
    if (a.startswith("'") and a.endswith("'") and "{" not in a and "%" not in a) or (
        a.startswith('"') and a.endswith('"') and "{" not in a and "%" not in a
    ):
        return ("high", False)
    if _PY_FSTRING_INTERP_RE.search(a) or _PY_STRING_PERCENT_RE.search(a) or _PY_STRING_FORMAT_RE.search(a):
        return ("high", True)
    if "+" in a and ("'" in a or '"' in a):
        return ("high", True)
    return ("medium", True)


# ---------------------------------------------------------------------------
# File-shape gate
# ---------------------------------------------------------------------------


def _looks_like_mcp_server(text: str, suffix: str) -> bool:
    """True if ``text`` references an MCP SDK in a way that suggests an MCP server.

    Cheap substring checks — no regex — because this runs on every candidate
    source file in the tree.
    """
    if suffix == ".py":
        return any(s in text for s in MCP_SIGNALS_PY)
    return any(s in text for s in MCP_SIGNALS_JS)


def _is_mcp_tree(root: Path) -> bool:
    """Quick whole-tree check: does ANY source file look MCP-shaped?

    Used as an early-exit when the user passes a directory that isn't an MCP
    server (e.g., a generic webapp). Avoids opening every file in a 100k-file
    repo when the answer is clearly 'this isn't an MCP server'.
    """
    seen = 0
    for path in root.rglob("*"):
        seen += 1
        if seen > 5000:
            # Give up on the cheap pre-check; let the per-file gate decide.
            return True
        if not path.is_file():
            continue
        if path.suffix.lower() not in SOURCE_EXTENSIONS:
            continue
        if any(skip in path.parts for skip in SKIP_DIRS):
            continue
        try:
            head = path.read_text(encoding="utf-8", errors="replace")[:8000]
        except OSError:
            continue
        if _looks_like_mcp_server(head, path.suffix.lower()):
            return True
    return False


# ---------------------------------------------------------------------------
# Scanner entry point
# ---------------------------------------------------------------------------


def scan_source(root: Path) -> list[SourceFinding]:
    """Scan ``root`` for MCP server source-code vulnerabilities.

    Returns a list of :class:`SourceFinding`. Empty list if the tree
    doesn't look like an MCP server or contains no vulnerable patterns.
    """
    if not root.is_dir():
        return []

    if not _is_mcp_tree(root):
        return []

    findings: list[SourceFinding] = []
    files_seen = 0

    for path in root.rglob("*"):
        if files_seen >= MAX_FILES or len(findings) >= MAX_FINDINGS:
            break
        if not path.is_file():
            continue
        suffix = path.suffix.lower()
        if suffix not in SOURCE_EXTENSIONS:
            continue
        if any(skip in path.parts for skip in SKIP_DIRS):
            continue

        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        if not _looks_like_mcp_server(text, suffix):
            continue

        files_seen += 1
        rel = str(path.relative_to(root))

        if suffix == ".py":
            findings.extend(_scan_python(text, rel))
        else:
            findings.extend(_scan_javascript(text, rel))

    return findings


# ---------------------------------------------------------------------------
# Per-language scanners
# ---------------------------------------------------------------------------


def _scan_javascript(text: str, rel_file: str) -> list[SourceFinding]:
    out: list[SourceFinding] = []

    # First pass: identify locally-bound names that are aliases for the
    # promisified ``exec`` (i.e., the ``execAsync`` pattern from the article).
    promisified_aliases: set[str] = set()
    for m in _JS_PROMISIFY_BIND_RE.finditer(text):
        promisified_aliases.add(m.group(1))

    lines = text.splitlines()

    # Pre-build alias regexes so we don't recompile per line.
    alias_patterns = [
        (alias, re.compile(rf"\b{re.escape(alias)}\s*\("))
        for alias in promisified_aliases
    ]

    for line_no, raw_line in enumerate(lines, start=1):
        line = raw_line
        if not line.strip() or line.lstrip().startswith("//"):
            continue

        # Direct `exec(...)` / `execSync(...)` / `child_process.exec(...)`.
        # Walk all matches on this line (rare to have more than one, but cheap).
        for m in _JS_DIRECT_EXEC_RE.finditer(line):
            api = f"child_process.{m.group(1)}"
            arg = _first_arg_from(lines, line_no - 1, m.end())
            conf, flag = _classify_arg_js(arg)
            if flag:
                out.append(_build_finding_js(api, conf, rel_file, line_no, m.start(), line))

        # Promisified alias call sites: `await execAsync(...)`.
        for alias, pattern in alias_patterns:
            am = pattern.search(line)
            if am is None:
                continue
            arg = _first_arg_from(lines, line_no - 1, am.end())
            conf, flag = _classify_arg_js(arg)
            if flag:
                out.append(
                    _build_finding_js(
                        f"util.promisify(child_process.exec) [bound as `{alias}`]",
                        conf,
                        rel_file,
                        line_no,
                        am.start(),
                        line,
                    )
                )

    return out


def _first_arg_from(lines: list[str], line_idx: int, start_col: int) -> str:
    """Extract the first positional argument of a call whose ``(`` ends at
    ``start_col`` on line ``line_idx`` (0-indexed). Reads up to 5 more lines
    if the argument spans line breaks (very common with template literals).

    Returns the substring from ``start_col`` to the first top-level ``,`` or
    ``)``. Quote nesting is honoured for ``"`` / ``'`` / `` ` `` so a comma
    inside a string doesn't truncate the arg.
    """
    chunks: list[str] = []
    # Use up to 6 lines (current + 5 lookahead). Calls that span more than that
    # are rare and we'd rather miss the finding than false-positive on a
    # parser miscount.
    for offset in range(0, 6):
        idx = line_idx + offset
        if idx >= len(lines):
            break
        seg = lines[idx][start_col:] if offset == 0 else lines[idx]
        chunks.append(seg)
    blob = "\n".join(chunks)

    depth = 0
    in_str: str | None = None
    i = 0
    while i < len(blob):
        ch = blob[i]
        if in_str:
            if ch == "\\" and i + 1 < len(blob):
                i += 2
                continue
            if ch == in_str:
                in_str = None
            i += 1
            continue
        if ch in ("'", '"', "`"):
            in_str = ch
            i += 1
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                return blob[:i].strip()
            depth -= 1
        elif ch == "," and depth == 0:
            return blob[:i].strip()
        i += 1
    return blob.strip()


def _scan_python(text: str, rel_file: str) -> list[SourceFinding]:
    out: list[SourceFinding] = []

    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        # subprocess.* with shell=True. We need a small lookahead to grab the
        # call's body (until matching `)` on this line for the simple case).
        m = _PY_SUBPROCESS_CALL_RE.search(line)
        if m and _PY_SHELL_TRUE_RE.search(line):
            # Pull the first argument as best we can (everything up to the
            # first comma or shell=, whichever comes first).
            after = line[m.end():]
            first_arg = after.split(",", 1)[0]
            api = f"subprocess.{m.group('api')}(shell=True)"
            conf, flag = _classify_arg_py(first_arg)
            if flag:
                out.append(_build_finding_py(api, conf, rel_file, line_no, m.start(), line))

        # os.system("...")
        m = _PY_OS_SYSTEM_RE.search(line)
        if m:
            conf, flag = _classify_arg_py(m.group("arg"))
            if flag:
                out.append(_build_finding_py("os.system", conf, rel_file, line_no, m.start(), line))

        # os.popen("...")
        m = _PY_OS_POPEN_RE.search(line)
        if m:
            conf, flag = _classify_arg_py(m.group("arg"))
            if flag:
                out.append(_build_finding_py("os.popen", conf, rel_file, line_no, m.start(), line))

    return out


# ---------------------------------------------------------------------------
# Finding construction
# ---------------------------------------------------------------------------


_JS_FIX_HINT = (
    "Replace with execFile or spawn passing arguments as an array — no shell parser involved."
)
_PY_FIX_HINT = (
    "Drop shell=True and pass arguments as a list: subprocess.run([cmd, *args]). "
    "For os.system / os.popen, switch to subprocess with a list argument."
)


def _build_finding_js(
    api: str, confidence: str, rel_file: str, line_no: int, column: int, raw_line: str
) -> SourceFinding:
    return SourceFinding(
        finding_type="shell-injection",
        severity="critical" if confidence == "high" else "high",
        file=rel_file,
        line=line_no,
        column=column + 1,  # 1-indexed for human display
        api_used=api,
        confidence=confidence,
        snippet=raw_line.strip()[:200],
        server_name="",
        remediation=_JS_FIX_HINT,
    )


def _build_finding_py(
    api: str, confidence: str, rel_file: str, line_no: int, column: int, raw_line: str
) -> SourceFinding:
    return SourceFinding(
        finding_type="shell-injection",
        severity="critical" if confidence == "high" else "high",
        file=rel_file,
        line=line_no,
        column=column + 1,
        api_used=api,
        confidence=confidence,
        snippet=raw_line.strip()[:200],
        server_name="",
        remediation=_PY_FIX_HINT,
    )


__all__ = ["scan_source", "SourceFinding"]
