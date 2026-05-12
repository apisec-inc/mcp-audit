"""Tests for the MCP source-code vulnerability scanner."""
from __future__ import annotations

from pathlib import Path

from mcp_audit.scanners.source import scan_source

FIXTURES = Path(__file__).parent / "fixtures" / "source_scan"


# ---------------------------------------------------------------------------
# Positive cases: the scanner must find vulnerable patterns.
# ---------------------------------------------------------------------------


def test_finds_promisified_exec_in_js_mcp_server() -> None:
    """The classic Prompt-In-Shell-Out CVE pattern: util.promisify(exec) alias
    called with a template literal interpolating tool args."""
    findings = scan_source(FIXTURES / "vulnerable_mcp_js")

    # The fixture has 3 vulnerable sinks (execAsync template, exec concat,
    # execSync template) plus one safe literal call that should NOT be flagged.
    assert len(findings) == 3, [f.to_dict() for f in findings]
    apis = sorted({f.api_used for f in findings})

    # execAsync via util.promisify should appear (high signal).
    assert any("promisify" in a for a in apis), apis
    # Direct exec and execSync should both appear.
    assert any("child_process.exec" in a and "Sync" not in a for a in apis), apis
    assert any("execSync" in a for a in apis), apis


def test_all_js_findings_are_critical_high_confidence() -> None:
    """Every vulnerable sink in the JS fixture uses visible interpolation."""
    findings = scan_source(FIXTURES / "vulnerable_mcp_js")
    assert all(f.severity == "critical" for f in findings)
    assert all(f.confidence == "high" for f in findings)


def test_finds_subprocess_shell_true_in_python_mcp_server() -> None:
    """subprocess.run(..., shell=True) with f-string interpolation is flagged."""
    findings = scan_source(FIXTURES / "vulnerable_mcp_py")
    apis = sorted({f.api_used for f in findings})
    # All three vulnerable APIs should be detected.
    assert any("subprocess.run(shell=True)" in a for a in apis), apis
    assert any("os.system" in a for a in apis), apis
    assert any("os.popen" in a for a in apis), apis


def test_python_findings_skip_the_safe_list_arg_call() -> None:
    """subprocess.run([cmd]) with no shell=True must not be flagged."""
    findings = scan_source(FIXTURES / "vulnerable_mcp_py")
    # The safe always_safe() function passes ["uptime"] and no shell flag.
    # It must not appear in findings.
    for f in findings:
        assert "always_safe" not in f.snippet, (
            "scanner flagged the safe list-arg call: " + f.snippet
        )


# ---------------------------------------------------------------------------
# Negative cases: the scanner must NOT flag safe code or non-MCP code.
# ---------------------------------------------------------------------------


def test_safe_execfile_pattern_not_flagged() -> None:
    """execFile is the recommended SAFE alternative and must not be flagged."""
    findings = scan_source(FIXTURES / "safe_mcp_js")
    assert findings == []


def test_non_mcp_project_is_silently_skipped() -> None:
    """A directory with no MCP SDK references produces no findings, even if
    it contains exec calls. We don't try to find every shell-injection bug
    in the world — only the ones inside MCP servers."""
    findings = scan_source(FIXTURES / "not_an_mcp")
    assert findings == []


def test_nonexistent_path_returns_empty() -> None:
    findings = scan_source(FIXTURES / "does-not-exist")
    assert findings == []


# ---------------------------------------------------------------------------
# Finding shape contract: callers (CLI, JSON output, SARIF) depend on this.
# ---------------------------------------------------------------------------


def test_finding_fields_are_complete_for_renderers() -> None:
    findings = scan_source(FIXTURES / "vulnerable_mcp_js")
    assert findings  # sanity
    f = findings[0]
    # Every field a renderer expects:
    assert f.finding_type == "shell-injection"
    assert f.severity in {"critical", "high"}
    assert f.confidence in {"high", "medium"}
    assert f.file and "/" in f.file or "\\" in f.file or f.file.endswith(".js")
    assert f.line > 0
    assert f.column > 0
    assert f.api_used
    assert f.snippet
    assert f.remediation  # short fix hint, distinct from the long risk-flag guidance
