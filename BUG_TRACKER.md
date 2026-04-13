# MCP Audit — Bug Tracker

**Last Updated:** April 7, 2026

---

## Critical

### BUG-001: Anthropic keys mislabeled as OpenAI
**Status:** Open | **Found:** April 7, 2026
**File:** `mcp_audit/data/secret_patterns.py:98`

The `openai_key` pattern (`sk-[0-9a-zA-Z]{20,}`) matches before the `anthropic_key` pattern (`sk-ant-[0-9a-zA-Z-]{40,}`) due to dict insertion order + first-match-wins `break` at line 362. An Anthropic key like `sk-ant-abc123...` is reported as "OpenAI API Key."

**Fix:** Either reorder patterns (specific before generic) or remove the `break` and use longest-match logic.

---

### BUG-002: Raw secrets written to JSON output
**Status:** Open | **Found:** April 7, 2026
**File:** `mcp_audit/models.py:67`

`ScanResult.to_dict()` copies the full `env` dict with plaintext secret values. Running `mcp-audit scan --output results.json` writes every secret unmasked to disk. The `secrets` list is properly masked but `env` is not.

**Fix:** Mask values in `env` dict that match detected secret patterns before serialization.

---

### BUG-003: Registry name matching too loose
**Status:** Open | **Found:** April 7, 2026
**File:** `mcp_audit/data/__init__.py:96-98`

`lookup_mcp` uses substring matching: `"github" in "github-stealer-malware"` returns True. A malicious MCP inherits trust score and verified status from a legitimate registry entry.

**Fix:** Match on exact name, exact package, or exact endpoint — not substring of name.

---

## High

### BUG-004: ReDoS in policy pattern matching
**Status:** Open | **Found:** April 7, 2026
**File:** `mcp_audit/commands/policy.py:269`

User-supplied policy patterns are converted to regex (`*` → `.*`) without escaping other regex characters. A pattern like `@scope/(a+)+` causes catastrophic backtracking.

**Fix:** Use `re.escape()` on everything except the `*` wildcard, or switch to `fnmatch.fnmatch()`.

---

### BUG-005: Bare except clauses in trust scoring
**Status:** Open | **Found:** April 7, 2026
**File:** `mcp_audit/commands/trust.py:219, 287, 340`

`except:` catches `KeyboardInterrupt`, `SystemExit`, `MemoryError`. User cannot Ctrl-C out of a trust check.

**Fix:** Change to `except Exception:`.

---

### BUG-006: No tests for CycloneDX or SARIF output
**Status:** Open | **Found:** April 7, 2026
**Files:** `mcp_audit/outputs/cyclonedx.py` (439 lines), `mcp_audit/outputs/sarif.py` (279 lines)

Both output formats are completely untested. CycloneDX has spec compliance issues (non-standard `provides` key in dependencies, `modelCard` structure may not validate). SARIF `shortDescription` references a `description` key that doesn't exist in risk flag info — always falls back to the flag name.

**Fix:** Add tests. Validate output against CycloneDX 1.6 and SARIF 2.1.0 schemas.

---

### BUG-007: Regex patterns not precompiled
**Status:** Open | **Found:** April 7, 2026
**File:** `mcp_audit/data/secret_patterns.py:317-361`

25+ patterns recompiled via `re.search()` on every env var for every MCP. At 100 MCPs with 10 env vars each = 25,000 regex compilations.

**Fix:** `COMPILED_PATTERNS = {k: re.compile(v["pattern"]) for k, v in SECRET_PATTERNS.items()}` at module load.

---

### BUG-008: CORS wildcard on backend API
**Status:** Open | **Found:** April 7, 2026
**File:** `backend/api/report.ts:59`

`Access-Control-Allow-Origin: *` means any website can submit reports if it knows the API key.

**Fix:** Restrict to `apisec-inc.github.io` origin.

---

### BUG-009: Not published to PyPI
**Status:** Open | **Found:** April 7, 2026
**File:** GitHub Issue #3

External user tried `pip install` and it broke. The package is not on PyPI. Every competitor is (`cisco-ai-mcp-scanner`, `mcp-scan`). Losing users at the install step.

**Fix:** Publish to PyPI. Fix the missing file referenced in Issue #3.

---

## Medium

### BUG-010: Secret masking reveals too much for short values
**Status:** Open | **Found:** April 7, 2026
**File:** `mcp_audit/data/secret_patterns.py:279`

For an 8-character secret (minimum detection length), masking reveals 4 of 8 characters (50%). For a 5-character value, reveals 4 of 5.

**Fix:** For values under 12 chars, show only first 2 chars + mask the rest. Never reveal more than 25%.

---

### BUG-011: YAML parser doesn't strip inline comments
**Status:** Open | **Found:** April 7, 2026
**File:** `mcp_audit/commands/policy.py:157`

`- "@anthropic/*"  # verified publisher` keeps the comment in the value. Breaks pattern matching in policy validation.

**Fix:** Strip `#` comments from values before processing.

---

### BUG-012: Docker image parsing ignores flags
**Status:** Open | **Found:** April 7, 2026
**File:** `mcp_audit/models.py:269-272`

`docker run -d --name foo image:tag` returns `-d` as the image name. Takes the arg immediately after `run` without skipping flags.

**Fix:** Skip args starting with `-` after `run` to find the actual image name.

---

### BUG-013: Scanner code duplicated across 6 files
**Status:** Open | **Found:** April 7, 2026
**Files:** `scanners/claude.py`, `cursor.py`, `vscode.py`, `windsurf.py`, `zed.py`

Identical pattern: get path → check exists → json.loads → extract mcpServers → loop. Should be a shared function.

**Fix:** Extract `scan_config_file(path, found_in, mcp_keys)` shared utility.

---

### BUG-014: `_truncate()` duplicated in 4 files
**Status:** Open | **Found:** April 7, 2026
**Files:** `scan.py:490`, `trust.py:435`, `policy.py:365`, `analyze.py:258`

Identical function in 4 places.

**Fix:** Move to a shared `utils.py`.

---

### BUG-015: Backend leaks emails to Google Sheets
**Status:** Open | **Found:** April 7, 2026
**File:** `backend/api/report.ts:127-136`

User emails sent to external Google Apps Script. Contradicts "no PII collected" claim.

**Fix:** Either disclose email collection to users or remove the Google Sheets call.

---

### BUG-016: `_should_skip` uses substring matching
**Status:** Open | **Found:** April 7, 2026
**File:** `mcp_audit/scanners/project.py:81`

`"node_modules" in path_str` matches `my_node_modules_backup`. Should check path components.

**Fix:** Split path and check components, or use `pathlib.PurePath.parts`.

---

### BUG-017: CycloneDX uses non-standard `provides` key
**Status:** Open | **Found:** April 7, 2026
**File:** `mcp_audit/outputs/cyclonedx.py:275`

`dependency.provides` is not part of the CycloneDX spec. Fails schema validation.

**Fix:** Remove or replace with `dependsOn`.

---

### BUG-018: CycloneDX XML output missing fields present in JSON
**Status:** Open | **Found:** April 7, 2026
**File:** `mcp_audit/outputs/cyclonedx.py:368-424`

XML serializer skips `modelCard`, `externalReferences`, and other fields. JSON and XML outputs are not equivalent.

**Fix:** Align XML output with JSON output.

---

### BUG-019: `datetime.utcnow()` deprecated
**Status:** Open | **Found:** April 7, 2026
**Files:** `cyclonedx.py:57`, `sarif.py:58`

Deprecated since Python 3.12.

**Fix:** Use `datetime.now(timezone.utc)`.

---

### BUG-020: CSV output doesn't properly escape all fields
**Status:** Open | **Found:** April 7, 2026
**File:** `mcp_audit/outputs/formatter.py:335-336`

Only `source` and `config_path` are quoted. A name containing a comma corrupts the CSV.

**Fix:** Use Python's `csv` module.

---

## Low

### BUG-021: Environment variable skip is too narrow
**Status:** Open | **Found:** April 7, 2026
**File:** `mcp_audit/data/secret_patterns.py:314-315`

Only skips `$VAR` and `${VAR}`. Misses `%VAR%` (Windows), `$(command)`, and `env:VAR` patterns.

**Fix:** Add Windows and other env var reference patterns.

---

### BUG-022: `generic_password` matches any 8+ char string
**Status:** Open | **Found:** April 7, 2026
**File:** `mcp_audit/data/secret_patterns.py:250-253`

`DB_PASSWORD=localhost` flagged as a secret. Pattern `.{8,}` with context key `PASSWORD` is too broad.

**Fix:** Add common non-secret value exclusions (hostnames, `localhost`, file paths).

---

### BUG-023: pyproject.toml parser is fragile
**Status:** Open | **Found:** April 7, 2026
**File:** `mcp_audit/scanners/project.py:338-371`

Only detects `[project.dependencies]` section header. PEP 621 inline `dependencies = [...]` array is missed.

**Fix:** Handle inline array syntax.

---

### BUG-024: No deduplication across scanners
**Status:** Open | **Found:** April 7, 2026
**File:** `mcp_audit/commands/scan.py:91-170`

Same MCP config in multiple paths (symlinks, overlapping scans) reported as separate findings.

**Fix:** Deduplicate by config content hash or canonical path.

---

## Fixed

### BUG-025: Hardcoded API key in scan command
**Status:** Fixed (PR #7) | **Found:** April 7, 2026
**File:** `mcp_audit/commands/scan.py:951`

Report backend API key hardcoded in source. Moved to `MCP_AUDIT_API_KEY` environment variable.

---

## Summary

| Severity | Open | Fixed | Total |
|----------|------|-------|-------|
| Critical | 3 | 0 | 3 |
| High | 6 | 0 | 6 |
| Medium | 11 | 0 | 11 |
| Low | 4 | 0 | 4 |
| **Total** | **24** | **1** | **25** |
