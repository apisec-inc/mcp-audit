"""
Tests for OWASP LLM Top 10 mapping
"""

import pytest
from mcp_audit.data.owasp_llm import (
    OWASP_LLM_TOP_10,
    OWASP_LLM_TRIGGERS,
    get_owasp_llm_for_finding,
    get_owasp_llm_for_secret,
    get_owasp_llm_for_risk_flag,
    get_scan_owasp_coverage,
)


class TestOwaspDefinitions:
    """Test OWASP LLM Top 10 definitions"""

    def test_all_categories_defined(self):
        """All expected OWASP LLM categories are defined"""
        expected = ["LLM01", "LLM02", "LLM03", "LLM06", "LLM07", "LLM09", "LLM10"]
        for cat in expected:
            assert cat in OWASP_LLM_TOP_10
            assert "name" in OWASP_LLM_TOP_10[cat]
            assert "description" in OWASP_LLM_TOP_10[cat]
            assert "mcp_relevance" in OWASP_LLM_TOP_10[cat]

    def test_triggers_defined(self):
        """Trigger conditions are defined for all categories"""
        for cat in OWASP_LLM_TOP_10:
            assert cat in OWASP_LLM_TRIGGERS
            assert "conditions" in OWASP_LLM_TRIGGERS[cat]
            assert "description" in OWASP_LLM_TRIGGERS[cat]


class TestSecretMapping:
    """Test OWASP LLM mapping for secrets"""

    def test_github_pat_maps_to_llm02_llm07(self):
        """GitHub PAT maps to sensitive info disclosure and prompt leakage"""
        refs = get_owasp_llm_for_secret("github_pat")
        ids = [r["id"] for r in refs]
        assert "LLM02" in ids
        assert "LLM07" in ids

    def test_aws_key_maps_to_llm02_llm07(self):
        """AWS key maps to sensitive info disclosure and prompt leakage"""
        refs = get_owasp_llm_for_secret("aws_access_key")
        ids = [r["id"] for r in refs]
        assert "LLM02" in ids
        assert "LLM07" in ids

    def test_unknown_secret_returns_llm02_llm07(self):
        """Unknown secret type still returns LLM02 and LLM07"""
        refs = get_owasp_llm_for_secret("unknown_type")
        ids = [r["id"] for r in refs]
        assert "LLM02" in ids
        assert "LLM07" in ids


class TestRiskFlagMapping:
    """Test OWASP LLM mapping for risk flags"""

    def test_shell_access_maps_to_llm06(self):
        """shell-access maps to excessive agency"""
        refs = get_owasp_llm_for_risk_flag("shell-access")
        ids = [r["id"] for r in refs]
        assert "LLM06" in ids

    def test_database_access_maps_to_llm06(self):
        """database-access maps to excessive agency"""
        refs = get_owasp_llm_for_risk_flag("database-access")
        ids = [r["id"] for r in refs]
        assert "LLM06" in ids

    def test_filesystem_access_maps_to_llm06(self):
        """filesystem-access maps to excessive agency"""
        refs = get_owasp_llm_for_risk_flag("filesystem-access")
        ids = [r["id"] for r in refs]
        assert "LLM06" in ids

    def test_secrets_in_env_maps_to_llm02_llm07(self):
        """secrets-in-env maps to sensitive disclosure and prompt leakage"""
        refs = get_owasp_llm_for_risk_flag("secrets-in-env")
        ids = [r["id"] for r in refs]
        assert "LLM02" in ids
        assert "LLM07" in ids

    def test_unsafe_command_allowlist_maps_to_llm06(self):
        """unsafe-command-allowlist maps to excessive agency"""
        refs = get_owasp_llm_for_risk_flag("unsafe-command-allowlist")
        ids = [r["id"] for r in refs]
        assert "LLM06" in ids

    def test_unverified_source_maps_to_llm03(self):
        """unverified-source maps to supply chain"""
        refs = get_owasp_llm_for_risk_flag("unverified-source")
        ids = [r["id"] for r in refs]
        assert "LLM03" in ids

    def test_unknown_flag_returns_empty(self):
        """Unknown risk flag returns empty list"""
        refs = get_owasp_llm_for_risk_flag("unknown-flag")
        assert refs == []


class TestFindingMapping:
    """Test OWASP LLM mapping for findings"""

    def test_mcp_discovered_maps_to_llm01(self):
        """MCP discovery maps to prompt injection attack surface"""
        refs = get_owasp_llm_for_finding("mcp_discovered")
        ids = [r["id"] for r in refs]
        assert "LLM01" in ids

    def test_secrets_trigger_llm02(self):
        """has_secrets=True triggers LLM02"""
        refs = get_owasp_llm_for_finding("any", has_secrets=True)
        ids = [r["id"] for r in refs]
        assert "LLM02" in ids

    def test_unknown_mcp_triggers_llm03(self):
        """is_known=False triggers LLM03"""
        refs = get_owasp_llm_for_finding("any", is_known=False)
        ids = [r["id"] for r in refs]
        assert "LLM03" in ids

    def test_shell_access_flag_triggers_llm06(self):
        """shell-access flag triggers LLM06"""
        refs = get_owasp_llm_for_finding("any", risk_flags=["shell-access"])
        ids = [r["id"] for r in refs]
        assert "LLM06" in ids

    def test_unsafe_command_allowlist_flag_triggers_llm06(self):
        """unsafe-command-allowlist flag triggers LLM06"""
        refs = get_owasp_llm_for_finding("any", risk_flags=["unsafe-command-allowlist"])
        ids = [r["id"] for r in refs]
        assert "LLM06" in ids

    def test_ai_models_trigger_llm09_llm10(self):
        """has_models=True triggers LLM09 and LLM10"""
        refs = get_owasp_llm_for_finding("any", has_models=True)
        ids = [r["id"] for r in refs]
        assert "LLM09" in ids
        assert "LLM10" in ids

    def test_apis_trigger_llm10(self):
        """has_apis=True triggers LLM10"""
        refs = get_owasp_llm_for_finding("any", has_apis=True)
        ids = [r["id"] for r in refs]
        assert "LLM10" in ids


class TestScanCoverage:
    """Test OWASP LLM coverage for scan results"""

    def test_empty_results_returns_empty_coverage(self):
        """Empty results return empty coverage"""
        coverage = get_scan_owasp_coverage([])
        assert coverage == {}

    def test_coverage_includes_llm01_when_mcps_found(self):
        """Coverage includes LLM01 when MCPs are found"""
        # Create a mock result with minimal data
        class MockResult:
            def __init__(self):
                self.secrets = []
                self.apis = []
                self.model = None
                self.is_known = True
                self.risk_flags = []

        coverage = get_scan_owasp_coverage([MockResult()])
        assert "LLM01" in coverage
        assert coverage["LLM01"]["covered"] is True

    def test_coverage_includes_llm02_when_secrets_found(self):
        """Coverage includes LLM02 when secrets are found"""
        class MockResult:
            def __init__(self):
                self.secrets = [{"type": "test"}]
                self.apis = []
                self.model = None
                self.is_known = True
                self.risk_flags = []

        coverage = get_scan_owasp_coverage([MockResult()])
        assert "LLM02" in coverage

    def test_coverage_includes_llm03_for_unknown_mcps(self):
        """Coverage includes LLM03 for unknown MCPs"""
        class MockResult:
            def __init__(self):
                self.secrets = []
                self.apis = []
                self.model = None
                self.is_known = False
                self.risk_flags = []

        coverage = get_scan_owasp_coverage([MockResult()])
        assert "LLM03" in coverage
