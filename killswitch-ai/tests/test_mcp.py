"""
Tests for the killswitch MCP server module.

Tests cover:
- Underlying logic functions (_scan, _get_status, _get_stats,
  _recent_findings, _get_policy) without starting the stdio server
- Privacy guarantees (no secret values, no smtp_password, no meta IDs)
- Response shapes
- MCP tool registration
"""
from __future__ import annotations

import asyncio
import json
import pytest


class TestScanTool:
    def test_clean_text_returns_clean(self):
        from killswitch.mcp.server import _scan
        result = _scan("Hello, please summarize this document.")
        assert result["clean"] is True
        assert result["findings"] == []
        assert result["finding_count"] == 0
        assert result["max_severity"] is None

    def test_detects_openai_key(self):
        from killswitch.mcp.server import _scan
        key = "sk-proj-" + "AbCdEfGhIjKlMnOpQrStUvWx123456"
        result = _scan(f"Here is my key: {key}")
        assert not result["clean"]
        types = [f["type"] for f in result["findings"]]
        assert "openai_key" in types

    def test_detects_anthropic_key(self):
        from killswitch.mcp.server import _scan
        key = "sk-ant-" + "api03-AbCdEfGhIjKlMnOpQrStUvWxYz1234567890ABCD"
        result = _scan(key)
        assert not result["clean"]
        types = [f["type"] for f in result["findings"]]
        assert "anthropic_key" in types

    def test_no_secret_values_echoed_in_output(self):
        from killswitch.mcp.server import _scan
        key = "sk-proj-" + "AbCdEfGhIjKlMnOpQrStUvWx123456"
        result = _scan(f"key: {key}")
        result_str = json.dumps(result)
        assert key not in result_str

    def test_input_text_not_in_output(self):
        from killswitch.mcp.server import _scan
        sentinel = "UNIQUESENTINELTEXT_DO_NOT_ECHO_12345"
        result = _scan(f"please summarize: {sentinel}")
        result_str = json.dumps(result)
        assert sentinel not in result_str

    def test_result_has_required_fields(self):
        from killswitch.mcp.server import _scan
        result = _scan("test input")
        assert "clean" in result
        assert "finding_count" in result
        assert "max_severity" in result
        assert "findings" in result
        assert "note" in result

    def test_finding_shape_no_matched_preview(self):
        from killswitch.mcp.server import _scan
        key = "sk-proj-" + "AbCdEfGhIjKlMnOpQrStUvWx123456"
        result = _scan(key)
        assert result["findings"]
        f = result["findings"][0]
        assert "finding_id" in f
        assert "severity" in f
        assert "type" in f
        assert "category" in f
        assert "description" in f
        assert "recommendation" in f
        assert "matched_text_preview" not in f

    def test_note_mentions_voluntary_guardrail(self):
        from killswitch.mcp.server import _scan
        result = _scan("hello")
        assert "voluntary" in result["note"].lower() or "opt-in" in result["note"].lower() or "guardrail" in result["note"].lower()

    def test_finding_count_matches_list(self):
        from killswitch.mcp.server import _scan
        key = "sk-proj-" + "AbCdEfGhIjKlMnOpQrStUvWx123456"
        result = _scan(key)
        assert result["finding_count"] == len(result["findings"])


class TestGetStatusTool:
    def test_returns_expected_fields(self):
        from killswitch.mcp.server import _get_status
        result = _get_status()
        assert "mode" in result
        assert "protection_active" in result
        assert "commands_analyzed" in result
        assert "prohibited_stopped" in result
        assert "sensitive_stopped" in result

    def test_protection_active_reflects_mode(self):
        from killswitch.mcp.server import _get_status
        result = _get_status()
        if result["mode"] == "off":
            assert result["protection_active"] is False
        else:
            assert result["protection_active"] is True

    def test_counts_are_non_negative_ints(self):
        from killswitch.mcp.server import _get_status
        result = _get_status()
        assert isinstance(result["commands_analyzed"], int)
        assert result["commands_analyzed"] >= 0
        assert isinstance(result["prohibited_stopped"], int)
        assert result["prohibited_stopped"] >= 0


class TestGetStatsTool:
    def test_returns_expected_fields(self):
        from killswitch.mcp.server import _get_stats
        result = _get_stats()
        assert "commands_analyzed" in result
        assert "finding_types" in result
        assert "decisions" in result
        assert "severity_counts" in result
        assert "finding_categories" in result

    def test_distribution_fields_are_dicts(self):
        from killswitch.mcp.server import _get_stats
        result = _get_stats()
        assert isinstance(result["finding_types"], dict)
        assert isinstance(result["decisions"], dict)
        assert isinstance(result["providers"], dict)


class TestRecentFindingsTool:
    def test_returns_expected_shape(self):
        from killswitch.mcp.server import _recent_findings
        result = _recent_findings()
        assert "findings" in result
        assert "total" in result
        assert "shown" in result
        assert isinstance(result["findings"], list)

    def test_limit_is_respected(self):
        from killswitch.mcp.server import _recent_findings
        result = _recent_findings(limit=3)
        assert len(result["findings"]) <= 3

    def test_shown_matches_list_length(self):
        from killswitch.mcp.server import _recent_findings
        result = _recent_findings(limit=5)
        assert result["shown"] == len(result["findings"])

    def test_finding_fields_when_present(self):
        from killswitch.mcp.server import _recent_findings
        result = _recent_findings(limit=100)
        for f in result["findings"]:
            assert "finding_id" in f
            assert "severity" in f
            assert "type" in f
            assert "description" in f


class TestGetPolicyTool:
    def test_returns_expected_fields(self):
        from killswitch.mcp.server import _get_policy
        result = _get_policy()
        assert "policy" in result
        assert "using_defaults" in result
        assert "config_file" in result

    def test_no_smtp_password_in_output(self):
        from killswitch.mcp.server import _get_policy
        result = _get_policy()
        result_str = json.dumps(result)
        assert "smtp_password" not in result_str

    def test_no_smtp_user_in_output(self):
        from killswitch.mcp.server import _get_policy
        result = _get_policy()
        result_str = json.dumps(result)
        assert "smtp_user" not in result_str

    def test_no_meta_block_in_policy(self):
        from killswitch.mcp.server import _get_policy
        result = _get_policy()
        assert "meta" not in result["policy"]

    def test_no_telemetry_block_in_policy(self):
        from killswitch.mcp.server import _get_policy
        result = _get_policy()
        assert "telemetry" not in result["policy"]

    def test_policy_contains_mode(self):
        from killswitch.mcp.server import _get_policy
        result = _get_policy()
        assert "mode" in result["policy"]

    def test_using_defaults_is_bool(self):
        from killswitch.mcp.server import _get_policy
        result = _get_policy()
        assert isinstance(result["using_defaults"], bool)


class TestMcpServerRegistration:
    def test_server_module_importable(self):
        from killswitch.mcp import server
        assert server is not None

    def test_mcp_instance_created(self):
        from killswitch.mcp.server import mcp
        assert mcp is not None

    def test_serve_function_exists(self):
        from killswitch.mcp.server import serve
        assert callable(serve)

    def test_all_five_tools_registered(self):
        from killswitch.mcp.server import mcp
        tools = asyncio.run(mcp.list_tools())
        tool_names = {t.name for t in tools}
        assert "scan" in tool_names
        assert "get_status" in tool_names
        assert "get_stats" in tool_names
        assert "recent_findings" in tool_names
        assert "get_policy" in tool_names

    def test_scan_tool_has_description_mentioning_guardrail(self):
        from killswitch.mcp.server import mcp
        tools = asyncio.run(mcp.list_tools())
        scan_tool = next(t for t in tools if t.name == "scan")
        desc_lower = (scan_tool.description or "").lower()
        assert "guardrail" in desc_lower or "opt-in" in desc_lower or "voluntary" in desc_lower

    def test_scan_tool_accepts_text_param(self):
        from killswitch.mcp.server import mcp
        tools = asyncio.run(mcp.list_tools())
        scan_tool = next(t for t in tools if t.name == "scan")
        schema = scan_tool.inputSchema
        assert "text" in schema.get("properties", {})

    def test_recent_findings_accepts_limit_param(self):
        from killswitch.mcp.server import mcp
        tools = asyncio.run(mcp.list_tools())
        rf_tool = next(t for t in tools if t.name == "recent_findings")
        schema = rf_tool.inputSchema
        assert "limit" in schema.get("properties", {})
