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
            assert "decision" in f

    def test_decision_field_present_in_schema(self):
        from killswitch.mcp.server import _recent_findings
        result = _recent_findings(limit=1)
        assert "findings" in result
        if result["findings"]:
            assert "decision" in result["findings"][0]


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

    def test_allowlist_field_present(self):
        from killswitch.mcp.server import _get_policy
        result = _get_policy()
        assert "allowlist" in result

    def test_allowlist_is_list(self):
        from killswitch.mcp.server import _get_policy
        result = _get_policy()
        assert isinstance(result["allowlist"], list)

    def test_allowlist_reflects_config(self):
        from killswitch.mcp.server import _get_policy
        from killswitch.core.config import get_config, set_config, Config
        cfg = Config()
        cfg.allowlist = ["safe-token", "internal-key"]
        set_config(cfg)
        try:
            result = _get_policy()
            assert "safe-token" in result["allowlist"]
            assert "internal-key" in result["allowlist"]
        finally:
            set_config(Config())

    def test_allowlist_empty_when_config_has_none(self):
        from killswitch.mcp.server import _get_policy
        from killswitch.core.config import get_config, set_config, Config
        cfg = Config()
        cfg.allowlist = []
        set_config(cfg)
        try:
            result = _get_policy()
            assert result["allowlist"] == []
        finally:
            set_config(Config())

    def test_prohibited_terms_field_present(self):
        from killswitch.mcp.server import _get_policy
        result = _get_policy()
        assert "prohibited_terms" in result

    def test_prohibited_terms_is_list(self):
        from killswitch.mcp.server import _get_policy
        result = _get_policy()
        assert isinstance(result["prohibited_terms"], list)

    def test_prohibited_terms_reflects_config(self):
        from killswitch.mcp.server import _get_policy
        from killswitch.core.config import set_config, Config
        cfg = Config()
        cfg.prohibited_terms = ["secret-word", "do-not-leak"]
        set_config(cfg)
        try:
            result = _get_policy()
            assert "secret-word" in result["prohibited_terms"]
            assert "do-not-leak" in result["prohibited_terms"]
        finally:
            set_config(Config())

    def test_prohibited_terms_empty_when_config_has_none(self):
        from killswitch.mcp.server import _get_policy
        from killswitch.core.config import set_config, Config
        cfg = Config()
        cfg.prohibited_terms = []
        set_config(cfg)
        try:
            result = _get_policy()
            assert result["prohibited_terms"] == []
        finally:
            set_config(Config())


class TestUpdatePolicyTool:
    """Tests for _update_policy: valid updates and invalid input rejection."""

    def setup_method(self):
        from killswitch.core.config import set_config, Config
        self._original = Config()
        set_config(Config())

    def teardown_method(self, tmp_path=None):
        from killswitch.core.config import set_config, Config
        set_config(self._original)

    def test_update_mode_valid(self, tmp_path):
        from killswitch.mcp.server import _update_policy
        from killswitch.core.config import get_config, set_config, Config
        cfg = Config()
        cfg._source_path = tmp_path / "killswitch.yml"
        set_config(cfg)
        result = _update_policy(mode="kill")
        assert result["ok"] is True
        assert result["changes"]["mode"]["new"] == "kill"
        assert get_config().mode == "kill"

    def test_update_mode_all_valid_values(self, tmp_path):
        from killswitch.mcp.server import _update_policy, VALID_MODES
        from killswitch.core.config import set_config, Config
        for valid_mode in VALID_MODES:
            cfg = Config()
            cfg._source_path = tmp_path / "killswitch.yml"
            set_config(cfg)
            result = _update_policy(mode=valid_mode)
            assert result["ok"] is True, f"mode={valid_mode} should be valid"

    def test_update_mode_invalid_rejected(self, tmp_path):
        from killswitch.mcp.server import _update_policy
        from killswitch.core.config import set_config, Config
        cfg = Config()
        cfg._source_path = tmp_path / "killswitch.yml"
        set_config(cfg)
        result = _update_policy(mode="blastoff")
        assert result["ok"] is False
        assert result["errors"]
        assert any("blastoff" in e for e in result["errors"])

    def test_add_prohibited_terms(self, tmp_path):
        from killswitch.mcp.server import _update_policy
        from killswitch.core.config import get_config, set_config, Config
        cfg = Config()
        cfg._source_path = tmp_path / "killswitch.yml"
        set_config(cfg)
        result = _update_policy(prohibited_terms_add=["SUPER_SECRET", "DO_NOT_LEAK"])
        assert result["ok"] is True
        terms = get_config().prohibited_terms
        assert "SUPER_SECRET" in terms
        assert "DO_NOT_LEAK" in terms

    def test_add_prohibited_terms_no_duplicates(self, tmp_path):
        from killswitch.mcp.server import _update_policy
        from killswitch.core.config import get_config, set_config, Config
        cfg = Config()
        existing = cfg.prohibited_terms[0]
        cfg._source_path = tmp_path / "killswitch.yml"
        set_config(cfg)
        _update_policy(prohibited_terms_add=[existing])
        terms = get_config().prohibited_terms
        assert terms.count(existing) == 1

    def test_remove_prohibited_terms(self, tmp_path):
        from killswitch.mcp.server import _update_policy
        from killswitch.core.config import get_config, set_config, Config
        cfg = Config()
        term_to_remove = cfg.prohibited_terms[0]
        cfg._source_path = tmp_path / "killswitch.yml"
        set_config(cfg)
        result = _update_policy(prohibited_terms_remove=[term_to_remove])
        assert result["ok"] is True
        assert term_to_remove not in get_config().prohibited_terms

    def test_update_actions_valid(self, tmp_path):
        from killswitch.mcp.server import _update_policy
        from killswitch.core.config import get_config, set_config, Config
        cfg = Config()
        cfg._source_path = tmp_path / "killswitch.yml"
        set_config(cfg)
        result = _update_policy(actions={"jwt_token": "kill", "high_entropy_string": "pause"})
        assert result["ok"] is True
        updated_cfg = get_config()
        assert updated_cfg.actions["jwt_token"] == "kill"
        assert updated_cfg.actions["high_entropy_string"] == "pause"

    def test_update_actions_invalid_action_rejected(self, tmp_path):
        from killswitch.mcp.server import _update_policy
        from killswitch.core.config import set_config, Config
        cfg = Config()
        cfg._source_path = tmp_path / "killswitch.yml"
        set_config(cfg)
        result = _update_policy(actions={"jwt_token": "explode"})
        assert result["ok"] is False
        assert result["errors"]
        assert any("explode" in e for e in result["errors"])

    def test_multiple_validation_errors_all_returned(self, tmp_path):
        from killswitch.mcp.server import _update_policy
        from killswitch.core.config import set_config, Config
        cfg = Config()
        cfg._source_path = tmp_path / "killswitch.yml"
        set_config(cfg)
        result = _update_policy(
            mode="invalid_mode",
            actions={"jwt_token": "bad_action"},
        )
        assert result["ok"] is False
        assert len(result["errors"]) >= 2

    def test_no_op_call_succeeds(self, tmp_path):
        from killswitch.mcp.server import _update_policy
        from killswitch.core.config import set_config, Config
        cfg = Config()
        cfg._source_path = tmp_path / "killswitch.yml"
        set_config(cfg)
        result = _update_policy()
        assert result["ok"] is True
        assert result["changes"] == {}

    def test_result_has_note_mentioning_immediate_effect(self, tmp_path):
        from killswitch.mcp.server import _update_policy
        from killswitch.core.config import set_config, Config
        cfg = Config()
        cfg._source_path = tmp_path / "killswitch.yml"
        set_config(cfg)
        result = _update_policy(mode="off")
        assert "note" in result
        assert "immediately" in result["note"].lower() or "take effect" in result["note"].lower()

    def test_changes_persisted_to_disk(self, tmp_path):
        import yaml
        from killswitch.mcp.server import _update_policy
        from killswitch.core.config import set_config, Config
        cfg = Config()
        cfg._source_path = tmp_path / "killswitch.yml"
        set_config(cfg)
        _update_policy(mode="redact")
        data = yaml.safe_load((tmp_path / "killswitch.yml").read_text())
        mode_val = data.get("mode", {})
        assert mode_val.get("default_action") == "redact"

    def test_result_contains_config_file_path(self, tmp_path):
        from killswitch.mcp.server import _update_policy
        from killswitch.core.config import set_config, Config
        cfg = Config()
        cfg._source_path = tmp_path / "killswitch.yml"
        set_config(cfg)
        result = _update_policy(mode="pause")
        assert "config_file" in result
        assert result["config_file"] is not None

    def test_allowlist_add(self, tmp_path):
        from killswitch.mcp.server import _update_policy
        from killswitch.core.config import get_config, set_config, Config
        cfg = Config()
        cfg._source_path = tmp_path / "killswitch.yml"
        set_config(cfg)
        result = _update_policy(allowlist_add=["my-safe-token", "internal-key"])
        assert result["ok"] is True
        allowlist = get_config().allowlist
        assert "my-safe-token" in allowlist
        assert "internal-key" in allowlist

    def test_allowlist_add_no_duplicates(self, tmp_path):
        from killswitch.mcp.server import _update_policy
        from killswitch.core.config import get_config, set_config, Config
        cfg = Config()
        cfg.allowlist = ["existing-entry"]
        cfg._source_path = tmp_path / "killswitch.yml"
        set_config(cfg)
        _update_policy(allowlist_add=["existing-entry"])
        allowlist = get_config().allowlist
        assert allowlist.count("existing-entry") == 1

    def test_allowlist_remove(self, tmp_path):
        from killswitch.mcp.server import _update_policy
        from killswitch.core.config import get_config, set_config, Config
        cfg = Config()
        cfg.allowlist = ["keep-me", "remove-me"]
        cfg._source_path = tmp_path / "killswitch.yml"
        set_config(cfg)
        result = _update_policy(allowlist_remove=["remove-me"])
        assert result["ok"] is True
        allowlist = get_config().allowlist
        assert "remove-me" not in allowlist
        assert "keep-me" in allowlist

    def test_allowlist_remove_nonexistent_is_noop(self, tmp_path):
        from killswitch.mcp.server import _update_policy
        from killswitch.core.config import get_config, set_config, Config
        cfg = Config()
        cfg.allowlist = ["keep-me"]
        cfg._source_path = tmp_path / "killswitch.yml"
        set_config(cfg)
        result = _update_policy(allowlist_remove=["not-present"])
        assert result["ok"] is True
        assert get_config().allowlist == ["keep-me"]

    def test_allowlist_changes_recorded_in_changes(self, tmp_path):
        from killswitch.mcp.server import _update_policy
        from killswitch.core.config import set_config, Config
        cfg = Config()
        cfg.allowlist = ["old-entry"]
        cfg._source_path = tmp_path / "killswitch.yml"
        set_config(cfg)
        result = _update_policy(
            allowlist_add=["new-entry"],
            allowlist_remove=["old-entry"],
        )
        assert result["ok"] is True
        assert "allowlist_added" in result["changes"]
        assert "new-entry" in result["changes"]["allowlist_added"]
        assert "allowlist_removed" in result["changes"]
        assert "old-entry" in result["changes"]["allowlist_removed"]

    def test_allowlist_persisted_to_disk(self, tmp_path):
        import yaml
        from killswitch.mcp.server import _update_policy
        from killswitch.core.config import set_config, Config
        cfg = Config()
        cfg._source_path = tmp_path / "killswitch.yml"
        set_config(cfg)
        _update_policy(allowlist_add=["safe-pattern"])
        data = yaml.safe_load((tmp_path / "killswitch.yml").read_text())
        allowlist = data.get("detection", {}).get("allowlist", [])
        assert "safe-pattern" in allowlist

    def test_allowlist_no_op_when_not_supplied(self, tmp_path):
        from killswitch.mcp.server import _update_policy
        from killswitch.core.config import get_config, set_config, Config
        cfg = Config()
        cfg.allowlist = ["unchanged"]
        cfg._source_path = tmp_path / "killswitch.yml"
        set_config(cfg)
        result = _update_policy(mode="pause")
        assert result["ok"] is True
        assert get_config().allowlist == ["unchanged"]
        assert "allowlist_added" not in result["changes"]
        assert "allowlist_removed" not in result["changes"]


class TestCheckPolicyTool:
    """Tests for _check_policy: all three outcomes — prohibited, allowlisted, neither."""

    def setup_method(self):
        from killswitch.core.config import set_config, Config
        cfg = Config()
        cfg.prohibited_terms = ["forbidden-word", "do-not-send"]
        cfg.allowlist = ["safe-token", "internal-key"]
        set_config(cfg)

    def teardown_method(self, _method=None):
        from killswitch.core.config import set_config, Config
        set_config(Config())

    def test_prohibited_term_returns_prohibited(self):
        from killswitch.mcp.server import _check_policy
        result = _check_policy("forbidden-word")
        assert result["prohibited"] is True
        assert result["allowlisted"] is False
        assert result["status"] == "prohibited"

    def test_allowlisted_term_returns_allowlisted(self):
        from killswitch.mcp.server import _check_policy
        result = _check_policy("safe-token")
        assert result["prohibited"] is False
        assert result["allowlisted"] is True
        assert result["status"] == "allowlisted"

    def test_unknown_term_returns_neither(self):
        from killswitch.mcp.server import _check_policy
        result = _check_policy("totally-unrelated-word")
        assert result["prohibited"] is False
        assert result["allowlisted"] is False
        assert result["status"] == "neither"

    def test_term_echoed_in_response(self):
        from killswitch.mcp.server import _check_policy
        result = _check_policy("some-term")
        assert result["term"] == "some-term"

    def test_result_has_required_fields(self):
        from killswitch.mcp.server import _check_policy
        result = _check_policy("anything")
        assert "term" in result
        assert "prohibited" in result
        assert "allowlisted" in result
        assert "status" in result

    def test_status_values_are_valid(self):
        from killswitch.mcp.server import _check_policy
        valid_statuses = {"prohibited", "allowlisted", "neither"}
        for term in ["forbidden-word", "safe-token", "unknown"]:
            result = _check_policy(term)
            assert result["status"] in valid_statuses

    def test_prohibited_takes_precedence_when_in_both(self):
        from killswitch.mcp.server import _check_policy
        from killswitch.core.config import set_config, Config
        cfg = Config()
        cfg.prohibited_terms = ["overlap-term"]
        cfg.allowlist = ["overlap-term"]
        set_config(cfg)
        result = _check_policy("overlap-term")
        assert result["prohibited"] is True
        assert result["allowlisted"] is True
        assert result["status"] == "prohibited"

    def test_second_prohibited_term_also_detected(self):
        from killswitch.mcp.server import _check_policy
        result = _check_policy("do-not-send")
        assert result["status"] == "prohibited"

    def test_second_allowlist_term_also_detected(self):
        from killswitch.mcp.server import _check_policy
        result = _check_policy("internal-key")
        assert result["status"] == "allowlisted"

    def test_empty_lists_returns_neither(self):
        from killswitch.mcp.server import _check_policy
        from killswitch.core.config import set_config, Config
        cfg = Config()
        cfg.prohibited_terms = []
        cfg.allowlist = []
        set_config(cfg)
        result = _check_policy("anything")
        assert result["status"] == "neither"
        assert result["prohibited"] is False
        assert result["allowlisted"] is False


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

    def test_all_seven_tools_registered(self):
        from killswitch.mcp.server import mcp
        tools = asyncio.run(mcp.list_tools())
        tool_names = {t.name for t in tools}
        assert "scan" in tool_names
        assert "get_status" in tool_names
        assert "get_stats" in tool_names
        assert "recent_findings" in tool_names
        assert "get_policy" in tool_names
        assert "check_policy" in tool_names
        assert "update_policy" in tool_names

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
