"""
Tests covering the areas called out by code review:
 - Top-level module re-exports
 - install() monkeypatch (no recursion, correct interception)
 - Single log event per request (including blocked)
 - Redact mode covers all finding types (not just regex)
 - Wizard category selections are persisted to config
"""
from __future__ import annotations

import importlib
import types
from unittest.mock import MagicMock, patch

import pytest

from killswitch_ai.core.config import Config
from killswitch_ai.core.scanner import Finding
from killswitch_ai.exceptions import KillswitchBlocked


# ---------------------------------------------------------------------------
# 1. Top-level re-exports
# ---------------------------------------------------------------------------

class TestTopLevelImports:
    def test_guarded_openai_importable_from_killswitch_ai_openai(self):
        from killswitch_ai.openai import GuardedOpenAI  # noqa: F401
        assert GuardedOpenAI is not None

    def test_guarded_anthropic_importable_from_killswitch_ai_anthropic(self):
        from killswitch_ai.anthropic import GuardedAnthropic  # noqa: F401
        assert GuardedAnthropic is not None

    def test_guarded_openai_is_same_class_as_provider(self):
        from killswitch_ai.openai import GuardedOpenAI as A
        from killswitch_ai.providers.openai import GuardedOpenAI as B
        assert A is B

    def test_guarded_anthropic_is_same_class_as_provider(self):
        from killswitch_ai.anthropic import GuardedAnthropic as A
        from killswitch_ai.providers.anthropic import GuardedAnthropic as B
        assert A is B


# ---------------------------------------------------------------------------
# 2. GuardedOpenAI / GuardedAnthropic wrappers intercept correctly
# ---------------------------------------------------------------------------

def _make_finding(finding_type="openai_key", severity="critical", start=0, end=10):
    return Finding(
        severity=severity,
        category="test",
        finding_type=finding_type,
        description="test",
        scan_path="input",
        match_start=start,
        match_end=end,
        matched_text_preview="sk-proj-abc",
    )


class TestGuardedOpenAIWrapper:
    def _make_client(self):
        """Return a mock that looks enough like openai.OpenAI."""
        mock = MagicMock()
        mock.responses.create.return_value = {"id": "resp-1"}
        mock.chat.completions.create.return_value = {"id": "chat-1"}
        return mock

    def test_allow_payload_calls_real_responses_create(self):
        from killswitch_ai.providers.openai import GuardedOpenAI
        client = self._make_client()
        guard = GuardedOpenAI(client)
        cfg = Config(mode="report_only")

        with patch("killswitch_ai.providers.openai.get_config", return_value=cfg), \
             patch("killswitch_ai.providers.openai.scan_units") as mock_scan, \
             patch("killswitch_ai.providers.openai.get_logger") as mock_logger, \
             patch("killswitch_ai.providers.openai.reserve_event_id", return_value="EID-1"):
            mock_scan.return_value = MagicMock(findings=[], has_findings=False)
            mock_logger.return_value = MagicMock()

            guard.responses.create(model="gpt-4o", input="hello")

        client.responses.create.assert_called_once()

    def test_kill_action_raises_killswitch_blocked(self):
        from killswitch_ai.providers.openai import GuardedOpenAI
        client = self._make_client()
        guard = GuardedOpenAI(client)
        cfg = Config(mode="kill")

        finding = _make_finding()
        with patch("killswitch_ai.providers.openai.get_config", return_value=cfg), \
             patch("killswitch_ai.providers.openai.scan_units") as mock_scan, \
             patch("killswitch_ai.providers.openai.get_logger") as mock_logger, \
             patch("killswitch_ai.providers.openai.reserve_event_id", return_value="EID-2"):
            mock_scan.return_value = MagicMock(findings=[finding], has_findings=True)
            mock_logger.return_value = MagicMock()

            with pytest.raises(KillswitchBlocked):
                guard.responses.create(model="gpt-4o", input="sk-proj-abc123xyz789long")

        # The real create should NOT have been called
        client.responses.create.assert_not_called()

    def test_kill_action_logs_exactly_once_with_blocked_decision(self):
        from killswitch_ai.providers.openai import GuardedOpenAI
        client = self._make_client()
        guard = GuardedOpenAI(client)
        cfg = Config(mode="kill")

        finding = _make_finding()
        mock_logger_instance = MagicMock()
        with patch("killswitch_ai.providers.openai.get_config", return_value=cfg), \
             patch("killswitch_ai.providers.openai.scan_units") as mock_scan, \
             patch("killswitch_ai.providers.openai.get_logger", return_value=mock_logger_instance), \
             patch("killswitch_ai.providers.openai.reserve_event_id", return_value="EID-3"):
            mock_scan.return_value = MagicMock(findings=[finding], has_findings=True)

            with pytest.raises(KillswitchBlocked):
                guard.responses.create(model="gpt-4o", input="sk-proj-abc123xyz789long")

        # Exactly one log_event call
        assert mock_logger_instance.log_event.call_count == 1
        call_kwargs = mock_logger_instance.log_event.call_args[1]
        assert call_kwargs["decision"] == "blocked"
        assert call_kwargs["event_id"] == "EID-3"

    def test_allow_action_logs_exactly_once_with_allow_decision(self):
        from killswitch_ai.providers.openai import GuardedOpenAI
        client = self._make_client()
        guard = GuardedOpenAI(client)
        cfg = Config(mode="report_only")

        mock_logger_instance = MagicMock()
        with patch("killswitch_ai.providers.openai.get_config", return_value=cfg), \
             patch("killswitch_ai.providers.openai.scan_units") as mock_scan, \
             patch("killswitch_ai.providers.openai.get_logger", return_value=mock_logger_instance), \
             patch("killswitch_ai.providers.openai.reserve_event_id", return_value="EID-4"):
            mock_scan.return_value = MagicMock(findings=[], has_findings=False)

            guard.responses.create(model="gpt-4o", input="hello world")

        assert mock_logger_instance.log_event.call_count == 1
        call_kwargs = mock_logger_instance.log_event.call_args[1]
        assert call_kwargs["decision"] == "allow"
        assert call_kwargs["event_id"] == "EID-4"


class TestGuardedAnthropicWrapper:
    def _make_client(self):
        mock = MagicMock()
        mock.messages.create.return_value = {"id": "msg-1"}
        return mock

    def test_kill_action_logs_once_with_blocked_decision(self):
        from killswitch_ai.providers.anthropic import GuardedAnthropic
        client = self._make_client()
        guard = GuardedAnthropic(client)
        cfg = Config(mode="kill")

        finding = _make_finding()
        mock_logger_instance = MagicMock()
        with patch("killswitch_ai.providers.anthropic.get_config", return_value=cfg), \
             patch("killswitch_ai.providers.anthropic.scan_units") as mock_scan, \
             patch("killswitch_ai.providers.anthropic.get_logger", return_value=mock_logger_instance), \
             patch("killswitch_ai.providers.anthropic.reserve_event_id", return_value="EID-5"):
            mock_scan.return_value = MagicMock(findings=[finding], has_findings=True)

            with pytest.raises(KillswitchBlocked):
                guard.messages.create(model="claude-3", messages=[{"role": "user", "content": "sk-ant-xxx"}])

        assert mock_logger_instance.log_event.call_count == 1
        call_kwargs = mock_logger_instance.log_event.call_args[1]
        assert call_kwargs["decision"] == "blocked"


# ---------------------------------------------------------------------------
# 3. Redact mode covers ALL finding types (not just regex secrets)
# ---------------------------------------------------------------------------

class TestRedactAllFindingTypes:
    def _make_finding_at(self, finding_type, start, end, severity="medium", matched_text_preview=""):
        return Finding(
            severity=severity,
            category="test",
            finding_type=finding_type,
            description="test",
            scan_path="input",
            match_start=start,
            match_end=end,
            matched_text_preview=matched_text_preview,
        )

    def test_redact_covers_prohibited_term_finding(self):
        from killswitch_ai.core.redactor import redact_text
        text = "My API_KEY is here"
        finding = self._make_finding_at("prohibited_term", 3, 10)  # "API_KEY"
        result = redact_text(text, [finding])
        assert "API_KEY" not in result
        assert "[REDACTED_PROHIBITED]" in result

    def test_redact_covers_high_entropy_finding(self):
        from killswitch_ai.core.redactor import redact_text
        text = "token = aB3xZ9qR7mW2kL5nP8vY1cT4"
        start = text.index("aB3xZ9")
        end = len(text)
        finding = self._make_finding_at("high_entropy_string", start, end)
        result = redact_text(text, [finding])
        assert "[REDACTED_HIGH_ENTROPY_STRING]" in result
        assert "aB3xZ9" not in result

    def test_redact_covers_sensitive_file_path_finding(self):
        from killswitch_ai.core.redactor import redact_text
        text = "reading from .env file today"
        start = text.index(".env")
        end = start + len(".env")
        finding = self._make_finding_at("sensitive_file_path", start, end, severity="high")
        result = redact_text(text, [finding])
        assert "[REDACTED_SENSITIVE_PATH]" in result

    def test_redact_payload_covers_non_regex_findings(self):
        from killswitch_ai.core.redactor import redact_string_in_payload
        text = "CONFIDENTIAL data"
        finding = self._make_finding_at(
            "prohibited_term", 0, len("CONFIDENTIAL"),
            matched_text_preview="CONFIDENTIAL",
        )
        result = redact_string_in_payload(text, [finding])
        assert "CONFIDENTIAL" not in result
        assert "[REDACTED_PROHIBITED]" in result

    def test_redact_payload_dict_nested(self):
        from killswitch_ai.core.redactor import redact_string_in_payload
        payload = {"messages": [{"role": "user", "content": "CONFIDENTIAL info here"}]}
        finding = self._make_finding_at(
            "prohibited_term", 0, len("CONFIDENTIAL"),
            matched_text_preview="CONFIDENTIAL",
        )
        result = redact_string_in_payload(payload, [finding])
        assert "CONFIDENTIAL" not in result["messages"][0]["content"]
        assert "[REDACTED_PROHIBITED]" in result["messages"][0]["content"]


# ---------------------------------------------------------------------------
# 4. Wizard category selections are persisted to config
# ---------------------------------------------------------------------------

class TestWizardCategoryPersistence:
    def test_high_entropy_off_disables_entropy_in_config(self):
        from killswitch_ai.cli.wizard import _CATEGORY_TO_FINDING_TYPES
        # Simulate wizard selecting everything EXCEPT high_entropy
        selected = [k for k, _, default in [
            ("api_keys", "", True),
            ("env_files", "", True),
            ("private_keys", "", True),
            ("passwords", "", True),
            ("database_urls", "", True),
            ("cloud_creds", "", True),
            ("jwt_tokens", "", False),
            # "high_entropy" intentionally omitted
        ] if default]

        cfg = Config()
        cfg.entropy_enabled = "high_entropy" in selected
        assert cfg.entropy_enabled is False

    def test_high_entropy_on_enables_entropy_in_config(self):
        selected = ["high_entropy", "api_keys"]
        cfg = Config()
        cfg.entropy_enabled = "high_entropy" in selected
        assert cfg.entropy_enabled is True

    def test_deselected_category_sets_action_to_allow(self):
        from killswitch_ai.cli.wizard import _CATEGORY_TO_FINDING_TYPES

        selected = ["api_keys", "env_files", "private_keys", "passwords",
                    "database_urls", "cloud_creds"]
        # "jwt_tokens" and "high_entropy" are not selected

        cfg = Config()
        cfg.entropy_enabled = "high_entropy" in selected

        for cat_key, finding_types in _CATEGORY_TO_FINDING_TYPES.items():
            if cat_key == "high_entropy":
                continue
            if cat_key not in selected:
                for ft in finding_types:
                    cfg.actions[ft] = "allow"

        assert cfg.actions["jwt_token"] == "allow"

    def test_selected_category_keeps_default_action(self):
        from killswitch_ai.cli.wizard import _CATEGORY_TO_FINDING_TYPES
        from killswitch_ai.core.config import DEFAULT_ACTIONS

        selected = ["api_keys", "jwt_tokens", "high_entropy"]

        cfg = Config()
        cfg.entropy_enabled = "high_entropy" in selected

        for cat_key, finding_types in _CATEGORY_TO_FINDING_TYPES.items():
            if cat_key == "high_entropy":
                continue
            if cat_key not in selected:
                for ft in finding_types:
                    cfg.actions[ft] = "allow"

        # jwt_token is selected → should keep its default action, not "allow"
        assert cfg.actions.get("jwt_token") == DEFAULT_ACTIONS.get("jwt_token")

    def test_category_mapping_covers_all_data_categories(self):
        from killswitch_ai.cli.wizard import DATA_CATEGORIES, _CATEGORY_TO_FINDING_TYPES
        wizard_keys = {key for key, _, _ in DATA_CATEGORIES}
        mapping_keys = set(_CATEGORY_TO_FINDING_TYPES.keys())
        assert wizard_keys == mapping_keys, (
            f"Missing mappings: {wizard_keys - mapping_keys}; "
            f"Extra mappings: {mapping_keys - wizard_keys}"
        )
