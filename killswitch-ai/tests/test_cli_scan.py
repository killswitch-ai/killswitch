"""
Tests for `killswitch scan` CLI command behavior.
Covers: plain output (findings / no-findings), JSON mode, decision line.
"""
from __future__ import annotations

import json
from io import StringIO
from unittest.mock import MagicMock, patch

import pytest

from killswitch_ai.core.config import Config
from killswitch_ai.core.scanner import Finding, ScanResult


def _make_finding(
    finding_type="openai_key",
    severity="critical",
    description="Possible OpenAI API key",
    start=0,
    end=10,
):
    return Finding(
        finding_id="KAI-F-TEST-aabbcc",
        severity=severity,
        category="secret_pattern",
        finding_type=finding_type,
        description=description,
        recommendation="Rotate the key.",
        scan_path="cli.scan",
        match_start=start,
        match_end=end,
        matched_text_preview="sk-proj-abc",
    )


def _run_scan_cmd(text: str, json_output: bool = False):
    """
    Invoke _cmd_scan and return captured stdout as a string.
    """
    import sys
    import argparse
    from killswitch_ai.cli.main import _cmd_scan

    args = argparse.Namespace(text=text, json=json_output)
    captured = StringIO()
    old_stdout = sys.stdout
    sys.stdout = captured
    try:
        _cmd_scan(args)
    finally:
        sys.stdout = old_stdout
    return captured.getvalue()


class TestCliScanNoFindings:
    def test_no_findings_prints_all_clear(self):
        cfg = Config(mode="pause")
        empty_result = ScanResult(findings=[], scanned_units=1)
        with patch("killswitch_ai.core.config.get_config", return_value=cfg), \
             patch("killswitch_ai.core.scanner.scan_units", return_value=empty_result):
            output = _run_scan_cmd("Hello, world!")

        assert "No issues detected" in output
        assert "allow" in output.lower()

    def test_no_findings_json_mode_returns_empty_list(self):
        cfg = Config(mode="pause")
        empty_result = ScanResult(findings=[], scanned_units=1)
        with patch("killswitch_ai.core.config.get_config", return_value=cfg), \
             patch("killswitch_ai.core.scanner.scan_units", return_value=empty_result):
            output = _run_scan_cmd("Hello, world!", json_output=True)

        data = json.loads(output)
        assert data == {"findings": []}

    def test_no_findings_json_has_correct_structure(self):
        cfg = Config(mode="kill")
        empty_result = ScanResult(findings=[], scanned_units=1)
        with patch("killswitch_ai.core.config.get_config", return_value=cfg), \
             patch("killswitch_ai.core.scanner.scan_units", return_value=empty_result):
            output = _run_scan_cmd("safe text", json_output=True)

        data = json.loads(output)
        assert "findings" in data
        assert isinstance(data["findings"], list)


class TestCliScanWithFindings:
    def test_findings_printed_in_plain_mode(self):
        cfg = Config(mode="kill")
        finding = _make_finding()
        result = ScanResult(findings=[finding], scanned_units=1)
        with patch("killswitch_ai.core.config.get_config", return_value=cfg), \
             patch("killswitch_ai.core.scanner.scan_units", return_value=result):
            output = _run_scan_cmd("sk-proj-abc123xyzlong")

        assert "CRITICAL" in output
        assert "Possible OpenAI API key" in output
        assert "KAI-F-TEST-aabbcc" in output

    def test_findings_include_decision_line(self):
        cfg = Config(mode="kill")
        finding = _make_finding()
        result = ScanResult(findings=[finding], scanned_units=1)
        with patch("killswitch_ai.core.config.get_config", return_value=cfg), \
             patch("killswitch_ai.core.scanner.scan_units", return_value=result):
            output = _run_scan_cmd("sk-proj-abc123xyzlong")

        # Decision line should show the mode and resolved action
        assert "kill" in output.lower() or "KILL" in output

    def test_findings_json_mode_structure(self):
        cfg = Config(mode="pause")
        finding = _make_finding()
        result = ScanResult(findings=[finding], scanned_units=1)
        with patch("killswitch_ai.core.config.get_config", return_value=cfg), \
             patch("killswitch_ai.core.scanner.scan_units", return_value=result):
            output = _run_scan_cmd("sk-proj-abc123xyzlong", json_output=True)

        data = json.loads(output)
        assert len(data["findings"]) == 1
        f = data["findings"][0]
        assert f["finding_id"] == "KAI-F-TEST-aabbcc"
        assert f["severity"] == "critical"
        assert f["type"] == "openai_key"
        assert "description" in f

    def test_multiple_findings_all_shown(self):
        cfg = Config(mode="report_only")
        findings = [
            _make_finding("openai_key", "critical"),
            _make_finding("prohibited_term", "medium", "Prohibited term detected in prompt"),
        ]
        result = ScanResult(findings=findings, scanned_units=1)
        with patch("killswitch_ai.core.config.get_config", return_value=cfg), \
             patch("killswitch_ai.core.scanner.scan_units", return_value=result):
            output = _run_scan_cmd("some text with issues", json_output=True)

        data = json.loads(output)
        assert len(data["findings"]) == 2

    def test_count_line_mentions_number_of_issues(self):
        cfg = Config(mode="pause")
        findings = [_make_finding(), _make_finding("github_token", "critical")]
        result = ScanResult(findings=findings, scanned_units=1)
        with patch("killswitch_ai.core.config.get_config", return_value=cfg), \
             patch("killswitch_ai.core.scanner.scan_units", return_value=result):
            output = _run_scan_cmd("some text")

        assert "2" in output  # "Found 2 issue(s)"


class TestCliScanPrivacy:
    def test_prohibited_term_description_does_not_include_matched_text(self):
        """
        The Finding.description for prohibited terms must not contain the
        matched substring — it's persisted to disk via findings.jsonl.
        """
        from killswitch_ai.core.scanner import scan_text

        findings = scan_text(
            "my API_KEY is here",
            entropy_enabled=False,
        )
        term_findings = [f for f in findings if f.finding_type == "prohibited_term"]
        assert term_findings, "Expected at least one prohibited_term finding"
        for f in term_findings:
            # description should NOT contain the raw matched string
            assert "API_KEY" not in f.description, (
                f"Description leaks matched text: {f.description!r}"
            )
            # matched_text_preview may contain it (it's in-memory only)
            assert f.matched_text_preview  # still set for in-memory use

    def test_finding_description_is_taxonomy_safe(self):
        """Generic finding descriptions must use taxonomy language only."""
        from killswitch_ai.core.scanner import scan_text

        # Try a custom prohibited term from config
        findings = scan_text(
            "CONFIDENTIAL information is stored here",
            extra_prohibited_terms=["CONFIDENTIAL"],
            entropy_enabled=False,
        )
        for f in findings:
            if f.finding_type == "prohibited_term":
                assert "CONFIDENTIAL" not in f.description


class TestCliScanRecursivePayload:
    """
    Provider normalizers must recursively scan the entire payload, not just
    the top-level message content fields.
    """
    def test_openai_responses_scans_tool_args(self):
        from killswitch_ai.core.normalizer import normalize_openai_responses

        payload = {
            "input": "Hello",
            "tools": [
                {
                    "type": "function",
                    "function": {
                        "name": "call_db",
                        "parameters": {
                            "query": "SELECT * FROM users WHERE key = 'sk-proj-abc123xyzlong'"
                        },
                    },
                }
            ],
        }
        units = normalize_openai_responses(payload)
        contents = [u.content for u in units]
        # The secret inside tool args must be reachable
        assert any("sk-proj-abc123xyzlong" in c for c in contents), (
            f"Tool arg content not found in units: {contents}"
        )

    def test_anthropic_scans_tool_use_input(self):
        from killswitch_ai.core.normalizer import normalize_anthropic_messages

        payload = {
            "messages": [
                {
                    "role": "assistant",
                    "content": [
                        {
                            "type": "tool_use",
                            "id": "toolu_01",
                            "name": "run_query",
                            "input": {"api_key": "sk-proj-secret123xyzlong"},
                        }
                    ],
                }
            ]
        }
        units = normalize_anthropic_messages(payload)
        contents = [u.content for u in units]
        assert any("sk-proj-secret123xyzlong" in c for c in contents), (
            f"Tool use input not found in units: {contents}"
        )

    def test_openai_chat_scans_function_call_arguments(self):
        from killswitch_ai.core.normalizer import normalize_openai_chat

        payload = {
            "messages": [
                {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "function": {
                                "name": "do_thing",
                                "arguments": '{"secret":"sk-ant-api-SecretKeyLong123456"}',
                            }
                        }
                    ],
                }
            ]
        }
        units = normalize_openai_chat(payload)
        contents = [u.content for u in units]
        assert any("sk-ant-api-SecretKeyLong123456" in c for c in contents), (
            f"Function call arguments not found in units: {contents}"
        )
