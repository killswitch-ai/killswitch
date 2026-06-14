import pytest
from killswitch.core.redactor import redact_text, redact_string_in_payload, _replacement
from killswitch.core.scanner import Finding


def _make_finding(finding_type: str, start: int = 0, end: int = 10) -> Finding:
    return Finding(
        severity="critical",
        finding_type=finding_type,
        description="test finding",
        match_start=start,
        match_end=end,
    )


class TestRedactText:
    def test_basic_redaction(self):
        text = "prefix_sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ_suffix"
        finding = _make_finding("openai_key", start=7, end=44)
        result = redact_text(text, [finding])
        assert "[REDACTED_OPENAI_KEY]" in result
        assert "sk-proj" not in result

    def test_no_findings_returns_original(self):
        text = "clean text here"
        result = redact_text(text, [])
        assert result == text

    def test_empty_text(self):
        assert redact_text("", []) == ""

    def test_multiple_findings_redacted(self):
        text = "key=sk-proj-ABCDEFGHIJKLMNOPQ other=ghp_1234567890abcdefghijklmnopqrstuv"
        f1 = _make_finding("openai_key", start=4, end=30)
        f2 = _make_finding("github_token", start=38, end=72)
        result = redact_text(text, [f1, f2])
        assert "[REDACTED_OPENAI_KEY]" in result
        assert "[REDACTED_GITHUB_TOKEN]" in result


class TestRedactPayload:
    def test_string_payload(self):
        payload = "my key is sk-proj-AbCdEfGhIjKlMnOpQrStUvWx"
        result = redact_string_in_payload(payload, [])
        assert "[REDACTED_OPENAI_KEY]" in result

    def test_dict_payload(self):
        payload = {"input": "sk-proj-AbCdEfGhIjKlMnOpQrStUvWx123", "model": "gpt-4o"}
        result = redact_string_in_payload(payload, [])
        assert "[REDACTED_OPENAI_KEY]" in result["input"]
        assert result["model"] == "gpt-4o"

    def test_nested_dict_payload(self):
        payload = {
            "messages": [
                {"role": "user", "content": "my token: sk-proj-AbCdEfGhIjKlMnOpQrSt123"}
            ]
        }
        result = redact_string_in_payload(payload, [])
        assert "[REDACTED_OPENAI_KEY]" in result["messages"][0]["content"]

    def test_original_not_mutated(self):
        payload = {"input": "sk-proj-AbCdEfGhIjKlMnOpQrStUvWx123"}
        original_value = payload["input"]
        redact_string_in_payload(payload, [])
        assert payload["input"] == original_value

    def test_clean_payload_unchanged(self):
        payload = {"input": "Hello, how are you?", "model": "gpt-4o"}
        result = redact_string_in_payload(payload, [])
        assert result["input"] == "Hello, how are you?"


class TestReplacementLabels:
    def test_known_types(self):
        assert "OPENAI_KEY" in _replacement("openai_key")
        assert "PRIVATE_KEY" in _replacement("private_key")
        assert "GITHUB_TOKEN" in _replacement("github_token")
        assert "DATABASE_URL" in _replacement("database_url")

    def test_unknown_type_fallback(self):
        result = _replacement("some_custom_type")
        assert "REDACTED" in result
