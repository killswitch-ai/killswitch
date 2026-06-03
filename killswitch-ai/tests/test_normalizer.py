import pytest
from killswitch_ai.core.normalizer import (
    normalize_openai_responses,
    normalize_openai_chat,
    normalize_anthropic_messages,
    normalize_payload,
    normalize_generic,
)


class TestOpenAIResponsesNormalizer:
    def test_string_input(self):
        payload = {"input": "Hello world", "model": "gpt-4o"}
        units = normalize_openai_responses(payload)
        assert any(u.content == "Hello world" for u in units)

    def test_list_input(self):
        payload = {
            "input": [
                {"role": "user", "content": "What is the capital of France?"}
            ]
        }
        units = normalize_openai_responses(payload)
        texts = [u.content for u in units]
        assert any("What is the capital" in t for t in texts)

    def test_instructions_field(self):
        payload = {"input": "Hello", "instructions": "You are a helpful assistant."}
        units = normalize_openai_responses(payload)
        assert any(u.path == "instructions" for u in units)

    def test_empty_payload(self):
        units = normalize_openai_responses({})
        assert units == []


class TestOpenAIChatNormalizer:
    def test_simple_messages(self):
        payload = {
            "model": "gpt-4o",
            "messages": [
                {"role": "system", "content": "You are helpful."},
                {"role": "user", "content": "Tell me a joke."},
            ],
        }
        units = normalize_openai_chat(payload)
        contents = [u.content for u in units]
        assert "You are helpful." in contents
        assert "Tell me a joke." in contents

    def test_list_content_messages(self):
        payload = {
            "messages": [
                {
                    "role": "user",
                    "content": [{"type": "text", "text": "Analyze this"}],
                }
            ]
        }
        units = normalize_openai_chat(payload)
        assert any("Analyze this" in u.content for u in units)

    def test_no_messages(self):
        units = normalize_openai_chat({})
        assert units == []


class TestAnthropicNormalizer:
    def test_simple_messages(self):
        payload = {
            "model": "claude-opus-4-5",
            "max_tokens": 100,
            "system": "You are a pirate.",
            "messages": [
                {"role": "user", "content": "Hello there!"}
            ],
        }
        units = normalize_anthropic_messages(payload)
        contents = [u.content for u in units]
        assert "You are a pirate." in contents
        assert "Hello there!" in contents

    def test_system_as_list(self):
        payload = {
            "system": [{"type": "text", "text": "System instructions here."}],
            "messages": [],
        }
        units = normalize_anthropic_messages(payload)
        assert any("System instructions" in u.content for u in units)

    def test_nested_content_blocks(self):
        payload = {
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "Here is my key: sk-proj-abc123..."},
                    ],
                }
            ]
        }
        units = normalize_anthropic_messages(payload)
        assert any("sk-proj-abc123" in u.content for u in units)


class TestNormalizePayload:
    def test_openai_responses_routing(self):
        payload = {"input": "test", "model": "gpt-4o"}
        units = normalize_payload(payload, provider="openai", operation="responses.create")
        assert len(units) > 0

    def test_anthropic_routing(self):
        payload = {"messages": [{"role": "user", "content": "Hello"}]}
        units = normalize_payload(payload, provider="anthropic")
        assert len(units) > 0

    def test_generic_routing(self):
        payload = {"text": "some content"}
        units = normalize_payload(payload, provider="unknown")
        assert len(units) > 0

    def test_non_dict_payload(self):
        units = normalize_payload("just a plain string")
        assert any(u.content == "just a plain string" for u in units)
