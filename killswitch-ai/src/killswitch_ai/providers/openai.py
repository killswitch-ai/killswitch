from __future__ import annotations

from typing import Any, Optional

from ..core.config import get_config, Config
from ..core.decision import execute_decision
from ..core.normalizer import normalize_openai_responses, normalize_openai_chat
from ..core.policy import resolve_action
from ..core.scanner import scan_units
from ..logging.logger import get_logger


def _guard_payload(
    payload: dict,
    operation: str,
    cfg: Config,
) -> tuple[str, dict]:
    if operation == "responses.create":
        units = normalize_openai_responses(payload)
    else:
        units = normalize_openai_chat(payload)

    result = scan_units(
        units,
        extra_prohibited_terms=cfg.prohibited_terms,
        entropy_enabled=cfg.entropy_enabled,
        entropy_min_length=cfg.entropy_min_length,
        entropy_threshold=cfg.entropy_threshold,
    )

    action = resolve_action(result.findings, cfg.actions, cfg.mode)

    logger = get_logger(log_dir=cfg.log_dir)
    event = logger.log_event(
        provider="openai",
        operation=operation,
        mode=cfg.mode,
        decision=action if not result.has_findings else "pending",
        findings=result.findings,
    )

    final_action, sanitized = execute_decision(
        action=action,
        payload=payload,
        findings=result.findings,
        event_id=event.event_id,
        provider="openai",
        operation=operation,
    )

    logger.log_event(
        provider="openai",
        operation=operation,
        mode=cfg.mode,
        decision=final_action,
        findings=result.findings,
    )

    return final_action, sanitized


class GuardedOpenAI:
    """
    A drop-in wrapper for openai.OpenAI that scans payloads before sending.

    Usage::

        from openai import OpenAI
        from killswitch_ai.openai import GuardedOpenAI

        client = GuardedOpenAI(OpenAI())
        response = client.responses.create(model="gpt-4o", input="...")
    """

    def __init__(self, client: Any, config: Optional[Config] = None) -> None:
        self._client = client
        self._config = config
        self._responses = _GuardedResponses(client, self)
        self._chat = _GuardedChat(client, self)

    def _get_config(self) -> Config:
        return self._config or get_config()

    @property
    def responses(self) -> "_GuardedResponses":
        return self._responses

    @property
    def chat(self) -> "_GuardedChat":
        return self._chat

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)


class _GuardedResponses:
    def __init__(self, client: Any, guard: GuardedOpenAI) -> None:
        self._client = client
        self._guard = guard

    def create(self, **kwargs: Any) -> Any:
        cfg = self._guard._get_config()
        _, sanitized = _guard_payload(kwargs, "responses.create", cfg)
        return self._client.responses.create(**sanitized)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client.responses, name)


class _GuardedChat:
    def __init__(self, client: Any, guard: GuardedOpenAI) -> None:
        self._client = client
        self._guard = guard
        self.completions = _GuardedChatCompletions(client, guard)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client.chat, name)


class _GuardedChatCompletions:
    def __init__(self, client: Any, guard: GuardedOpenAI) -> None:
        self._client = client
        self._guard = guard

    def create(self, **kwargs: Any) -> Any:
        cfg = self._guard._get_config()
        _, sanitized = _guard_payload(kwargs, "chat.completions.create", cfg)
        return self._client.chat.completions.create(**sanitized)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client.chat.completions, name)
