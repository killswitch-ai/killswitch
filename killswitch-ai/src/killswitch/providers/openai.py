from __future__ import annotations

from typing import Any, Optional

from ..core.config import get_config, Config
from ..core.decision import execute_decision
from ..core.normalizer import normalize_openai_responses, normalize_openai_chat
from ..core.policy import resolve_action
from ..core.scanner import scan_units
from ..exceptions import KillswitchBlocked
from ..logging.logger import get_logger, reserve_event_id


def _guard_payload(
    payload: dict,
    operation: str,
    cfg: Config,
) -> tuple[str, dict]:
    from .. import verbose as _v

    _v.v1(f"Intercepting openai / {operation}")
    if _v.is_super():
        _v.sep("═")
        _v.v2(f"killswitch-ai is about to scan this request to openai / {operation}")
        _v.v2(f"  Active mode : {cfg.mode.upper()}")
        cfg_label = str(cfg._source_path) if cfg._source_path else "defaults (no killswitch.yml found)"
        _v.v2(f"  Config file : {cfg_label}")
        _v.blank()
        _v.v2(f"  What killswitch does:")
        _v.v2(f"    It extracts every piece of text from your payload — messages,")
        _v.v2(f"    system prompts, tool arguments — and scans each one for secrets,")
        _v.v2(f"    API keys, passwords, and other sensitive content BEFORE the")
        _v.v2(f"    network request is made. Nothing reaches OpenAI until it's clean.")
        _v.blank()

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
    # Reserve a stable event_id up-front so it can be shown in block/pause
    # notices before we know the final decision.
    event_id = reserve_event_id()

    try:
        final_action, sanitized = execute_decision(
            action=action,
            payload=payload,
            findings=result.findings,
            event_id=event_id,
            provider="openai",
            operation=operation,
        )
    except KillswitchBlocked:
        # Log the blocked outcome, then re-raise so the caller sees the exception.
        logger.log_event(
            provider="openai",
            operation=operation,
            mode=cfg.mode,
            decision="blocked",
            findings=result.findings,
            event_id=event_id,
        )
        try:
            from ..core.stats import record_call
            record_call(
                provider="openai",
                model=payload.get("model") or payload.get("model_id"),
                mode=cfg.mode,
                decision="blocked",
                finding_types=[f.finding_type for f in result.findings],
            )
        except Exception:
            pass
        raise

    # Single log entry per request with the definitive outcome.
    logger.log_event(
        provider="openai",
        operation=operation,
        mode=cfg.mode,
        decision=final_action,
        findings=result.findings,
        event_id=event_id,
    )

    try:
        from ..core.stats import record_call
        record_call(
            provider="openai",
            model=payload.get("model") or payload.get("model_id"),
            mode=cfg.mode,
            decision=final_action,
            finding_types=[f.finding_type for f in result.findings],
        )
    except Exception:
        pass

    from .. import verbose as _v
    if _v.is_super():
        _v.sep("═")
        _v.blank()

    return final_action, sanitized


class GuardedOpenAI:
    """
    A drop-in wrapper for openai.OpenAI that scans payloads before sending.

    Usage::

        from openai import OpenAI
        from killswitch.openai import GuardedOpenAI

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
        # Keep a reference to the real `responses` object captured BEFORE
        # GuardedOpenAI replaced the attribute, so create() delegates to the
        # original SDK implementation without risk of recursion.
        self._real_responses = client.responses if hasattr(client, 'responses') else None
        self._client = client
        self._guard = guard

    def create(self, **kwargs: Any) -> Any:
        cfg = self._guard._get_config()
        _, sanitized = _guard_payload(kwargs, "responses.create", cfg)
        target = self._real_responses or self._client.responses
        return target.create(**sanitized)

    def __getattr__(self, name: str) -> Any:
        target = self._real_responses or self._client.responses
        return getattr(target, name)


class _GuardedChat:
    def __init__(self, client: Any, guard: GuardedOpenAI) -> None:
        self._client = client
        self._guard = guard
        self.completions = _GuardedChatCompletions(client, guard)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client.chat, name)


class _GuardedChatCompletions:
    def __init__(self, client: Any, guard: GuardedOpenAI) -> None:
        # Capture the real completions object before any patching.
        self._real_completions = client.chat.completions if hasattr(client, 'chat') else None
        self._client = client
        self._guard = guard

    def create(self, **kwargs: Any) -> Any:
        cfg = self._guard._get_config()
        _, sanitized = _guard_payload(kwargs, "chat.completions.create", cfg)
        target = self._real_completions or self._client.chat.completions
        return target.create(**sanitized)

    def __getattr__(self, name: str) -> Any:
        target = self._real_completions or self._client.chat.completions
        return getattr(target, name)
