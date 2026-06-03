from __future__ import annotations

from typing import Any, Optional

from ..core.config import get_config, Config
from ..core.decision import execute_decision
from ..core.normalizer import normalize_anthropic_messages
from ..core.policy import resolve_action
from ..core.scanner import scan_units
from ..exceptions import KillswitchBlocked
from ..logging.logger import get_logger, reserve_event_id


def _guard_payload(
    payload: dict,
    operation: str,
    cfg: Config,
) -> tuple[str, dict]:
    units = normalize_anthropic_messages(payload)

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
            provider="anthropic",
            operation=operation,
        )
    except KillswitchBlocked:
        # Log the blocked outcome, then re-raise so the caller sees the exception.
        logger.log_event(
            provider="anthropic",
            operation=operation,
            mode=cfg.mode,
            decision="blocked",
            findings=result.findings,
            event_id=event_id,
        )
        try:
            from ..core.stats import record_call
            record_call(
                provider="anthropic",
                model=payload.get("model"),
                mode=cfg.mode,
                decision="blocked",
                finding_types=[f.finding_type for f in result.findings],
            )
        except Exception:
            pass
        raise

    # Single log entry per request with the definitive outcome.
    logger.log_event(
        provider="anthropic",
        operation=operation,
        mode=cfg.mode,
        decision=final_action,
        findings=result.findings,
        event_id=event_id,
    )

    try:
        from ..core.stats import record_call
        record_call(
            provider="anthropic",
            model=payload.get("model"),
            mode=cfg.mode,
            decision=final_action,
            finding_types=[f.finding_type for f in result.findings],
        )
    except Exception:
        pass

    return final_action, sanitized


class GuardedAnthropic:
    """
    A drop-in wrapper for anthropic.Anthropic that scans payloads before sending.

    Usage::

        from anthropic import Anthropic
        from killswitch_ai.anthropic import GuardedAnthropic

        client = GuardedAnthropic(Anthropic())
        response = client.messages.create(
            model="claude-opus-4-5",
            max_tokens=1024,
            messages=[{"role": "user", "content": "Hello"}],
        )
    """

    def __init__(self, client: Any, config: Optional[Config] = None) -> None:
        self._client = client
        self._config = config
        self._messages = _GuardedMessages(client, self)

    def _get_config(self) -> Config:
        return self._config or get_config()

    @property
    def messages(self) -> "_GuardedMessages":
        return self._messages

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)


class _GuardedMessages:
    def __init__(self, client: Any, guard: GuardedAnthropic) -> None:
        # Capture the real messages object BEFORE any replacement so that
        # create() delegates to the original SDK implementation without recursion.
        self._real_messages = client.messages if hasattr(client, 'messages') else None
        self._client = client
        self._guard = guard

    def create(self, **kwargs: Any) -> Any:
        cfg = self._guard._get_config()
        _, sanitized = _guard_payload(kwargs, "messages.create", cfg)
        target = self._real_messages or self._client.messages
        return target.create(**sanitized)

    def __getattr__(self, name: str) -> Any:
        target = self._real_messages or self._client.messages
        return getattr(target, name)
