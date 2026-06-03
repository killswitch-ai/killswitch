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
    from .. import verbose as _v

    _v.v1(f"Intercepting anthropic / {operation}")
    if _v.is_super():
        _v.sep("═")
        _v.v2(f"killswitch-ai is about to scan this request to anthropic / {operation}")
        _v.v2(f"  Active mode : {cfg.mode.upper()}")
        cfg_label = str(cfg._source_path) if cfg._source_path else "defaults (no killswitch.yml found)"
        _v.v2(f"  Config file : {cfg_label}")
        _v.blank()
        _v.v2(f"  What killswitch does:")
        _v.v2(f"    It extracts every piece of text from your payload — messages,")
        _v.v2(f"    system prompts, tool inputs — and scans each one for secrets,")
        _v.v2(f"    API keys, passwords, and other sensitive content BEFORE the")
        _v.v2(f"    network request is made. Nothing reaches Anthropic until it's clean.")
        _v.blank()

    units = normalize_anthropic_messages(payload)

    result = scan_units(
        units,
        extra_prohibited_terms=cfg.prohibited_terms,
        entropy_enabled=cfg.entropy_enabled,
        entropy_min_length=cfg.entropy_min_length,
        entropy_threshold=cfg.entropy_threshold,
        allowlist=cfg.allowlist,
        disabled_finding_types=cfg.disabled_finding_types,
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

    if _v.is_super():
        _v.sep("═")
        _v.blank()

    return final_action, sanitized


class GuardedAnthropic:
    """
    A drop-in wrapper for anthropic.Anthropic that scans payloads before sending.

    Usage::

        from anthropic import Anthropic
        from killswitch.anthropic import GuardedAnthropic

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
