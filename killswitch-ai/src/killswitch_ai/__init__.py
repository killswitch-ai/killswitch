"""
killswitch-ai — Local LLM egress control for Python apps.

Stops secrets and prohibited data from being sent to LLMs.

Quick start::

    # Option 1: Explicit wrapper (recommended)
    from openai import OpenAI
    from killswitch_ai.openai import GuardedOpenAI

    client = GuardedOpenAI(OpenAI())
    response = client.responses.create(model="gpt-4o", input="...")

    # Option 2: One-liner monkeypatch
    import killswitch_ai
    killswitch_ai.install()

    from openai import OpenAI
    client = OpenAI()  # now automatically guarded
"""

from __future__ import annotations

__version__ = "0.1.0"
__all__ = ["install", "scan", "KillswitchBlocked"]

from .exceptions import KillswitchBlocked


def install(mode: str | None = None) -> None:
    """
    Monkeypatch openai.OpenAI and anthropic.Anthropic so every subsequent
    instantiation is automatically guarded.

    Usage::

        import killswitch_ai
        killswitch_ai.install()          # uses mode from killswitch.yml (or "pause")
        killswitch_ai.install("kill")    # override mode for this session
    """
    from .core.config import get_config, set_config

    cfg = get_config()
    if mode is not None:
        cfg.mode = mode
        set_config(cfg)

    _patch_openai(cfg)
    _patch_anthropic(cfg)


def _patch_openai(cfg) -> None:
    try:
        import openai as _openai
        from .providers.openai import _guard_payload

        _orig_init = _openai.OpenAI.__init__

        def _guarded_init(self, *args, **kwargs):
            _orig_init(self, *args, **kwargs)
            # Capture the real objects BEFORE we overwrite instance attributes.
            # This breaks the circular reference: the shims close over the
            # originals, not over `self`, so no recursion is possible.
            _orig_responses = self.responses
            _orig_chat = self.chat

            class _ResponsesShim:
                def create(_, **kw):
                    _, sanitized = _guard_payload(kw, "responses.create", cfg)
                    return _orig_responses.create(**sanitized)

                def __getattr__(_, name):
                    return getattr(_orig_responses, name)

            class _CompletionsShim:
                def create(_, **kw):
                    _, sanitized = _guard_payload(kw, "chat.completions.create", cfg)
                    return _orig_chat.completions.create(**sanitized)

                def __getattr__(_, name):
                    return getattr(_orig_chat.completions, name)

            class _ChatShim:
                completions = _CompletionsShim()

                def __getattr__(_, name):
                    return getattr(_orig_chat, name)

            self.responses = _ResponsesShim()
            self.chat = _ChatShim()

        _openai.OpenAI.__init__ = _guarded_init
    except ImportError:
        pass


def _patch_anthropic(cfg) -> None:
    try:
        import anthropic as _anthropic
        from .providers.anthropic import _guard_payload

        _orig_init = _anthropic.Anthropic.__init__

        def _guarded_init(self, *args, **kwargs):
            _orig_init(self, *args, **kwargs)
            # Capture the real messages object BEFORE replacing it.
            _orig_messages = self.messages

            class _MessagesShim:
                def create(_, **kw):
                    _, sanitized = _guard_payload(kw, "messages.create", cfg)
                    return _orig_messages.create(**sanitized)

                def __getattr__(_, name):
                    return getattr(_orig_messages, name)

            self.messages = _MessagesShim()

        _anthropic.Anthropic.__init__ = _guarded_init
    except ImportError:
        pass


def scan(text: str) -> "ScanResult":
    """
    Scan a string and return a ScanResult with any findings.

    Usage::

        import killswitch_ai
        result = killswitch_ai.scan("my API_KEY is sk-proj-abc123...")
        for finding in result.findings:
            print(finding.description)
    """
    from .core.config import get_config
    from .core.normalizer import ScanUnit
    from .core.scanner import scan_units

    cfg = get_config()
    units = [ScanUnit(path="input", content=text)]
    return scan_units(
        units,
        extra_prohibited_terms=cfg.prohibited_terms,
        entropy_enabled=cfg.entropy_enabled,
        entropy_min_length=cfg.entropy_min_length,
        entropy_threshold=cfg.entropy_threshold,
    )
