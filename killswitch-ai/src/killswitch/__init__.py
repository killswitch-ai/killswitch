"""
killswitch-ai — Local LLM egress control for Python apps.

Stops secrets and prohibited data from being sent to LLMs.

Quick start::

    # Option 1: Explicit wrapper (recommended)
    from openai import OpenAI
    from killswitch.openai import GuardedOpenAI

    client = GuardedOpenAI(OpenAI())
    response = client.responses.create(model="gpt-4o", input="...")

    # Option 2: One-liner monkeypatch
    import killswitch
    killswitch.install()

    from openai import OpenAI
    client = OpenAI()  # now automatically guarded

Verbose output::

    # See every step killswitch takes — great for debugging or learning
    killswitch.install(verbose=1)   # key milestones
    killswitch.install(verbose=2)   # every pattern check, entropy score, decision

    # Or set via environment variable (works with any usage style):
    # KILLSWITCH_VERBOSE=1 python your_script.py
    # KILLSWITCH_VERBOSE=2 python your_script.py
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("killswitch-ai")
except PackageNotFoundError:
    __version__ = "0.0.0"
__all__ = ["install", "scan", "KillswitchBlocked"]

from .exceptions import KillswitchBlocked


def install(mode: str | None = None, verbose: int = 0) -> None:
    """
    Monkeypatch openai.OpenAI and anthropic.Anthropic so every subsequent
    instantiation is automatically guarded.

    Args:
        mode:    Override the active mode for this session.
                 One of: "kill", "pause", "redact", "report_only".
                 If omitted, the mode from killswitch.yml is used (default: "pause").
        verbose: How much output to print while scanning.
                 0 = silent (default) — only block/redact/pause notices.
                 1 = verbose — key milestones (intercepted, N findings, decision).
                 2 = super-verbose — every step explained in plain English.
                 You can also set KILLSWITCH_VERBOSE=1 or =2 in the environment.

    Usage::

        import killswitch
        killswitch.install()              # uses killswitch.yml mode (or "pause")
        killswitch.install("kill")        # override mode for this session
        killswitch.install(verbose=2)     # see exactly what killswitch is doing
    """
    from . import verbose as _verbose
    from .core.config import get_config, set_config

    if verbose:
        _verbose.set_level(verbose)

    cfg = get_config()
    if mode is not None:
        cfg.mode = mode
        set_config(cfg)

    if _verbose.is_on():
        cfg_label = str(cfg._source_path) if cfg._source_path else "defaults (no killswitch.yml found)"
        _verbose.v1(f"killswitch-ai installed  mode={cfg.mode.upper()}  config={cfg_label}")
        if _verbose.is_super():
            _verbose.blank()
            _verbose.v2(f"  killswitch is now active. Every call to openai.OpenAI or")
            _verbose.v2(f"  anthropic.Anthropic will be automatically intercepted and")
            _verbose.v2(f"  scanned before the network request is made.")
            _verbose.blank()

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
                    action, sanitized = _guard_payload(kw, "responses.create", cfg)
                    if action == "drop":
                        from .providers.openai import _dropped_response
                        return _dropped_response("responses.create")
                    return _orig_responses.create(**sanitized)

                def __getattr__(_, name):
                    return getattr(_orig_responses, name)

            class _CompletionsShim:
                def create(_, **kw):
                    action, sanitized = _guard_payload(kw, "chat.completions.create", cfg)
                    if action == "drop":
                        from .providers.openai import _dropped_response
                        return _dropped_response("chat.completions.create")
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
                    action, sanitized = _guard_payload(kw, "messages.create", cfg)
                    if action == "drop":
                        from .providers.anthropic import _dropped_response
                        return _dropped_response()
                    return _orig_messages.create(**sanitized)

                def __getattr__(_, name):
                    return getattr(_orig_messages, name)

            self.messages = _MessagesShim()

        _anthropic.Anthropic.__init__ = _guarded_init
    except ImportError:
        pass


def scan(text: str, verbose: int = 0) -> "ScanResult":
    """
    Scan a string and return a ScanResult with any findings.

    Args:
        text:    The text to scan.
        verbose: How much output to print (0=silent, 1=verbose, 2=super-verbose).

    Usage::

        import killswitch
        result = killswitch.scan("my API_KEY is sk-proj-abc123...")
        for finding in result.findings:
            print(finding.description)

        # See every step:
        result = killswitch.scan("...", verbose=2)
    """
    from . import verbose as _verbose
    from .core.config import get_config
    from .core.normalizer import ScanUnit
    from .core.scanner import scan_units

    if verbose:
        _verbose.set_level(verbose)

    cfg = get_config()
    units = [ScanUnit(path="input", content=text)]
    return scan_units(
        units,
        extra_prohibited_terms=cfg.prohibited_terms,
        entropy_enabled=cfg.entropy_enabled,
        entropy_min_length=cfg.entropy_min_length,
        entropy_threshold=cfg.entropy_threshold,
    )
