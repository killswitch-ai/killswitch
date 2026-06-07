from __future__ import annotations

import sys
from pathlib import Path
from typing import Dict, List, Tuple

from ..core.config import Config, EmailConfig, save_config


BANNER = r"""
  _    _ _ _               _ _       _              _ 
 | | _(_) | |_____      __(_) |_ ___| |__         __ _(_)
 | |/ / | | / __\ \ /\ / /| | __/ __| '_ \ _____ / _` | |
 |   <| | | \__ \\ V  V / | | || (__| | | |_____| (_| | |
 |_|\_\_|_|_|___/ \_/\_/  |_|\__\___|_| |_|      \__,_|_|

  Local LLM egress control. Stops secrets before they reach the LLM.
"""

MODE_DESCRIPTIONS = {
    "pause": (
        "Pause (recommended for most developers)\n"
        "     If a problem is found, killswitch-ai will stop and ask you what to do.\n"
        "     You can block, redact, or allow the request."
    ),
    "kill": (
        "Block automatically\n"
        "     If a problem is found, the request is blocked immediately.\n"
        "     Good for CI pipelines or production servers."
    ),
    "redact": (
        "Redact and continue\n"
        "     If a problem is found, the sensitive value is replaced with a\n"
        "     placeholder (e.g. [REDACTED_OPENAI_KEY]) and the request is sent.\n"
        "     Good if you want hands-off protection."
    ),
    "report_only": (
        "Log only (no blocking)\n"
        "     Requests always go through. Findings are logged locally.\n"
        "     Good for trying the tool out without disrupting your workflow."
    ),
}

# (key, label, default_on, default_action)
DATA_CATEGORIES: List[Tuple[str, str, bool, str]] = [
    ("api_keys",      "API keys (OpenAI, Anthropic, AWS, GitHub, Stripe, etc.)", True,  "kill"),
    ("env_files",     ".env files and environment variable files",                True,  "pause"),
    ("private_keys",  "Private keys and certificates (.pem, .key, id_rsa, etc.)", True, "kill"),
    ("passwords",     "Passwords and database credentials",                       True,  "pause"),
    ("database_urls", "Database connection URLs (postgres://, mysql://, etc.)",   True,  "pause"),
    ("cloud_creds",   "Cloud credentials (AWS, GCP, Azure config files)",         True,  "kill"),
    ("jwt_tokens",    "JWT tokens",                                                False, "redact"),
    ("high_entropy",  "High-entropy strings (might be secrets, might be hashes)", False, "report_only"),
]

# Maps wizard category keys → Config action overrides.
# When a category is deselected, these finding types are set to "allow" so
# they pass through without triggering the global mode.
_CATEGORY_TO_FINDING_TYPES: dict[str, list[str]] = {
    "api_keys":      ["openai_key", "anthropic_key", "aws_access_key", "github_token", "stripe_key"],
    "env_files":     ["sensitive_file_path"],
    "private_keys":  ["private_key"],
    "passwords":     ["generic_password"],
    "database_urls": ["database_url"],
    "cloud_creds":   ["aws_secret_key"],
    "jwt_tokens":    ["jwt_token"],
    "high_entropy":  ["high_entropy_string"],
}

_VALID_ACTIONS = {"kill", "redact", "pause", "report_only", "report-only"}
_ACTION_NORM: dict[str, str] = {
    "kill": "kill",
    "redact": "redact",
    "pause": "pause",
    "report_only": "report_only",
    "report-only": "report_only",
}


def _print(msg: str = "") -> None:
    print(msg)


def _hr(char: str = "─", width: int = 60) -> None:
    print(char * width)


def _ask(prompt: str, default: str = "") -> str:
    default_hint = f" [{default}]" if default else ""
    try:
        val = input(f"  {prompt}{default_hint}: ").strip()
        return val if val else default
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)


def _ask_yn(prompt: str, default: bool = True) -> bool:
    hint = "Y/n" if default else "y/N"
    try:
        val = input(f"  {prompt} [{hint}]: ").strip().lower()
        if not val:
            return default
        return val in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)


def _ask_action(category_label: str, default_action: str) -> str:
    """
    Prompt the user to choose an action for a data category.
    Returns the normalised action string.
    """
    _print()
    _print(f"    How should killswitch-ai handle {category_label}?")
    _print(f"    kill        — block the request immediately")
    _print(f"    redact      — replace the secret with [REDACTED], continue")
    _print(f"    pause       — ask you what to do at runtime")
    _print(f"    report-only — log only, let the request through")
    raw = _ask(f"    Action", default_action).lower().strip()
    return _ACTION_NORM.get(raw, default_action)


def run_wizard(config_path: Path | None = None) -> None:
    print(BANNER)
    _print("  Welcome to killswitch-ai setup.")
    _print("  This wizard takes about 1 minute. Fine-grained settings are")
    _print("  available any time in: killswitch menu")
    _print()
    _print("  Press Ctrl+C anytime to exit.")
    _print()
    _hr()

    # --- Step 1: Choose mode ---
    _print()
    _print("  STEP 1 OF 3 — What should happen when something is detected?")
    _print()
    for i, (key, desc) in enumerate(MODE_DESCRIPTIONS.items(), 1):
        _print(f"  {i}. {desc}")
        _print()

    mode_keys = list(MODE_DESCRIPTIONS.keys())
    mode_choice = _ask("Choose a number", "1")
    try:
        mode = mode_keys[int(mode_choice) - 1]
    except (ValueError, IndexError):
        mode = "pause"

    _print()
    _print(f"  ✓ Mode set to: {mode}")

    # --- Step 2: Email reports ---
    _print()
    _hr()
    _print()
    _print("  STEP 2 OF 3 — Email reports (optional)")
    _print()
    _print("  killswitch-ai can send you a weekly summary by email.")
    _print("  The summary contains ONLY anonymous counts — how many requests")
    _print("  were scanned, blocked, or flagged. No prompt text, no secret")
    _print("  values, no source code. Just numbers.")
    _print()

    wants_email = _ask_yn("Would you like weekly email summaries?", default=False)
    email_address = ""
    if wants_email:
        _print()
        _print("  What is your email address?")
        email_address = _ask("Email address")
        if email_address:
            _print()
            _print(f"  ✓ Email reports enabled for {email_address}")
            _print()
            _print("  What will be sent (nothing else):")
            _print("    • Total LLM calls scanned")
            _print("    • Number blocked / redacted / flagged")
            _print("    • Finding counts by severity and category")
            _print("    • A hashed install ID and project ID (never your actual path)")
            _print()
            _print("  To turn off anytime: killswitch email --off")
        else:
            wants_email = False

    # --- Step 3: Anonymous telemetry ---
    _print()
    _hr()
    _print()
    _print("  STEP 3 OF 3 — Anonymous usage telemetry (optional)")
    _print()
    _print("  Would you like to share anonymous aggregate usage trends?")
    _print()
    _print("  We collect:")
    _print("    - number of scans")
    _print("    - number of blocked requests")
    _print("    - finding categories")
    _print("    - severity counts")
    _print("    - provider type")
    _print("    - killswitch-ai version")
    _print("    - operating system family")
    _print()
    _print("  We do not collect:")
    _print("    - prompts")
    _print("    - responses")
    _print("    - source code")
    _print("    - file contents")
    _print("    - terminal output")
    _print("    - API keys")
    _print("    - secrets")
    _print("    - full commands")
    _print("    - absolute file paths")
    _print()
    _print("  Telemetry is off by default. You can change this anytime in")
    _print("  killswitch.yml under the 'telemetry' key.")
    _print()

    if wants_email:
        # Email reports require telemetry — turn it on automatically.
        wants_telemetry = True
        _print()
        _print("  ✓ Anonymous telemetry enabled automatically (required for email reports).")
    else:
        wants_telemetry = _ask_yn("Enable anonymous telemetry?", default=False)
        if wants_telemetry:
            _print()
            _print("  ✓ Anonymous telemetry enabled. Thank you!")

    # --- Save config ---
    # Apply default category settings — all defaults-on categories get their
    # default action, defaults-off categories are disabled. Fine-grained
    # overrides are available via `killswitch menu`.
    _print()
    _hr()
    _print()

    cfg = Config(mode=mode)
    cfg.email = EmailConfig(
        enabled=wants_email,
        address=email_address,
    )
    cfg.telemetry_enabled = wants_telemetry

    cfg.entropy_enabled = False  # high_entropy is off by default; toggle via menu

    for cat_key, label, default_on, default_action in DATA_CATEGORIES:
        finding_types = _CATEGORY_TO_FINDING_TYPES.get(cat_key, [])
        if not default_on:
            for ft in finding_types:
                cfg.actions[ft] = "allow"
        else:
            for ft in finding_types:
                cfg.actions[ft] = default_action

    save_path = config_path or (Path.cwd() / "killswitch.yml")
    save_config(cfg, save_path)

    _print(f"  ✓ Configuration saved to: {save_path}")

    # --- Done: Quick-start snippet ---
    _print()
    _hr("═")
    _print()
    _print("  You're all set! Here's how to use killswitch-ai:")
    _print()
    _print("  Option 1 — One-liner (easiest):")
    _print()
    _print("    import killswitch")
    _print("    killswitch.install()")
    _print()
    _print("    from openai import OpenAI")
    _print("    client = OpenAI()  # automatically protected")
    _print()
    _print("  Option 2 — Explicit wrapper:")
    _print()
    _print("    from openai import OpenAI")
    _print("    from killswitch.openai import GuardedOpenAI")
    _print()
    _print("    client = GuardedOpenAI(OpenAI())")
    _print()
    _print("  Verify it's working:")
    _print()
    _print("    killswitch test")
    _print()
    _print("  View your local reports anytime:")
    _print()
    _print("    killswitch menu")
    _print()
    _hr("═")
    _print()
