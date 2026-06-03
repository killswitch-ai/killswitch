from __future__ import annotations

import sys
from pathlib import Path
from typing import List

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

# (key, label, default_on)
DATA_CATEGORIES = [
    ("api_keys",         "API keys (OpenAI, Anthropic, AWS, GitHub, Stripe, etc.)",    True),
    ("env_files",        ".env files and environment variable files",                   True),
    ("private_keys",     "Private keys and certificates (.pem, .key, id_rsa, etc.)",   True),
    ("passwords",        "Passwords and database credentials",                          True),
    ("database_urls",    "Database connection URLs (postgres://, mysql://, etc.)",      True),
    ("cloud_creds",      "Cloud credentials (AWS, GCP, Azure config files)",            True),
    ("jwt_tokens",       "JWT tokens",                                                  False),
    ("high_entropy",     "High-entropy strings (might be secrets, might be hashes)",    False),
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


def run_wizard(config_path: Path | None = None) -> None:
    print(BANNER)
    _print("  Welcome to killswitch-ai setup.")
    _print("  This wizard will configure what to protect and what to do when")
    _print("  sensitive content is detected.")
    _print()
    _print("  Takes about 2 minutes. Press Ctrl+C anytime to exit.")
    _print()
    _hr()

    # --- Step 1: Choose mode ---
    _print()
    _print("  STEP 1 OF 4 — What should happen when something is detected?")
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

    # --- Step 2: Data categories ---
    _print()
    _hr()
    _print()
    _print("  STEP 2 OF 4 — What data should never be sent to an AI?")
    _print()
    _print("  Press Enter to keep the default [✓ = on, ✗ = off].")
    _print()

    selected_categories: List[str] = []
    for key, label, default_on in DATA_CATEGORIES:
        default_marker = "✓" if default_on else "✗"
        answer = _ask_yn(f"[{default_marker}] {label}", default=default_on)
        if answer:
            selected_categories.append(key)

    _print()
    _print(f"  ✓ Protecting {len(selected_categories)} data categories.")

    # --- Step 3: Email reports ---
    _print()
    _hr()
    _print()
    _print("  STEP 3 OF 4 — Email reports (optional)")
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
            _print("    • Finding counts by severity")
            _print("    • A hashed install ID and project ID (never your actual path)")
            _print()
            _print("  To turn off anytime: killswitch email --off")
        else:
            wants_email = False

    # --- Step 4: Build and save config ---
    _print()
    _hr()
    _print()
    _print("  STEP 4 OF 4 — Saving your configuration...")
    _print()

    cfg = Config(mode=mode)
    cfg.email = EmailConfig(
        enabled=wants_email,
        address=email_address,
    )

    # Apply category selections to the config:
    #
    # • high_entropy controls the entropy scanner flag.
    # • All other categories map to specific finding types.  When a category
    #   is deselected the corresponding action is set to "allow" so those
    #   findings pass through without triggering the global mode.
    cfg.entropy_enabled = "high_entropy" in selected_categories

    for cat_key, finding_types in _CATEGORY_TO_FINDING_TYPES.items():
        if cat_key == "high_entropy":
            continue  # handled above via entropy_enabled
        if cat_key not in selected_categories:
            for ft in finding_types:
                cfg.actions[ft] = "allow"

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
    _print("    import killswitch_ai")
    _print("    killswitch_ai.install()")
    _print()
    _print("    from openai import OpenAI")
    _print("    client = OpenAI()  # automatically protected")
    _print()
    _print("  Option 2 — Explicit wrapper:")
    _print()
    _print("    from openai import OpenAI")
    _print("    from killswitch_ai.openai import GuardedOpenAI")
    _print()
    _print("    client = GuardedOpenAI(OpenAI())")
    _print()
    _print("  View your local reports anytime:")
    _print()
    _print("    killswitch menu")
    _print()
    _print("  Test the scanner:")
    _print()
    _print('    killswitch scan "your text here"')
    _print()
    _hr("═")
    _print()
