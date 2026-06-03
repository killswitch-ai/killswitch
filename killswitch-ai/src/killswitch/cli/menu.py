from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ..core.config import get_config, load_config, save_config
from ..core.policy import explain_finding, what_does_this_mean
from ..core.scanner import Finding
from ..logging.logger import (
    aggregate_stats,
    find_event_by_id,
    find_finding_by_id,
    read_events,
    read_findings,
    read_latest_session,
)


FINDING_TYPES = [
    "openai_key",
    "anthropic_key",
    "aws_access_key",
    "aws_secret_key",
    "github_token",
    "stripe_key",
    "private_key",
    "jwt_token",
    "database_url",
    "env_file_reference",
    "prohibited_term",
    "sensitive_file_path",
    "generic_password",
    "high_entropy_string",
]

FINDING_TYPE_LABELS = {
    "openai_key":          "OpenAI API key",
    "anthropic_key":       "Anthropic API key",
    "aws_access_key":      "AWS access key ID",
    "aws_secret_key":      "AWS secret access key",
    "github_token":        "GitHub token",
    "stripe_key":          "Stripe API key",
    "private_key":         "Private key (PEM block)",
    "jwt_token":           "JWT token",
    "database_url":        "Database URL with credentials",
    "env_file_reference":  ".env file reference",
    "prohibited_term":     "Prohibited term",
    "sensitive_file_path": "Sensitive file path",
    "generic_password":    "Password assignment",
    "high_entropy_string": "High-entropy string",
}

_ACTION_CYCLE = ["kill", "pause", "redact", "report_only"]
_ACTION_LABELS = {
    "kill":        "BLOCK",
    "pause":       "PAUSE",
    "redact":      "REDACT",
    "report_only": "REPORT ONLY",
}


def _clear() -> None:
    print("\033[H\033[J", end="")


def _hr(char: str = "─", width: int = 60) -> None:
    print(char * width)


def _header(title: str) -> None:
    _hr("═")
    print(f"  killswitch-ai  |  {title}")
    _hr("─")
    print()


def _pause() -> None:
    try:
        input("\n  Press Enter to go back...")
    except (EOFError, KeyboardInterrupt):
        pass


def _ask(prompt: str, default: str = "") -> str:
    hint = f" [{default}]" if default else ""
    try:
        val = input(f"  {prompt}{hint}: ").strip()
        return val if val else default
    except (EOFError, KeyboardInterrupt):
        return default


def _menu_choice(options: list[str], prompt: str = "Choose") -> str:
    for i, opt in enumerate(options, 1):
        print(f"  {i}. {opt}")
    print()
    try:
        return input(f"  {prompt} [1]: ").strip() or "1"
    except (EOFError, KeyboardInterrupt):
        return "0"


def _severity_badge(sev: str) -> str:
    badges = {
        "critical": "🔴 CRITICAL",
        "high":     "🟠 HIGH",
        "medium":   "🟡 MEDIUM",
        "low":      "🔵 LOW",
    }
    return badges.get(sev.lower(), sev.upper())


def run_menu() -> None:
    cfg = get_config()
    while True:
        _clear()
        _header("Main Menu")
        print(f"  Current mode: {cfg.mode.upper()}")
        print(f"  Log directory: {cfg.log_dir}")
        print()

        choice = _menu_choice([
            "Latest blocked or flagged request",
            "Today's summary",
            "Last 7 days summary",
            "Change protection mode",
            "What gets blocked",
            "What gets reported",
            "Test the scanner",
            "Email reports on/off",
            "Privacy settings",
            "Exit",
        ])

        if choice == "1":
            _screen_latest_finding(cfg)
        elif choice == "2":
            _screen_stats_summary(cfg, days=1, label="Today")
        elif choice == "3":
            _screen_stats_summary(cfg, days=7, label="Last 7 days")
        elif choice == "4":
            _screen_change_mode(cfg)
        elif choice == "5":
            _screen_blocked_types(cfg)
        elif choice == "6":
            _screen_reported_types(cfg)
        elif choice == "7":
            _screen_test_scanner(cfg)
        elif choice == "8":
            _screen_email_toggle(cfg)
        elif choice == "9":
            _screen_privacy(cfg)
        elif choice in ("10", "0", ""):
            print("\n  Goodbye!\n")
            break


def _screen_latest_finding(cfg) -> None:
    _clear()
    _header("Latest Blocked or Flagged Request")

    session_dir = read_latest_session(log_dir=cfg.log_dir)
    if session_dir is None:
        print("  No requests have been scanned yet.")
        print()
        print("  Once killswitch-ai scans an LLM request, you'll see the")
        print("  details here — what was detected, why it was flagged, and")
        print("  what happened to the request.")
        _pause()
        return

    findings = read_findings(session_dir)
    events = read_events(session_dir)

    if not findings:
        print("  No findings in the latest session.")
        print("  That means no sensitive content was detected — great!")
        _pause()
        return

    top = findings[0]
    sev = _severity_badge(top.get("severity", ""))
    ftype = top.get("type", "unknown")
    desc = top.get("description", "")

    print(f"  Finding ID : {top.get('finding_id', '')}")
    print(f"  Severity   : {sev}")
    print(f"  Type       : {ftype}")
    print()
    print(f"  What was detected:")
    print(f"  {desc}")
    print()

    finding_obj = Finding(
        finding_id=top.get("finding_id", ""),
        severity=top.get("severity", "medium"),
        finding_type=ftype,
        description=desc,
    )
    explanation = explain_finding(finding_obj)
    _hr()
    print()
    print("  What does this mean?")
    print()
    for line in _wrap(explanation, 55):
        print(f"  {line}")
    print()
    _hr()
    print()
    print(f"  Recommendation:")
    print(f"  {top.get('recommendation', '')}")
    print()

    if events:
        last_event = events[-1]
        decision = last_event.get("decision", "")
        print(f"  Decision: {decision.upper()}")
        print()

    _pause()


def _screen_stats_summary(cfg, days: int = 7, label: str = "Last 7 days") -> None:
    _clear()
    _header(f"Summary — {label}")

    stats = aggregate_stats(log_dir=cfg.log_dir, days=days)

    total = stats["total_events"]
    if total == 0:
        print(f"  No LLM calls scanned in the last {days} day(s).")
        print()
        print("  killswitch-ai only shows data for requests that went through")
        print("  the GuardedOpenAI or GuardedAnthropic wrappers.")
        _pause()
        return

    blocked = stats["blocked"]
    redacted = stats["redacted"]
    flagged = stats["flagged"]
    critical = stats["critical_findings"]
    high = stats["high_findings"]

    print(f"  LLM calls scanned    {total:>6}")
    print(f"  Requests blocked     {blocked:>6}  ← nothing was sent to the LLM")
    print(f"  Requests redacted    {redacted:>6}  ← sensitive value replaced before sending")
    print(f"  Requests flagged     {flagged:>6}  ← logged but allowed through")
    print()
    _hr()
    print()
    print("  Findings by severity:")
    print()
    print(f"  🔴 Critical   {critical:>5}  (API keys, private keys — always block)")
    print(f"  🟠 High       {stats['high_findings']:>5}  (database URLs, JWTs)")
    print(f"  🟡 Medium     {stats['medium_findings']:>5}  (prohibited terms, passwords)")
    print(f"  🔵 Low        {stats['low_findings']:>5}  (high-entropy strings — might be harmless)")
    print()
    _hr()
    print()
    if critical > 0 or high > 0:
        print("  ⚠  You had critical or high findings.")
        print("     If any requests were allowed through, check your code")
        print("     for hardcoded secrets and remove them.")
    else:
        print("  ✓  No critical or high findings. Looking good!")
    print()
    _pause()


def _screen_change_mode(cfg) -> None:
    _clear()
    _header("Change Protection Mode")

    modes = {
        "pause":       "Pause and ask — stops and lets you decide (default)",
        "kill":        "Block automatically — stops all risky requests",
        "redact":      "Redact and continue — replaces secrets, keeps going",
        "report_only": "Log only — lets everything through, just logs it",
    }
    print("  Current mode:", cfg.mode.upper())
    print()
    for key, desc in modes.items():
        marker = "→" if key == cfg.mode else " "
        print(f"  {marker} {key:<14} {desc}")
    print()

    new_mode = _ask("Type a mode name (or press Enter to keep current)", cfg.mode)
    if new_mode in modes:
        cfg.mode = new_mode
        try:
            save_config(cfg)
            print(f"\n  ✓ Mode changed to: {new_mode.upper()}")
        except Exception as e:
            print(f"\n  Could not save config: {e}")
    else:
        print(f"\n  Mode unchanged ({cfg.mode}).")
    _pause()


def _screen_blocked_types(cfg) -> None:
    while True:
        _clear()
        _header("What Gets Blocked")
        print("  Set the action for each finding type.")
        print(f"  Global mode fallback: {cfg.mode.upper()}")
        print()
        print(f"  {'#':<4} {'Finding type':<34} Action")
        _hr()
        for i, ft in enumerate(FINDING_TYPES, 1):
            label = FINDING_TYPE_LABELS.get(ft, ft)
            action = cfg.actions.get(ft, cfg.mode)
            action_label = _ACTION_LABELS.get(action, action.upper())
            print(f"  {i:<4} {label:<34} [{action_label}]")
        print()
        print("  Type a number to cycle its action:")
        print("  BLOCK → PAUSE → REDACT → REPORT ONLY → BLOCK")
        print("  Press Enter to go back.")
        print()
        try:
            raw = input("  Choice: ").strip()
        except (EOFError, KeyboardInterrupt):
            return
        if not raw:
            return
        try:
            idx = int(raw) - 1
            ft = FINDING_TYPES[idx]
        except (ValueError, IndexError):
            continue
        current = cfg.actions.get(ft, cfg.mode)
        try:
            next_idx = (_ACTION_CYCLE.index(current) + 1) % len(_ACTION_CYCLE)
        except ValueError:
            next_idx = 0
        cfg.actions[ft] = _ACTION_CYCLE[next_idx]
        save_config(cfg)
        new_label = _ACTION_LABELS[cfg.actions[ft]]
        print(f"\n  ✓ {FINDING_TYPE_LABELS.get(ft, ft)} → [{new_label}]")


def _screen_reported_types(cfg) -> None:
    while True:
        _clear()
        _header("What Gets Reported")
        print("  Toggle finding types ON/OFF.")
        print("  OFF = completely ignored — no block, no log, no alert.")
        print()
        print(f"  {'#':<4} {'Finding type':<34} Reporting")
        _hr()
        for i, ft in enumerate(FINDING_TYPES, 1):
            label = FINDING_TYPE_LABELS.get(ft, ft)
            status = "OFF" if ft in cfg.disabled_finding_types else "ON"
            print(f"  {i:<4} {label:<34} [{status}]")
        print()
        _hr()
        print()
        print("  Allowlisted phrases (always allowed through, even if they match a pattern):")
        print()
        if cfg.allowlist:
            for j, phrase in enumerate(cfg.allowlist, 1):
                print(f"  a{j}  {phrase}")
        else:
            print("  (none — add one with \"a\")")
        print()
        print("  Enter a number to toggle ON/OFF")
        print("  \"a\" to add an allowlisted phrase")
        print("  \"r<n>\" to remove an allowlisted phrase (e.g. r1)")
        print("  Enter to go back.")
        print()
        try:
            raw = input("  Choice: ").strip()
        except (EOFError, KeyboardInterrupt):
            return
        if not raw:
            return
        if raw.lower() == "a":
            try:
                phrase = input("  Phrase to allowlist: ").strip()
            except (EOFError, KeyboardInterrupt):
                continue
            if phrase and phrase not in cfg.allowlist:
                cfg.allowlist.append(phrase)
                save_config(cfg)
                print(f'\n  ✓ Added: "{phrase}"')
            elif phrase:
                print("\n  Already in the allowlist.")
        elif raw.lower().startswith("r"):
            num_str = raw[1:].strip()
            try:
                ridx = int(num_str) - 1
                removed = cfg.allowlist.pop(ridx)
                save_config(cfg)
                print(f'\n  ✓ Removed: "{removed}"')
            except (ValueError, IndexError):
                print("\n  Invalid number.")
        else:
            try:
                idx = int(raw) - 1
                ft = FINDING_TYPES[idx]
            except (ValueError, IndexError):
                continue
            if ft in cfg.disabled_finding_types:
                cfg.disabled_finding_types.remove(ft)
                status = "ON"
            else:
                cfg.disabled_finding_types.append(ft)
                status = "OFF"
            save_config(cfg)
            print(f"\n  ✓ {FINDING_TYPE_LABELS.get(ft, ft)} → [{status}]")


def _screen_edit_protection(cfg) -> None:
    _clear()
    _header("Edit What to Protect")

    print("  Current prohibited terms (exact text that should never be sent):")
    print()
    for i, term in enumerate(cfg.prohibited_terms, 1):
        print(f"  {i:>2}. {term}")
    print()
    _hr()
    print()
    print("  Options:")
    print("  a. Add a new prohibited term")
    print("  r. Remove a term by number")
    print("  q. Go back")
    print()

    try:
        action = input("  Choice: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return

    if action == "a":
        new_term = _ask("New term to prohibit")
        if new_term and new_term not in cfg.prohibited_terms:
            cfg.prohibited_terms.append(new_term)
            save_config(cfg)
            print(f'\n  ✓ Added: "{new_term}"')
        elif new_term:
            print(f'\n  Already in the list: "{new_term}"')
    elif action == "r":
        num = _ask("Remove term number")
        try:
            idx = int(num) - 1
            removed = cfg.prohibited_terms.pop(idx)
            save_config(cfg)
            print(f'\n  ✓ Removed: "{removed}"')
        except (ValueError, IndexError):
            print("\n  Invalid number.")
    _pause()


def _screen_test_scanner(cfg) -> None:
    _clear()
    _header("Test the Scanner")

    print("  Type some text and killswitch-ai will show you exactly what")
    print("  it would detect — without sending anything anywhere.")
    print()

    try:
        text = input("  Text to scan: ").strip()
    except (EOFError, KeyboardInterrupt):
        return

    if not text:
        print("\n  Nothing to scan.")
        _pause()
        return

    from ..core.normalizer import ScanUnit
    from ..core.scanner import scan_units

    units = [ScanUnit(path="test", content=text)]
    result = scan_units(
        units,
        extra_prohibited_terms=cfg.prohibited_terms,
        entropy_enabled=cfg.entropy_enabled,
        entropy_min_length=cfg.entropy_min_length,
        entropy_threshold=cfg.entropy_threshold,
        allowlist=cfg.allowlist,
        disabled_finding_types=cfg.disabled_finding_types,
    )

    print()
    _hr()
    print()

    if not result.findings:
        print("  ✓ No issues detected in that text.")
        print("  killswitch-ai would allow this request through.")
    else:
        print(f"  Found {len(result.findings)} issue(s):")
        print()
        for f in result.findings:
            print(f"  {_severity_badge(f.severity)}  —  {f.description}")
            exp = explain_finding(f)
            print()
            for line in _wrap(exp, 54):
                print(f"    {line}")
            print()
        _hr()
        print()
        from ..core.policy import resolve_action
        action = resolve_action(result.findings, cfg.actions, cfg.mode)
        print(f"  In your current mode ({cfg.mode.upper()}), this request would be: {action.upper()}")

    _pause()


def _screen_email_toggle(cfg) -> None:
    _clear()
    _header("Email Reports")

    status = "ON" if cfg.email.enabled else "OFF"
    print(f"  Email reports are currently: {status}")
    if cfg.email.enabled:
        print(f"  Sending to: {cfg.email.address}")
    print()
    _hr()
    print()
    print("  Weekly email reports contain ONLY anonymous numbers:")
    print("  how many requests were scanned, blocked, redacted, or flagged.")
    print("  No prompt text, no secret values, no source code is ever included.")
    print()

    if cfg.email.enabled:
        turn_off = _ask("Turn off email reports? (yes/no)", "no")
        if turn_off.lower() in ("y", "yes"):
            cfg.email.enabled = False
            save_config(cfg)
            print("\n  ✓ Email reports turned off.")
    else:
        turn_on = _ask("Turn on email reports? (yes/no)", "no")
        if turn_on.lower() in ("y", "yes"):
            addr = _ask("Your email address")
            if addr:
                cfg.email.enabled = True
                cfg.email.address = addr
                save_config(cfg)
                print(f"\n  ✓ Email reports enabled. Sending to: {addr}")
                print("  To send a report now: killswitch report --send")
    _pause()


def _screen_privacy(cfg) -> None:
    _clear()
    _header("Privacy Settings")

    print("  killswitch-ai is designed to protect your data, including from itself.")
    print()
    _hr()
    print()
    print("  What is NEVER stored:")
    print("  • Your prompt text or messages")
    print("  • Secret values or API keys")
    print("  • Source code or file contents")
    print("  • Full request payloads")
    print()
    print("  What IS stored locally (in .killswitch/):")
    print("  • Event IDs and timestamps")
    print("  • Which provider and operation was called")
    print("  • The decision (blocked / allowed / redacted)")
    print("  • Finding type and severity (not the secret itself)")
    print("  • Recommendations")
    print()
    _hr()
    print()
    print("  Log directory:", cfg.log_dir)
    print()

    store_raw = "YES" if cfg.store_raw_payloads else "NO"
    store_secrets = "YES" if cfg.store_secret_values else "NO"
    email_on = "YES" if cfg.email.enabled else "NO"

    print(f"  Store raw payloads:  {store_raw}  (should be NO)")
    print(f"  Store secret values: {store_secrets}  (should be NO)")
    print(f"  Email reports:       {email_on}")
    print()
    _hr()
    print()
    print("  To see what data is in your logs:")
    print("  ls .killswitch/sessions/")
    _pause()


def _wrap(text: str, width: int = 55) -> list[str]:
    words = text.split()
    lines = []
    current = ""
    for word in words:
        if len(current) + len(word) + 1 <= width:
            current = (current + " " + word).strip()
        else:
            if current:
                lines.append(current)
            current = word
    if current:
        lines.append(current)
    return lines
