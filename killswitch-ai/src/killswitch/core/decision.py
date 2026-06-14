from __future__ import annotations

import sys
from typing import Any, List, Tuple

from .policy import explain_finding, resolve_action
from .redactor import redact_string_in_payload
from .scanner import Finding
from ..exceptions import KillswitchBlocked


def execute_decision(
    action: str,
    payload: Any,
    findings: List[Finding],
    event_id: str,
    provider: str = "",
    operation: str = "",
) -> Tuple[str, Any]:
    """
    Execute the resolved action.

    Returns:
        (final_action, sanitized_payload)
        final_action may differ from input if the user makes a choice in pause mode.
    """
    from .. import verbose as _v

    if action == "allow" or not findings:
        _v.v2("No findings — request passes through unchanged.")
        return "allow", payload

    # Level-2: explain how the action was chosen
    if _v.is_super():
        _v.sep()
        _v.v2("Resolving what to do...")
        _v.v2("  killswitch checks each finding against two things:")
        _v.v2("  1. Per-type rules in your config (e.g. 'openai_key → kill')")
        _v.v2("  2. Your default mode (the fallback if no specific rule exists)")
        _v.blank()
        top = findings[0]
        from .config import DEFAULT_ACTIONS
        if top.finding_type in DEFAULT_ACTIONS:
            _v.v2(f"  Per-type rule: {top.finding_type} → {DEFAULT_ACTIONS[top.finding_type]}")
        _v.v2(f"  Resolved action: {action.upper()}")
        _v.blank()

    if action == "kill":
        top = findings[0]
        _v.v1(f"Decision: BLOCK  "
              f"(finding={top.finding_type}, severity={top.severity.upper()})")
        if _v.is_super():
            _v.v2(f"ACTION: BLOCKING this request.")
            _v.v2(f"  → The LLM will NOT receive your message.")
            _v.v2(f"  → A KillswitchBlocked exception is raised in your code.")
            _v.v2(f"  → No secret value is stored in the logs.")
            _v.v2(f"  → To handle this, wrap your call:")
            _v.v2(f"")
            _v.v2(f"       from killswitch.exceptions import KillswitchBlocked")
            _v.v2(f"       try:")
            _v.v2(f"           response = client.chat.completions.create(...)")
            _v.v2(f"       except KillswitchBlocked as e:")
            _v.v2(f"           print('Blocked:', e)")
            _v.blank()
        _print_block_notice(findings, event_id, provider, operation)
        raise KillswitchBlocked(findings[0], event_id)

    if action == "drop":
        top = findings[0]
        _v.v1(f"Decision: DROP  "
              f"(finding={top.finding_type}, severity={top.severity.upper()})")
        if _v.is_super():
            _v.v2(f"ACTION: DROPPING this request.")
            _v.v2(f"  → The LLM will NOT receive your message.")
            _v.v2(f"  → A synthetic empty response is returned by provider wrappers.")
            _v.v2(f"  → No secret value is stored in the logs.")
            _v.blank()
        _print_drop_notice(findings, event_id, provider, operation)
        return "drop", payload

    if action == "pause":
        _v.v1(f"Decision: PAUSE  "
              f"(finding={findings[0].finding_type}, severity={findings[0].severity.upper()})")
        if _v.is_super():
            _v.v2(f"ACTION: PAUSING — asking you what to do.")
            _v.v2(f"  → Execution stops here until you respond.")
            _v.v2(f"  → You will be shown a menu: block, redact, or allow once.")
            _v.blank()
        return _handle_pause(payload, findings, event_id, provider, operation)

    if action == "redact":
        top = findings[0]
        _v.v1(f"Decision: REDACT  "
              f"(finding={top.finding_type}, severity={top.severity.upper()})")
        if _v.is_super():
            _v.v2(f"ACTION: REDACTING sensitive content.")
            _v.v2(f"  → The secret value is replaced with a [REDACTED_…] placeholder.")
            _v.v2(f"  → The sanitized message IS sent to the LLM.")
            _v.v2(f"  → The original secret is NOT stored in the logs.")
            _v.blank()
        sanitized = redact_string_in_payload(payload, findings)
        _print_redact_notice(findings, event_id)
        return "redact", sanitized

    if action == "report_only":
        top = findings[0]
        _v.v1(f"Decision: REPORT_ONLY  "
              f"(finding={top.finding_type}, severity={top.severity.upper()})")
        if _v.is_super():
            _v.v2(f"ACTION: Logging finding and allowing the request through.")
            _v.v2(f"  → The message IS sent to the LLM as-is.")
            _v.v2(f"  → The finding is recorded in your local log for review.")
            _v.v2(f"  → Use 'killswitch logs' to review findings later.")
            _v.blank()
        _print_report_notice(findings, event_id)
        return "report_only", payload

    return "allow", payload


def _print_drop_notice(
    findings: List[Finding], event_id: str, provider: str, operation: str
) -> None:
    top = findings[0]
    print(
        f"\n{'─' * 60}\n"
        f"  killswitch-ai dropped this LLM request.\n\n"
        f"  Finding : {top.finding_id}\n"
        f"  Severity: {top.severity.upper()}\n"
        f"  Reason  : {top.description}\n"
        f"  Event   : {event_id}\n"
        f"  Provider: {provider}  Operation: {operation}\n\n"
        f"  The request was NOT sent to the LLM.\n"
        f"  Provider wrappers return a synthetic empty response.\n"
        f"  No secret value was stored.\n"
        f"{'─' * 60}\n",
        file=sys.stderr,
    )


def _print_block_notice(
    findings: List[Finding], event_id: str, provider: str, operation: str
) -> None:
    top = findings[0]
    print(
        f"\n{'─' * 60}\n"
        f"  killswitch-ai blocked this LLM request.\n\n"
        f"  Finding : {top.finding_id}\n"
        f"  Severity: {top.severity.upper()}\n"
        f"  Reason  : {top.description}\n"
        f"  Event   : {event_id}\n"
        f"  Provider: {provider}  Operation: {operation}\n\n"
        f"  The request was NOT sent to the LLM.\n"
        f"  No secret value was stored.\n"
        f"{'─' * 60}\n",
        file=sys.stderr,
    )


def _print_redact_notice(findings: List[Finding], event_id: str) -> None:
    top = findings[0]
    print(
        f"\n{'─' * 60}\n"
        f"  killswitch-ai redacted sensitive content.\n\n"
        f"  Finding : {top.finding_id}\n"
        f"  Severity: {top.severity.upper()}\n"
        f"  Reason  : {top.description}\n"
        f"  Event   : {event_id}\n\n"
        f"  The sensitive value was replaced with a placeholder.\n"
        f"  The sanitized request was sent.\n"
        f"{'─' * 60}\n",
        file=sys.stderr,
    )


def _print_report_notice(findings: List[Finding], event_id: str) -> None:
    top = findings[0]
    print(
        f"\n  [killswitch-ai] Finding logged: {top.finding_id} "
        f"({top.severity}) — {top.description}. "
        f"Request allowed (report-only mode).\n",
        file=sys.stderr,
    )


def _handle_pause(
    payload: Any,
    findings: List[Finding],
    event_id: str,
    provider: str,
    operation: str,
) -> Tuple[str, Any]:
    top = findings[0]
    _print_pause_notice(findings, event_id, provider, operation)

    try:
        while True:
            print(
                "\nChoose:\n"
                "  1. Block request (safest)\n"
                "  2. Redact sensitive value and continue\n"
                "  3. Allow once (send as-is)\n"
                "  4. Exit (treat as block)\n",
                file=sys.stderr,
            )
            choice = input("Your choice [1]: ").strip() or "1"
            if choice == "1":
                raise KillswitchBlocked(top, event_id)
            elif choice == "2":
                sanitized = redact_string_in_payload(payload, findings)
                print(
                    f"  Sensitive content redacted. Sending sanitized request.\n",
                    file=sys.stderr,
                )
                return "redact", sanitized
            elif choice == "3":
                print(
                    f"  Allowed once. Request sent as-is. Logged.\n",
                    file=sys.stderr,
                )
                return "allow_once", payload
            elif choice == "4":
                raise KillswitchBlocked(top, event_id)
            else:
                print("  Please enter 1, 2, 3, or 4.", file=sys.stderr)
    except (EOFError, KeyboardInterrupt):
        print("\n  No input received — blocking request.\n", file=sys.stderr)
        raise KillswitchBlocked(top, event_id)


def _print_pause_notice(
    findings: List[Finding], event_id: str, provider: str, operation: str
) -> None:
    top = findings[0]
    explanation = explain_finding(top)
    print(
        f"\n{'─' * 60}\n"
        f"  killswitch-ai found possible sensitive content.\n\n"
        f"  Finding : {top.finding_id}\n"
        f"  Severity: {top.severity.upper()}\n"
        f"  Reason  : {top.description}\n"
        f"  Event   : {event_id}\n"
        f"  Provider: {provider}  Operation: {operation}\n\n"
        f"  {explanation}\n"
        f"{'─' * 60}",
        file=sys.stderr,
    )
