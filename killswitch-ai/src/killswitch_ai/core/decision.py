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
    if action == "allow" or not findings:
        return "allow", payload

    if action == "kill":
        _print_block_notice(findings, event_id, provider, operation)
        raise KillswitchBlocked(findings[0], event_id)

    if action == "pause":
        return _handle_pause(payload, findings, event_id, provider, operation)

    if action == "redact":
        sanitized = redact_string_in_payload(payload, findings)
        _print_redact_notice(findings, event_id)
        return "redact", sanitized

    if action == "report_only":
        _print_report_notice(findings, event_id)
        return "report_only", payload

    return "allow", payload


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
