from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="killswitch",
        description="killswitch-ai — local LLM egress control",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False,
        epilog="""
commands:
  init          Set up killswitch in this project (interactive wizard)
  menu          Open the interactive report and settings menu
  status        Show current mode and last session summary
  scan <text>   Test the scanner on a piece of text
  mode <mode>   Change the active mode (kill|pause|redact|report-only)
  logs          Show the latest session's findings
  event <id>    Look up a specific event by ID
  finding <id>  Look up a specific finding by ID
  report        Print the weekly summary report
  email         Toggle email reports (--on / --off)

examples:
  killswitch init
  killswitch menu
  killswitch scan "my API_KEY is sk-proj-abc123"
  killswitch scan -v "my API_KEY is sk-proj-abc123"
  killswitch scan --super-verbose "my text here"
  killswitch mode kill
  killswitch logs --latest
  killswitch report --send

verbose output (for scan):
  -v / --verbose        Show key steps as they happen — what was scanned, what
                        was found, and what decision was made.
  --super-verbose       Show every single step in plain English — each pattern
                        checked, entropy scores, how the decision was reached.
                        Great for beginners learning how killswitch works.

  You can also set KILLSWITCH_VERBOSE=1 or KILLSWITCH_VERBOSE=2 in your
  environment to enable verbose output for your Python scripts too:
    KILLSWITCH_VERBOSE=2 python my_app.py
""",
    )
    parser.add_argument(
        "-h", "--help",
        action="store_true",
        dest="open_menu",
        help="Open the interactive menu (change mode, view stats, settings)",
    )
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("init", help="Set up killswitch-ai (interactive wizard)")
    subparsers.add_parser("menu", help="Open the interactive menu")
    subparsers.add_parser("status", help="Show current status")

    scan_p = subparsers.add_parser(
        "scan",
        help="Test the scanner on text",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Scan a piece of text for secrets, API keys, and sensitive content.\n\n"
            "Use -v to see what killswitch is doing step by step.\n"
            "Use --super-verbose to see every pattern checked — great for learning."
        ),
    )
    scan_p.add_argument("text", nargs="?", help="Text to scan (or omit to be prompted)")
    scan_p.add_argument("--json", action="store_true", help="Output as JSON")
    scan_p.add_argument(
        "-v", "--verbose",
        action="store_true",
        help=(
            "Show key steps as they happen: what units were scanned, "
            "how many findings, and what decision was made."
        ),
    )
    scan_p.add_argument(
        "--super-verbose",
        action="store_true",
        help=(
            "Show every single step in plain English — each of the 10 secret patterns "
            "checked, prohibited term matching, entropy scores for every long string, "
            "and a full explanation of how the final decision was reached. "
            "Great for beginners who want to understand exactly how killswitch works."
        ),
    )

    mode_p = subparsers.add_parser("mode", help="Change protection mode")
    mode_p.add_argument(
        "new_mode",
        nargs="?",
        choices=["kill", "pause", "redact", "report-only", "report_only"],
        help="New mode",
    )

    logs_p = subparsers.add_parser("logs", help="View session logs")
    logs_p.add_argument("--latest", action="store_true", help="Show latest session")

    event_p = subparsers.add_parser("event", help="Look up an event by ID")
    event_p.add_argument("event_id", help="Event ID (e.g. KAI-E-20260602-a1b2c3)")

    finding_p = subparsers.add_parser("finding", help="Look up a finding by ID")
    finding_p.add_argument("finding_id", help="Finding ID (e.g. KAI-F-20260602-a1b2c3)")

    report_p = subparsers.add_parser("report", help="View or send the weekly report")
    report_p.add_argument("--send", action="store_true", help="Send via email")
    report_p.add_argument("--days", type=int, default=7, help="Days to include (default: 7)")

    email_p = subparsers.add_parser("email", help="Toggle email reports")
    email_group = email_p.add_mutually_exclusive_group()
    email_group.add_argument("--on", action="store_true")
    email_group.add_argument("--off", action="store_true")

    args = parser.parse_args()

    if getattr(args, "open_menu", False) or args.command is None:
        _cmd_menu()
        return

    if args.command == "init":
        _cmd_init()
    elif args.command == "menu":
        _cmd_menu()
    elif args.command == "status":
        _cmd_status()
    elif args.command == "scan":
        _cmd_scan(args)
    elif args.command == "mode":
        _cmd_mode(args)
    elif args.command == "logs":
        _cmd_logs(args)
    elif args.command == "event":
        _cmd_event(args)
    elif args.command == "finding":
        _cmd_finding(args)
    elif args.command == "report":
        _cmd_report(args)
    elif args.command == "email":
        _cmd_email(args)


def _cmd_init() -> None:
    from ..cli.wizard import run_wizard
    run_wizard()


def _cmd_menu() -> None:
    from ..cli.menu import run_menu
    from ..core.config import get_config
    get_config(reload=True)
    run_menu()


def _cmd_status() -> None:
    from ..core.config import get_config
    from ..logging.logger import aggregate_stats, read_latest_session

    cfg = get_config(reload=True)
    print()
    print(f"  killswitch-ai status")
    print(f"  {'─' * 40}")
    print(f"  Mode       : {cfg.mode.upper()}")
    print(f"  Config     : {cfg._source_path or 'no config file (using defaults)'}")
    print(f"  Log dir    : {cfg.log_dir}")
    print(f"  Email      : {'enabled → ' + cfg.email.address if cfg.email.enabled else 'off'}")
    print()

    stats = aggregate_stats(log_dir=cfg.log_dir, days=7)
    total = stats["total_events"]
    if total == 0:
        print("  No LLM calls scanned yet in the last 7 days.")
    else:
        print(f"  Last 7 days:")
        print(f"    {total} calls scanned")
        print(f"    {stats['blocked']} blocked  |  {stats['redacted']} redacted  |  {stats['flagged']} flagged")
        crit = stats["critical_findings"]
        high = stats["high_findings"]
        if crit or high:
            print(f"    ⚠  {crit} critical  {high} high findings")
    print()


def _cmd_scan(args) -> None:
    from ..core.config import get_config
    from ..core.normalizer import ScanUnit
    from ..core.scanner import scan_units
    from ..core.policy import explain_finding, resolve_action
    from .. import verbose as _verbose

    # Apply verbosity before scanning so output appears during the scan
    if getattr(args, "super_verbose", False):
        _verbose.set_level(2)
    elif getattr(args, "verbose", False):
        _verbose.set_level(1)

    text = args.text
    if not text:
        try:
            text = input("Text to scan: ").strip()
        except (EOFError, KeyboardInterrupt):
            return

    if not text:
        print("Nothing to scan.")
        return

    cfg = get_config(reload=True)

    if _verbose.is_super():
        _verbose.sep("═")
        _verbose.v2(f"killswitch scan — interactive scanner")
        _verbose.v2(f"  Mode   : {cfg.mode.upper()}")
        cfg_label = str(cfg._source_path) if cfg._source_path else "defaults (no killswitch.yml found)"
        _verbose.v2(f"  Config : {cfg_label}")
        _verbose.v2(f"  Input  : {len(text)} character(s)")
        _verbose.blank()

    units = [ScanUnit(path="cli.scan", content=text)]
    result = scan_units(
        units,
        extra_prohibited_terms=cfg.prohibited_terms,
        entropy_enabled=cfg.entropy_enabled,
        entropy_min_length=cfg.entropy_min_length,
        entropy_threshold=cfg.entropy_threshold,
        allowlist=cfg.allowlist,
        disabled_finding_types=cfg.disabled_finding_types,
    )

    if getattr(args, "json", False):
        output = {
            "findings": [
                {
                    "finding_id": f.finding_id,
                    "severity": f.severity,
                    "type": f.finding_type,
                    "description": f.description,
                }
                for f in result.findings
            ]
        }
        print(json.dumps(output, indent=2))
        return

    if _verbose.is_on():
        print()

    if not result.findings:
        print("  ✓ No issues detected.")
        print("  killswitch-ai would allow this text through.\n")
    else:
        print(f"  Found {len(result.findings)} issue(s):\n")
        for f in result.findings:
            sev = f.severity.upper()
            print(f"  [{sev}] {f.description}")
            print(f"         {f.finding_id}")
            print(f"         {explain_finding(f)[:120]}")
            print()
        action = resolve_action(result.findings, cfg.actions, cfg.mode)
        print(f"  Decision in {cfg.mode} mode: {action.upper()}")
        print()


def _cmd_mode(args) -> None:
    from ..core.config import get_config, save_config

    cfg = get_config(reload=True)
    new_mode = args.new_mode
    if not new_mode:
        print(f"\n  Current mode: {cfg.mode.upper()}")
        print("  Available: kill | pause | redact | report-only\n")
        return

    new_mode = new_mode.replace("-", "_")
    cfg.mode = new_mode
    save_config(cfg)
    print(f"\n  ✓ Mode set to: {new_mode.upper()}\n")


def _cmd_logs(args) -> None:
    from ..core.config import get_config
    from ..logging.logger import read_events, read_findings, read_latest_session

    cfg = get_config(reload=True)
    session_dir = read_latest_session(log_dir=cfg.log_dir)
    if session_dir is None:
        print("\n  No sessions found. No LLM calls have been scanned yet.\n")
        return

    print(f"\n  Session: {session_dir.name}")
    print(f"  Path   : {session_dir}\n")

    findings = read_findings(session_dir)
    events = read_events(session_dir)

    if not findings:
        print("  No findings in this session. All clear!\n")
    else:
        print(f"  Findings ({len(findings)}):\n")
        for f in findings:
            sev = f.get("severity", "").upper()
            print(f"  [{sev}] {f.get('finding_id')}  {f.get('description')}")
        print()

    if events:
        print(f"  Events ({len(events)}):\n")
        for e in events:
            print(f"  {e.get('event_id')}  {e.get('provider')}/{e.get('operation')}  → {e.get('decision', '').upper()}")
        print()


def _cmd_event(args) -> None:
    from ..core.config import get_config
    from ..logging.logger import find_event_by_id

    cfg = get_config(reload=True)
    event = find_event_by_id(args.event_id, log_dir=cfg.log_dir)
    if event is None:
        print(f"\n  Event not found: {args.event_id}\n")
        return
    print()
    for k, v in event.items():
        print(f"  {k:<25} {v}")
    print()


def _cmd_finding(args) -> None:
    from ..core.config import get_config
    from ..logging.logger import find_finding_by_id
    from ..core.scanner import Finding
    from ..core.policy import explain_finding

    cfg = get_config(reload=True)
    row = find_finding_by_id(args.finding_id, log_dir=cfg.log_dir)
    if row is None:
        print(f"\n  Finding not found: {args.finding_id}\n")
        return

    print()
    for k, v in row.items():
        print(f"  {k:<25} {v}")
    print()
    finding = Finding(
        finding_id=row.get("finding_id", ""),
        severity=row.get("severity", ""),
        finding_type=row.get("type", ""),
        description=row.get("description", ""),
    )
    print(f"  Explanation:\n  {explain_finding(finding)}\n")


def _cmd_report(args) -> None:
    from ..core.config import get_config
    from ..reporting.email_report import print_report_preview, send_report_email

    cfg = get_config(reload=True)
    days = getattr(args, "days", 7)

    if getattr(args, "send", False):
        send_report_email(cfg, days=days)
    else:
        print_report_preview(cfg, days=days)


def _cmd_email(args) -> None:
    from ..core.config import get_config, save_config

    cfg = get_config(reload=True)

    if getattr(args, "on", False):
        if not cfg.email.address:
            try:
                addr = input("  Your email address: ").strip()
            except (EOFError, KeyboardInterrupt):
                return
            if not addr:
                print("  No address provided.")
                return
            cfg.email.address = addr
        cfg.email.enabled = True
        save_config(cfg)
        print(f"\n  ✓ Email reports enabled → {cfg.email.address}")
        print("  To send now: killswitch report --send\n")

    elif getattr(args, "off", False):
        cfg.email.enabled = False
        save_config(cfg)
        print("\n  ✓ Email reports disabled.\n")
    else:
        status = "ON" if cfg.email.enabled else "OFF"
        print(f"\n  Email reports: {status}")
        if cfg.email.enabled:
            print(f"  Address: {cfg.email.address}")
        print("  Use --on or --off to change.\n")
