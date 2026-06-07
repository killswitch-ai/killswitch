from __future__ import annotations

import hashlib
import json
import urllib.request
from datetime import datetime, timezone
from typing import Optional

from ..core.config import Config
from ..logging.logger import aggregate_stats

_EMAIL_REPORT_ENDPOINT = "https://api.killswitch-ai.com/api/email-report"


def build_anonymized_report(cfg: Config, days: int = 7) -> dict:
    """
    Assemble anonymized metadata for email reporting.
    Never includes prompt text, file contents, secret values, or full payloads.
    Only includes: hashed IDs, event counts, finding counts, category breakdowns.
    """
    stats = aggregate_stats(log_dir=cfg.log_dir, days=days)

    install_hash = hashlib.sha256(cfg.install_id.encode()).hexdigest()[:16]
    project_hash = hashlib.sha256(cfg.project_id.encode()).hexdigest()[:16]

    return {
        "install_id_hash": install_hash,
        "project_id_hash": project_hash,
        "period_days": days,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_events": stats["total_events"],
        "blocked": stats["blocked"],
        "redacted": stats["redacted"],
        "flagged": stats["flagged"],
        "allowed": stats["allowed"],
        "critical_findings": stats["critical_findings"],
        "high_findings": stats["high_findings"],
        "medium_findings": stats["medium_findings"],
        "low_findings": stats["low_findings"],
        "finding_categories": stats.get("finding_categories", {}),
        "finding_types": stats.get("finding_types", {}),
    }


def send_report_email(cfg: Config, days: int = 7, endpoint: Optional[str] = None) -> bool:
    """
    Send the weekly anonymized report via the killswitch-ai API server (Resend).
    Returns True on success, False on failure.
    No SMTP configuration required.
    """
    if not cfg.email.enabled or not cfg.email.address:
        print("Email reporting is not enabled. Run: killswitch email --on")
        return False

    report = build_anonymized_report(cfg, days=days)
    payload = {"to": cfg.email.address, **report}
    url = (endpoint or "").strip() or _EMAIL_REPORT_ENDPOINT

    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status in (200, 201):
                print(f"Weekly report sent to {cfg.email.address}")
                return True
            print(f"Failed to send email report (status {resp.status})")
            return False
    except Exception as e:
        print(f"Failed to send email report: {e}")
        return False


def print_report_preview(cfg: Config, days: int = 7) -> None:
    """Print the report locally without sending it."""
    report = build_anonymized_report(cfg, days=days)
    period = report["period_days"]
    lines = [
        "killswitch-ai Weekly Summary",
        "=" * 40,
        "",
        f"Period: Last {period} days",
        f"Generated: {report['generated_at']}",
        "",
        "Activity",
        "-" * 20,
        f"  Total LLM calls scanned : {report['total_events']}",
        f"  Requests blocked        : {report['blocked']}",
        f"  Requests redacted       : {report['redacted']}",
        f"  Requests flagged (logged): {report['flagged']}",
        f"  Requests allowed        : {report['allowed']}",
        "",
        "Findings by severity",
        "-" * 20,
        f"  Critical : {report['critical_findings']}",
        f"  High     : {report['high_findings']}",
        f"  Medium   : {report['medium_findings']}",
        f"  Low      : {report['low_findings']}",
    ]
    cats = report.get("finding_categories", {})
    if cats:
        lines += ["", "Findings by category", "-" * 20]
        for cat, count in cats.items():
            lines.append(f"  {cat:<30} {count}")
    print("\n".join(lines))
