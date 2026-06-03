from __future__ import annotations

import hashlib
import smtplib
import ssl
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

from ..core.config import Config
from ..logging.logger import aggregate_stats


def build_anonymized_report(cfg: Config, days: int = 7) -> dict:
    """
    Assemble anonymized metadata for email reporting.
    Never includes prompt text, file contents, secret values, or full payloads.
    Only includes: hashed IDs, event counts, finding counts.
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
    }


def format_email_body(report: dict) -> str:
    """Format the anonymized report as a plain-text email body."""
    period = report["period_days"]
    total = report["total_events"]
    blocked = report["blocked"]
    redacted = report["redacted"]
    flagged = report["flagged"]
    critical = report["critical_findings"]
    high = report["high_findings"]

    lines = [
        "killswitch-ai Weekly Summary",
        "=" * 40,
        "",
        f"Period: Last {period} days",
        f"Generated: {report['generated_at']}",
        "",
        "Activity",
        "-" * 20,
        f"  Total LLM calls scanned : {total}",
        f"  Requests blocked        : {blocked}",
        f"  Requests redacted       : {redacted}",
        f"  Requests flagged        : {flagged}",
        "",
        "Findings by severity",
        "-" * 20,
        f"  Critical : {critical}",
        f"  High     : {high}",
        f"  Medium   : {report['medium_findings']}",
        f"  Low      : {report['low_findings']}",
        "",
        "Privacy notice",
        "-" * 20,
        "This report contains only anonymized counts.",
        "No prompt text, file contents, secret values, or payload data",
        "was included in this email.",
        "",
        f"Install ID (hashed): {report['install_id_hash']}",
        f"Project ID (hashed): {report['project_id_hash']}",
        "",
        "To turn off email reports: killswitch email --off",
        "To view detailed local reports: killswitch menu",
    ]
    return "\n".join(lines)


def format_html_body(report: dict) -> str:
    """Format the anonymized report as an HTML email body."""
    period = report["period_days"]
    total = report["total_events"]
    blocked = report["blocked"]
    redacted = report["redacted"]
    flagged = report["flagged"]
    critical = report["critical_findings"]
    high = report["high_findings"]

    return f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><style>
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; color: #1a1a1a; max-width: 560px; margin: 40px auto; padding: 0 20px; }}
h1 {{ font-size: 20px; color: #d32f2f; margin-bottom: 4px; }}
.subtitle {{ color: #666; font-size: 14px; margin-bottom: 32px; }}
.section {{ margin-bottom: 24px; }}
.section h2 {{ font-size: 13px; text-transform: uppercase; letter-spacing: .05em; color: #666; border-bottom: 1px solid #eee; padding-bottom: 6px; margin-bottom: 12px; }}
.stat {{ display: flex; justify-content: space-between; padding: 6px 0; font-size: 15px; }}
.stat .label {{ color: #444; }}
.stat .value {{ font-weight: 600; color: #111; }}
.critical {{ color: #d32f2f; }}
.high {{ color: #e64a19; }}
.notice {{ background: #f5f5f5; border-left: 3px solid #ccc; padding: 12px 16px; font-size: 13px; color: #555; border-radius: 2px; }}
.footer {{ font-size: 12px; color: #aaa; margin-top: 32px; }}
</style></head>
<body>
<h1>killswitch-ai</h1>
<p class="subtitle">Weekly Summary — Last {period} days</p>

<div class="section">
  <h2>Activity</h2>
  <div class="stat"><span class="label">LLM calls scanned</span><span class="value">{total}</span></div>
  <div class="stat"><span class="label">Requests blocked</span><span class="value">{blocked}</span></div>
  <div class="stat"><span class="label">Requests redacted</span><span class="value">{redacted}</span></div>
  <div class="stat"><span class="label">Requests flagged</span><span class="value">{flagged}</span></div>
</div>

<div class="section">
  <h2>Findings by severity</h2>
  <div class="stat"><span class="label">Critical</span><span class="value critical">{critical}</span></div>
  <div class="stat"><span class="label">High</span><span class="value high">{high}</span></div>
  <div class="stat"><span class="label">Medium</span><span class="value">{report['medium_findings']}</span></div>
  <div class="stat"><span class="label">Low</span><span class="value">{report['low_findings']}</span></div>
</div>

<div class="notice">
  <strong>Privacy:</strong> This report contains only anonymized counts.
  No prompt text, file contents, secret values, or payload data was included.
</div>

<p class="footer">
  Install ID (hashed): {report['install_id_hash']}<br>
  Project ID (hashed): {report['project_id_hash']}<br><br>
  To turn off: <code>killswitch email --off</code> &nbsp;|&nbsp;
  Detailed local reports: <code>killswitch menu</code>
</p>
</body></html>"""


def send_report_email(cfg: Config, days: int = 7) -> bool:
    """
    Send the weekly anonymized report email.
    Returns True on success, False on failure.
    Requires email.smtp_host to be configured in killswitch.yml.
    """
    if not cfg.email.enabled or not cfg.email.address:
        print("Email reporting is not enabled. Run: killswitch email --on")
        return False

    if not cfg.email.smtp_host:
        print(
            "SMTP is not configured. Add smtp_host, smtp_user, and smtp_password\n"
            "to the email section of killswitch.yml to enable email sending.\n\n"
            "Example:\n"
            "  email:\n"
            "    smtp_host: smtp.gmail.com\n"
            "    smtp_port: 587\n"
            "    smtp_user: you@gmail.com\n"
            "    smtp_password: your-app-password\n"
        )
        return False

    report = build_anonymized_report(cfg, days=days)
    text_body = format_email_body(report)
    html_body = format_html_body(report)

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"killswitch-ai Weekly Summary — {report['total_events']} scans"
    msg["From"] = cfg.email.from_address
    msg["To"] = cfg.email.address
    msg.attach(MIMEText(text_body, "plain"))
    msg.attach(MIMEText(html_body, "html"))

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP(cfg.email.smtp_host, cfg.email.smtp_port) as server:
            server.ehlo()
            server.starttls(context=context)
            if cfg.email.smtp_user:
                server.login(cfg.email.smtp_user, cfg.email.smtp_password)
            server.sendmail(
                cfg.email.from_address,
                cfg.email.address,
                msg.as_string(),
            )
        print(f"Weekly report sent to {cfg.email.address}")
        return True
    except Exception as e:
        print(f"Failed to send email: {e}")
        return False


def print_report_preview(cfg: Config, days: int = 7) -> None:
    """Print the report locally without sending it."""
    report = build_anonymized_report(cfg, days=days)
    print(format_email_body(report))
