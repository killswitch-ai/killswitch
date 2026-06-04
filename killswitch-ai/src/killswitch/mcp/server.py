"""
killswitch-ai MCP server.

Exposes five read-only tools over stdio:

  scan            — pre-flight scan of text, returns findings metadata
  get_status      — current mode and headline stats
  get_stats       — full aggregate counts and distribution maps
  recent_findings — recent audit events (type/severity/decision only)
  get_policy      — active killswitch.yml settings (or defaults)

Privacy guarantees
------------------
- scan()          never echoes input text or secret values in its response
- recent_findings reads from on-disk findings.jsonl which already strips
                  raw prompt text and secret values
- get_policy      strips smtp_password, smtp_user, and meta identifiers
- No tool writes to disk or changes any configuration

Important framing
-----------------
This server is a voluntary, opt-in guardrail.  An agent chooses whether to
call these tools.  For automatic enforcement that intercepts every LLM call
regardless, use killswitch.install() or GuardedOpenAI/GuardedAnthropic.
"""
from __future__ import annotations

import sys
from typing import Any, Dict, List, Optional

try:
    from mcp.server.fastmcp import FastMCP
    _mcp_available = True
except ImportError:
    _mcp_available = False
    FastMCP = None  # type: ignore[assignment,misc]


mcp: Any = FastMCP("killswitch-ai") if _mcp_available else None


# ── Underlying logic functions (importable for testing) ──────────────────────

def _scan(text: str) -> Dict[str, Any]:
    """
    Scan text for secrets and sensitive content.  Returns metadata only —
    the input text and any matched secret values are never included in the
    response.
    """
    from ..core.config import get_config
    from ..core.normalizer import ScanUnit
    from ..core.scanner import scan_units

    cfg = get_config()
    units = [ScanUnit(path="mcp.scan", content=text)]
    result = scan_units(
        units,
        extra_prohibited_terms=cfg.prohibited_terms,
        entropy_enabled=cfg.entropy_enabled,
        entropy_min_length=cfg.entropy_min_length,
        entropy_threshold=cfg.entropy_threshold,
        allowlist=cfg.allowlist,
        disabled_finding_types=cfg.disabled_finding_types,
    )

    findings = [
        {
            "finding_id": f.finding_id,
            "severity": f.severity,
            "type": f.finding_type,
            "category": f.category,
            "description": f.description,
            "recommendation": f.recommendation,
        }
        for f in result.findings
    ]

    return {
        "clean": not result.has_findings,
        "finding_count": len(findings),
        "max_severity": result.max_severity,
        "findings": findings,
        "note": (
            "This is a voluntary pre-flight guardrail. "
            "For automatic enforcement that intercepts every LLM call, "
            "use killswitch.install() or GuardedOpenAI/GuardedAnthropic in your code."
        ),
    }


def _get_status() -> Dict[str, Any]:
    """Return current mode and headline aggregate counts."""
    from ..core.config import get_config
    from ..core.stats import get_totals

    cfg = get_config()
    totals = get_totals()

    return {
        "mode": cfg.mode,
        "protection_active": cfg.mode != "off",
        "config_file": str(cfg._source_path) if cfg._source_path else None,
        "commands_analyzed": totals.get("commands_analyzed", 0),
        "prohibited_stopped": totals.get("prohibited_stopped", 0),
        "sensitive_stopped": totals.get("sensitive_stopped", 0),
        "last_seen_timestamp": totals.get("last_seen_timestamp"),
    }


def _get_stats() -> Dict[str, Any]:
    """Return full aggregate statistics from the local stats database."""
    from ..core.stats import get_totals

    totals = get_totals()
    return {
        "commands_analyzed": totals.get("commands_analyzed", 0),
        "prohibited_stopped": totals.get("prohibited_stopped", 0),
        "sensitive_stopped": totals.get("sensitive_stopped", 0),
        "providers": totals.get("providers", {}),
        "modes": totals.get("modes", {}),
        "finding_types": totals.get("finding_types", {}),
        "decisions": totals.get("decisions", {}),
        "operation_types": totals.get("operation_types", {}),
        "severity_counts": totals.get("severity_counts", {}),
        "finding_categories": totals.get("finding_categories", {}),
        "detector_layers": totals.get("detector_layers", {}),
        "first_scan_timestamp": totals.get("first_scan_timestamp"),
        "last_seen_timestamp": totals.get("last_seen_timestamp"),
    }


def _recent_findings(limit: int = 20) -> Dict[str, Any]:
    """
    Return recent audit findings from the local log.  Only metadata is
    returned — no prompt text or secret values are ever stored in the logs
    and none will appear here.
    """
    import json
    from pathlib import Path

    from ..core.config import get_config

    cfg = get_config()
    sessions_dir = Path(cfg.log_dir) / "sessions"

    if not sessions_dir.exists():
        return {"findings": [], "total": 0, "shown": 0}

    all_findings: List[Dict[str, Any]] = []
    for findings_file in sorted(sessions_dir.rglob("findings.jsonl"), reverse=True):
        for line in findings_file.read_text().strip().splitlines():
            try:
                row = json.loads(line)
                all_findings.append({
                    "finding_id": row.get("finding_id", ""),
                    "event_id": row.get("event_id", ""),
                    "session_id": row.get("session_id", ""),
                    "timestamp": row.get("timestamp", ""),
                    "severity": row.get("severity", ""),
                    "category": row.get("category", ""),
                    "type": row.get("type", ""),
                    "description": row.get("description", ""),
                    "recommendation": row.get("recommendation", ""),
                })
            except Exception:
                pass
        if len(all_findings) >= limit * 2:
            break

    all_findings.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    shown = all_findings[:limit]

    return {
        "findings": shown,
        "total": len(all_findings),
        "shown": len(shown),
    }


def _get_policy() -> Dict[str, Any]:
    """
    Return the active killswitch policy (killswitch.yml or built-in defaults).
    Sensitive SMTP credentials and internal identifiers are stripped.
    """
    from ..core.config import get_config

    cfg = get_config()
    policy = cfg.to_dict()

    email_block = policy.get("email", {})
    email_block.pop("smtp_password", None)
    email_block.pop("smtp_user", None)

    policy.pop("meta", None)
    policy.pop("telemetry", None)

    return {
        "policy": policy,
        "config_file": str(cfg._source_path) if cfg._source_path else None,
        "using_defaults": cfg._source_path is None,
    }


# ── MCP tool registrations ───────────────────────────────────────────────────

if mcp is not None:

    @mcp.tool()
    def scan(text: str) -> Dict[str, Any]:
        """
        Pre-flight scan: check text for secrets, API keys, and sensitive
        content before using it in an LLM call.

        Returns findings with severity, type, and description — the input
        text and any matched secret values are never echoed back.

        IMPORTANT: This is a voluntary opt-in guardrail. An agent that calls
        this tool provides defense-in-depth, but it is not the same as
        automatic enforcement. For guaranteed inline enforcement that
        intercepts every LLM call regardless of agent behaviour, use
        killswitch.install() or GuardedOpenAI / GuardedAnthropic in your code.
        """
        return _scan(text)

    @mcp.tool()
    def get_status() -> Dict[str, Any]:
        """
        Return the current killswitch status: active mode, whether protection
        is on, config file location, and headline counts (LLM calls scanned,
        prohibited terms stopped, sensitive data stopped).
        """
        return _get_status()

    @mcp.tool()
    def get_stats() -> Dict[str, Any]:
        """
        Return full aggregate statistics from the local killswitch stats
        database: call counts, finding distributions by type/severity/category,
        provider and model breakdown, and decision outcomes.

        All data is local aggregate metadata — no prompt text or secret values
        are ever stored in the stats database.
        """
        return _get_stats()

    @mcp.tool()
    def recent_findings(limit: int = 20) -> Dict[str, Any]:
        """
        Return recent audit findings from the local killswitch log.

        Each finding includes: finding_id, event_id, timestamp, severity,
        category, type, description, and recommendation. Raw prompt text and
        secret values are never stored in the log and will not appear here.

        Use limit to control how many findings are returned (default: 20).
        """
        return _recent_findings(limit=limit)

    @mcp.tool()
    def get_policy() -> Dict[str, Any]:
        """
        Return the active killswitch policy configuration from killswitch.yml,
        or the built-in defaults if no config file is present.

        Includes: mode, detection settings, prohibited terms, per-finding-type
        actions, logging settings, and email report settings. SMTP credentials
        and internal identifiers are stripped.
        """
        return _get_policy()


# ── Entry point ──────────────────────────────────────────────────────────────

def serve() -> None:
    """Start the killswitch MCP server over stdio."""
    if not _mcp_available:
        print(
            "Error: the 'mcp' package is not installed.\n"
            "Install it with:  pip install 'killswitch-ai[mcp]'",
            file=sys.stderr,
        )
        sys.exit(1)
    mcp.run()
