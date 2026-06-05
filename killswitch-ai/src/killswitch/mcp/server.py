"""
killswitch-ai MCP server.

Exposes seven tools over stdio (six read-only, one write):

  scan            — pre-flight scan of text, returns findings metadata
  get_status      — current mode and headline stats
  get_stats       — full aggregate counts and distribution maps
  recent_findings — recent audit events (type/severity/decision only)
  get_policy      — active killswitch.yml settings (or defaults)
  check_policy    — check whether a single term is prohibited, allowlisted,
                    or neither (without running a full scan)
  update_policy   — partial update to killswitch.yml (mode, prohibited_terms,
                    allowlist, per-finding-type actions); changes take effect
                    immediately

Privacy guarantees
------------------
- scan()          never echoes input text or secret values in its response
- recent_findings reads from on-disk findings.jsonl which already strips
                  raw prompt text and secret values
- get_policy      strips smtp_password, smtp_user, and meta identifiers
- update_policy   only modifies mode, prohibited_terms, allowlist, and
                  actions fields

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
    Return recent audit findings from the local log, enriched with the
    decision (blocked/allowed/redacted/etc.) from the corresponding event.

    Only metadata is returned — no prompt text or secret values are ever
    stored in the logs and none will appear here.
    """
    import json
    from pathlib import Path

    from ..core.config import get_config

    cfg = get_config()
    sessions_dir = Path(cfg.log_dir) / "sessions"

    if not sessions_dir.exists():
        return {"findings": [], "total": 0, "shown": 0}

    all_findings: List[Dict[str, Any]] = []

    # Walk session dirs newest-first.  For each, build event_id→decision from
    # events.jsonl, then enrich findings from findings.jsonl with that map.
    session_dirs = sorted(sessions_dir.rglob("session.json"), reverse=True)
    for session_meta_file in session_dirs:
        sd = session_meta_file.parent

        event_decisions: Dict[str, str] = {}
        events_file = sd / "events.jsonl"
        if events_file.exists():
            for line in events_file.read_text().strip().splitlines():
                try:
                    row = json.loads(line)
                    eid = row.get("event_id", "")
                    if eid:
                        event_decisions[eid] = row.get("decision", "")
                except Exception:
                    pass

        findings_file = sd / "findings.jsonl"
        if findings_file.exists():
            for line in findings_file.read_text().strip().splitlines():
                try:
                    row = json.loads(line)
                    event_id = row.get("event_id", "")
                    all_findings.append({
                        "finding_id": row.get("finding_id", ""),
                        "event_id": event_id,
                        "session_id": row.get("session_id", ""),
                        "timestamp": row.get("timestamp", ""),
                        "severity": row.get("severity", ""),
                        "category": row.get("category", ""),
                        "type": row.get("type", ""),
                        "description": row.get("description", ""),
                        "recommendation": row.get("recommendation", ""),
                        "decision": event_decisions.get(event_id, ""),
                    })
                except Exception:
                    pass

        if len(all_findings) >= limit * 4:
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
        "allowlist": list(cfg.allowlist),
        "prohibited_terms": list(cfg.prohibited_terms),
        "config_file": str(cfg._source_path) if cfg._source_path else None,
        "using_defaults": cfg._source_path is None,
    }


def _check_policy(term: str) -> Dict[str, Any]:
    """
    Check whether a single term is prohibited, allowlisted, or neither,
    using the active killswitch policy.

    This is a lightweight membership check — it does not run the full
    detection pipeline (no regex matching, entropy analysis, or secret
    scanning).  Use `scan` when you want to know whether text would be
    blocked by a detector.  Use `check_policy` when you want to ask a
    simpler question: "is this exact string in the prohibited_terms or
    allowlist?"

    Returns a dict with:
      - term:        the term that was checked (echoed back for clarity)
      - prohibited:  True if the term appears in prohibited_terms
      - allowlisted: True if the term appears in the allowlist
      - status:      one of "prohibited" | "allowlisted" | "neither"
    """
    from ..core.config import get_config

    cfg = get_config()
    prohibited = term in cfg.prohibited_terms
    allowlisted = term in cfg.allowlist

    if prohibited:
        status = "prohibited"
    elif allowlisted:
        status = "allowlisted"
    else:
        status = "neither"

    return {
        "term": term,
        "prohibited": prohibited,
        "allowlisted": allowlisted,
        "status": status,
    }


VALID_MODES = {"kill", "pause", "redact", "report_only", "off"}
VALID_ACTIONS = {"kill", "pause", "redact", "report_only", "off"}


def _update_policy(
    mode: Optional[str] = None,
    prohibited_terms_add: Optional[List[str]] = None,
    prohibited_terms_remove: Optional[List[str]] = None,
    allowlist_add: Optional[List[str]] = None,
    allowlist_remove: Optional[List[str]] = None,
    actions: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """
    Partially update the active killswitch policy and persist it to
    killswitch.yml.  Changes take effect immediately for all subsequent
    LLM calls.

    Only mode, prohibited_terms, allowlist, and per-finding-type actions
    may be changed.  All parameters are optional — only the fields you
    supply are modified.
    """
    from ..core.config import get_config, save_config, set_config

    errors: List[str] = []

    if mode is not None and mode not in VALID_MODES:
        errors.append(
            f"Invalid mode {mode!r}. Must be one of: {', '.join(sorted(VALID_MODES))}."
        )

    if actions is not None:
        for finding_type, action in actions.items():
            if action not in VALID_ACTIONS:
                errors.append(
                    f"Invalid action {action!r} for finding type {finding_type!r}. "
                    f"Must be one of: {', '.join(sorted(VALID_ACTIONS))}."
                )

    if errors:
        return {"ok": False, "errors": errors}

    cfg = get_config()

    changes: Dict[str, Any] = {}

    if mode is not None:
        changes["mode"] = {"old": cfg.mode, "new": mode}
        cfg.mode = mode

    if prohibited_terms_add:
        added = [t for t in prohibited_terms_add if t not in cfg.prohibited_terms]
        cfg.prohibited_terms = list(cfg.prohibited_terms) + added
        changes["prohibited_terms_added"] = added

    if prohibited_terms_remove:
        before = set(cfg.prohibited_terms)
        cfg.prohibited_terms = [t for t in cfg.prohibited_terms if t not in prohibited_terms_remove]
        removed = list(before - set(cfg.prohibited_terms))
        changes["prohibited_terms_removed"] = removed

    if allowlist_add:
        added_al = [t for t in allowlist_add if t not in cfg.allowlist]
        cfg.allowlist = list(cfg.allowlist) + added_al
        changes["allowlist_added"] = added_al

    if allowlist_remove:
        before_al = set(cfg.allowlist)
        cfg.allowlist = [t for t in cfg.allowlist if t not in allowlist_remove]
        removed_al = list(before_al - set(cfg.allowlist))
        changes["allowlist_removed"] = removed_al

    if actions:
        updated_actions: Dict[str, str] = {}
        for finding_type, action in actions.items():
            old = cfg.actions.get(finding_type)
            cfg.actions[finding_type] = action
            updated_actions[finding_type] = {"old": old, "new": action}  # type: ignore[assignment]
        changes["actions_updated"] = updated_actions

    saved_path = save_config(cfg, path=cfg._source_path)
    cfg._source_path = saved_path
    set_config(cfg)

    return {
        "ok": True,
        "changes": changes,
        "config_file": str(saved_path),
        "note": (
            "Changes have been saved to killswitch.yml and take effect "
            "immediately for all new LLM calls. "
            "Existing in-flight calls are not affected."
        ),
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

        The response contains top-level `allowlist` and `prohibited_terms` keys
        (each a list of strings) alongside `policy`, so agents can check either
        list without parsing the nested detection block. Use update_policy with
        allowlist_add / allowlist_remove or prohibited_terms_add /
        prohibited_terms_remove to modify entries.
        """
        return _get_policy()

    @mcp.tool()
    def check_policy(term: str) -> Dict[str, Any]:
        """
        Check whether a single term is prohibited, allowlisted, or neither,
        using the active killswitch policy.

        This is a lightweight membership check — it does NOT run the full
        detection pipeline (no regex matching, entropy analysis, or secret
        scanning).  Use `scan` when you want to know whether a block of text
        would be blocked by a detector.  Use `check_policy` when you want to
        ask a simpler, targeted question: "is this exact string in
        prohibited_terms or the allowlist?"

        Returns:
          - term:        the term that was checked
          - prohibited:  True if the term is in prohibited_terms
          - allowlisted: True if the term is in the allowlist
          - status:      "prohibited" | "allowlisted" | "neither"

        Note: a term that appears in both prohibited_terms and the allowlist
        is reported as "prohibited" (prohibited_terms takes precedence in
        status, though both flags are returned so you can inspect both).
        """
        return _check_policy(term)

    @mcp.tool()
    def update_policy(
        mode: Optional[str] = None,
        prohibited_terms_add: Optional[List[str]] = None,
        prohibited_terms_remove: Optional[List[str]] = None,
        allowlist_add: Optional[List[str]] = None,
        allowlist_remove: Optional[List[str]] = None,
        actions: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Partially update killswitch policy settings and persist them to
        killswitch.yml. Changes take effect immediately for all new LLM calls.

        All parameters are optional — only supplied fields are changed:

        - mode: global default action for findings with no specific override.
          Allowed values: kill | pause | redact | report_only | off
        - prohibited_terms_add: list of new terms to add to the prohibited list.
        - prohibited_terms_remove: list of existing terms to remove from the
          prohibited list.
        - allowlist_add: list of terms or patterns to add to the allowlist.
          Allowlisted entries are never flagged, even if they match a detector.
        - allowlist_remove: list of terms or patterns to remove from the
          allowlist.
        - actions: dict mapping finding type name to an action, e.g.
          {"jwt_token": "kill", "high_entropy_string": "pause"}.
          Allowed actions: kill | pause | redact | report_only | off

        WARNING: Changes take effect immediately for all subsequent LLM calls.
        Setting mode to "off" disables all killswitch protection.

        Returns ok=True with a summary of changes on success, or ok=False with
        a list of validation errors on invalid input.
        """
        return _update_policy(
            mode=mode,
            prohibited_terms_add=prohibited_terms_add,
            prohibited_terms_remove=prohibited_terms_remove,
            allowlist_add=allowlist_add,
            allowlist_remove=allowlist_remove,
            actions=actions,
        )


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
