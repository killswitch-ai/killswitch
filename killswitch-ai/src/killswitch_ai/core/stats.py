"""
Local SQLite statistics tracker.

Maintains a single aggregate_stats row in ~/.killswitch/stats.db that
accumulates counts across every killswitch-ai-intercepted LLM call.
No prompt text, no secret values — only counts and distribution maps.
"""
from __future__ import annotations

import json
import sqlite3
import sys
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional


_DB_PATH = Path.home() / ".killswitch" / "stats.db"
_lock = threading.Lock()


_CREATE_SQL = """
CREATE TABLE IF NOT EXISTS aggregate_stats (
    id                  INTEGER PRIMARY KEY DEFAULT 1,
    commands_analyzed   INTEGER  NOT NULL DEFAULT 0,
    prohibited_stopped  INTEGER  NOT NULL DEFAULT 0,
    sensitive_stopped   INTEGER  NOT NULL DEFAULT 0,
    agents_json         TEXT     NOT NULL DEFAULT '{}',
    providers_json      TEXT     NOT NULL DEFAULT '{}',
    modes_json          TEXT     NOT NULL DEFAULT '{}',
    finding_types_json  TEXT     NOT NULL DEFAULT '{}',
    last_telemetry_at   TEXT,
    updated_at          TEXT     NOT NULL DEFAULT (datetime('now'))
);
INSERT OR IGNORE INTO aggregate_stats (id) VALUES (1);
"""


def _connect() -> sqlite3.Connection:
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(_DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(_CREATE_SQL)
    conn.commit()
    return conn


def _inc_json(raw: str, keys: List[str]) -> str:
    """Increment each key in a JSON counter map by 1."""
    d: Dict[str, int] = json.loads(raw or "{}")
    for k in keys:
        if k:
            d[k] = d.get(k, 0) + 1
    return json.dumps(d)


def record_call(
    provider: str,
    model: Optional[str],
    mode: str,
    decision: str,
    finding_types: List[str],
) -> None:
    """
    Record one intercepted LLM call.

    Parameters
    ----------
    provider:      "openai" or "anthropic"
    model:         Model name from the request payload (e.g. "gpt-4o").
                   None if the call did not include a model field.
    mode:          The configured killswitch mode.
    decision:      The action that was taken: "allow", "blocked", "redact",
                   "allow_once", "report_only", etc.
    finding_types: List of finding_type strings from all findings in this call.
    """
    prohibited_hit = "prohibited_term" in finding_types
    sensitive_hit = bool(finding_types) and not all(
        ft == "prohibited_term" for ft in finding_types
    )

    with _lock:
        try:
            conn = _connect()
            row = conn.execute("SELECT * FROM aggregate_stats WHERE id = 1").fetchone()

            new_agents = _inc_json(row["agents_json"], [model] if model else [])
            new_providers = _inc_json(row["providers_json"], [provider])
            new_modes = _inc_json(row["modes_json"], [mode])
            new_finding_types = _inc_json(row["finding_types_json"], finding_types)

            conn.execute(
                """
                UPDATE aggregate_stats SET
                    commands_analyzed  = commands_analyzed + 1,
                    prohibited_stopped = prohibited_stopped + ?,
                    sensitive_stopped  = sensitive_stopped  + ?,
                    agents_json        = ?,
                    providers_json     = ?,
                    modes_json         = ?,
                    finding_types_json = ?,
                    updated_at         = datetime('now')
                WHERE id = 1
                """,
                (
                    1 if prohibited_hit else 0,
                    1 if sensitive_hit else 0,
                    new_agents,
                    new_providers,
                    new_modes,
                    new_finding_types,
                ),
            )
            conn.commit()
            conn.close()
        except Exception:
            pass  # Stats are best-effort; never crash the calling code


def get_totals() -> Dict[str, Any]:
    """Return the current aggregate stats as a plain dict."""
    try:
        conn = _connect()
        row = conn.execute("SELECT * FROM aggregate_stats WHERE id = 1").fetchone()
        conn.close()
        if row is None:
            return {}
        return {
            "commands_analyzed":  row["commands_analyzed"],
            "prohibited_stopped": row["prohibited_stopped"],
            "sensitive_stopped":  row["sensitive_stopped"],
            "agents":             json.loads(row["agents_json"] or "{}"),
            "providers":          json.loads(row["providers_json"] or "{}"),
            "modes":              json.loads(row["modes_json"] or "{}"),
            "finding_types":      json.loads(row["finding_types_json"] or "{}"),
            "last_telemetry_at":  row["last_telemetry_at"],
        }
    except Exception:
        return {}


def mark_telemetry_sent() -> None:
    """Update the last_telemetry_at timestamp after a successful send."""
    try:
        conn = _connect()
        conn.execute(
            "UPDATE aggregate_stats SET last_telemetry_at = datetime('now') WHERE id = 1"
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


def _detect_os() -> str:
    p = sys.platform
    if p == "darwin":
        return "macos"
    if p.startswith("win"):
        return "windows"
    if p.startswith("linux"):
        return "linux"
    return "unknown"


def build_telemetry_payload(install_id: str, lib_version: str) -> Dict[str, Any]:
    """Build the payload dict for the telemetry POST request."""
    totals = get_totals()
    return {
        "install_id":          install_id,
        "lib_version":         lib_version,
        "python_version":      f"{sys.version_info.major}.{sys.version_info.minor}",
        "os_type":             _detect_os(),
        "commands_analyzed":   totals.get("commands_analyzed", 0),
        "prohibited_stopped":  totals.get("prohibited_stopped", 0),
        "sensitive_stopped":   totals.get("sensitive_stopped", 0),
        "agents":              totals.get("agents") or None,
        "providers":           totals.get("providers") or None,
        "modes":               totals.get("modes") or None,
        "finding_types":       totals.get("finding_types") or None,
    }
