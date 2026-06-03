from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from ..core.scanner import Finding


def _new_session_id() -> str:
    now = datetime.now(timezone.utc)
    short = uuid.uuid4().hex[:8]
    return f"KAI-S-{now.strftime('%Y%m%d')}-{now.strftime('%H%M%S')}-{short}"


def _new_event_id() -> str:
    now = datetime.now(timezone.utc)
    short = uuid.uuid4().hex[:6]
    return f"KAI-E-{now.strftime('%Y%m%d')}-{short}"


@dataclass
class EventRecord:
    event_id: str = field(default_factory=_new_event_id)
    session_id: str = ""
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    provider: str = ""
    operation: str = ""
    mode: str = ""
    decision: str = ""
    finding_ids: List[str] = field(default_factory=list)
    raw_payload_stored: bool = False
    secret_values_stored: bool = False


class KillswitchLogger:
    def __init__(self, log_dir: str = ".killswitch") -> None:
        self.log_dir = Path(log_dir)
        self._session_id = _new_session_id()
        self._session_dir: Optional[Path] = None
        self._events_file: Optional[Path] = None
        self._findings_file: Optional[Path] = None
        self._event_count = 0

    def _ensure_session_dir(self) -> Path:
        if self._session_dir is not None:
            return self._session_dir
        now = datetime.now(timezone.utc)
        session_dir = (
            self.log_dir
            / "sessions"
            / now.strftime("%Y")
            / now.strftime("%m")
            / now.strftime("%d")
            / self._session_id
        )
        session_dir.mkdir(parents=True, exist_ok=True)
        self._session_dir = session_dir

        session_meta = {
            "session_id": self._session_id,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "pid": __import__("os").getpid(),
        }
        (session_dir / "session.json").write_text(
            json.dumps(session_meta, indent=2)
        )

        self._events_file = session_dir / "events.jsonl"
        self._findings_file = session_dir / "findings.jsonl"

        index_dir = self.log_dir / "indexes"
        index_dir.mkdir(parents=True, exist_ok=True)
        (index_dir / "latest-session.txt").write_text(
            str(session_dir.resolve())
        )

        return session_dir

    def log_event(
        self,
        provider: str,
        operation: str,
        mode: str,
        decision: str,
        findings: List[Finding],
    ) -> EventRecord:
        self._ensure_session_dir()
        self._event_count += 1

        event = EventRecord(
            session_id=self._session_id,
            provider=provider,
            operation=operation,
            mode=mode,
            decision=decision,
            finding_ids=[f.finding_id for f in findings],
            raw_payload_stored=False,
            secret_values_stored=False,
        )

        event_row = {
            "event_id": event.event_id,
            "session_id": event.session_id,
            "timestamp": event.timestamp,
            "provider": event.provider,
            "operation": event.operation,
            "mode": event.mode,
            "decision": event.decision,
            "finding_ids": event.finding_ids,
            "raw_payload_stored": False,
            "secret_values_stored": False,
        }
        with open(self._events_file, "a") as f:
            f.write(json.dumps(event_row) + "\n")

        for finding in findings:
            finding_row = {
                "finding_id": finding.finding_id,
                "event_id": event.event_id,
                "session_id": self._session_id,
                "timestamp": event.timestamp,
                "severity": finding.severity,
                "category": finding.category,
                "type": finding.finding_type,
                "description": finding.description,
                "recommendation": finding.recommendation,
                "scan_path": finding.scan_path,
            }
            with open(self._findings_file, "a") as f:
                f.write(json.dumps(finding_row) + "\n")

        return event

    @property
    def session_id(self) -> str:
        return self._session_id


_global_logger: Optional[KillswitchLogger] = None


def get_logger(log_dir: str = ".killswitch") -> KillswitchLogger:
    global _global_logger
    if _global_logger is None:
        _global_logger = KillswitchLogger(log_dir=log_dir)
    return _global_logger


def reset_logger() -> None:
    global _global_logger
    _global_logger = None


def read_latest_session(log_dir: str = ".killswitch") -> Optional[Path]:
    index = Path(log_dir) / "indexes" / "latest-session.txt"
    if not index.exists():
        return None
    session_path = Path(index.read_text().strip())
    if session_path.exists():
        return session_path
    return None


def read_findings(session_dir: Path) -> List[dict]:
    fp = session_dir / "findings.jsonl"
    if not fp.exists():
        return []
    rows = []
    for line in fp.read_text().strip().splitlines():
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return rows


def read_events(session_dir: Path) -> List[dict]:
    fp = session_dir / "events.jsonl"
    if not fp.exists():
        return []
    rows = []
    for line in fp.read_text().strip().splitlines():
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return rows


def find_event_by_id(event_id: str, log_dir: str = ".killswitch") -> Optional[dict]:
    sessions_dir = Path(log_dir) / "sessions"
    if not sessions_dir.exists():
        return None
    for events_file in sessions_dir.rglob("events.jsonl"):
        for line in events_file.read_text().strip().splitlines():
            try:
                row = json.loads(line)
                if row.get("event_id") == event_id:
                    return row
            except json.JSONDecodeError:
                pass
    return None


def find_finding_by_id(finding_id: str, log_dir: str = ".killswitch") -> Optional[dict]:
    sessions_dir = Path(log_dir) / "sessions"
    if not sessions_dir.exists():
        return None
    for findings_file in sessions_dir.rglob("findings.jsonl"):
        for line in findings_file.read_text().strip().splitlines():
            try:
                row = json.loads(line)
                if row.get("finding_id") == finding_id:
                    return row
            except json.JSONDecodeError:
                pass
    return None


def aggregate_stats(log_dir: str = ".killswitch", days: int = 7) -> dict:
    from datetime import timedelta

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    stats = {
        "total_events": 0,
        "blocked": 0,
        "redacted": 0,
        "flagged": 0,
        "allowed": 0,
        "critical_findings": 0,
        "high_findings": 0,
        "medium_findings": 0,
        "low_findings": 0,
    }
    sessions_dir = Path(log_dir) / "sessions"
    if not sessions_dir.exists():
        return stats

    for events_file in sessions_dir.rglob("events.jsonl"):
        for line in events_file.read_text().strip().splitlines():
            try:
                row = json.loads(line)
                ts = datetime.fromisoformat(row.get("timestamp", ""))
                if ts < cutoff:
                    continue
                stats["total_events"] += 1
                decision = row.get("decision", "")
                if decision == "blocked":
                    stats["blocked"] += 1
                elif decision == "redacted" or decision == "redact":
                    stats["redacted"] += 1
                elif decision in ("paused", "allow_once", "report_only"):
                    stats["flagged"] += 1
                else:
                    stats["allowed"] += 1
            except Exception:
                pass

    for findings_file in sessions_dir.rglob("findings.jsonl"):
        for line in findings_file.read_text().strip().splitlines():
            try:
                row = json.loads(line)
                ts = datetime.fromisoformat(row.get("timestamp", ""))
                if ts < cutoff:
                    continue
                sev = row.get("severity", "")
                if sev == "critical":
                    stats["critical_findings"] += 1
                elif sev == "high":
                    stats["high_findings"] += 1
                elif sev == "medium":
                    stats["medium_findings"] += 1
                elif sev == "low":
                    stats["low_findings"] += 1
            except Exception:
                pass

    return stats
