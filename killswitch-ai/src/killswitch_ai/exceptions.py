from __future__ import annotations
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .core.scanner import Finding
    from .logging.logger import EventRecord


class KillswitchBlocked(Exception):
    """Raised when killswitch-ai blocks an LLM request in kill mode."""

    def __init__(self, finding: "Finding", event_id: str) -> None:
        self.finding = finding
        self.event_id = event_id
        super().__init__(
            f"\n\nkillswitch-ai blocked this LLM request.\n\n"
            f"  Finding : {finding.finding_id}\n"
            f"  Severity: {finding.severity}\n"
            f"  Reason  : {finding.description}\n"
            f"  Event   : {event_id}\n\n"
            f"The request was not sent to the LLM.\n"
            f"No secret value was stored.\n"
        )


class KillswitchConfigError(Exception):
    """Raised when the killswitch.yml configuration is invalid."""
