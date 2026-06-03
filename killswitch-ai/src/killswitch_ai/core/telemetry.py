"""
Anonymous telemetry sender.

Sends aggregated, anonymized usage stats to the killswitch-ai API when the
user has opted in.  Always fire-and-forget on a daemon thread — if the network
is unavailable the call fails silently and the user's workflow is unaffected.

What is sent:
  • install_id  — stable anonymous UUID, never tied to user identity
  • lib_version, python_version, os_type  — environment metadata
  • commands_analyzed, prohibited_stopped, sensitive_stopped  — integer counts
  • agents, providers, modes, finding_types  — aggregated distribution maps
                                              (model name → count, etc.)

What is never sent:
  • Prompt text or message content
  • Matched secret values
  • File paths, project paths, or CWD
  • Any personally identifying information
"""
from __future__ import annotations

import threading
from typing import Optional

_TELEMETRY_ENDPOINT = "https://killswitch-ai.replit.app/api/telemetry"


def send_telemetry(
    install_id: str,
    lib_version: str,
    endpoint: Optional[str] = None,
) -> None:
    """
    Fire-and-forget: build payload from local stats and POST to the endpoint.
    Returns immediately; the actual HTTP request runs on a daemon thread.
    """
    url = (endpoint or "").strip() or _TELEMETRY_ENDPOINT

    def _send() -> None:
        try:
            from .stats import build_telemetry_payload, mark_telemetry_sent
            import json
            import urllib.request

            payload = build_telemetry_payload(install_id, lib_version)
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status in (200, 201):
                    mark_telemetry_sent()
        except Exception:
            pass  # Always silent — never disrupt the user

    t = threading.Thread(target=_send, daemon=True)
    t.start()


def maybe_send_telemetry(cfg: "Config") -> None:  # type: ignore[name-defined]
    """
    Called once per process startup (from install() or killswitch context manager).
    Sends telemetry only if the user has opted in.
    """
    if not getattr(cfg, "telemetry_enabled", False):
        return
    from .. import __version__
    send_telemetry(
        install_id=cfg.install_id,
        lib_version=__version__,
        endpoint=getattr(cfg, "telemetry_endpoint", None),
    )
