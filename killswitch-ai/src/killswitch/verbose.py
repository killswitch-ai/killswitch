"""
killswitch-ai verbose / debug output module.

Controls how much diagnostic text killswitch prints to stderr while it works.

  Level 0 (default) — Silent: Only critical notices (blocks, redactions, pause prompts).
  Level 1 (-v)      — Verbose: Key milestones — intercepted, scanning, decision.
  Level 2 (-vv)     — Super-verbose: Every step explained in plain English.
                       Great for beginners learning exactly what killswitch does.

Set via:
  Environment variable:  KILLSWITCH_VERBOSE=1   or   KILLSWITCH_VERBOSE=2
  Python API:            killswitch.install(verbose=2)
  CLI (scan command):    killswitch scan -v "..."
                         killswitch scan --super-verbose "..."
"""
from __future__ import annotations

import os
import sys

_level: int = int(os.environ.get("KILLSWITCH_VERBOSE", "0") or "0")


def get_level() -> int:
    """Return the current verbosity level (0, 1, or 2)."""
    return _level


def set_level(level: int) -> None:
    """Set the verbosity level. Clamps to 0–2."""
    global _level
    _level = max(0, min(2, int(level)))


def is_on() -> bool:
    return _level >= 1


def is_super() -> bool:
    return _level >= 2


def vprint(msg: str, level: int = 1) -> None:
    """Print to stderr if the current level >= `level`."""
    if _level >= level:
        print(f"[killswitch] {msg}", file=sys.stderr)


def v1(msg: str) -> None:
    """Print at verbose (level 1) or higher."""
    vprint(msg, level=1)


def v2(msg: str) -> None:
    """Print at super-verbose (level 2) only."""
    vprint(msg, level=2)


def sep(char: str = "─", width: int = 55, level: int = 2) -> None:
    """Print a separator line."""
    vprint(char * width, level=level)


def blank(level: int = 2) -> None:
    vprint("", level=level)
