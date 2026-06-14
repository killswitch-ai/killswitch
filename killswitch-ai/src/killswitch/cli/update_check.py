from __future__ import annotations


def check_for_update() -> None:
    """Best-effort update hook.

    The CLI should never fail because update checking is unavailable.  This
    placeholder keeps command dispatch stable until a real, opt-in update
    checker is implemented.
    """
    return None
