"""
Top-level convenience module so users can write:

    from killswitch.anthropic import GuardedAnthropic
"""
from .providers.anthropic import GuardedAnthropic

__all__ = ["GuardedAnthropic"]
