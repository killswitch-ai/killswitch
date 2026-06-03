"""
Top-level convenience module so users can write:

    from killswitch.openai import GuardedOpenAI
"""
from .providers.openai import GuardedOpenAI

__all__ = ["GuardedOpenAI"]
