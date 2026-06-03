"""
Top-level convenience module so users can write:

    from killswitch_ai.openai import GuardedOpenAI
"""
from .providers.openai import GuardedOpenAI

__all__ = ["GuardedOpenAI"]
