"""
killswitch-mcp — MCP server for killswitch-ai.

Install:
    pip install killswitch-mcp

Start:
    killswitch-mcp

See https://killswitch-ai.com/mcp for client configuration.
"""

from killswitch.mcp.server import serve

__all__ = ["serve"]
