"""
killswitch MCP server.

Exposes killswitch-ai functionality as Model Context Protocol tools for use
with MCP-capable clients (Claude Desktop, Cursor, etc.).

Install with the mcp extra:

    pip install "killswitch-ai[mcp]"

Start the server:

    killswitch mcp

Or via the dedicated entry point:

    killswitch-mcp

NOTE: This MCP server is a **voluntary, opt-in** guardrail.  For automatic
inline enforcement that intercepts every LLM call regardless of what an agent
chooses to do, use ``killswitch.install()`` or the GuardedOpenAI /
GuardedAnthropic wrappers in your code.
"""
