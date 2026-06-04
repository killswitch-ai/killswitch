# killswitch-mcp

MCP server for [killswitch-ai](https://killswitch-ai.com) — give Claude Desktop, Cursor, or any MCP-capable client a live window into your egress guardrails.

## Install

```bash
pip install killswitch-mcp
```

This installs `killswitch-ai` and `mcp` automatically.

## Start the server

```bash
killswitch-mcp
```

The server speaks MCP over stdio and waits for a client to connect.

## Client configuration

### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows), then restart Claude Desktop:

```json
{
  "mcpServers": {
    "killswitch": {
      "command": "killswitch-mcp"
    }
  }
}
```

### Cursor

Open **Settings → Cursor Settings → MCP**, click *Add new global MCP server*, and paste:

```json
{
  "mcpServers": {
    "killswitch": {
      "command": "killswitch-mcp"
    }
  }
}
```

## Tools

| Tool | Description |
|------|-------------|
| `scan` | Pre-flight scan text before sending to an LLM — returns findings metadata, never echoes input |
| `get_status` | Current enforcement mode and headline event counts |
| `get_stats` | Full aggregate stats from the local audit database |
| `recent_findings` | Recent audit findings with type, severity, and decision |
| `get_policy` | Active killswitch.yml policy (credentials stripped) |

All tools are **read-only**. None write to disk or affect any running `killswitch.install()` session.

## Important

The MCP server is a voluntary, opt-in guardrail. For automatic inline enforcement that intercepts every LLM call regardless of what an agent requests, use `killswitch.install()` in your Python process.

## License

Apache 2.0 — [Yodabyte LLC](https://killswitch-ai.com)
