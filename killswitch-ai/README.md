# killswitch-ai

[![PyPI version](https://img.shields.io/pypi/v/killswitch-ai.svg)](https://pypi.org/project/killswitch-ai/)
[![Python](https://img.shields.io/pypi/pyversions/killswitch-ai.svg)](https://pypi.org/project/killswitch-ai/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://github.com/killswitch-ai/killswitch/actions/workflows/release.yml/badge.svg)](https://github.com/killswitch-ai/killswitch/actions)

**Local LLM egress control for Python developers.** Stops API keys, secrets, `.env` files, and sensitive payloads before they reach OpenAI, Anthropic, or any LLM API — without leaving your machine.

---

## Install

```bash
pip install killswitch-ai
```

With provider extras:

```bash
pip install "killswitch-ai[openai]"      # OpenAI
pip install "killswitch-ai[anthropic]"   # Anthropic
pip install "killswitch-ai[all]"         # Both
```

---

## Quick start

### One-liner

```python
import killswitch
killswitch.install()

from openai import OpenAI
client = OpenAI()  # now protected — every request is scanned first
```

### Explicit wrapper

```python
from openai import OpenAI
from killswitch.openai import GuardedOpenAI

client = GuardedOpenAI(OpenAI())
```

### Anthropic

```python
from anthropic import Anthropic
from killswitch.anthropic import GuardedAnthropic

client = GuardedAnthropic(Anthropic())
```

### Scan text directly

```python
import killswitch

result = killswitch.scan("my API_KEY is sk-proj-abc123...")
for finding in result.findings:
    print(finding.severity, finding.description)
```

---

## How it works

```
Your code  →  killswitch  →  LLM API
               ↓
           scan prompt
               ↓
         finding detected?
          ┌──────────────────────────────┐
          │  kill        →  raise error  │
          │  pause       →  ask you      │
          │  redact      →  [REDACTED]   │
          │  report_only →  log + allow  │
          └──────────────────────────────┘
```

Everything runs locally. No prompts, responses, file contents, or secret values leave your machine for inspection.

---

## What gets detected

| Layer | Examples |
|-------|---------|
| **Prohibited terms** | `API_KEY`, `SECRET_KEY`, `CONFIDENTIAL`, custom terms |
| **Secret patterns** | OpenAI keys (`sk-proj-…`), Anthropic keys, AWS keys, GitHub tokens, Stripe keys, private key PEM blocks, JWT tokens, database URLs |
| **Entropy detection** | Long random-looking strings that might be secrets |
| **Sensitive file paths** | `.env`, `*.pem`, `id_rsa`, `credentials.json`, `kubeconfig` |
| **Structured payloads** | Recursively scans every field in nested JSON |

### Current scope

killswitch-ai is currently focused on LLM egress control for secrets, credentials,
tokens, sensitive file references, prohibited terms, and high-entropy strings. Broad
PII detection such as email addresses and phone numbers is not currently included;
that should be treated as a future enhancement rather than an existing guarantee.

---

## Modes

| Mode | What happens |
|------|-------------|
| `pause` | Stops and asks you what to do (default) |
| `kill` | Blocks the request, raises `KillswitchBlocked` |
| `drop` | Blocks the request silently — no exception, returns empty response |
| `redact` | Replaces secrets with `[REDACTED_X]` and continues |
| `report_only` | Allows the request but logs a finding |
| `off` | Disables all scanning — requests pass through with zero overhead |

**`kill` vs `drop`:** Both prevent the request from reaching the LLM. `kill` raises a `KillswitchBlocked` exception so the block is impossible to miss. `drop` returns a synthetic empty response (`response.choices[0].message.content == ""`) so the rest of your code keeps running without any error handling — check `response._killswitch_dropped` if you need to detect it.

Change mode anytime:

```bash
killswitch mode kill
killswitch mode drop
killswitch mode pause
killswitch mode redact
killswitch mode report-only

# Quick on/off toggle:
killswitch off   # disable scanning entirely
killswitch on    # re-enable (restores to pause mode)
```

---

## Set up

```bash
killswitch init
```

Runs an interactive wizard: choose a mode, pick data categories to protect, optionally enable weekly email summaries. Writes `killswitch.yml` to your project.

Then verify installation:

```bash
killswitch test
```

---

## CLI

```bash
killswitch init                    # Interactive setup wizard
killswitch test                    # Verify the scanner is working
killswitch status                  # Show current mode and recent stats
killswitch scan "text to scan"     # Test the scanner on text
killswitch menu                    # Open the interactive report menu
killswitch mode kill               # Change active mode
killswitch logs --latest           # View latest session findings
killswitch event KAI-E-...         # Look up a specific event
killswitch finding KAI-F-...       # Look up a specific finding
killswitch report                  # Print the weekly summary
killswitch report --send           # Send weekly report by email
killswitch email --on              # Enable email reports
killswitch email --off             # Disable email reports
```

---

## Configuration (`killswitch.yml`)

```yaml
mode:
  default_action: pause            # kill | drop | pause | redact | report_only

detection:
  prohibited_terms:
    - "API_KEY"
    - "SECRET_KEY"
    - "PRIVATE KEY"
    - "MY_CUSTOM_TERM"
  entropy_detection:
    enabled: true
    min_length: 24
    threshold: 4.2

actions:
  private_key: kill
  openai_key: kill
  anthropic_key: kill
  database_url: pause
  prohibited_term: pause
  high_entropy_string: report_only

logging:
  enabled: true
  log_dir: .killswitch
  store_raw_payloads: false        # never stores prompt text
  store_secret_values: false       # never stores secret values

email:
  enabled: false
  address: ""
  frequency: weekly
```

---

## Local logs

Every scan writes an audit event to `.killswitch/sessions/`. Raw prompts and secret values are never stored.

**Stored:** event ID, timestamp, provider, operation, decision (blocked / allowed / redacted), finding type, severity, recommendations.

**Never stored:** prompt text, LLM responses, secret values, API keys, source code, file contents.

---

## Privacy

- All scanning runs locally — nothing leaves your machine for inspection
- No prompts or responses are uploaded
- No secret values are stored in logs or telemetry
- Anonymous opt-in telemetry reports only aggregate counts (scans, blocks, finding categories) — disabled by default

---

## FAQ

**How do I update killswitch?**

```bash
pip install --upgrade killswitch-ai
```

If you installed with pipx:

```bash
pipx upgrade killswitch-ai
```

killswitch will also notify you automatically when a newer version is available — you'll see a notice at the end of any command output, just like pip does.

---

**Installing on macOS**

macOS with Homebrew Python blocks system-wide pip installs. Use this copy-paste sequence in your terminal:

```bash
python3 -m venv ~/.venv
source ~/.venv/bin/activate
pip install "killswitch-ai[all]"
killswitch init
```

To activate automatically in every new terminal window, add it to your shell profile (one-time):

```bash
echo 'source ~/.venv/bin/activate' >> ~/.zshrc
```

Then reload: `source ~/.zshrc`

> **Note:** `~/.venv` is a global venv — good for CLI use. If you want to use killswitch-ai as a library inside a specific project, create a local venv instead: `python3 -m venv .venv` from your project folder and activate with `source .venv/bin/activate`.

For the CLI only (no library import), pipx also works:

```bash
brew install pipx
pipx install "killswitch-ai[all]"
```

---

**`ModuleNotFoundError: No module named 'killswitch_ai'`**

The import name is `killswitch`, not `killswitch_ai`:

```python
import killswitch        # ✓ correct
import killswitch_ai     # ✗ wrong
```

Also note: if you installed via pipx, the package is only available as a CLI tool (`killswitch` command) — it cannot be imported in scripts. Install into a venv for library use.

---

**How do I temporarily disable killswitch without uninstalling?**

Switch to `report_only` mode — requests pass through normally, findings are only logged:

```bash
killswitch mode report-only
```

Turn protection back on:

```bash
killswitch mode pause     # stops and asks before sending
killswitch mode kill      # blocks automatically
```

Or, if you called `killswitch.install()` in your code, just comment it out:

```python
# killswitch.install()
```

---

**How do I uninstall killswitch?**

```bash
pip uninstall killswitch-ai
```

This removes the library and the `killswitch` CLI. Your `killswitch.yml` config file and `.killswitch/` log directory are left in place — delete them manually if you want a clean removal:

```bash
rm killswitch.yml
rm -rf .killswitch
```

---

## MCP server

killswitch-ai ships with an optional [Model Context Protocol](https://modelcontextprotocol.io/) server so MCP-capable clients (Claude Desktop, Cursor, etc.) can interact with it directly.

### Install

```bash
pip install "killswitch-ai[mcp]"
```

### Start the server

```bash
killswitch mcp
```

Or via the dedicated entry point:

```bash
killswitch-mcp
```

Both commands start the server over stdio, ready to be connected to any MCP client.

### Client configuration

**Claude Desktop** (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "killswitch": {
      "command": "killswitch-mcp"
    }
  }
}
```

**Cursor** (`.cursor/mcp.json` in your project, or global `~/.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "killswitch": {
      "command": "killswitch-mcp"
    }
  }
}
```

### Available tools

| Tool | What it does |
|------|-------------|
| `scan` | Pre-flight scan text for secrets before passing to an LLM |
| `get_status` | Current mode, protection on/off, headline counts |
| `get_stats` | Full aggregate stats (finding types, decisions, providers) |
| `recent_findings` | Recent audit events — type, severity, decision only |
| `get_policy` | Active `killswitch.yml` settings (or built-in defaults) |

### Important: opt-in guardrail vs. enforcement

The MCP server is a **voluntary, opt-in** layer — an agent that calls `scan` provides defense-in-depth. It is not the same as automatic enforcement.

For guaranteed inline enforcement that intercepts *every* LLM call regardless of what an agent chooses to do, use `killswitch.install()` or the `GuardedOpenAI` / `GuardedAnthropic` wrappers in your code.

### Privacy

- `scan` never echoes the input text or matched secret values in its response
- `recent_findings` reads from the local audit log which already strips raw prompt text and secret values
- `get_policy` strips SMTP credentials and internal identifiers

---

## Links

- **Website:** [killswitch-ai.com](https://killswitch-ai.com)
- **PyPI:** [pypi.org/project/killswitch-ai](https://pypi.org/project/killswitch-ai/)
- **Issues:** [github.com/killswitch-ai/killswitch/issues](https://github.com/killswitch-ai/killswitch/issues)

---

## License

MIT
