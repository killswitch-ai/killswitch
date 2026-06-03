# killswitch-ai

**Stop secrets before they reach the LLM.**

`killswitch-ai` is a pip-installable Python library that scans your LLM prompts and payloads *before* they are sent to OpenAI, Anthropic, or other providers. If sensitive content is detected — API keys, passwords, private keys, database URLs — it can block the request, pause for your approval, redact the secret, or simply log and notify.

Everything runs locally. No prompts, responses, file contents, or secret values leave your machine for inspection.

---

## Install

```bash
pip install killswitch-ai
```

With provider extras:

```bash
pip install "killswitch-ai[openai]"      # OpenAI support
pip install "killswitch-ai[anthropic]"   # Anthropic support
pip install "killswitch-ai[all]"         # Both
```

---

## Quick start

### Option 1 — One-liner (easiest)

```python
import killswitch_ai
killswitch_ai.install()

from openai import OpenAI
client = OpenAI()

# This request is now automatically scanned before sending
response = client.responses.create(
    model="gpt-4o",
    input="Please help me debug this issue..."
)
```

### Option 2 — Explicit wrapper (recommended for production)

```python
from openai import OpenAI
from killswitch_ai.openai import GuardedOpenAI

client = GuardedOpenAI(OpenAI())

response = client.responses.create(
    model="gpt-4o",
    input="Summarize this document..."
)
```

### Anthropic

```python
from anthropic import Anthropic
from killswitch_ai.anthropic import GuardedAnthropic

client = GuardedAnthropic(Anthropic())

response = client.messages.create(
    model="claude-opus-4-5",
    max_tokens=1024,
    messages=[{"role": "user", "content": "Hello"}],
)
```

### Scan text directly

```python
import killswitch_ai

result = killswitch_ai.scan("my API_KEY is sk-proj-abc123...")
for finding in result.findings:
    print(finding.severity, finding.description)
```

---

## Set up

```bash
killswitch init
```

This runs an interactive wizard that asks you:

1. What should happen when something is detected? (pause / block / redact / log-only)
2. What data categories should never be sent? (API keys, .env files, private keys, etc.)
3. Do you want weekly email summaries? (optional, anonymized counts only)

Then writes `killswitch.yml` to your project.

---

## Modes

| Mode | What happens |
|------|-------------|
| `pause` | Stops and asks you what to do (default) |
| `kill` | Blocks the request automatically |
| `redact` | Replaces secrets with `[REDACTED_X]` and continues |
| `report_only` | Allows the request but logs a finding |

Change mode anytime:

```bash
killswitch mode kill
killswitch mode pause
killswitch mode redact
killswitch mode report-only
```

---

## What gets detected

| Layer | Examples |
|-------|---------|
| Prohibited terms | `API_KEY`, `SECRET_KEY`, `CONFIDENTIAL`, custom terms |
| Secret patterns | OpenAI keys (`sk-proj-...`), Anthropic keys, AWS keys, GitHub tokens, Stripe keys, private key blocks, JWT tokens, database URLs |
| Entropy detection | Long random-looking strings that might be secrets |
| Sensitive file paths | `.env`, `*.pem`, `id_rsa`, `credentials.json`, `kubeconfig` |
| Structured payloads | Recursively scans every field in nested JSON |

---

## CLI commands

```bash
killswitch init                    # Interactive setup wizard
killswitch menu                    # Open the interactive report menu
killswitch status                  # Show current mode and recent stats
killswitch scan "text to scan"     # Test the scanner on a piece of text
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

## Configuration (killswitch.yml)

```yaml
mode:
  default_action: pause            # kill | pause | redact | report_only

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
  store_raw_payloads: false        # never store prompt text
  store_secret_values: false       # never store secret values

email:
  enabled: false
  address: ""
  frequency: weekly
```

---

## Local logs

Every scan produces a local audit event under `.killswitch/sessions/`. Raw prompts and secret values are never stored.

What IS stored:
- Event ID, timestamp, provider, operation
- The decision (blocked / allowed / redacted)
- Finding type and severity (not the secret itself)
- Recommendations

What is NEVER stored:
- Prompt text or LLM responses
- Secret values or API keys
- Source code or file contents

---

## Email reports (optional)

If you opt in during `killswitch init`, you'll receive a weekly summary email containing only anonymized counts — how many requests were scanned, blocked, or flagged. No prompt text, secrets, or file contents are ever included.

What the email contains:
- Total LLM calls scanned
- Blocked / redacted / flagged counts
- Finding counts by severity
- A hashed install ID and project ID (never your actual path)

Turn off anytime:

```bash
killswitch email --off
```

---

## Privacy

- All scanning happens locally on your machine
- No prompts or responses are uploaded for inspection
- No secret values are stored in logs
- Email reports contain only anonymized counts

---

## License

MIT
