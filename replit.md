# killswitch-ai

A pip-installable Python library that stops secrets and sensitive data from reaching LLMs — scanning prompts, messages, and payloads locally before any request is sent.

## Run & Operate

- `cd killswitch-ai && pip install -e ".[dev]"` — install library in dev mode
- `cd killswitch-ai && pytest` — run all tests
- `killswitch init` — interactive setup wizard (after install)
- `killswitch menu` — local report browser (after install)
- `killswitch status` — show current mode and stats

## Stack

- Pure Python 3.9+ library
- No mandatory dependencies (only `pyyaml`)
- Optional: `openai>=1.0`, `anthropic>=0.20`
- Tests: `pytest`
- Build: `hatchling`

## Where things live

- `killswitch-ai/` — Python package root
- `killswitch-ai/src/killswitch_ai/` — library source
  - `core/` — config, normalizer, scanner, policy, decision, redactor
  - `providers/` — GuardedOpenAI, GuardedAnthropic wrappers
  - `logging/` — local JSONL event logger
  - `reporting/` — email report builder
  - `cli/` — argparse CLI entry point, wizard, menu
- `killswitch-ai/tests/` — pytest test suite
- `killswitch-ai/README.md` — full usage documentation

## Architecture decisions

- Layered scanner (5 layers): prohibited terms → regex patterns → entropy → sensitive paths → structured payload scanning
- Local-first: nothing leaves the machine for inspection
- Four modes: kill, pause, redact, report_only
- Logs store only metadata (event ID, finding type, severity, decision) — never raw prompts or secret values
- Email reports use hashed install/project IDs — never actual paths or secrets

## Product

killswitch-ai is a developer security library. Python developers add it to any LLM project to automatically scan outgoing payloads. Key features:
- Wraps OpenAI and Anthropic clients transparently
- Detects API keys, private keys, database URLs, JWTs, high-entropy strings
- Beginner-friendly CLI menu for browsing local reports
- Opt-in weekly email summaries (anonymized counts only)

## User preferences

_Populate as you build._

## Gotchas

- Install with `pip install -e ".[dev]"` from the `killswitch-ai/` directory
- Config is read from `killswitch.yml` in the current working directory
- Log directory defaults to `.killswitch/` relative to cwd
- `killswitch_ai.install()` monkeypatches at import time — call before importing openai/anthropic

## Pointers

- See the `pnpm-workspace` skill for Node.js workspace structure
