# Phase 2 Fixes Summary

Branch: `phase2/fixes-and-tests`  
Base commit: `b78a7f61bcf1ddc12a7c94a2ae2256d0fcbc0cc7`  
Scope: fixes and tests from Phase 1 only. No OpenClaw integration was implemented.

## Files Changed

- `killswitch-ai/pyproject.toml`
- `killswitch-ai/README.md`
- `killswitch-ai/src/killswitch/__init__.py`
- `killswitch-ai/src/killswitch/cli/main.py`
- `killswitch-ai/src/killswitch/cli/update_check.py`
- `killswitch-ai/src/killswitch/core/decision.py`
- `killswitch-ai/src/killswitch/core/policy.py`
- `killswitch-ai/src/killswitch/core/scanner.py`
- `killswitch-ai/src/killswitch/providers/anthropic.py`
- `killswitch-ai/src/killswitch/providers/openai.py`
- `killswitch-ai/tests/test_cli_scan.py`
- `killswitch-ai/tests/test_cli_subprocess.py`
- `killswitch-ai/tests/test_config.py`
- `killswitch-ai/tests/test_decision.py`
- `killswitch-ai/tests/test_normalizer.py`
- `killswitch-ai/tests/test_providers_and_install.py`
- `killswitch-ai/tests/test_redactor.py`
- `killswitch-ai/tests/test_scanner.py`
- `killswitch-ai/tests/test_version_imports_logging.py`
- `PHASE2_FIXES_SUMMARY.md`
- `PHASE2_TEST_RESULTS.md`

## Fixes Implemented

### Operational CLI crash

Added `killswitch.cli.update_check` as a safe no-op update hook so CLI command dispatch no longer fails on a missing import.

Added a Windows-safe stream encoding guard in `killswitch.cli.main` so commands such as `status` can print box-drawing characters without `UnicodeEncodeError` on cp1252 consoles.

### Stale test imports

Updated tests from stale `killswitch_ai.*` imports to the shipped `killswitch.*` package path. No compatibility shim was added because the README already documents `killswitch` as the correct import path and the smaller maintainable fix is to align tests with the public package.

### Version mismatch

Changed runtime version reporting to read from installed package metadata via `importlib.metadata.version("killswitch-ai")`. Runtime version now matches package metadata.

### Anthropic/OpenAI key classification

Updated the OpenAI key regex so `sk-ant-*` values are not classified as OpenAI keys. Added regression coverage proving dummy Anthropic keys classify as Anthropic and dummy OpenAI keys classify as OpenAI.

### Drop behavior

The README and CLI already present `drop` as an intended supported mode. Based on that documented behavior, `drop` was implemented minimally rather than removed:

- `resolve_action` recognizes `drop`.
- `execute_decision("drop", ...)` returns a `drop` decision without raising.
- OpenAI and Anthropic wrappers do not call the underlying provider when the resolved action is `drop`.
- Provider wrappers return a synthetic empty response with `_killswitch_dropped = True`.

### MCP packaging/docs alignment

Added an `mcp` optional dependency extra and a `killswitch-mcp` console script so the README commands match package metadata and installed entry points.

### PII detection scope

Email and phone detection were intentionally not implemented in Phase 2. The README now documents that broad PII detection is a future enhancement, while the current scope is secrets, credentials, tokens, sensitive file references, prohibited terms, and high-entropy strings.

## Tests Added or Updated

- CLI subprocess tests for `--help`, `status`, and `scan --json`.
- Import path correctness tests.
- Runtime/package version consistency test.
- Default logging privacy test proving raw dummy secret values are not written to JSONL logs.
- Decision tests for `drop`, `off`, and supported mode behavior.
- Provider wrapper drop regression test proving the real provider is not called.
- Scanner regression test for Anthropic/OpenAI classification.

## Issues Left for Future Work

- Broad email and phone PII detection remains a future enhancement.
- The update-check hook is currently a no-op. A real update checker should be opt-in or best-effort and must never break command execution.
- The synthetic dropped response is intentionally minimal. If users need exact SDK response-object compatibility, add provider-specific response adapters and tests.
- OpenClaw integration is intentionally not included in this phase.

## Risks and Assumptions

- `drop` was implemented because it is already documented as a supported mode. If product direction changes, the alternative is to remove `drop` from docs/CLI and tests.
- `mode: off` now takes precedence over per-finding actions and resolves to allow. This matches the README claim that scanning is disabled in off mode.
- No real secrets or customer data were used. Tests use dummy values only.
