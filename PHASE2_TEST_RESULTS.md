# Phase 2 Test Results

Branch: `phase2/fixes-and-tests`  
Environment: Windows PowerShell, Python 3.13.5  
Package under test: `killswitch-ai`

## Commands Run

| Command | Working directory | Result |
|---|---|---:|
| `git switch -c phase2/fixes-and-tests` | repo root | Pass |
| `..\..\.venv-dev\Scripts\python.exe -m pytest -q` | `killswitch-ai` | Pass, `190 passed in 11.33s` |
| `..\..\.venv-dev\Scripts\python.exe -m pytest tests\test_scanner.py -q` | `killswitch-ai` | Pass, `25 passed in 0.60s` |
| `..\..\.venv-dev\Scripts\python.exe -m pytest tests\test_mcp.py -q` | `killswitch-ai` | Pass, `71 passed in 7.61s` |
| `..\..\..\.venv-dev\Scripts\python.exe -m compileall killswitch` | `killswitch-ai/src` | Pass |
| `..\..\.venv-dev\Scripts\python.exe -m pip check` | `killswitch-ai` | Pass, `No broken requirements found.` |
| `..\..\.venv-dev\Scripts\killswitch.exe --help` | `killswitch-ai` | Pass |
| `..\..\.venv-dev\Scripts\killswitch.exe status` | `killswitch-ai` | Pass |
| `..\..\.venv-dev\Scripts\killswitch.exe scan "hello world" --json` | `killswitch-ai` | Pass, returned empty findings |
| `..\..\.venv-dev\Scripts\killswitch.exe scan "sk-proj-AbCdEfGhIjKlMnOpQrStUvWx123456" --json` | `killswitch-ai` | Pass, returned one `openai_key` finding |
| `..\..\.venv-dev\Scripts\python.exe -m build --wheel` | `killswitch-ai` | Pass, built `killswitch_ai-0.1.6-py3-none-any.whl` |
| `git diff --check` | repo root | Pass |

## Pass/Fail Summary

All required Phase 2 checks passed after the fixes.

## Notes

- One initial compileall attempt used the wrong relative venv path from `killswitch-ai/src`; it failed before running the package check. The command was rerun with the correct path and passed.
- The CLI tests and manual CLI commands used only harmless text and dummy/fake secret strings.
- No OpenClaw integration or proof-of-concept was implemented.
