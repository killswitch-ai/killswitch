from __future__ import annotations

import json
import os
import subprocess
import sys


def _run_cli(tmp_path, *args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run(
        [
            sys.executable,
            "-c",
            "from killswitch.cli.main import main; main()",
            *args,
        ],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
        timeout=10,
    )


def test_cli_help_runs(tmp_path):
    result = _run_cli(tmp_path, "--help")

    assert result.returncode == 0
    assert "killswitch-ai" in result.stdout
    assert "scan" in result.stdout


def test_cli_status_runs(tmp_path):
    result = _run_cli(tmp_path, "status")

    assert result.returncode == 0
    assert "killswitch-ai status" in result.stdout
    assert "Mode" in result.stdout


def test_cli_scan_json_clean_text(tmp_path):
    result = _run_cli(tmp_path, "scan", "hello world", "--json")

    assert result.returncode == 0
    assert json.loads(result.stdout) == {"findings": []}


def test_cli_scan_json_dummy_secret(tmp_path):
    result = _run_cli(
        tmp_path,
        "scan",
        "sk-proj-AbCdEfGhIjKlMnOpQrStUvWx123456",
        "--json",
    )

    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert data["findings"][0]["type"] == "openai_key"
    assert data["findings"][0]["severity"] == "critical"
