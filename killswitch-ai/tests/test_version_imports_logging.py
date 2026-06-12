from __future__ import annotations

import importlib.metadata
import importlib.util

from killswitch.core.scanner import Finding
from killswitch.logging.logger import KillswitchLogger


def test_public_import_path_is_killswitch():
    assert importlib.util.find_spec("killswitch") is not None


def test_legacy_killswitch_ai_import_is_not_required():
    assert importlib.util.find_spec("killswitch_ai") is None


def test_runtime_version_matches_package_metadata():
    import killswitch

    assert killswitch.__version__ == importlib.metadata.version("killswitch-ai")


def test_default_logging_does_not_store_raw_dummy_secret(tmp_path):
    dummy_secret = "sk-proj-AbCdEfGhIjKlMnOpQrStUvWx123456"
    finding = Finding(
        severity="critical",
        category="secret_pattern",
        finding_type="openai_key",
        description="Possible OpenAI API key",
        scan_path="test",
        matched_text_preview=dummy_secret,
    )

    logger = KillswitchLogger(log_dir=str(tmp_path / ".killswitch"))
    logger.log_event(
        provider="test",
        operation="unit",
        mode="kill",
        decision="blocked",
        findings=[finding],
        event_id="KAI-E-test",
    )

    jsonl_text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (tmp_path / ".killswitch").rglob("*.jsonl")
    )
    assert dummy_secret not in jsonl_text
    assert '"raw_payload_stored": false' in jsonl_text
    assert '"secret_values_stored": false' in jsonl_text
