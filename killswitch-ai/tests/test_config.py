import pytest
import tempfile
from pathlib import Path

from killswitch.core.config import Config, load_config, save_config, get_config, set_config


class TestConfigDefaults:
    def test_default_mode_is_pause(self):
        cfg = Config()
        assert cfg.mode == "pause"

    def test_default_prohibited_terms_not_empty(self):
        cfg = Config()
        assert len(cfg.prohibited_terms) > 0
        assert "API_KEY" in cfg.prohibited_terms

    def test_default_email_disabled(self):
        cfg = Config()
        assert cfg.email.enabled is False

    def test_default_entropy_enabled(self):
        cfg = Config()
        assert cfg.entropy_enabled is True

    def test_install_id_generated(self):
        cfg1 = Config()
        cfg2 = Config()
        assert cfg1.install_id != cfg2.install_id


class TestConfigSaveLoad:
    def test_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "killswitch.yml"
            cfg = Config(mode="kill")
            cfg.email.enabled = True
            cfg.email.address = "test@example.com"
            save_config(cfg, path)

            loaded = load_config(path)
            assert loaded.mode == "kill"
            assert loaded.email.enabled is True
            assert loaded.email.address == "test@example.com"

    def test_missing_config_returns_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nonexistent.yml"
            cfg = load_config(path)
            assert cfg.mode == "pause"

    def test_save_creates_parent_dirs(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nested" / "dir" / "killswitch.yml"
            cfg = Config()
            save_config(cfg, path)
            assert path.exists()

    def test_partial_config_merges_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "killswitch.yml"
            path.write_text("mode:\n  default_action: kill\n")
            cfg = load_config(path)
            assert cfg.mode == "kill"
            assert len(cfg.prohibited_terms) > 0

    def test_config_to_dict_roundtrip(self):
        cfg = Config(mode="redact")
        d = cfg.to_dict()
        assert d["mode"]["default_action"] == "redact"
        assert "prohibited_terms" in d["detection"]


class TestConfigActions:
    def test_get_action_for_known_type(self):
        cfg = Config()
        action = cfg.get_action("openai_key")
        assert action == "kill"

    def test_get_action_fallback_to_mode(self):
        cfg = Config(mode="pause")
        action = cfg.get_action("unknown_type_xyz")
        assert action == "pause"
