from __future__ import annotations

import hashlib
import os
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from ..exceptions import KillswitchConfigError

DEFAULT_PROHIBITED_TERMS: List[str] = [
    "API_KEY",
    "SECRET_KEY",
    "AWS_SECRET_ACCESS_KEY",
    "PRIVATE KEY",
    "BEGIN RSA PRIVATE KEY",
    "BEGIN OPENSSH PRIVATE KEY",
    "DO_NOT_SEND_TO_AI",
    "CONFIDENTIAL",
]

def _compute_project_id() -> str:
    cwd = str(Path.cwd().resolve())
    return hashlib.sha256(cwd.encode()).hexdigest()[:16]


DEFAULT_ACTIONS: Dict[str, str] = {
    "private_key": "kill",
    "openai_key": "kill",
    "anthropic_key": "kill",
    "aws_secret_key": "kill",
    "aws_access_key": "kill",
    "github_token": "kill",
    "stripe_key": "kill",
    "jwt_token": "pause",
    "database_url": "pause",
    "env_file_reference": "pause",
    "prohibited_term": "pause",
    "sensitive_file_path": "pause",
    "high_entropy_string": "report_only",
    "generic_password": "report_only",
}


@dataclass
class EmailConfig:
    enabled: bool = False
    address: str = ""
    frequency: str = "weekly"
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    from_address: str = "killswitch-ai <noreply@killswitch-ai.dev>"


@dataclass
class Config:
    mode: str = "pause"
    prohibited_terms: List[str] = field(default_factory=lambda: list(DEFAULT_PROHIBITED_TERMS))
    actions: Dict[str, str] = field(default_factory=lambda: dict(DEFAULT_ACTIONS))
    log_enabled: bool = True
    log_dir: str = ".killswitch"
    store_raw_payloads: bool = False
    store_secret_values: bool = False
    entropy_enabled: bool = True
    entropy_min_length: int = 24
    entropy_threshold: float = 4.2
    email: EmailConfig = field(default_factory=EmailConfig)
    telemetry_enabled: bool = False
    telemetry_endpoint: str = ""
    install_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    project_id: str = field(default_factory=_compute_project_id)
    _source_path: Optional[Path] = field(default=None, repr=False)

    def get_action(self, finding_type: str) -> str:
        return self.actions.get(finding_type, self.mode)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mode": {"default_action": self.mode},
            "detection": {
                "prohibited_terms": self.prohibited_terms,
                "entropy_detection": {
                    "enabled": self.entropy_enabled,
                    "min_length": self.entropy_min_length,
                    "threshold": self.entropy_threshold,
                },
            },
            "actions": self.actions,
            "logging": {
                "enabled": self.log_enabled,
                "log_dir": self.log_dir,
                "store_raw_payloads": self.store_raw_payloads,
                "store_secret_values": self.store_secret_values,
            },
            "email": {
                "enabled": self.email.enabled,
                "address": self.email.address,
                "frequency": self.email.frequency,
                "smtp_host": self.email.smtp_host,
                "smtp_port": self.email.smtp_port,
                "smtp_user": self.email.smtp_user,
                "from_address": self.email.from_address,
            },
            "telemetry": {
                "enabled": self.telemetry_enabled,
                "endpoint": self.telemetry_endpoint,
            },
            "meta": {
                "install_id": self.install_id,
                "project_id": self.project_id,
            },
        }


def _find_config_path() -> Optional[Path]:
    candidates = [
        Path.cwd() / "killswitch.yml",
        Path.cwd() / ".killswitch" / "config.yml",
        Path.home() / ".killswitch" / "config.yml",
    ]
    for p in candidates:
        if p.exists():
            return p
    return None


def load_config(path: Optional[Path] = None) -> Config:
    if path is None:
        path = _find_config_path()

    if path is None or not path.exists():
        return Config()

    try:
        with open(path) as f:
            data = yaml.safe_load(f) or {}
    except Exception as e:
        raise KillswitchConfigError(f"Could not read {path}: {e}") from e

    cfg = Config()
    cfg._source_path = path

    mode_block = data.get("mode", {})
    if isinstance(mode_block, dict):
        cfg.mode = mode_block.get("default_action", cfg.mode)
    elif isinstance(mode_block, str):
        cfg.mode = mode_block

    detection = data.get("detection", {})
    if "prohibited_terms" in detection:
        cfg.prohibited_terms = list(detection["prohibited_terms"])
    entropy = detection.get("entropy_detection", {})
    cfg.entropy_enabled = entropy.get("enabled", cfg.entropy_enabled)
    cfg.entropy_min_length = entropy.get("min_length", cfg.entropy_min_length)
    cfg.entropy_threshold = entropy.get("threshold", cfg.entropy_threshold)

    if "actions" in data:
        cfg.actions.update(data["actions"])

    logging_block = data.get("logging", {})
    cfg.log_enabled = logging_block.get("enabled", cfg.log_enabled)
    cfg.log_dir = logging_block.get("log_dir", cfg.log_dir)
    cfg.store_raw_payloads = logging_block.get("store_raw_payloads", False)
    cfg.store_secret_values = logging_block.get("store_secret_values", False)

    email_block = data.get("email", {})
    cfg.email.enabled = email_block.get("enabled", False)
    cfg.email.address = email_block.get("address", "")
    cfg.email.frequency = email_block.get("frequency", "weekly")
    cfg.email.smtp_host = email_block.get("smtp_host", "")
    cfg.email.smtp_port = email_block.get("smtp_port", 587)
    cfg.email.smtp_user = email_block.get("smtp_user", "")
    cfg.email.smtp_password = email_block.get("smtp_password", "")
    cfg.email.from_address = email_block.get("from_address", cfg.email.from_address)

    telemetry_block = data.get("telemetry", {})
    cfg.telemetry_enabled = telemetry_block.get("enabled", False)
    cfg.telemetry_endpoint = telemetry_block.get("endpoint", "")

    meta = data.get("meta", {})
    cfg.install_id = meta.get("install_id", cfg.install_id)
    cfg.project_id = meta.get("project_id", cfg.project_id)

    return cfg


def save_config(cfg: Config, path: Optional[Path] = None) -> Path:
    if path is None:
        path = Path.cwd() / "killswitch.yml"
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        yaml.dump(cfg.to_dict(), f, default_flow_style=False, sort_keys=False)
    return path


_cached_config: Optional[Config] = None


def get_config(reload: bool = False) -> Config:
    global _cached_config
    if _cached_config is None or reload:
        _cached_config = load_config()
    return _cached_config


def set_config(cfg: Config) -> None:
    global _cached_config
    _cached_config = cfg
