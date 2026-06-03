from __future__ import annotations

import copy
import re
from typing import Any, List

from .scanner import Finding, SECRET_PATTERNS


REDACT_LABELS = {
    "openai_key": "OPENAI_KEY",
    "anthropic_key": "ANTHROPIC_KEY",
    "aws_access_key": "AWS_ACCESS_KEY",
    "aws_secret_key": "AWS_SECRET_KEY",
    "github_token": "GITHUB_TOKEN",
    "stripe_key": "STRIPE_KEY",
    "private_key": "PRIVATE_KEY",
    "jwt_token": "JWT_TOKEN",
    "database_url": "DATABASE_URL",
    "generic_password": "PASSWORD",
    "prohibited_term": "PROHIBITED",
    "high_entropy_string": "HIGH_ENTROPY_STRING",
    "sensitive_file_path": "SENSITIVE_PATH",
}


def _replacement(finding_type: str) -> str:
    label = REDACT_LABELS.get(finding_type, finding_type.upper())
    return f"[REDACTED_{label}]"


def redact_text(text: str, findings: List[Finding]) -> str:
    """
    Redact matched portions of text based on findings.
    Works from the end of the string backwards so offsets stay valid.
    """
    if not findings or not text:
        return text

    text_findings = sorted(
        [f for f in findings if f.match_end > f.match_start],
        key=lambda f: f.match_start,
        reverse=True,
    )

    result = text
    for f in text_findings:
        if f.match_start >= 0 and f.match_end <= len(result):
            replacement = _replacement(f.finding_type)
            result = result[: f.match_start] + replacement + result[f.match_end :]

    return result


def redact_string_in_payload(payload: Any, findings: List[Finding]) -> Any:
    """
    Recursively redact a payload (dict/list/str) using findings.
    Returns a deep copy — never mutates the original.
    """
    payload = copy.deepcopy(payload)
    return _redact_obj(payload, findings)


def _redact_obj(obj: Any, findings: List[Finding]) -> Any:
    if isinstance(obj, str):
        for pattern_type, _, _, pattern in SECRET_PATTERNS:
            obj = pattern.sub(_replacement(pattern_type), obj)
        return obj
    elif isinstance(obj, dict):
        return {k: _redact_obj(v, findings) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_redact_obj(item, findings) for item in obj]
    return obj
