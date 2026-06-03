from __future__ import annotations

import copy
import re
from typing import Any, List

from .scanner import Finding, SECRET_PATTERNS, SENSITIVE_FILE_PATTERNS


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

# Finding types handled by the SECRET_PATTERNS regex sweep.
_REGEX_FINDING_TYPES: frozenset[str] = frozenset(
    pt for pt, _, _, _ in SECRET_PATTERNS
)


def _replacement(finding_type: str) -> str:
    label = REDACT_LABELS.get(finding_type, finding_type.upper())
    return f"[REDACTED_{label}]"


def redact_text(text: str, findings: List[Finding]) -> str:
    """
    Redact matched portions of *one specific string* using position offsets.

    This is a low-level helper for direct callers that already know every
    finding in the list was generated from ``text`` (i.e. the offsets are
    valid for this exact string).  Do **not** call this from recursive payload
    walkers where ``text`` could be any arbitrary field — use
    ``redact_string_in_payload`` instead.

    Works from the end of the string backwards so offsets stay valid.
    """
    if not findings or not text:
        return text

    text_findings = sorted(
        [f for f in findings if f.match_end > f.match_start and f.match_end <= len(text)],
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

    Each finding type is handled with a strategy that is safe to apply
    globally across all strings in the payload (no position-offset reuse):

    1. ``SECRET_PATTERNS`` regex sweep — self-contained patterns that match
       the same secret regardless of which field it appears in.
    2. ``SENSITIVE_FILE_PATTERNS`` regex sweep — same approach for file paths.
    3. ``matched_text_preview`` substring replacement — for non-regex finding
       types (prohibited_term, high_entropy_string) the scanner records the
       exact matched substring; we replace that literal text wherever it
       appears in any field.

    Position-based offsets (``match_start``/``match_end``) are intentionally
    **not** used here — those offsets are relative to the specific scanned
    string and would corrupt unrelated fields of the same or shorter length.
    """
    payload = copy.deepcopy(payload)
    return _redact_obj(payload, findings)


def _redact_obj(obj: Any, findings: List[Finding]) -> Any:
    if isinstance(obj, str):
        result = obj

        # Strategy 1: Regex sweep for all SECRET_PATTERNS-based finding types.
        # The patterns are self-contained and correct to apply to any string.
        for pattern_type, _, _, pattern in SECRET_PATTERNS:
            result = pattern.sub(_replacement(pattern_type), result)

        # Strategy 2: Regex sweep for sensitive file path references.
        # Applied when any sensitive_file_path finding is present.
        if any(f.finding_type == "sensitive_file_path" for f in findings):
            for fp_pattern in SENSITIVE_FILE_PATTERNS:
                result = fp_pattern.sub(
                    lambda _m: _replacement("sensitive_file_path"), result
                )

        # Strategy 3: Literal substring replacement for non-regex finding types
        # (prohibited_term, high_entropy_string).  The scanner stores the exact
        # matched text in ``matched_text_preview`` (in-memory only).  Replacing
        # that literal text is safe because it targets the actual sensitive
        # value, not a position offset.
        for f in findings:
            if f.finding_type in _REGEX_FINDING_TYPES:
                continue  # already covered by Strategy 1
            if f.finding_type == "sensitive_file_path":
                continue  # already covered by Strategy 2
            if f.matched_text_preview:
                result = result.replace(
                    f.matched_text_preview, _replacement(f.finding_type)
                )

        return result
    elif isinstance(obj, dict):
        return {k: _redact_obj(v, findings) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_redact_obj(item, findings) for item in obj]
    return obj
