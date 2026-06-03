from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class ScanUnit:
    path: str
    content: str
    source_file: Optional[str] = None


def normalize_openai_responses(payload: Dict[str, Any]) -> List[ScanUnit]:
    """Normalize OpenAI Responses API payload (input field)."""
    units: List[ScanUnit] = []
    inp = payload.get("input")
    if isinstance(inp, str):
        units.append(ScanUnit(path="input", content=inp))
    elif isinstance(inp, list):
        for i, item in enumerate(inp):
            units.extend(_walk(item, f"input[{i}]"))
    instructions = payload.get("instructions") or payload.get("system")
    if isinstance(instructions, str):
        units.append(ScanUnit(path="instructions", content=instructions))
    return units


def normalize_openai_chat(payload: Dict[str, Any]) -> List[ScanUnit]:
    """Normalize OpenAI Chat Completions payload (messages list)."""
    units: List[ScanUnit] = []
    messages = payload.get("messages", [])
    for i, msg in enumerate(messages):
        content = msg.get("content", "")
        if isinstance(content, str):
            units.append(ScanUnit(path=f"messages[{i}].content", content=content))
        elif isinstance(content, list):
            for j, part in enumerate(content):
                units.extend(_walk(part, f"messages[{i}].content[{j}]"))
    system = payload.get("system")
    if system:
        units.extend(_walk(system, "system"))
    return units


def normalize_anthropic_messages(payload: Dict[str, Any]) -> List[ScanUnit]:
    """Normalize Anthropic Messages API payload."""
    units: List[ScanUnit] = []
    system = payload.get("system")
    if isinstance(system, str):
        units.append(ScanUnit(path="system", content=system))
    elif isinstance(system, list):
        for i, block in enumerate(system):
            units.extend(_walk(block, f"system[{i}]"))
    for i, msg in enumerate(payload.get("messages", [])):
        content = msg.get("content", "")
        if isinstance(content, str):
            units.append(ScanUnit(path=f"messages[{i}].content", content=content))
        elif isinstance(content, list):
            for j, block in enumerate(content):
                units.extend(_walk(block, f"messages[{i}].content[{j}]"))
    return units


def normalize_generic(payload: Any) -> List[ScanUnit]:
    """Normalize any arbitrary payload by walking it recursively."""
    return _walk(payload, "payload")


def _walk(obj: Any, path: str) -> List[ScanUnit]:
    units: List[ScanUnit] = []
    if isinstance(obj, str):
        if obj.strip():
            units.append(ScanUnit(path=path, content=obj))
    elif isinstance(obj, dict):
        for k, v in obj.items():
            units.extend(_walk(v, f"{path}.{k}"))
    elif isinstance(obj, (list, tuple)):
        for i, item in enumerate(obj):
            units.extend(_walk(item, f"{path}[{i}]"))
    return units


def normalize_payload(
    payload: Any,
    provider: str = "generic",
    operation: str = "",
) -> List[ScanUnit]:
    """
    Top-level normalizer: pick the right strategy based on provider + operation,
    then fall back to generic recursive walk.
    """
    if not isinstance(payload, dict):
        return normalize_generic(payload)

    if provider == "openai":
        if "responses" in operation or operation == "responses.create":
            return normalize_openai_responses(payload)
        if "chat" in operation or "completions" in operation:
            return normalize_openai_chat(payload)
        return normalize_openai_chat(payload) or normalize_openai_responses(payload)

    if provider == "anthropic":
        return normalize_anthropic_messages(payload)

    return normalize_generic(payload)
