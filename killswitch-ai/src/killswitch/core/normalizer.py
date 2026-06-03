from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set


@dataclass
class ScanUnit:
    path: str
    content: str
    source_file: Optional[str] = None


def normalize_openai_responses(payload: Dict[str, Any]) -> List[ScanUnit]:
    """
    Normalize OpenAI Responses API payload.

    Scans provider-known fields first (``input``, ``instructions``), then
    performs a full recursive walk of the entire payload so that tool args,
    metadata, and any custom nested fields are also inspected.
    """
    units: List[ScanUnit] = []
    covered: Set[str] = set()

    inp = payload.get("input")
    if isinstance(inp, str):
        units.append(ScanUnit(path="input", content=inp))
        covered.add("input")
    elif isinstance(inp, list):
        for i, item in enumerate(inp):
            for u in _walk(item, f"input[{i}]"):
                units.append(u)
                covered.add(u.path)

    instructions = payload.get("instructions") or payload.get("system")
    if isinstance(instructions, str):
        path = "instructions"
        units.append(ScanUnit(path=path, content=instructions))
        covered.add(path)

    # Full recursive walk to catch tool arguments, metadata, and any other
    # string fields not covered by the provider-specific extraction above.
    for u in _walk(payload, "payload"):
        if u.path not in covered:
            units.append(u)

    return units


def normalize_openai_chat(payload: Dict[str, Any]) -> List[ScanUnit]:
    """
    Normalize OpenAI Chat Completions payload.

    Scans ``messages[*].content`` and ``system`` explicitly, then does a
    full recursive walk for tool calls, function arguments, and other fields.
    """
    units: List[ScanUnit] = []
    covered: Set[str] = set()

    messages = payload.get("messages", [])
    for i, msg in enumerate(messages):
        content = msg.get("content", "")
        if isinstance(content, str):
            path = f"messages[{i}].content"
            units.append(ScanUnit(path=path, content=content))
            covered.add(path)
        elif isinstance(content, list):
            for j, part in enumerate(content):
                for u in _walk(part, f"messages[{i}].content[{j}]"):
                    units.append(u)
                    covered.add(u.path)

    system = payload.get("system")
    if system:
        for u in _walk(system, "system"):
            units.append(u)
            covered.add(u.path)

    # Full recursive walk for tool calls, function args, metadata, etc.
    for u in _walk(payload, "payload"):
        if u.path not in covered:
            units.append(u)

    return units


def normalize_anthropic_messages(payload: Dict[str, Any]) -> List[ScanUnit]:
    """
    Normalize Anthropic Messages API payload.

    Scans ``system`` and ``messages[*].content`` explicitly, then does a
    full recursive walk for tool inputs and any other nested fields.
    """
    units: List[ScanUnit] = []
    covered: Set[str] = set()

    system = payload.get("system")
    if isinstance(system, str):
        units.append(ScanUnit(path="system", content=system))
        covered.add("system")
    elif isinstance(system, list):
        for i, block in enumerate(system):
            for u in _walk(block, f"system[{i}]"):
                units.append(u)
                covered.add(u.path)

    for i, msg in enumerate(payload.get("messages", [])):
        content = msg.get("content", "")
        if isinstance(content, str):
            path = f"messages[{i}].content"
            units.append(ScanUnit(path=path, content=content))
            covered.add(path)
        elif isinstance(content, list):
            for j, block in enumerate(content):
                for u in _walk(block, f"messages[{i}].content[{j}]"):
                    units.append(u)
                    covered.add(u.path)

    # Full recursive walk to catch tool_use inputs, metadata, etc.
    for u in _walk(payload, "payload"):
        if u.path not in covered:
            units.append(u)

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
