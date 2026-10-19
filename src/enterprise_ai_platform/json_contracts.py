"""Small, strict JSON boundaries shared by provider and RAG contracts."""

from __future__ import annotations

import json
import math
from typing import cast

from pydantic import JsonValue as _PydanticJSONValue

type JSONScalar = str | int | float | bool | None
type JSONValue = _PydanticJSONValue
type JSONObject = dict[str, JSONValue]


class DuplicateJSONKeyError(ValueError):
    """Raised when untrusted JSON repeats an object key."""


def unwrap_single_json_fence(value: str) -> str:
    """Remove one exact JSON Markdown fence and reject ambiguous envelopes."""

    stripped = value.strip()
    if not stripped.startswith("```"):
        return value
    lines = stripped.splitlines()
    if len(lines) < 3 or lines[0] != "```json" or lines[-1] != "```":
        raise ValueError("JSON fence is malformed or ambiguous")
    payload = "\n".join(lines[1:-1])
    if not payload.strip() or "```" in payload:
        raise ValueError("JSON fence is empty or nested")
    return payload


def _reject_duplicate_keys(pairs: list[tuple[str, JSONValue]]) -> JSONObject:
    result: JSONObject = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJSONKeyError("JSON object contains a duplicate key")
        result[key] = value
    return result


def _reject_non_finite_constant(_value: str) -> JSONValue:
    raise ValueError("JSON numbers must be finite")


def _validate_json_value(value: object) -> None:
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("JSON numbers must be finite")
        return
    if isinstance(value, list):
        for item in value:
            _validate_json_value(item)
        return
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise TypeError("JSON object keys must be strings")
        for item in value.values():
            _validate_json_value(item)
        return
    raise TypeError("value is not JSON-compatible")


def strict_json_loads(value: str) -> JSONValue:
    """Parse standards-compliant JSON while rejecting duplicate object keys."""

    parsed = json.loads(
        value,
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_non_finite_constant,
    )
    _validate_json_value(parsed)
    return cast(JSONValue, parsed)


def defensive_json_copy(value: JSONValue) -> JSONValue:
    """Return a detached JSON-only copy and reject non-JSON or non-finite data."""

    _validate_json_value(value)
    serialized = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return strict_json_loads(serialized)
