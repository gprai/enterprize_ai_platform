"""Canonical bounded serialization for orchestration records."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from enum import Enum
from typing import cast
from uuid import UUID

from pydantic import BaseModel, ValidationError

from enterprise_ai_platform.json_contracts import (
    DuplicateJSONKeyError,
    JSONValue,
    strict_json_loads,
)

from .errors import OrchestrationValidationError


def _json_value(value: object) -> JSONValue:
    if isinstance(value, BaseModel):
        return cast(JSONValue, value.model_dump(mode="json", by_alias=True))
    if isinstance(value, Enum):
        return cast(JSONValue, value.value)
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise OrchestrationValidationError
        return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
    if isinstance(value, UUID):
        return str(value)
    if value is None or isinstance(value, (str, bool, int, float)):
        return cast(JSONValue, value)
    if isinstance(value, tuple | list):
        return [_json_value(item) for item in value]
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise OrchestrationValidationError
        return {str(key): _json_value(item) for key, item in value.items()}
    raise OrchestrationValidationError


def canonical_bytes(value: object) -> bytes:
    """Return compact, sorted UTF-8 JSON with exactly one trailing newline."""

    try:
        payload = json.dumps(
            _json_value(value),
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        raise OrchestrationValidationError from None
    return payload + b"\n"


def fingerprint(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def load_canonical_model[ModelT: BaseModel](
    model_type: type[ModelT], payload: bytes, *, maximum_bytes: int = 65_536
) -> ModelT:
    """Reject malformed, oversized, duplicate-key, or noncanonical persisted state."""

    if (
        not payload
        or len(payload) > maximum_bytes
        or not payload.endswith(b"\n")
        or payload.endswith(b"\n\n")
    ):
        raise OrchestrationValidationError
    try:
        strict_json_loads(payload.decode("utf-8", errors="strict"))
        model = model_type.model_validate_json(payload, strict=True)
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        DuplicateJSONKeyError,
        ValidationError,
        TypeError,
        ValueError,
    ):
        raise OrchestrationValidationError from None
    if canonical_bytes(model) != payload:
        raise OrchestrationValidationError
    return model
