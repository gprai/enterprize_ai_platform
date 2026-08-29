"""Canonical, bounded serialization for redacted W4-002 control records."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from enum import Enum
from typing import TypeVar, cast

from pydantic import BaseModel, ValidationError

from enterprise_ai_platform.json_contracts import (
    DuplicateJSONKeyError,
    JSONValue,
    strict_json_loads,
)

from .errors import AgentStateValidationError

ModelT = TypeVar("ModelT", bound=BaseModel)


def _json_value(value: object) -> JSONValue:
    if isinstance(value, BaseModel):
        return cast(JSONValue, value.model_dump(mode="json"))
    if isinstance(value, Enum):
        return cast(JSONValue, value.value)
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise AgentStateValidationError
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
    if value is None or isinstance(value, (str, bool, int, float)):
        return cast(JSONValue, value)
    if isinstance(value, tuple | list):
        return [_json_value(item) for item in value]
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise AgentStateValidationError
        return {str(key): _json_value(item) for key, item in value.items()}
    raise AgentStateValidationError


def canonical_bytes(value: object) -> bytes:
    """Return canonical UTF-8 JSON with exactly one trailing newline."""

    try:
        encoded = json.dumps(
            _json_value(value),
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        raise AgentStateValidationError from None
    return encoded + b"\n"


def fingerprint(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def hash_identifier(value: str) -> str:
    """Create a pseudonymous reference without retaining the identifier."""

    if not value or len(value) > 500:
        raise AgentStateValidationError
    return hashlib.sha256(value.encode("utf-8", errors="strict")).hexdigest()


def load_canonical_model(
    model_type: type[ModelT],
    payload: bytes,
    *,
    maximum_bytes: int,
) -> ModelT:
    """Reject malformed input before strict model and canonical-form validation."""

    if not payload or len(payload) > maximum_bytes or not payload.endswith(b"\n"):
        raise AgentStateValidationError
    if payload.endswith(b"\n\n"):
        raise AgentStateValidationError
    try:
        text = payload.decode("utf-8")
        raw = strict_json_loads(text)
        reparsed = json.dumps(
            raw,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        model = model_type.model_validate_json(reparsed, strict=True)
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        DuplicateJSONKeyError,
        ValidationError,
        TypeError,
        ValueError,
    ):
        raise AgentStateValidationError from None
    if canonical_bytes(model) != payload:
        raise AgentStateValidationError
    return model
