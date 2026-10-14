"""Canonical serialization and identities for W9-001 training records."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from decimal import Decimal
from enum import Enum
from typing import cast

from pydantic import BaseModel

from enterprise_ai_platform.json_contracts import JSONValue

from .errors import TrainingValidationError


def _json_value(value: object) -> JSONValue:
    if isinstance(value, BaseModel):
        return cast(JSONValue, value.model_dump(mode="json"))
    if isinstance(value, Enum):
        return cast(JSONValue, value.value)
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise TrainingValidationError("non-finite decimal is forbidden")
        return cast(JSONValue, format(value, "f"))
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
            raise TrainingValidationError("timestamps must be UTC")
        return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
    if value is None or isinstance(value, str | bool | int | float):
        return cast(JSONValue, value)
    if isinstance(value, tuple | list):
        return [_json_value(item) for item in value]
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise TrainingValidationError("canonical objects require string keys")
        return {key: _json_value(item) for key, item in value.items()}
    raise TrainingValidationError("unsupported canonical value")


def canonical_json(value: object) -> str:
    return json.dumps(
        _json_value(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def fingerprint(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()
