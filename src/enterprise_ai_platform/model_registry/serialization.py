"""Canonical JSON and immutable identities for W9-003 registry records."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from decimal import Decimal
from enum import Enum
from typing import cast

from pydantic import BaseModel

from enterprise_ai_platform.json_contracts import JSONValue

from .errors import RegistryValidationError


def _json_value(value: object) -> JSONValue:
    if isinstance(value, BaseModel):
        return cast(JSONValue, value.model_dump(mode="json"))
    if isinstance(value, Enum):
        return cast(JSONValue, value.value)
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise RegistryValidationError("non-finite decimal is forbidden")
        return cast(JSONValue, format(value, "f"))
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
            raise RegistryValidationError("timestamps must use UTC")
        return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
    if value is None or isinstance(value, str | bool | int | float):
        return cast(JSONValue, value)
    if isinstance(value, tuple | list):
        return [_json_value(item) for item in value]
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise RegistryValidationError("canonical objects require string keys")
        return {key: _json_value(item) for key, item in value.items()}
    raise RegistryValidationError("unsupported canonical value")


def canonical_bytes(value: object) -> bytes:
    """Return sorted compact UTF-8 JSON with exactly one final newline."""

    try:
        encoded = json.dumps(
            _json_value(value),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        raise RegistryValidationError("value is not canonically serializable") from None
    return encoded + b"\n"


def fingerprint(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()
