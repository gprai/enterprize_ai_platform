"""Canonical JSON identities for W9-004 evidence."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from enum import Enum
from typing import cast

from pydantic import BaseModel

from enterprise_ai_platform.json_contracts import JSONValue

from .errors import SupplyChainValidationError


def _json_value(value: object) -> JSONValue:
    if isinstance(value, BaseModel):
        return _json_value(value.model_dump(mode="python"))
    if isinstance(value, Enum):
        return cast(JSONValue, value.value)
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
            raise SupplyChainValidationError("timestamps must use UTC")
        return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
    if value is None or isinstance(value, str | bool | int | float):
        return cast(JSONValue, value)
    if isinstance(value, tuple | list):
        return [_json_value(item) for item in value]
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise SupplyChainValidationError("canonical objects require string keys")
        return {key: _json_value(item) for key, item in value.items()}
    raise SupplyChainValidationError("unsupported canonical value")


def canonical_bytes(value: object) -> bytes:
    try:
        encoded = json.dumps(
            _json_value(value),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        raise SupplyChainValidationError("value is not canonically serializable") from None
    return encoded + b"\n"


def fingerprint(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()
