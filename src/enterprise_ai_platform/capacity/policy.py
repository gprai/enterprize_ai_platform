"""Strict duplicate-safe loader for the W8-004 capacity policy."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import yaml  # type: ignore[import-untyped]
from pydantic import ValidationError

from .errors import CapacityValidationError
from .models import CapacityPolicy
from .serialization import fingerprint

DEFAULT_POLICY_PATH = Path("configs/capacity/inference-capacity-cost-policy.yaml")


class _UniqueKeyLoader(yaml.SafeLoader):  # type: ignore[misc]
    pass


def _construct_unique_mapping(
    loader: _UniqueKeyLoader, node: Any, deep: bool = False
) -> dict[object, object]:
    result: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise CapacityValidationError(f"duplicate YAML key: {key!r}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def load_capacity_policy(path: Path = DEFAULT_POLICY_PATH) -> CapacityPolicy:
    try:
        payload = path.read_bytes()
        if not payload or len(payload) > 65_536 or payload.startswith((b"\xff\xfe", b"\xfe\xff")):
            raise CapacityValidationError("capacity policy encoding or size is invalid")
        text = payload.decode("utf-8", errors="strict")
        if "&" in text or "*" in text:
            raise CapacityValidationError("YAML aliases are not permitted")
        loader = _UniqueKeyLoader(text)
        try:
            raw = loader.get_single_data()
        finally:
            loader.dispose()
        if not isinstance(raw, dict):
            raise CapacityValidationError("capacity policy must be a mapping")
        return CapacityPolicy.model_validate(cast(dict[str, object], raw), strict=False)
    except CapacityValidationError:
        raise
    except (OSError, UnicodeError, yaml.YAMLError, ValidationError, ValueError) as error:
        raise CapacityValidationError("invalid capacity policy") from error


def policy_identity(policy: CapacityPolicy) -> str:
    return fingerprint(policy)
