"""Strict loader for the owner-approved W3-001 RAG policy."""

from __future__ import annotations

import importlib
import math
from pathlib import Path
from typing import Any, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from enterprise_ai_platform.rag.errors import RAGConfigurationError

APPROVED_RAG_POLICY: Final[dict[str, object]] = {
    "top_k": 5,
    "min_score": 0.50,
    "minimum_qualifying_chunks": 1,
    "max_context_characters": 12000,
    "max_output_tokens": 512,
    "prompt_version": "w3-001.v1",
}


_yaml: Any = importlib.import_module("yaml")
_UniqueKeyLoader: Any = type("_UniqueKeyLoader", (_yaml.SafeLoader,), {})


def _construct_unique_mapping(
    loader: Any,
    node: Any,
    deep: bool = False,
) -> dict[object, object]:
    result: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise RAGConfigurationError
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueKeyLoader.add_constructor(
    _yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


class RAGPolicy(BaseModel):
    """Frozen policy whose values are constrained to the approved W3 baseline."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    top_k: int = Field(ge=1, le=100)
    min_score: float = Field(ge=-1.0, le=1.0)
    minimum_qualifying_chunks: int = Field(ge=1, le=100)
    max_context_characters: int = Field(ge=1, le=100_000)
    max_output_tokens: int = Field(ge=1, le=8192)
    prompt_version: Literal["w3-001.v1"] = "w3-001.v1"

    @model_validator(mode="after")
    def require_approved_values(self) -> RAGPolicy:
        if self.model_dump(mode="python") != APPROVED_RAG_POLICY:
            raise ValueError("RAG policy differs from the approved W3-001 baseline")
        return self


def _require_strict_policy_types(raw: dict[object, object]) -> dict[str, object]:
    expected_types: dict[str, type[object]] = {
        "top_k": int,
        "min_score": float,
        "minimum_qualifying_chunks": int,
        "max_context_characters": int,
        "max_output_tokens": int,
        "prompt_version": str,
    }
    if set(raw) != set(expected_types) or not all(isinstance(key, str) for key in raw):
        raise RAGConfigurationError
    checked: dict[str, object] = {}
    for key, expected_type in expected_types.items():
        value = raw[key]
        if not isinstance(value, expected_type) or (
            expected_type is int and isinstance(value, bool)
        ):
            raise RAGConfigurationError
        if isinstance(value, float) and not math.isfinite(value):
            raise RAGConfigurationError
        checked[key] = value
    return checked


def load_rag_policy(path: Path) -> RAGPolicy:
    """Load an order-independent exact policy without accepting YAML coercions."""

    try:
        raw: Any = _yaml.load(
            path.read_text(encoding="utf-8"),
            Loader=_UniqueKeyLoader,
        )
    except RAGConfigurationError:
        raise
    except Exception:
        raise RAGConfigurationError from None
    if not isinstance(raw, dict):
        raise RAGConfigurationError
    checked = _require_strict_policy_types(raw)
    if checked != APPROVED_RAG_POLICY:
        raise RAGConfigurationError
    try:
        return RAGPolicy.model_validate(checked, strict=True)
    except ValidationError:
        raise RAGConfigurationError from None
