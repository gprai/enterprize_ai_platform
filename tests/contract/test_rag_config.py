"""Contract tests for exact, strict, order-independent RAG policy loading."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from enterprise_ai_platform.rag.config import RAGPolicy, load_rag_policy
from enterprise_ai_platform.rag.errors import RAGConfigurationError


def _write_policy(path: Path, content: str) -> Path:
    path.write_text(content, encoding="utf-8")
    return path


def test_reordered_exact_policy_is_valid(tmp_path: Path) -> None:
    policy_path = _write_policy(
        tmp_path / "rag.yaml",
        """{
          "prompt_version": "w3-001.v1",
          "max_output_tokens": 512,
          "max_context_characters": 12000,
          "minimum_qualifying_chunks": 1,
          "min_score": 0.50,
          "top_k": 5
        }""",
    )

    policy = load_rag_policy(policy_path)

    assert policy.top_k == 5
    assert policy.min_score == 0.50
    with pytest.raises(ValidationError):
        policy.top_k = 6


@pytest.mark.parametrize(
    "content",
    [
        '{"top_k":5,"top_k":5,"min_score":0.5,"minimum_qualifying_chunks":1,'
        '"max_context_characters":12000,"max_output_tokens":512,'
        '"prompt_version":"w3-001.v1"}',
        '{"top_k":true,"min_score":0.5,"minimum_qualifying_chunks":1,'
        '"max_context_characters":12000,"max_output_tokens":512,'
        '"prompt_version":"w3-001.v1"}',
        '{"top_k":"5","min_score":0.5,"minimum_qualifying_chunks":1,'
        '"max_context_characters":12000,"max_output_tokens":512,'
        '"prompt_version":"w3-001.v1"}',
        '{"top_k":5,"min_score":.nan,"minimum_qualifying_chunks":1,'
        '"max_context_characters":12000,"max_output_tokens":512,'
        '"prompt_version":"w3-001.v1"}',
        '{"top_k":5,"min_score":0.45,"minimum_qualifying_chunks":1,'
        '"max_context_characters":12000,"max_output_tokens":512,'
        '"prompt_version":"w3-001.v1"}',
        '{"top_k":5,"min_score":0.5,"minimum_qualifying_chunks":0,'
        '"max_context_characters":12000,"max_output_tokens":512,'
        '"prompt_version":"w3-001.v1"}',
        '{"top_k":5,"min_score":0.5,"minimum_qualifying_chunks":1,'
        '"max_context_characters":12000,"max_output_tokens":513,'
        '"prompt_version":"w3-001.v1"}',
        '{"top_k":5,"min_score":0.5,"minimum_qualifying_chunks":1,'
        '"max_context_characters":12000,"max_output_tokens":512,'
        '"prompt_version":"w3-001.v2"}',
        '{"top_k":5,"min_score":0.5,"minimum_qualifying_chunks":1,'
        '"max_context_characters":12000,"max_output_tokens":512,'
        '"prompt_version":"w3-001.v1","unknown":1}',
    ],
)
def test_non_exact_policy_is_rejected(tmp_path: Path, content: str) -> None:
    with pytest.raises(RAGConfigurationError):
        load_rag_policy(_write_policy(tmp_path / "rag.yaml", content))


def test_policy_schema_is_frozen_and_forbids_unknown_fields() -> None:
    schema = RAGPolicy.model_json_schema()

    assert schema["additionalProperties"] is False
    with pytest.raises(ValidationError):
        RAGPolicy(
            top_k=6,
            min_score=0.50,
            minimum_qualifying_chunks=1,
            max_context_characters=12000,
            max_output_tokens=512,
            prompt_version="w3-001.v1",
        )
