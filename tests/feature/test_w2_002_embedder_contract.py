from __future__ import annotations

import asyncio
import json
from copy import deepcopy
from pathlib import Path

from tools.platformctl.validate import (
    EXPECTED_EVAL_IMPLEMENTATION_PATHS,
    validate_feature_matrix,
)

from enterprise_ai_platform.embeddings.base import (
    EmbeddingContract,
    assert_embedding_contract,
)
from enterprise_ai_platform.embeddings.fake import FakeEmbeddingProvider

ROOT = Path(__file__).resolve().parents[2]
EXPECTED_RAG_IMPLEMENTATION_PATHS = (
    "src/enterprise_ai_platform/embeddings/__init__.py",
    "src/enterprise_ai_platform/embeddings/base.py",
    "src/enterprise_ai_platform/embeddings/errors.py",
    "src/enterprise_ai_platform/embeddings/fake.py",
    "src/enterprise_ai_platform/embeddings/sentence_transformer.py",
    "tests/unit/test_embedder.py",
    "tests/contract/test_embedder.py",
    "tests/integration/test_sentence_transformer_embedder.py",
    "tests/feature/test_w2_002_embedder_contract.py",
    "tests/security/test_embedder_security.py",
    "tests/teardown/test_w2_002_embedder_cleanliness.py",
)
EXPECTED_RAG_TRACKER_STEPS = (
    "W2-03",
    "W2-01",
    "W2-02",
    "W2-04",
    "W2-08",
    "W2-05",
)


def test_rag_feature_matrix_preserves_structured_w2_002_ownership() -> None:
    matrix = json.loads((ROOT / "feature-matrix.yaml").read_text(encoding="utf-8"))
    features = matrix["features"]

    assert [feature["id"] for feature in features] == [
        "MVP-001",
        "RAG-001",
        "EVAL-001",
        "API-001",
        "AGENT-001",
    ]
    assert "W2-05" not in features[0]["linked_tracker_steps"]
    rag_steps = features[1]["linked_tracker_steps"]
    rag_paths = features[1]["implementation_paths"]
    assert rag_steps[: len(EXPECTED_RAG_TRACKER_STEPS)] == list(
        EXPECTED_RAG_TRACKER_STEPS
    )
    path_positions = [rag_paths.index(path) for path in EXPECTED_RAG_IMPLEMENTATION_PATHS]
    assert path_positions == sorted(path_positions)
    eval_paths = features[2]["implementation_paths"]
    assert eval_paths == list(EXPECTED_EVAL_IMPLEMENTATION_PATHS)
    assert len(eval_paths) == len(set(eval_paths)) == 33
    assert eval_paths[25] == "tools/evaluationctl.py"

    unapproved = deepcopy(matrix)
    unapproved["features"].append(
        {
            "id": "W2-05",
            "status": "Not Started",
            "implementation_paths": list(EXPECTED_RAG_IMPLEMENTATION_PATHS),
            "linked_tracker_steps": ["W2-05"],
        }
    )
    assert validate_feature_matrix(unapproved)


def test_w2_002_feature_uses_fake_without_model_or_network_access() -> None:
    provider = FakeEmbeddingProvider()
    contract = EmbeddingContract(
        model_id=provider.model_id,
        model_revision=provider.model_revision,
        dimension=provider.dimension,
        normalized=provider.normalized,
        metric="cosine",
    )

    assert_embedding_contract(provider, contract)
    assert len(asyncio.run(provider.embed_query("feature query"))) == 384
