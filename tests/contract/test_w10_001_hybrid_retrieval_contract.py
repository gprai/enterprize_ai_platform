"""Contract tests for provider-neutral W10-001 hybrid retrieval."""

from __future__ import annotations

import pytest

import enterprise_ai_platform.retrieval as retrieval
from enterprise_ai_platform.retrieval.adapters.opensearch import OpenSearchVectorStore
from enterprise_ai_platform.retrieval.errors import VectorStoreValidationError
from enterprise_ai_platform.retrieval.hybrid import (
    APPROVED_HYBRID_POLICY,
    IN_MEMORY_CAPABILITIES,
    OPENSEARCH_CAPABILITIES,
    QDRANT_CAPABILITIES,
    HybridRetrievalPolicy,
    RetrievalMode,
    build_retrieval_identity,
)
from enterprise_ai_platform.retrieval.models import CollectionSpec, Query, RetrievedChunk


def test_public_contract_exports_typed_hybrid_policy_and_identity() -> None:
    assert retrieval.RetrievalMode is RetrievalMode
    assert retrieval.APPROVED_HYBRID_POLICY is APPROVED_HYBRID_POLICY
    assert retrieval.HybridRetrievalPolicy.__name__ == "HybridRetrievalPolicy"
    assert retrieval.RetrievalIdentity.__name__ == "RetrievalIdentity"
    assert retrieval.BackendCapabilities.__name__ == "BackendCapabilities"


def test_backend_capabilities_are_explicit_without_silent_fallback() -> None:
    assert OPENSEARCH_CAPABILITIES.retrieval_modes == frozenset(
        {RetrievalMode.VECTOR, RetrievalMode.HYBRID}
    )
    assert QDRANT_CAPABILITIES.retrieval_modes == frozenset({RetrievalMode.VECTOR})
    assert IN_MEMORY_CAPABILITIES.retrieval_modes == frozenset({RetrievalMode.VECTOR})

    with pytest.raises(VectorStoreValidationError):
        QDRANT_CAPABILITIES.require(RetrievalMode.HYBRID)
    with pytest.raises(VectorStoreValidationError):
        IN_MEMORY_CAPABILITIES.require(RetrievalMode.HYBRID)
    with pytest.raises(VectorStoreValidationError):
        OpenSearchVectorStore(object(), retrieval_mode="hybrid")  # type: ignore[arg-type]
    with pytest.raises(VectorStoreValidationError):
        OpenSearchVectorStore(
            object(),
            hybrid_policy=HybridRetrievalPolicy(
                vector_weight=0.25,
                lexical_weight=0.75,
            ),
        )


def test_retrieval_identity_binds_collection_embedding_mode_analyzer_and_policy() -> None:
    collection = CollectionSpec(name="enterprise_ai_sandbox")

    vector_identity = build_retrieval_identity(collection, RetrievalMode.VECTOR)
    hybrid_identity = build_retrieval_identity(collection, RetrievalMode.HYBRID)

    assert vector_identity.collection == hybrid_identity.collection == collection
    assert vector_identity.lexical_analyzer is None
    assert hybrid_identity.lexical_analyzer == "standard"
    assert vector_identity.policy_sha256 == hybrid_identity.policy_sha256
    assert vector_identity != hybrid_identity


def test_existing_query_and_result_schemas_gain_no_vendor_or_channel_fields() -> None:
    assert tuple(Query.model_fields) == ("text", "top_k", "min_score")
    assert tuple(RetrievedChunk.model_fields)[-1] == "score"
    assert not {
        "opensearch",
        "vector_score",
        "lexical_score",
        "vendor_object",
    }.intersection(RetrievedChunk.model_fields)
