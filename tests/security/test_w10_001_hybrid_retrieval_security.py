"""Fail-closed authorization and provider-boundary tests for W10-001."""

from __future__ import annotations

import asyncio

import pytest

from enterprise_ai_platform.retrieval.adapters.opensearch import OpenSearchVectorStore
from enterprise_ai_platform.retrieval.errors import (
    VectorStoreAuthorizationError,
    VectorStoreTimeoutError,
    VectorStoreUnavailableError,
    VectorStoreValidationError,
)
from enterprise_ai_platform.retrieval.hybrid import RetrievalMode
from enterprise_ai_platform.retrieval.models import CollectionSpec, Query
from tests.fakes.w10_001_hybrid_retrieval import (
    FakeHybridOpenSearchClient,
    approved_vector,
    make_chunk,
    make_hit,
    reader_auth,
)


def test_cross_tenant_provider_result_aborts_the_complete_hybrid_request() -> None:
    async def scenario() -> None:
        authorized = make_chunk(0)
        cross_tenant = make_chunk(1, tenant_id="tenant-b")
        client = FakeHybridOpenSearchClient(
            vector_hits=[make_hit(authorized, 1.0)],
            lexical_hits=[make_hit(cross_tenant, 1.0)],
        )
        store = OpenSearchVectorStore(client, retrieval_mode=RetrievalMode.HYBRID)
        specification = CollectionSpec(name="enterprise_ai_sandbox")
        await store.create_or_validate_collection(specification)

        with pytest.raises(VectorStoreAuthorizationError):
            await store.search(
                specification,
                Query(text="private synthetic query"),
                approved_vector(),
                reader_auth(groups=frozenset({"synthetic-group"})),
            )

        filters = [call["body"]["query"]["bool"]["filter"] for call in client.search_calls]
        assert len(filters) == 2
        assert filters[0] == filters[1]
        assert {"term": {"tenant_id": "tenant-a"}} in filters[0]
        assert {"terms": {"classification": ["PUBLIC", "INTERNAL", "CONFIDENTIAL"]}} in filters[0]
        acl_filter = filters[0][3]["bool"]["should"]
        assert {"terms": {"allowed_roles": ["reader"]}} in acl_filter
        assert {"terms": {"allowed_groups": ["synthetic-group"]}} in acl_filter

    asyncio.run(scenario())


def test_malformed_or_mismatched_vendor_hit_fails_closed() -> None:
    async def scenario() -> None:
        source = make_chunk(0)
        malformed = make_hit(source, 1.0)
        malformed["_id"] = "0" * 64
        client = FakeHybridOpenSearchClient(
            vector_hits=[make_hit(source, 1.0)],
            lexical_hits=[malformed],
        )
        store = OpenSearchVectorStore(client, retrieval_mode=RetrievalMode.HYBRID)
        specification = CollectionSpec(name="enterprise_ai_sandbox")
        await store.create_or_validate_collection(specification)

        with pytest.raises(VectorStoreValidationError):
            await store.search(
                specification,
                Query(text="synthetic"),
                approved_vector(),
                reader_auth(),
            )

    asyncio.run(scenario())


def test_channel_failure_never_returns_partial_results_or_sensitive_error_text() -> None:
    async def scenario() -> None:
        source = make_chunk(0)
        client = FakeHybridOpenSearchClient(
            vector_hits=[make_hit(source, 1.0)],
            lexical_hits=[make_hit(source, 1.0)],
        )
        client.failures_remaining["lexical"] = 2

        async def no_wait(_delay: float) -> None:
            return None

        store = OpenSearchVectorStore(
            client,
            retrieval_mode=RetrievalMode.HYBRID,
            retry_delay=lambda: 0.1,
            sleep=no_wait,
        )
        specification = CollectionSpec(name="enterprise_ai_sandbox")
        await store.create_or_validate_collection(specification)
        sensitive_query = "synthetic-private-query-value"

        with pytest.raises(VectorStoreUnavailableError) as captured:
            await store.search(
                specification,
                Query(text=sensitive_query),
                approved_vector(),
                reader_auth(),
            )

        assert sensitive_query not in str(captured.value)
        assert len(client.search_calls) <= 4
        assert client.active_searches == 0

    asyncio.run(scenario())


def test_overall_deadline_cancels_and_awaits_both_channels() -> None:
    async def scenario() -> None:
        client = FakeHybridOpenSearchClient()
        client.blocked_channels = {"vector", "lexical"}
        store = OpenSearchVectorStore(
            client,
            retrieval_mode=RetrievalMode.HYBRID,
            max_attempts=1,
        )
        specification = CollectionSpec(name="enterprise_ai_sandbox")
        await store.create_or_validate_collection(specification)

        with pytest.raises(VectorStoreTimeoutError):
            await store.search(
                specification,
                Query(text="synthetic"),
                approved_vector(),
                reader_auth(),
                timeout_seconds=0.01,
            )

        assert client.active_searches == 0

    asyncio.run(scenario())
