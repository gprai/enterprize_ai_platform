"""Security tests for the W2-004 service authorization boundary."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from enterprise_ai_platform.embeddings.fake import FakeEmbeddingProvider
from enterprise_ai_platform.retrieval.adapters.fake import InMemoryVectorStore
from enterprise_ai_platform.retrieval.errors import VectorStoreAuthorizationError
from enterprise_ai_platform.retrieval.models import (
    AuthContext,
    Chunk,
    Classification,
    CollectionSpec,
    IngestionStatus,
    PiiStatus,
    Query,
    Role,
    deterministic_chunk_id,
)
from enterprise_ai_platform.retrieval.service import RetrievalService

EMPTY_GROUPS: frozenset[str] = frozenset()
READER_ROLES: frozenset[Role] = frozenset({Role.READER})


def auth(
    tenant_id: str,
    role: Role,
    *,
    clearance: Classification = Classification.INTERNAL,
    groups: frozenset[str] = EMPTY_GROUPS,
    expires_at: datetime | None = None,
) -> AuthContext:
    return AuthContext(
        subject_id=f"w2-004-{tenant_id}-{role.value}",
        tenant_id=tenant_id,
        roles=frozenset({role}),
        clearance=clearance,
        groups=groups,
        expires_at=expires_at,
    )


def chunk(
    vector: tuple[float, ...],
    *,
    roles: frozenset[Role] = READER_ROLES,
    groups: frozenset[str] = EMPTY_GROUPS,
) -> Chunk:
    content_hash = "c" * 64
    document_id = "w2-004-security-document"
    return Chunk(
        tenant_id="tenant-a",
        source_id="DOC-W2-004-SECURITY",
        media_type="text/plain",
        document_id=document_id,
        document_version="v1",
        classification=Classification.INTERNAL,
        allowed_roles=roles,
        allowed_groups=groups,
        data_owner="security-team",
        content_hash=content_hash,
        pii_status=PiiStatus.CLEAR,
        ingestion_status=IngestionStatus.INDEXED,
        chunk_id=deterministic_chunk_id(
            tenant_id="tenant-a",
            document_id=document_id,
            document_version="v1",
            content_hash=content_hash,
            chunk_index=0,
        ),
        chunk_index=0,
        text="Synthetic access-control fixture",
        embedding=vector,
    )


def test_tenant_clearance_role_and_group_fail_closed() -> None:
    async def scenario() -> None:
        embedder = FakeEmbeddingProvider()
        store = InMemoryVectorStore()
        specification = CollectionSpec(name="w2_004_security")
        query = Query(text="approved security query")
        await store.create_or_validate_collection(specification)
        await store.upsert_chunks(
            specification,
            (
                chunk(
                    await embedder.embed_query(query.text),
                    roles=frozenset(),
                    groups=frozenset({"approved-group"}),
                ),
            ),
            auth("tenant-a", Role.INGESTOR, clearance=Classification.RESTRICTED),
        )
        service = RetrievalService(
            embedder=embedder,
            vector_store=store,
            collection_spec=specification,
        )

        allowed = await service.retrieve(
            query,
            auth(
                "tenant-a",
                Role.REVIEWER,
                groups=frozenset({"approved-group"}),
            ),
        )
        assert len(allowed) == 1
        for denied in (
            auth("tenant-b", Role.REVIEWER, groups=frozenset({"approved-group"})),
            auth(
                "tenant-a",
                Role.REVIEWER,
                clearance=Classification.PUBLIC,
                groups=frozenset({"approved-group"}),
            ),
            auth("tenant-a", Role.READER),
            auth("tenant-a", Role.REVIEWER, groups=frozenset({"wrong-group"})),
        ):
            assert await service.retrieve(query, denied) == ()

    asyncio.run(scenario())


def test_expired_context_and_errors_disclose_no_sensitive_query() -> None:
    sensitive = "restricted acquisition details"
    service = RetrievalService(
        embedder=FakeEmbeddingProvider(),
        vector_store=InMemoryVectorStore(),
        collection_spec=CollectionSpec(name="w2_004_security_expired"),
    )
    expired = datetime.now(UTC) - timedelta(seconds=1)
    with pytest.raises(VectorStoreAuthorizationError) as failure:
        asyncio.run(
            service.retrieve(
                Query(text=sensitive),
                auth("tenant-a", Role.READER, expires_at=expired),
            )
        )
    assert sensitive not in str(failure.value)
