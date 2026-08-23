"""Security tests for tenant, clearance, ACL, expiry and mutation isolation."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from enterprise_ai_platform.retrieval.adapters.fake import InMemoryVectorStore
from enterprise_ai_platform.retrieval.errors import VectorStoreAuthorizationError
from enterprise_ai_platform.retrieval.models import (
    APPROVED_EMBEDDING_DIMENSION,
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


def vector() -> tuple[float, ...]:
    return tuple([1.0] + [0.0] * (APPROVED_EMBEDDING_DIMENSION - 1))


def auth(
    tenant_id: str,
    role: Role,
    *,
    clearance: Classification = Classification.RESTRICTED,
    groups: frozenset[str] | None = None,
    expires_at: datetime | None = None,
) -> AuthContext:
    return AuthContext(
        subject_id=f"{tenant_id}-{role.value}",
        tenant_id=tenant_id,
        roles=frozenset({role}),
        clearance=clearance,
        groups=frozenset() if groups is None else groups,
        expires_at=expires_at,
    )


def chunk(
    tenant_id: str,
    *,
    classification: Classification = Classification.INTERNAL,
    roles: frozenset[Role] | None = None,
    groups: frozenset[str] | None = None,
) -> Chunk:
    content_hash = ("a" if tenant_id == "tenant-a" else "b") * 64
    document_id = f"{tenant_id}-policy"
    return Chunk(
        tenant_id=tenant_id,
        document_id=document_id,
        document_version="v1",
        classification=classification,
        allowed_roles=frozenset({Role.READER}) if roles is None else roles,
        allowed_groups=frozenset() if groups is None else groups,
        data_owner=f"{tenant_id}-owner",
        content_hash=content_hash,
        pii_status=PiiStatus.CLEAR,
        ingestion_status=IngestionStatus.INDEXED,
        chunk_id=deterministic_chunk_id(
            tenant_id=tenant_id,
            document_id=document_id,
            document_version="v1",
            content_hash=content_hash,
            chunk_index=0,
        ),
        chunk_index=0,
        text=f"Synthetic content for {tenant_id}",
        embedding=vector(),
    )


def test_cross_tenant_query_returns_zero_unauthorized_chunks() -> None:
    async def scenario() -> None:
        store = InMemoryVectorStore()
        specification = CollectionSpec(name="w2_001_isolation")
        await store.create_or_validate_collection(specification)
        await store.upsert_chunks(
            specification,
            (chunk("tenant-a"),),
            auth("tenant-a", Role.INGESTOR),
        )
        await store.upsert_chunks(
            specification,
            (chunk("tenant-b"),),
            auth("tenant-b", Role.INGESTOR),
        )
        tenant_a = await store.search(
            specification,
            Query(text="policy"),
            vector(),
            auth("tenant-a", Role.READER),
        )
        unknown_tenant = await store.search(
            specification,
            Query(text="policy"),
            vector(),
            auth("tenant-c", Role.READER),
        )
        assert [result.tenant_id for result in tenant_a] == ["tenant-a"]
        assert unknown_tenant == ()

    asyncio.run(scenario())


def test_empty_acl_clearance_and_admin_do_not_bypass_authorization() -> None:
    async def scenario() -> None:
        store = InMemoryVectorStore()
        specification = CollectionSpec(name="w2_001_acl")
        await store.create_or_validate_collection(specification)
        protected = chunk(
            "tenant-a",
            classification=Classification.CONFIDENTIAL,
            roles=frozenset(),
        )
        await store.upsert_chunks(
            specification,
            (protected,),
            auth("tenant-a", Role.INGESTOR),
        )
        for context in (
            auth("tenant-a", Role.READER, clearance=Classification.INTERNAL),
            auth("tenant-a", Role.ADMIN),
        ):
            assert (
                await store.search(
                    specification,
                    Query(text="policy"),
                    vector(),
                    context,
                )
                == ()
            )

    asyncio.run(scenario())


def test_group_acl_is_allowed_but_expired_claims_fail_closed() -> None:
    async def scenario() -> None:
        store = InMemoryVectorStore()
        specification = CollectionSpec(name="w2_001_groups")
        await store.create_or_validate_collection(specification)
        grouped = chunk("tenant-a", roles=frozenset(), groups=frozenset({"finance"}))
        await store.upsert_chunks(
            specification,
            (grouped,),
            auth("tenant-a", Role.INGESTOR),
        )
        results = await store.search(
            specification,
            Query(text="policy"),
            vector(),
            auth("tenant-a", Role.READER, groups=frozenset({"finance"})),
        )
        assert len(results) == 1
        expired = datetime.now(UTC) - timedelta(seconds=1)
        with pytest.raises(VectorStoreAuthorizationError):
            await store.search(
                specification,
                Query(text="policy"),
                vector(),
                auth("tenant-a", Role.READER, expires_at=expired),
            )

    asyncio.run(scenario())


def test_readers_reviewers_and_cross_tenant_ingestors_cannot_mutate() -> None:
    async def scenario() -> None:
        store = InMemoryVectorStore()
        specification = CollectionSpec(name="w2_001_mutation")
        await store.create_or_validate_collection(specification)
        tenant_a_chunk = chunk("tenant-a")
        for context in (
            auth("tenant-a", Role.READER),
            auth("tenant-a", Role.REVIEWER),
            auth("tenant-b", Role.INGESTOR),
        ):
            with pytest.raises(VectorStoreAuthorizationError):
                await store.upsert_chunks(specification, (tenant_a_chunk,), context)

    asyncio.run(scenario())
