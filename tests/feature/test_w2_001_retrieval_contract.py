"""Feature proof for the W2-001 provider-neutral rollback boundary."""

from __future__ import annotations

import asyncio
from pathlib import Path

from enterprise_ai_platform.retrieval.adapters.fake import InMemoryVectorStore
from enterprise_ai_platform.retrieval.errors import VectorStoreUnavailableError
from enterprise_ai_platform.retrieval.models import CollectionSpec

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def test_domain_contract_has_no_vendor_imports() -> None:
    contract_files = (
        REPOSITORY_ROOT / "src/enterprise_ai_platform/retrieval/models.py",
        REPOSITORY_ROOT / "src/enterprise_ai_platform/retrieval/vector_store.py",
        REPOSITORY_ROOT / "src/enterprise_ai_platform/retrieval/authorization.py",
    )
    forbidden = ("qdrant_client", "opensearchpy", "AsyncQdrantClient", "AsyncOpenSearch")
    for path in contract_files:
        content = path.read_text(encoding="utf-8")
        assert not any(token in content for token in forbidden)


def test_fake_remains_a_zero_provider_rollback_target() -> None:
    async def scenario() -> None:
        unavailable = InMemoryVectorStore(available=False)
        assert not await unavailable.healthcheck()
        fallback = InMemoryVectorStore()
        await fallback.create_or_validate_collection(CollectionSpec(name="w2_001_rollback"))
        assert await fallback.healthcheck()

    asyncio.run(scenario())


def test_normalized_error_exposes_no_provider_detail() -> None:
    failure = VectorStoreUnavailableError()
    assert str(failure) == "vector store is unavailable"
    assert failure.retryable is True
