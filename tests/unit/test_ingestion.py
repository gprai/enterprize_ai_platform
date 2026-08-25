"""Unit tests for deterministic fake-only ingestion orchestration."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from enterprise_ai_platform.embeddings.errors import EmbeddingProviderFailure
from enterprise_ai_platform.embeddings.fake import FakeEmbeddingProvider
from enterprise_ai_platform.ingestion.errors import IngestionSourceError
from enterprise_ai_platform.ingestion.identity import (
    content_hash_for,
    document_id_for,
    document_version_for,
)
from enterprise_ai_platform.ingestion.models import (
    CorpusDocument,
    CorpusManifest,
    IngestionRecordStatus,
    load_pii_policy,
)
from enterprise_ai_platform.ingestion.normalization import decode_and_normalize
from enterprise_ai_platform.ingestion.pii import StaticPiiAnalyzer
from enterprise_ai_platform.ingestion.pipeline import IngestionPipeline
from enterprise_ai_platform.ingestion.tokenizer import DeterministicTestTokenizer
from enterprise_ai_platform.retrieval.adapters.fake import InMemoryVectorStore
from enterprise_ai_platform.retrieval.models import (
    AuthContext,
    Classification,
    CollectionSpec,
    Query,
    Role,
)

ROOT = Path(__file__).resolve().parents[2]


def source() -> CorpusDocument:
    return CorpusDocument(
        source_path="approved/source.md",
        source_id="DOC-UNIT-SOURCE",
        tenant_id="tenant-a",
        classification=Classification.INTERNAL,
        allowed_roles=(Role.READER,),
        allowed_groups=(),
        data_owner="Gyan Prakash Rai",
        media_type="text/markdown",
    )


def auth() -> AuthContext:
    return AuthContext(
        subject_id="w2-003-unit-ingestor",
        tenant_id="tenant-a",
        roles=frozenset({Role.INGESTOR}),
        clearance=Classification.RESTRICTED,
    )


def pipeline(
    store: InMemoryVectorStore,
    embedder: FakeEmbeddingProvider | None = None,
    *,
    sleep: object | None = None,
) -> IngestionPipeline:
    async def no_sleep(delay: float) -> None:
        del delay

    return IngestionPipeline(
        embedder=embedder or FakeEmbeddingProvider(),
        vector_store=store,
        tokenizer=DeterministicTestTokenizer(),
        pii_analyzer=StaticPiiAnalyzer(),
        collection_spec=CollectionSpec(name="w2_003_unit"),
        sleep=no_sleep if sleep is None else sleep,  # type: ignore[arg-type]
        jitter=lambda: 0.0,
        clock=lambda: 1.0,
    )


def write_source(root: Path, content: bytes) -> None:
    path = root / "approved" / "source.md"
    path.parent.mkdir(parents=True)
    path.write_bytes(content)


def test_identity_uses_length_prefixes_and_original_bytes() -> None:
    first_document = document_id_for("tenant-a", "DOC-UNIT-SOURCE")
    assert first_document == document_id_for("tenant-a", "DOC-UNIT-SOURCE")
    assert first_document != document_id_for("tenant-a", "DOC-UNIT-SOURCE-2")

    crlf = b"Alpha\r\nBeta\r\n"
    lf = b"Alpha\nBeta\n"
    assert decode_and_normalize(crlf) == decode_and_normalize(lf)
    first_hash = content_hash_for(crlf)
    second_hash = content_hash_for(lf)
    assert first_hash != second_hash
    assert document_version_for(first_document, first_hash) != document_version_for(
        first_document,
        second_hash,
    )


@pytest.mark.parametrize(
    ("tenant_id", "source_id"),
    (
        ("", "DOC-UNIT-SOURCE"),
        (" tenant-a", "DOC-UNIT-SOURCE"),
        ("tenant-a", "\n"),
    ),
)
def test_malformed_identity_inputs_fail_closed(
    tenant_id: str,
    source_id: str,
) -> None:
    with pytest.raises(IngestionSourceError):
        document_id_for(tenant_id, source_id)


@pytest.mark.parametrize(
    ("document_id", "content_hash"),
    (("not-a-digest", "a" * 64), ("a" * 64, "A" * 64), ("a" * 64, "")),
)
def test_malformed_version_inputs_fail_closed(
    document_id: str,
    content_hash: str,
) -> None:
    with pytest.raises(IngestionSourceError):
        document_version_for(document_id, content_hash)


def test_normalization_applies_only_the_approved_sequence() -> None:
    original = "\ufeff  Café  \r\n\r\nSecond\t \r\n".encode()
    assert decode_and_normalize(original) == "  Café\n\nSecond"


def test_fake_pipeline_is_idempotent_and_preserves_retrievable_provenance(
    tmp_path: Path,
) -> None:
    write_source(tmp_path, b"Approved synthetic ingestion text.")
    store = InMemoryVectorStore()
    ingestion = pipeline(store)
    manifest = CorpusManifest(documents=(source(),))
    policy = load_pii_policy(ROOT / "configs" / "pii-policy.yaml")

    async def scenario() -> None:
        first = await ingestion.ingest(
            manifest=manifest,
            source_root=tmp_path,
            pii_policy=policy,
            tenant_id="tenant-a",
            auth_context=auth(),
        )
        second = await ingestion.ingest(
            manifest=manifest,
            source_root=tmp_path,
            pii_policy=policy,
            tenant_id="tenant-a",
            auth_context=auth(),
        )
        assert first.manifest.records[0].document_id == second.manifest.records[0].document_id
        assert (
            first.manifest.records[0].document_version
            == second.manifest.records[0].document_version
        )
        results = await store.search(
            CollectionSpec(name="w2_003_unit"),
            Query(text="approved"),
            tuple([1.0] + [0.0] * 383),
            AuthContext(
                subject_id="w2-003-reader",
                tenant_id="tenant-a",
                roles=frozenset({Role.READER}),
                clearance=Classification.INTERNAL,
            ),
        )
        assert len(results) == 1
        assert results[0].source_id == "DOC-UNIT-SOURCE"
        assert results[0].media_type == "text/markdown"

    asyncio.run(scenario())


class FailOnceEmbedder(FakeEmbeddingProvider):
    def __init__(self) -> None:
        super().__init__()
        self.attempts = 0

    async def embed_documents(self, texts: list[str]) -> tuple[tuple[float, ...], ...]:
        self.attempts += 1
        if self.attempts == 1:
            raise EmbeddingProviderFailure
        return await super().embed_documents(texts)


def test_only_classified_transient_embedding_failure_is_retried(tmp_path: Path) -> None:
    write_source(tmp_path, b"Approved retry fixture.")
    delays: list[float] = []

    async def record_sleep(delay: float) -> None:
        delays.append(delay)

    embedder = FailOnceEmbedder()
    ingestion = pipeline(InMemoryVectorStore(), embedder, sleep=record_sleep)

    outcome = asyncio.run(
        ingestion.ingest(
            manifest=CorpusManifest(documents=(source(),)),
            source_root=tmp_path,
            pii_policy=load_pii_policy(ROOT / "configs" / "pii-policy.yaml"),
            tenant_id="tenant-a",
            auth_context=auth(),
        )
    )

    assert embedder.attempts == 2
    assert delays == [0.1]
    assert outcome.exit_code == 0
    assert outcome.manifest.records[0].status is IngestionRecordStatus.INDEXED
