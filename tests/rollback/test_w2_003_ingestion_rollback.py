"""Rollback tests for exact-version compensation and indeterminate cleanup."""

from __future__ import annotations

import asyncio
from pathlib import Path

from enterprise_ai_platform.embeddings.fake import FakeEmbeddingProvider
from enterprise_ai_platform.ingestion.models import (
    CorpusDocument,
    CorpusManifest,
    IngestionRecordStatus,
    load_pii_policy,
)
from enterprise_ai_platform.ingestion.pii import StaticPiiAnalyzer
from enterprise_ai_platform.ingestion.pipeline import IngestionPipeline
from enterprise_ai_platform.ingestion.tokenizer import DeterministicTestTokenizer
from enterprise_ai_platform.retrieval.adapters.fake import InMemoryVectorStore
from enterprise_ai_platform.retrieval.errors import VectorStoreUnavailableError
from enterprise_ai_platform.retrieval.models import (
    AuthContext,
    Classification,
    CollectionSpec,
    Query,
    Role,
)

ROOT = Path(__file__).resolve().parents[2]


class PartialFailureStore(InMemoryVectorStore):
    def __init__(self) -> None:
        super().__init__()
        self.fail_upsert = False
        self.fail_compensation = False
        self.compensation_calls: list[tuple[str, str]] = []

    async def upsert_chunks(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        await super().upsert_chunks(*args, **kwargs)
        if self.fail_upsert:
            raise VectorStoreUnavailableError

    async def delete_by_document_version(
        self,
        specification,
        document_id,
        document_version,
        auth_context,
        *,
        timeout_seconds=None,
    ):  # type: ignore[no-untyped-def]
        self.compensation_calls.append((document_id, document_version))
        if self.fail_compensation:
            raise VectorStoreUnavailableError
        await super().delete_by_document_version(
            specification,
            document_id,
            document_version,
            auth_context,
            timeout_seconds=timeout_seconds,
        )


def source() -> CorpusDocument:
    return CorpusDocument(
        source_path="approved/source.md",
        source_id="DOC-ROLLBACK",
        tenant_id="tenant-a",
        classification=Classification.INTERNAL,
        allowed_roles=(Role.READER,),
        allowed_groups=(),
        data_owner="Gyan Prakash Rai",
        media_type="text/markdown",
    )


def auth(role: Role = Role.INGESTOR) -> AuthContext:
    return AuthContext(
        subject_id=f"rollback-{role.value}",
        tenant_id="tenant-a",
        roles=frozenset({role}),
        clearance=Classification.RESTRICTED,
    )


def pipeline(store: InMemoryVectorStore) -> IngestionPipeline:
    return IngestionPipeline(
        embedder=FakeEmbeddingProvider(),
        vector_store=store,
        tokenizer=DeterministicTestTokenizer(),
        pii_analyzer=StaticPiiAnalyzer(),
        collection_spec=CollectionSpec(name="w2_003_rollback"),
        clock=lambda: 1.0,
    )


def write_source(root: Path, content: str) -> None:
    path = root / "approved" / "source.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_partial_new_version_is_compensated_without_deleting_prior_version(
    tmp_path: Path,
) -> None:
    store = PartialFailureStore()
    ingestion = pipeline(store)
    manifest = CorpusManifest(documents=(source(),))
    policy = load_pii_policy(ROOT / "configs" / "pii-policy.yaml")

    async def scenario() -> None:
        write_source(tmp_path, "Approved version one")
        first = await ingestion.ingest(
            manifest=manifest,
            source_root=tmp_path,
            pii_policy=policy,
            tenant_id="tenant-a",
            auth_context=auth(),
        )
        first_version = first.manifest.records[0].document_version
        store.fail_upsert = True
        write_source(tmp_path, "Approved version two")
        second = await ingestion.ingest(
            manifest=manifest,
            source_root=tmp_path,
            pii_policy=policy,
            tenant_id="tenant-a",
            auth_context=auth(),
        )

        assert second.exit_code == 4
        assert second.manifest.records[0].status is IngestionRecordStatus.COMPENSATED
        assert store.compensation_calls == [
            (
                second.manifest.records[0].document_id,
                second.manifest.records[0].document_version,
            )
        ]
        results = await store.search(
            CollectionSpec(name="w2_003_rollback"),
            Query(text="approved"),
            tuple([1.0] + [0.0] * 383),
            auth(Role.READER),
        )
        assert {result.document_version for result in results} == {first_version}

    asyncio.run(scenario())


def test_failed_compensation_is_reported_as_rollback_indeterminate(
    tmp_path: Path,
) -> None:
    write_source(tmp_path, "Approved indeterminate rollback fixture")
    store = PartialFailureStore()
    store.fail_upsert = True
    store.fail_compensation = True

    outcome = asyncio.run(
        pipeline(store).ingest(
            manifest=CorpusManifest(documents=(source(),)),
            source_root=tmp_path,
            pii_policy=load_pii_policy(ROOT / "configs" / "pii-policy.yaml"),
            tenant_id="tenant-a",
            auth_context=auth(),
        )
    )

    assert outcome.exit_code == 5
    assert (
        outcome.manifest.records[0].status
        is IngestionRecordStatus.ROLLBACK_INDETERMINATE
    )
    assert outcome.manifest.records[0].error_code == "ingestion_rollback_indeterminate"


class CancellingStore(InMemoryVectorStore):
    def __init__(self) -> None:
        super().__init__()
        self.mutation_started = asyncio.Event()
        self.release = asyncio.Event()
        self.upsert_calls = 0

    async def upsert_chunks(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        self.upsert_calls += 1
        await super().upsert_chunks(*args, **kwargs)
        self.mutation_started.set()
        await self.release.wait()


def test_cancellation_starts_no_new_upsert_and_compensates_uncertain_version(
    tmp_path: Path,
) -> None:
    write_source(tmp_path, "Approved cancellation fixture")

    async def scenario() -> None:
        store = CancellingStore()
        task = asyncio.create_task(
            pipeline(store).ingest(
                manifest=CorpusManifest(documents=(source(),)),
                source_root=tmp_path,
                pii_policy=load_pii_policy(ROOT / "configs" / "pii-policy.yaml"),
                tenant_id="tenant-a",
                auth_context=auth(),
            )
        )
        await store.mutation_started.wait()
        task.cancel()
        outcome = await task

        assert outcome.exit_code == 130
        assert outcome.manifest.records[0].status is IngestionRecordStatus.CANCELLED
        assert store.upsert_calls == 1
        assert (
            await store.search(
                CollectionSpec(name="w2_003_rollback"),
                Query(text="approved"),
                tuple([1.0] + [0.0] * 383),
                auth(Role.READER),
            )
            == ()
        )

    asyncio.run(scenario())
