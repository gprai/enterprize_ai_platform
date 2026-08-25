"""Owner-controlled W2-004 local ingestion and authorized retrieval proof."""

from __future__ import annotations

import asyncio
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from qdrant_client import AsyncQdrantClient

from enterprise_ai_platform.embeddings.sentence_transformer import (
    SentenceTransformerEmbedder,
)
from enterprise_ai_platform.ingestion.models import (
    IngestionRecordStatus,
    StarterQuestion,
    load_corpus_manifest,
    load_pii_policy,
    load_starter_fixture,
)
from enterprise_ai_platform.ingestion.pii import SyntheticPiiAnalyzer
from enterprise_ai_platform.ingestion.pipeline import IngestionPipeline
from enterprise_ai_platform.ingestion.tokenizer import MiniLmTokenizer
from enterprise_ai_platform.retrieval.adapters.qdrant import QdrantVectorStore
from enterprise_ai_platform.retrieval.models import (
    AuthContext,
    Classification,
    CollectionSpec,
    PiiStatus,
    Query,
    Role,
)
from enterprise_ai_platform.retrieval.service import RetrievalService

RUN_REAL = "RUN_W2_004_LOCAL_RETRIEVAL"
PHASE = "W2_004_PHASE"
QDRANT_URL = "W2_004_QDRANT_URL"
SNAPSHOT = "W2_004_MODEL_SNAPSHOT"
REGRESSION_OVERRIDE = "W2_004_EXPECTED_SOURCE_OVERRIDE"
INTERNAL_QDRANT_URL = "http://qdrant:6333"
COLLECTION_NAME = "w2_004_local_retrieval"
APPROVED_REVISION = "1110a243fdf4706b3f48f1d95db1a4f5529b4d41"
APPROVED_SNAPSHOT = Path(
    "/opt/model-cache/models--sentence-transformers--all-MiniLM-L6-v2/"
    f"snapshots/{APPROVED_REVISION}"
)
APPROVED_BLOB_ROOT = Path(
    "/opt/model-cache/models--sentence-transformers--all-MiniLM-L6-v2/blobs"
)
APPROVED_SOURCE_IDS = {
    "DOC-SOT-V1.1",
    "DOC-COACHING-BLUEPRINT",
    "DOC-RESTRICTED-TEST",
}
ROOT = Path(__file__).resolve().parents[2]
EMPTY_GROUPS: frozenset[str] = frozenset()


@dataclass(frozen=True, slots=True)
class Runtime:
    client: Any
    store: QdrantVectorStore
    specification: CollectionSpec
    ingestion: IngestionPipeline
    retrieval: RetrievalService


def require_phase(*allowed: str) -> str:
    if os.environ.get(RUN_REAL) != "1":
        pytest.skip("W2-004 real local retrieval is owner-controlled and opt-in")
    phase = os.environ.get(PHASE)
    if phase not in allowed:
        pytest.skip(f"W2-004 phase must be one of: {', '.join(allowed)}")
    if os.environ.get(QDRANT_URL) != INTERNAL_QDRANT_URL:
        pytest.fail("W2-004 requires the approved internal Qdrant service URL")
    if os.environ.get("HF_HUB_OFFLINE") != "1":
        pytest.fail("Hugging Face offline mode is required")
    if os.environ.get("TRANSFORMERS_OFFLINE") != "1":
        pytest.fail("Transformers offline mode is required")
    if os.environ.get("CUDA_VISIBLE_DEVICES") != "-1":
        pytest.fail("CPU-only execution is required")
    if os.environ.get("HF_TOKEN") or os.environ.get("HUGGING_FACE_HUB_TOKEN"):
        pytest.fail("authentication tokens are prohibited")
    snapshot_value = os.environ.get(SNAPSHOT)
    if snapshot_value != APPROVED_SNAPSHOT.as_posix():
        pytest.fail("the exact approved snapshot mount is required")
    return phase
    try:
        resolved_weights = (
            APPROVED_SNAPSHOT / "model.safetensors"
        ).resolve(strict=True)
    except OSError:
        pytest.fail("the approved model artifact is not reachable")

    if not resolved_weights.is_relative_to(APPROVED_BLOB_ROOT):
        pytest.fail("the model artifact must resolve inside the approved blob mount")


def auth(
    tenant_id: str,
    *roles: Role,
    clearance: Classification = Classification.RESTRICTED,
    groups: frozenset[str] = EMPTY_GROUPS,
) -> AuthContext:
    return AuthContext(
        subject_id=f"w2-004-{tenant_id}-{'-'.join(role.value for role in roles)}",
        tenant_id=tenant_id,
        roles=frozenset(roles),
        clearance=clearance,
        groups=groups,
    )


def create_runtime() -> Runtime:
    client = AsyncQdrantClient(url=INTERNAL_QDRANT_URL, timeout=60)
    store = QdrantVectorStore(client)
    specification = CollectionSpec(name=COLLECTION_NAME)
    embedder = SentenceTransformerEmbedder(APPROVED_SNAPSHOT)
    return Runtime(
        client=client,
        store=store,
        specification=specification,
        ingestion=IngestionPipeline(
            embedder=embedder,
            vector_store=store,
            tokenizer=MiniLmTokenizer(APPROVED_SNAPSHOT),
            pii_analyzer=SyntheticPiiAnalyzer(),
            collection_spec=specification,
        ),
        retrieval=RetrievalService(
            embedder=embedder,
            vector_store=store,
            collection_spec=specification,
            timeout_seconds=60.0,
        ),
    )


async def ingest_all(runtime: Runtime) -> tuple[tuple[str, str, int], ...]:
    manifest = load_corpus_manifest(ROOT / "data/sample/corpus-manifest.json")
    policy = load_pii_policy(ROOT / "configs/pii-policy.yaml")
    summaries: list[tuple[str, str, int]] = []
    for tenant_id in ("tenant-a", "tenant-b"):
        outcome = await runtime.ingestion.ingest(
            manifest=manifest,
            source_root=ROOT / "data/sample",
            pii_policy=policy,
            tenant_id=tenant_id,
            auth_context=auth(tenant_id, Role.INGESTOR),
        )
        assert outcome.exit_code == 0
        assert all(
            record.status is IngestionRecordStatus.INDEXED
            for record in outcome.manifest.records
        )
        summaries.extend(
            (record.source_id, record.document_version or "", record.chunk_count)
            for record in outcome.manifest.records
        )
    return tuple(summaries)


async def chunk_inventory(runtime: Runtime) -> tuple[tuple[str, ...], int]:
    records, next_offset = await runtime.client.scroll(
        collection_name=runtime.specification.name,
        limit=10_000,
        with_payload=True,
        with_vectors=False,
    )
    assert next_offset is None
    chunks = [
        record
        for record in records
        if (record.payload or {}).get("enterprise_ai_record_type") == "chunk"
    ]
    identities = tuple(sorted(str(record.id) for record in chunks))
    count = await runtime.client.count(
        collection_name=runtime.specification.name,
        exact=True,
    )
    return identities, int(count.count)


def expected_source_ids(
    question: StarterQuestion,
    regression_override: str | None,
) -> tuple[str, ...]:
    if question.id == "Q1" and regression_override is not None:
        return (regression_override,)
    return question.expected_source_ids


async def validate_queries(
    runtime: Runtime,
    *,
    regression_override: str | None = None,
) -> tuple[dict[str, object], ...]:
    questions = load_starter_fixture(ROOT / "configs/eval/w2-starter.jsonl")
    report: list[dict[str, object]] = []
    for question in questions:
        results = await runtime.retrieval.retrieve(
            Query(text=question.question, top_k=5),
            auth(
                question.tenant_id,
                *question.roles,
                clearance=question.clearance,
            ),
        )
        expected = expected_source_ids(question, regression_override)
        if question.id != "Q5":
            assert expected
            assert set(expected).intersection(result.source_id for result in results)
        report.append(
            {
                "question_id": question.id,
                "expected_source_ids": list(expected),
                "results": [
                    {
                        "source_id": result.source_id,
                        "rank": rank,
                        "score": round(result.score, 8),
                    }
                    for rank, result in enumerate(results, start=1)
                ],
                "evaluation": "RETRIEVAL_ONLY" if question.id == "Q5" else "TOP_5",
            }
        )
    return tuple(report)


async def validate_isolation_and_quarantine(runtime: Runtime) -> None:
    question = load_starter_fixture(ROOT / "configs/eval/w2-starter.jsonl")[0]
    query = Query(text=question.question, top_k=5)
    denied_contexts = (
        auth("tenant-c", Role.READER),
        auth(
            "tenant-a",
            Role.READER,
            clearance=Classification.PUBLIC,
        ),
        auth("tenant-a", Role.REVIEWER),
        auth("tenant-a", Role.REVIEWER, groups=frozenset({"wrong-group"})),
    )
    for denied in denied_contexts:
        assert await runtime.retrieval.retrieve(query, denied) == ()

    records, next_offset = await runtime.client.scroll(
        collection_name=runtime.specification.name,
        limit=10_000,
        with_payload=True,
        with_vectors=False,
    )
    assert next_offset is None
    chunk_payloads = [
        dict(record.payload or {})
        for record in records
        if (record.payload or {}).get("enterprise_ai_record_type") == "chunk"
    ]
    assert chunk_payloads
    assert {payload["source_id"] for payload in chunk_payloads}.issubset(
        APPROVED_SOURCE_IDS
    )
    assert all(
        payload.get("pii_status") != PiiStatus.QUARANTINED.value
        for payload in chunk_payloads
    )


def test_fake_retrieval_feature_uses_no_model_or_network() -> None:
    from enterprise_ai_platform.embeddings.fake import FakeEmbeddingProvider
    from enterprise_ai_platform.retrieval.adapters.fake import InMemoryVectorStore
    from enterprise_ai_platform.retrieval.models import (
        Chunk,
        IngestionStatus,
        deterministic_chunk_id,
    )

    async def scenario() -> None:
        embedder = FakeEmbeddingProvider()
        store = InMemoryVectorStore()
        specification = CollectionSpec(name="w2_004_feature_fake")
        query = Query(text="approved local retrieval")
        content_hash = "f" * 64
        document_id = "w2-004-feature-fake"
        vector = await embedder.embed_query(query.text)
        source = Chunk(
            tenant_id="tenant-a",
            source_id="DOC-W2-004-FAKE",
            media_type="text/plain",
            document_id=document_id,
            document_version="v1",
            classification=Classification.INTERNAL,
            allowed_roles=frozenset({Role.READER}),
            allowed_groups=frozenset(),
            data_owner="retrieval-team",
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
            text="Synthetic feature fixture",
            embedding=vector,
        )
        await store.create_or_validate_collection(specification)
        await store.upsert_chunks(
            specification,
            (source,),
            auth("tenant-a", Role.INGESTOR),
        )
        results = await RetrievalService(
            embedder=embedder,
            vector_store=store,
            collection_spec=specification,
        ).retrieve(query, auth("tenant-a", Role.READER))
        assert [result.source_id for result in results] == ["DOC-W2-004-FAKE"]

    asyncio.run(scenario())


def test_real_ingestion_is_initially_absent_and_idempotent() -> None:
    require_phase("ingest")

    async def scenario() -> None:
        runtime = create_runtime()
        try:
            assert await runtime.store.healthcheck(timeout_seconds=60.0)
            if await runtime.client.collection_exists(COLLECTION_NAME):
                pytest.fail("the W2-004 collection already exists; refusing reuse")
            first_summary = await ingest_all(runtime)
            first_ids, first_count = await chunk_inventory(runtime)
            second_summary = await ingest_all(runtime)
            second_ids, second_count = await chunk_inventory(runtime)
            assert first_summary == second_summary
            assert first_ids == second_ids
            assert first_count == second_count
            print(
                json.dumps(
                    {
                        "phase": "ingest",
                        "status": "PASS",
                        "sources": [item[0] for item in first_summary],
                        "chunk_point_count": len(first_ids),
                        "total_point_count": first_count,
                    },
                    sort_keys=True,
                )
            )
        finally:
            await runtime.client.close()

    asyncio.run(scenario())


def test_real_authorized_top_five_and_isolation() -> None:
    phase = require_phase("query", "regression")

    async def scenario() -> None:
        runtime = create_runtime()
        try:
            if not await runtime.client.collection_exists(COLLECTION_NAME):
                pytest.fail("the approved W2-004 collection is absent")
            await runtime.store.create_or_validate_collection(runtime.specification)
            override = os.environ.get(REGRESSION_OVERRIDE)
            if phase == "query" and override is not None:
                pytest.fail("a regression override is prohibited in the query phase")
            if phase == "regression" and override != "DOC-RESTRICTED-TEST":
                pytest.fail("the exact approved regression override is required")
            report = await validate_queries(
                runtime,
                regression_override=override if phase == "regression" else None,
            )
            await validate_isolation_and_quarantine(runtime)
            print(
                json.dumps(
                    {"phase": phase, "status": "PASS", "questions": report},
                    sort_keys=True,
                )
            )
        finally:
            await runtime.client.close()

    asyncio.run(scenario())


def test_remove_only_the_exact_w2_004_collection() -> None:
    require_phase("remove")

    async def scenario() -> None:
        runtime = create_runtime()
        try:
            if not await runtime.client.collection_exists(COLLECTION_NAME):
                pytest.fail("the approved W2-004 collection is already absent")
            await runtime.store.create_or_validate_collection(runtime.specification)
            await runtime.client.delete_collection(COLLECTION_NAME)
            assert not await runtime.client.collection_exists(COLLECTION_NAME)
            print(
                json.dumps(
                    {"phase": "remove", "status": "PASS", "collection": COLLECTION_NAME},
                    sort_keys=True,
                )
            )
        finally:
            await runtime.client.close()

    asyncio.run(scenario())
