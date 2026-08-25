"""Security tests for PII-before-embedding and approved-exception controls."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from enterprise_ai_platform.embeddings.fake import FakeEmbeddingProvider
from enterprise_ai_platform.ingestion.models import (
    CorpusDocument,
    CorpusManifest,
    PiiFinding,
    load_pii_policy,
)
from enterprise_ai_platform.ingestion.pii import (
    SingaporeNricFinRecognizer,
    StaticPiiAnalyzer,
    apply_pii_policy,
)
from enterprise_ai_platform.ingestion.pipeline import IngestionPipeline, build_parser
from enterprise_ai_platform.ingestion.tokenizer import DeterministicTestTokenizer
from enterprise_ai_platform.retrieval.adapters.fake import InMemoryVectorStore
from enterprise_ai_platform.retrieval.authorization import require_ingestion_authorized
from enterprise_ai_platform.retrieval.errors import VectorStoreAuthorizationError
from enterprise_ai_platform.retrieval.models import (
    ApprovedException,
    AuthContext,
    Classification,
    CollectionSpec,
    Document,
    IngestionStatus,
    PiiStatus,
    Role,
)

ROOT = Path(__file__).resolve().parents[2]


class TrackingEmbedder(FakeEmbeddingProvider):
    def __init__(self) -> None:
        super().__init__()
        self.document_calls = 0

    async def embed_documents(self, texts: list[str]) -> tuple[tuple[float, ...], ...]:
        self.document_calls += 1
        return await super().embed_documents(texts)


class TrackingTokenizer(DeterministicTestTokenizer):
    def __init__(self) -> None:
        self.calls = 0

    def token_spans(self, text: str):  # type: ignore[no-untyped-def]
        self.calls += 1
        return super().token_spans(text)


class TrackingStore(InMemoryVectorStore):
    def __init__(self) -> None:
        super().__init__()
        self.provider_calls = 0

    async def create_or_validate_collection(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        self.provider_calls += 1
        return await super().create_or_validate_collection(*args, **kwargs)

    async def upsert_chunks(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        self.provider_calls += 1
        return await super().upsert_chunks(*args, **kwargs)


def corpus_source() -> CorpusDocument:
    return CorpusDocument(
        source_path="approved/pii.md",
        source_id="DOC-PII-SECURITY",
        tenant_id="tenant-a",
        classification=Classification.INTERNAL,
        allowed_roles=(Role.READER,),
        allowed_groups=(),
        data_owner="Gyan Prakash Rai",
        media_type="text/markdown",
    )


def ingestor(*roles: Role) -> AuthContext:
    return AuthContext(
        subject_id="pii-security-ingestor",
        tenant_id="tenant-a",
        roles=frozenset(roles),
        clearance=Classification.RESTRICTED,
    )


def test_high_risk_pii_quarantines_before_tokenizer_embedder_or_store(
    tmp_path: Path,
) -> None:
    path = tmp_path / "approved" / "pii.md"
    path.parent.mkdir(parents=True)
    path.write_text("Approved synthetic security fixture.", encoding="utf-8")
    finding = PiiFinding(
        entity_type="CREDENTIAL_SECRET",
        start=0,
        end=8,
        confidence=0.5,
    )
    embedder = TrackingEmbedder()
    tokenizer = TrackingTokenizer()
    store = TrackingStore()
    pipeline = IngestionPipeline(
        embedder=embedder,
        vector_store=store,
        tokenizer=tokenizer,
        pii_analyzer=StaticPiiAnalyzer((finding,)),
        collection_spec=CollectionSpec(name="w2_003_pii_security"),
    )

    outcome = asyncio.run(
        pipeline.ingest(
            manifest=CorpusManifest(documents=(corpus_source(),)),
            source_root=tmp_path,
            pii_policy=load_pii_policy(ROOT / "configs" / "pii-policy.yaml"),
            tenant_id="tenant-a",
            auth_context=ingestor(Role.INGESTOR),
        )
    )

    assert outcome.exit_code == 3
    assert outcome.manifest.records[0].pii_status is PiiStatus.QUARANTINED
    assert tokenizer.calls == 0
    assert embedder.document_calls == 0
    assert store.provider_calls == 0
    encoded = outcome.manifest.model_dump_json()
    assert "Approved synthetic security fixture" not in encoded


def test_common_pii_is_replaced_with_exact_typed_placeholders() -> None:
    text = "Alice uses alice@example.invalid"
    findings = (
        PiiFinding(entity_type="PERSON", start=0, end=5, confidence=0.8),
        PiiFinding(
            entity_type="EMAIL_ADDRESS",
            start=11,
            end=len(text),
            confidence=0.8,
        ),
    )

    decision = apply_pii_policy(
        text,
        findings,
        load_pii_policy(ROOT / "configs" / "pii-policy.yaml"),
    )

    assert decision.status is PiiStatus.REDACTED
    assert decision.processed_text == "<PERSON> uses <EMAIL_ADDRESS>"
    assert "Alice" not in decision.processed_text


def test_plausible_nric_shape_is_found_even_when_checksum_is_not_approval() -> None:
    findings = SingaporeNricFinRecognizer().find("Synthetic value S0000000A only")

    assert len(findings) == 1
    assert findings[0].entity_type == "SG_NRIC_FIN"
    assert findings[0].confidence in {0.5, 0.85}


def exception_document(exception: ApprovedException) -> Document:
    return Document(
        tenant_id="tenant-a",
        source_id="DOC-EXCEPTION",
        media_type="text/plain",
        document_id="a" * 64,
        document_version="b" * 64,
        classification=Classification.RESTRICTED,
        allowed_roles=frozenset({Role.READER}),
        allowed_groups=frozenset(),
        data_owner="Gyan Prakash Rai",
        content_hash="c" * 64,
        pii_status=PiiStatus.APPROVED_EXCEPTION,
        ingestion_status=IngestionStatus.INDEXED,
        approved_exception=exception,
        content="Synthetic exception boundary",
    )


def test_exception_requires_matching_owner_document_entity_tenant_and_dual_roles() -> None:
    now = datetime.now(UTC)
    exception = ApprovedException(
        owner="Gyan Prakash Rai",
        rationale="Owner-approved synthetic exception test",
        expires_at=now + timedelta(hours=1),
        document_id="a" * 64,
        entity_types=frozenset({"PASSPORT_NUMBER"}),
    )
    document = exception_document(exception)

    require_ingestion_authorized(
        document,
        ingestor(Role.INGESTOR, Role.ADMIN),
        detected_entity_types=("PASSPORT_NUMBER",),
        now=now,
    )
    for context, entities in (
        (ingestor(Role.INGESTOR), ("PASSPORT_NUMBER",)),
        (ingestor(Role.ADMIN), ("PASSPORT_NUMBER",)),
        (ingestor(Role.INGESTOR, Role.ADMIN), ("BANK_ACCOUNT",)),
    ):
        with pytest.raises(VectorStoreAuthorizationError):
            require_ingestion_authorized(
                document,
                context,
                detected_entity_types=entities,
                now=now,
            )

    expired = exception.model_copy(update={"expires_at": now - timedelta(seconds=1)})
    with pytest.raises(VectorStoreAuthorizationError):
        require_ingestion_authorized(
            exception_document(expired),
            ingestor(Role.INGESTOR, Role.ADMIN),
            detected_entity_types=("PASSPORT_NUMBER",),
            now=now,
        )


def test_cli_exposes_no_exception_self_approval_argument() -> None:
    help_text = build_parser().format_help().casefold()

    assert "exception" not in help_text
    assert "rationale" not in help_text
