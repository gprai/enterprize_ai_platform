"""Local pypdf integration tests with no OCR, image conversion, or network."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from pypdf import PdfWriter
from pypdf.generic import (
    DecodedStreamObject,
    DictionaryObject,
    NameObject,
)

from enterprise_ai_platform.embeddings.fake import FakeEmbeddingProvider
from enterprise_ai_platform.ingestion.errors import IngestionSourceError
from enterprise_ai_platform.ingestion.loaders import load_source
from enterprise_ai_platform.ingestion.models import (
    MAX_EXTRACTED_CHARACTERS,
    CorpusDocument,
    CorpusManifest,
    load_pii_policy,
)
from enterprise_ai_platform.ingestion.pii import StaticPiiAnalyzer
from enterprise_ai_platform.ingestion.pipeline import IngestionPipeline
from enterprise_ai_platform.ingestion.tokenizer import DeterministicTestTokenizer
from enterprise_ai_platform.retrieval.adapters.fake import InMemoryVectorStore
from enterprise_ai_platform.retrieval.models import (
    AuthContext,
    Classification,
    CollectionSpec,
    Role,
)

ROOT = Path(__file__).resolve().parents[2]


def pdf_source() -> CorpusDocument:
    return CorpusDocument(
        source_path="approved/source.pdf",
        source_id="DOC-PDF",
        tenant_id="tenant-a",
        classification=Classification.INTERNAL,
        allowed_roles=(Role.READER,),
        allowed_groups=(),
        data_owner="Gyan Prakash Rai",
        media_type="application/pdf",
    )


def write_text_pdf(path: Path, text: str) -> None:
    writer = PdfWriter()
    page = writer.add_blank_page(width=612, height=792)
    font = DictionaryObject(
        {
            NameObject("/Type"): NameObject("/Font"),
            NameObject("/Subtype"): NameObject("/Type1"),
            NameObject("/BaseFont"): NameObject("/Helvetica"),
        }
    )
    font_reference = writer._add_object(font)  # noqa: SLF001
    page[NameObject("/Resources")] = DictionaryObject(
        {NameObject("/Font"): DictionaryObject({NameObject("/F1"): font_reference})}
    )
    stream = DecodedStreamObject()
    safe_text = text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    stream.set_data(f"BT /F1 12 Tf 72 720 Td ({safe_text}) Tj ET".encode())
    page[NameObject("/Contents")] = writer._add_object(stream)  # noqa: SLF001
    path.parent.mkdir(parents=True)
    with path.open("wb") as handle:
        writer.write(handle)


def test_text_pdf_is_extracted_locally_with_original_bytes_retained(tmp_path: Path) -> None:
    path = tmp_path / "approved" / "source.pdf"
    write_text_pdf(path, "Approved synthetic PDF text")

    loaded = load_source(tmp_path, pdf_source())

    assert loaded.original_bytes.startswith(b"%PDF-")
    assert "Approved synthetic PDF text" in loaded.normalized_text
    assert loaded.media_type == "application/pdf"


def test_malformed_encrypted_image_only_and_over_page_pdf_are_quarantined(
    tmp_path: Path,
) -> None:
    path = tmp_path / "approved" / "source.pdf"
    path.parent.mkdir(parents=True)

    path.write_bytes(b"%PDF-not-a-valid-pdf")
    with pytest.raises(IngestionSourceError):
        load_source(tmp_path, pdf_source())

    encrypted = PdfWriter()
    encrypted.add_blank_page(width=100, height=100)
    encrypted.encrypt("synthetic-password")  # noqa: S106 - synthetic test fixture
    with path.open("wb") as handle:
        encrypted.write(handle)
    with pytest.raises(IngestionSourceError):
        load_source(tmp_path, pdf_source())

    image_only = PdfWriter()
    image_only.add_blank_page(width=100, height=100)
    with path.open("wb") as handle:
        image_only.write(handle)
    with pytest.raises(IngestionSourceError):
        load_source(tmp_path, pdf_source())

    too_many_pages = PdfWriter()
    for _ in range(51):
        too_many_pages.add_blank_page(width=100, height=100)
    with path.open("wb") as handle:
        too_many_pages.write(handle)
    with pytest.raises(IngestionSourceError):
        load_source(tmp_path, pdf_source())


def test_pdf_extracted_character_expansion_limit_is_enforced(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ExpandedPage:
        def extract_text(self) -> str:
            return "x" * (MAX_EXTRACTED_CHARACTERS + 1)

    class ExpandedReader:
        is_encrypted = False
        pages = (ExpandedPage(),)

        def __init__(self, *args: object, **kwargs: object) -> None:
            del args, kwargs

    path = tmp_path / "approved" / "source.pdf"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"%PDF-synthetic-expansion-test")
    monkeypatch.setattr(
        "enterprise_ai_platform.ingestion.loaders.PdfReader",
        ExpandedReader,
    )

    with pytest.raises(IngestionSourceError):
        load_source(tmp_path, pdf_source())


def test_rejected_pdf_causes_zero_tokenizer_embedder_and_store_calls(
    tmp_path: Path,
) -> None:
    class TrackingEmbedder(FakeEmbeddingProvider):
        calls = 0

        async def embed_documents(
            self,
            texts: list[str],
        ) -> tuple[tuple[float, ...], ...]:
            self.calls += 1
            return await super().embed_documents(texts)

    class TrackingTokenizer(DeterministicTestTokenizer):
        calls = 0

        def token_spans(self, text: str):  # type: ignore[no-untyped-def]
            self.calls += 1
            return super().token_spans(text)

    class TrackingStore(InMemoryVectorStore):
        calls = 0

        async def create_or_validate_collection(
            self,
            *args: object,
            **kwargs: object,
        ) -> None:
            self.calls += 1
            await super().create_or_validate_collection(
                *args,  # type: ignore[arg-type]
                **kwargs,
            )

    path = tmp_path / "approved" / "source.pdf"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"%PDF-not-a-valid-pdf")
    embedder = TrackingEmbedder()
    tokenizer = TrackingTokenizer()
    store = TrackingStore()
    pipeline = IngestionPipeline(
        embedder=embedder,
        vector_store=store,
        tokenizer=tokenizer,
        pii_analyzer=StaticPiiAnalyzer(),
        collection_spec=CollectionSpec(name="w2_003_pdf_boundary"),
    )
    auth_context = AuthContext(
        subject_id="w2-003-pdf-ingestor",
        tenant_id="tenant-a",
        roles=frozenset({Role.INGESTOR}),
        clearance=Classification.RESTRICTED,
    )

    outcome = asyncio.run(
        pipeline.ingest(
            manifest=CorpusManifest(documents=(pdf_source(),)),
            source_root=tmp_path,
            pii_policy=load_pii_policy(ROOT / "configs" / "pii-policy.yaml"),
            tenant_id="tenant-a",
            auth_context=auth_context,
        )
    )

    assert outcome.exit_code == 3
    assert tokenizer.calls == 0
    assert embedder.calls == 0
    assert store.calls == 0
