"""Contract tests for strict corpus and redacted output manifests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from enterprise_ai_platform.ingestion.errors import IngestionConfigurationError
from enterprise_ai_platform.ingestion.models import (
    IngestionManifest,
    IngestionManifestRecord,
    IngestionRecordStatus,
    load_corpus_manifest,
)
from enterprise_ai_platform.retrieval.models import PiiStatus

ROOT = Path(__file__).resolve().parents[2]


def test_approved_corpus_manifest_is_exact_and_ordered() -> None:
    manifest = load_corpus_manifest(ROOT / "data" / "sample" / "corpus-manifest.json")

    assert manifest.dataset_name == "enterprise-ai-learning-corpus-v1"
    assert [document.source_id for document in manifest.documents] == [
        "DOC-SOT-V1.1",
        "DOC-COACHING-BLUEPRINT",
        "DOC-RESTRICTED-TEST",
    ]
    assert [document.tenant_id for document in manifest.documents] == [
        "tenant-a",
        "tenant-a",
        "tenant-b",
    ]


def test_duplicate_unknown_missing_and_modified_corpus_data_is_rejected(
    tmp_path: Path,
) -> None:
    approved = (ROOT / "data" / "sample" / "corpus-manifest.json").read_text()
    variants = (
        approved.replace(
            '"schema_version": "1.0",',
            '"schema_version": "1.0", "schema_version": "1.0",',
            1,
        ),
        approved.replace('"dataset_name":', '"unexpected": true, "dataset_name":', 1),
        approved.replace('"source_id": "DOC-SOT-V1.1",', "", 1),
        approved.replace("enterprise-ai-learning-corpus-v1", "unapproved-corpus", 1),
        approved.replace("DOC-COACHING-BLUEPRINT", "DOC-SOT-V1.1", 1),
        approved.replace(
            "approved/source-of-truth-v1.1.md",
            "C:/private/source-of-truth-v1.1.md",
            1,
        ),
    )
    for index, content in enumerate(variants):
        candidate = tmp_path / f"invalid-{index}.json"
        candidate.write_text(content, encoding="utf-8")
        with pytest.raises(IngestionConfigurationError):
            load_corpus_manifest(candidate)


def test_output_manifest_is_strict_redacted_json() -> None:
    record = IngestionManifestRecord(
        source_path="approved/source.md",
        source_id="DOC-SOURCE",
        tenant_id="tenant-a",
        media_type="text/markdown",
        status=IngestionRecordStatus.QUARANTINED,
        pii_status=PiiStatus.QUARANTINED,
        document_id="a" * 64,
        document_version="b" * 64,
        content_hash="c" * 64,
        error_code="pii_high_risk_quarantined",
    )
    manifest = IngestionManifest(
        dataset_name="enterprise-ai-learning-corpus-v1",
        tenant_id="tenant-a",
        tokenizer_id="enterprise-ai/deterministic-test-tokenizer",
        tokenizer_revision="w2-003-v1",
        selected_count=1,
        indexed_count=0,
        quarantined_count=1,
        failed_count=0,
        compensated_count=0,
        duration_ms=1,
        exit_code=3,
        records=(record,),
    )

    encoded = manifest.model_dump_json()
    decoded = json.loads(encoded)
    assert decoded["records"][0]["error_code"] == "pii_high_risk_quarantined"
    forbidden = (
        '"raw_text":',
        '"matched_text":',
        '"embedding":',
        '"exception_rationale":',
        '"stack":',
    )
    assert not any(token in encoded.casefold() for token in forbidden)

    with pytest.raises(ValidationError):
        IngestionManifest.model_validate({**manifest.model_dump(), "unexpected": True})
    with pytest.raises(ValidationError):
        IngestionManifest.model_validate({**manifest.model_dump(), "quarantined_count": 0})
    with pytest.raises(ValidationError):
        IngestionManifest.model_validate({**manifest.model_dump(), "exit_code": 1})
