"""Unit coverage for W7-002 extraction and quality thresholds."""

from __future__ import annotations

from collections import Counter

import pytest

from enterprise_ai_platform.processing.contracts import MetricName, QualityStatus
from enterprise_ai_platform.processing.pipeline import DeterministicExtractor, ProcessingError
from enterprise_ai_platform.processing.quality import CompatibleQualityEngine
from tests.fakes.w7_002_processing import make_batch, make_document, processing_config


def test_text_extraction_is_deterministic_and_hash_bound() -> None:
    document, content = make_document(content=b"line one  \r\nline two\n")
    extractor = DeterministicExtractor()

    assert extractor.extract(document.source, content) == "line one\nline two"
    with pytest.raises(ProcessingError, match="CONTENT_HASH_MISMATCH"):
        extractor.extract(document.source, b"x" * len(content))


def test_small_batch_reports_insufficient_duplicate_sample_without_false_pass() -> None:
    document, _ = make_document()
    batch = make_batch((document,))
    report = CompatibleQualityEngine(processing_config()).evaluate(
        batch,
        (),
        quarantined_count=0,
        failure_metrics=Counter({MetricName.EXTRACTION_FAILURE: 0}),
    )

    assert report.status is QualityStatus.INSUFFICIENT_SAMPLE
    assert report.observations[2].status is QualityStatus.INSUFFICIENT_SAMPLE
    assert report.threshold_identity_sha256


def test_volume_outside_inclusive_half_to_double_boundary_fails() -> None:
    document, _ = make_document()
    report = CompatibleQualityEngine(processing_config()).evaluate(
        make_batch((document,), expected_document_count=3),
        (),
        quarantined_count=0,
    )

    assert report.status is QualityStatus.FAIL
    assert report.observations[1].safe_reason_code == "VOLUME_DRIFT"


def test_duplicate_rate_above_ten_percent_fails_for_sufficient_sample() -> None:
    documents = []
    for index in range(20):
        key = "d" * 64 if index < 4 else None
        document, _ = make_document(
            document_id=f"document-{index}",
            idempotency_key=key,
        )
        documents.append(document)
    batch = make_batch(tuple(documents))

    report = CompatibleQualityEngine(processing_config()).evaluate(
        batch,
        (),
        quarantined_count=0,
    )

    assert report.status is QualityStatus.FAIL
    assert report.duplicate_count == 3
    assert report.observations[2].safe_reason_code == "DUPLICATE_RATE_DRIFT"


def test_invalid_encoding_and_file_signature_fail_closed() -> None:
    invalid_encoding, encoding_bytes = make_document(content=b"\xff\xfe")
    invalid_signature, signature_bytes = make_document(content=b"%PDF-not-text")
    extractor = DeterministicExtractor()

    with pytest.raises(ProcessingError, match="ENCODING_OR_CONTENT_INVALID"):
        extractor.extract(invalid_encoding.source, encoding_bytes)
    with pytest.raises(ProcessingError, match="FILE_FORMAT_INVALID"):
        extractor.extract(invalid_signature.source, signature_bytes)
