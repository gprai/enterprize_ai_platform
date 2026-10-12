"""Security and privacy coverage for W7-002 processing."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from enterprise_ai_platform.processing.contracts import DocumentRequest
from enterprise_ai_platform.processing.quality import CompatibleQualityEngine
from tests.fakes.w7_002_processing import make_batch, make_document, processing_config


def test_cross_tenant_partition_and_source_are_rejected_before_processing() -> None:
    document, _ = make_document()
    raw = document.model_dump(mode="python")
    raw["partition"]["tenant_id"] = "tenant-b"

    with pytest.raises(ValidationError):
        DocumentRequest.model_validate(raw, strict=False)


def test_quality_report_contains_no_source_content_or_secret_fields() -> None:
    sensitive = b"synthetic-private-marker-secret-value"
    document, _ = make_document(content=sensitive)
    report = CompatibleQualityEngine(processing_config()).evaluate(
        make_batch((document,)),
        (),
        quarantined_count=1,
    )
    serialized = json.dumps(report.model_dump(mode="json"), sort_keys=True)

    assert sensitive.decode() not in serialized
    assert "normalized_text" not in serialized
    assert "secret" not in serialized.casefold()


def test_config_disables_network_and_requires_separate_destructive_approval() -> None:
    config = processing_config()

    assert config.capabilities.network_access == "disabled"
    assert config.capabilities.destructive_reprocessing == "separate_owner_approval_required"
