"""Contract coverage for strict W7-002 schemas and configuration."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from enterprise_ai_platform.processing.contracts import (
    DocumentRequest,
    ProcessingContractError,
    load_processing_config,
)
from tests.fakes.w7_002_processing import make_document, processing_config


def test_approved_config_has_stable_identity_and_exact_thresholds() -> None:
    first = processing_config()
    second = processing_config()

    assert first.identity == second.identity
    assert first.quality.minimum_drift_sample == 20
    assert first.quality.duplicate_warning_maximum_ratio == 0.10
    assert first.processing.concurrency == 1


def test_duplicate_yaml_key_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "duplicate.yaml"
    path.write_text("schema_version: one\nschema_version: two\n", encoding="utf-8")

    with pytest.raises(ProcessingContractError):
        load_processing_config(path)


def test_unknown_field_and_tenant_substitution_fail_closed() -> None:
    document, _ = make_document()
    raw = document.model_dump(mode="python")
    raw["unexpected"] = "not-approved"
    with pytest.raises(ValidationError):
        DocumentRequest.model_validate(raw, strict=False)

    raw.pop("unexpected")
    raw["partition"]["tenant_id"] = "tenant-b"
    with pytest.raises(ValidationError, match="partition tenant"):
        DocumentRequest.model_validate(raw, strict=False)


def test_missing_field_and_upstream_source_identity_substitution_fail_closed() -> None:
    document, _ = make_document()
    missing = document.model_dump(mode="python")
    missing.pop("document_id")
    with pytest.raises(ValidationError):
        DocumentRequest.model_validate(missing, strict=False)

    substituted = document.model_dump(mode="python")
    substituted["source"]["upstream_source_identity_sha256"] = "f" * 64
    with pytest.raises(ValidationError, match="source identity"):
        DocumentRequest.model_validate(substituted, strict=False)
