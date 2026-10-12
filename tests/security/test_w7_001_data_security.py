"""Security coverage for W7-001 redaction and fail-closed metadata."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from enterprise_ai_platform.ingestion.governance import canonical_json_bytes
from tests.fakes.w7_001_data_foundation import make_event


def test_audit_safe_contract_contains_no_source_content_or_credentials() -> None:
    event = make_event()
    encoded = canonical_json_bytes(
        {
            "correlation_id": event.processing.correlation_id,
            "source_identity": event.source.original_content_sha256,
            "reason": "METADATA_VALID",
        }
    ).lower()
    for forbidden in (b"document content", b"credential", b"token", b"vector", b"exception"):
        assert forbidden not in encoded


@pytest.mark.parametrize("field", ["tenant_id", "classification", "retention_class"])
def test_missing_governance_metadata_fails_closed(field: str) -> None:
    event = make_event()
    payload = event.model_dump(mode="python")
    del payload["governance"][field]
    with pytest.raises(ValidationError):
        type(event).model_validate(payload)
