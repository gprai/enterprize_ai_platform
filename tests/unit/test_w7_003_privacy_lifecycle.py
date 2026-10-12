"""Unit coverage for W7-003 privacy decisions and bounded approvals."""

from __future__ import annotations

from datetime import timedelta

import pytest
from pydantic import ValidationError

from enterprise_ai_platform.ingestion.models import PiiFinding
from enterprise_ai_platform.ingestion.privacy_lifecycle import (
    DestructiveApproval,
    EvidenceState,
    PrivacyDisposition,
    ReindexRequest,
    assess_privacy,
)
from tests.fakes.w7_003_privacy_lifecycle import FIXED_NOW, approval, discovery, plan, source


def test_clear_and_redacted_privacy_assessments_are_content_safe() -> None:
    target = source()
    macie = discovery(target.identity)
    clear = assess_privacy(
        text="synthetic public text",
        source_identity_sha256=target.identity,
        classification="INTERNAL",
        presidio_findings=(),
        macie=macie,
    )
    finding = PiiFinding(entity_type="EMAIL_ADDRESS", start=0, end=16, confidence=0.9)
    redacted = assess_privacy(
        text="user@example.com",
        source_identity_sha256=target.identity,
        classification="INTERNAL",
        presidio_findings=(finding,),
        macie=macie,
        redacted_text="<EMAIL_ADDRESS>",
    )

    assert clear.disposition is PrivacyDisposition.CLEAR
    assert redacted.disposition is PrivacyDisposition.REDACTED
    assert redacted.redacted_text == "<EMAIL_ADDRESS>"
    assert "user@example.com" not in redacted.model_dump_json()


def test_mismatch_error_and_missing_redaction_quarantine() -> None:
    target = source()
    finding = PiiFinding(entity_type="EMAIL_ADDRESS", start=0, end=1, confidence=0.9)
    for macie in (
        discovery("f" * 64),
        discovery(target.identity, state=EvidenceState.FAIL, classification=None),
        discovery(target.identity, classification="PUBLIC"),
    ):
        result = assess_privacy(
            text="x",
            source_identity_sha256=target.identity,
            classification="INTERNAL",
            presidio_findings=(finding,),
            macie=macie,
        )
        assert result.disposition is PrivacyDisposition.QUARANTINED


def test_approval_exceeding_fifteen_minutes_is_rejected() -> None:
    value = approval(plan()).model_dump(mode="python")
    value["expires_at"] = FIXED_NOW + timedelta(minutes=15, seconds=1)
    with pytest.raises(ValidationError, match="15 minutes"):
        DestructiveApproval.model_validate(value)


def test_reindex_requires_prior_and_new_distinct_manifests() -> None:
    with pytest.raises(ValidationError, match="new manifest"):
        ReindexRequest(
            schema_version="w7-003.reindex.v1",
            source=source(),
            prior_manifest_sha256="a" * 64,
            privacy_assessment_sha256="b" * 64,
            quality_report_sha256="c" * 64,
            new_manifest_sha256="a" * 64,
        )
