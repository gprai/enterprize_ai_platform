"""Business-flow tests for identity, evidence and supply-chain hardening."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError
from tools.platformctl.image_lifecycle import (
    CoverageResult,
    OciIdentity,
    PackageReconciliation,
    validate_oci_identity,
    validate_package_reconciliation,
)

from enterprise_ai_platform.api.production_identity import SessionStatus, validate_trusted_claims
from enterprise_ai_platform.retrieval.models import Classification, Role

HASH = "a" * 64


def _claims() -> dict[str, object]:
    return {
        "issuer": "https://issuer.example",
        "audience": "enterprise-ai",
        "subject": "user-001",
        "tenant": "tenant-a",
        "groups": frozenset({"readers"}),
        "roles": frozenset({Role.READER}),
        "key_id": "kid-001",
        "issued_at": datetime(2026, 10, 11, 0, 0, tzinfo=UTC),
        "not_before": datetime(2026, 10, 11, 0, 0, tzinfo=UTC),
        "expires_at": datetime(2026, 10, 11, 0, 30, tzinfo=UTC),
        "session_status": SessionStatus.ACTIVE,
        "claim_source_sha256": HASH,
        "clearance": Classification.INTERNAL,
        "token_id": "request-001",
    }


def test_validated_claims_create_existing_auth_context() -> None:
    context = validate_trusted_claims(
        _claims(),
        trusted_issuer="https://issuer.example",
        trusted_audience="enterprise-ai",
        now=datetime(2026, 10, 11, 0, 5, tzinfo=UTC),
    )
    assert context.subject_id == "user-001"
    assert context.tenant_id == "tenant-a"


def test_oci_identities_and_incomplete_package_coverage_remain_distinct() -> None:
    identity = OciIdentity(
        "sha256:" + "1" * 64,
        "sha256:" + "2" * 64,
        "sha256:" + "3" * 64,
        "4" * 64,
    )
    assert validate_oci_identity(identity) == identity
    package = PackageReconciliation(
        HASH,
        "SPDX",
        "b" * 64,
        "c" * 64,
        None,
        None,
        "example",
        "1.0",
        "apk",
        "pkg:apk/example@1.0",
        "pkg:apk/example@1.0",
        "representation unchanged",
        CoverageResult.INDETERMINATE,
        1,
    )
    assert validate_package_reconciliation(package) == package


def test_missing_or_spoofed_identity_claims_are_rejected_before_use() -> None:
    values = _claims()
    values["x_trusted_subject"] = "spoofed"
    with pytest.raises(ValidationError):
        validate_trusted_claims(
            values,
            trusted_issuer="https://issuer.example",
            trusted_audience="enterprise-ai",
            now=datetime(2026, 10, 11, 0, 5, tzinfo=UTC),
        )
