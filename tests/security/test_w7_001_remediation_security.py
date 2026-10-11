"""Security-negative coverage for W7-001."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError
from tools.platformctl.live_validation import W6004Error, require_non_pass_for_limited_evidence

from enterprise_ai_platform.api.production_identity import ProductionIdentityClaims, SessionStatus
from enterprise_ai_platform.retrieval.models import Classification, Role


def test_stale_missing_conflicting_and_caller_trusted_claims_fail_closed() -> None:
    base = {
        "issuer": "https://issuer.example",
        "audience": "enterprise-ai",
        "subject": "user-001",
        "tenant": "tenant-a",
        "groups": frozenset(),
        "roles": frozenset({Role.READER}),
        "key_id": "kid-001",
        "issued_at": datetime(2026, 10, 11, 0, 0, tzinfo=UTC),
        "not_before": datetime(2026, 10, 11, 0, 0, tzinfo=UTC),
        "expires_at": datetime(2026, 10, 11, 0, 30, tzinfo=UTC),
        "session_status": SessionStatus.ACTIVE,
        "claim_source_sha256": "a" * 64,
        "clearance": Classification.INTERNAL,
        "token_id": "token-001",
    }
    for mutation in (
        {"subject": None},
        {"session_status": SessionStatus.REVOKED},
        {"caller_trusted_role": "admin"},
    ):
        with pytest.raises(ValidationError):
            ProductionIdentityClaims.model_validate({**base, **mutation}, strict=True)
    claims = ProductionIdentityClaims.model_validate(base, strict=True)
    with pytest.raises(ValueError, match="stale"):
        claims.to_auth_context(now=datetime(2026, 10, 11, 1, 0, tzinfo=UTC))


def test_limited_waived_or_disputed_evidence_never_becomes_pass() -> None:
    for disposition in ("FAILED", "PARTIAL", "WAIVED", "LIMITED", "CLOSURE_TAIL"):
        with pytest.raises(W6004Error):
            require_non_pass_for_limited_evidence(status="PASS", disposition=disposition)
    with pytest.raises(W6004Error):
        require_non_pass_for_limited_evidence(
            status="PASS", disposition="CURRENT", scanner_disagreement=True
        )
