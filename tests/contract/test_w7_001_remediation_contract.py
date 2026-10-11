"""Closed-schema contract coverage for W7-001."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from tools.platformctl.contracts import ContractError, validate_temporary_iam_operation
from tools.platformctl.lifecycle_models import (
    W7_001_SCHEMA_VERSION,
    BedrockLoggingContract,
    ControlResult,
    TemporaryIamOperation,
)
from tools.platformctl.live_validation import W6004Error, validate_bedrock_logging_contract
from tools.production_readiness import load_review, validate_review

ROOT = Path(__file__).resolve().parents[2]
HASH = "a" * 64


def test_temporary_iam_is_exact_expiring_and_restored() -> None:
    operation = TemporaryIamOperation(
        W7_001_SCHEMA_VERSION,
        "iam-001",
        "arn:aws:iam::526338061652:role/exact-role",
        ("logs:GetLogEvents",),
        ("arn:aws:logs:ap-southeast-1:526338061652:log-group:exact",),
        (("aws:RequestedRegion", "ap-southeast-1"),),
        HASH,
        "approval-001",
        "2026-10-11T00:00:00Z",
        "2026-10-11T00:30:00Z",
        "2026-10-11T00:45:00Z",
        HASH,
        HASH,
        ControlResult.PASS,
        ControlResult.PASS,
    )
    validate_temporary_iam_operation(operation, datetime(2026, 10, 11, 0, 15, tzinfo=UTC))
    with pytest.raises(ContractError, match="SCOPE"):
        validate_temporary_iam_operation(
            TemporaryIamOperation(**{**operation.__dict__, "actions": ("logs:*",)}),
            datetime(2026, 10, 11, 0, 15, tzinfo=UTC),
        )


def test_bedrock_logging_defaults_off_and_requires_disablement_identity() -> None:
    contract = BedrockLoggingContract(
        W7_001_SCHEMA_VERSION,
        False,
        True,
        "526338061652",
        "ap-southeast-1",
        None,
        None,
        1,
        "alias/bedrock-logging",
        HASH,
        HASH,
        None,
        ControlResult.NOT_RUN,
    )
    assert validate_bedrock_logging_contract(contract) == contract
    with pytest.raises(W6004Error):
        validate_bedrock_logging_contract(
            BedrockLoggingContract(**{**contract.__dict__, "raw_protected_content_allowed": True})
        )


def test_production_readiness_template_remains_unapproved() -> None:
    review = validate_review(load_review(ROOT / "configs/readiness/production-readiness.yaml"))
    assert review["classification"] == "NOT ESTABLISHED"
    assert review["decision"] is None
    assert review["decided_at"] is None
