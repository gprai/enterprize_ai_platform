from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from enterprise_ai_platform.orchestration.errors import OrchestrationValidationError
from enterprise_ai_platform.orchestration.models import EventBridgeEnvelope
from enterprise_ai_platform.orchestration.policy import load_workflow_policy
from enterprise_ai_platform.orchestration.serialization import (
    canonical_bytes,
    load_canonical_model,
)
from tests.fakes.w8_003_orchestration import make_auth, make_event, make_policy

ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / "configs" / "orchestration" / "async-workflow-policy.yaml"


def test_policy_has_the_exact_owner_approved_bounds() -> None:
    policy = load_workflow_policy(POLICY_PATH)

    assert policy.feature_ids == ("ORCH-001", "COST-004")
    assert policy.limits.maximum_transitions == 32
    assert policy.limits.maximum_fanout == 8
    assert policy.limits.maximum_active_global == 4
    assert policy.limits.maximum_active_per_tenant == 2
    assert policy.limits.maximum_pending_per_tenant == 8
    assert policy.retry.backoff_seconds == (1, 2)
    assert policy.live_execution == "NOT_AUTHORIZED"
    assert policy.provisioning == "NOT_RUN"


def test_eventbridge_alias_and_canonical_round_trip_are_exact() -> None:
    policy = make_policy()
    event = make_event(policy, make_auth())
    payload = canonical_bytes(event)

    assert b'"detail-type":"AsynchronousInferenceRequested"' in payload
    assert load_canonical_model(EventBridgeEnvelope, payload) == event
    assert len(payload) <= policy.limits.maximum_event_bytes


def test_duplicate_or_reordered_persisted_json_fails_closed() -> None:
    event = make_event(make_policy(), make_auth())
    canonical = canonical_bytes(event)
    duplicate = canonical.replace(b'{"account":', b'{"account":"000000000000","account":', 1)
    parsed = json.loads(canonical)
    reordered_value = dict(reversed(tuple(parsed.items())))
    reordered = (
        json.dumps(reordered_value, ensure_ascii=False, separators=(",", ":")).encode() + b"\n"
    )

    with pytest.raises(OrchestrationValidationError):
        load_canonical_model(EventBridgeEnvelope, duplicate)
    with pytest.raises(OrchestrationValidationError):
        load_canonical_model(EventBridgeEnvelope, reordered)


def test_unknown_event_fields_and_mismatched_detail_type_are_rejected() -> None:
    event = make_event(make_policy(), make_auth())
    unknown = event.model_dump(mode="python", by_alias=True)
    unknown["unexpected"] = "reject"
    mismatch = event.model_dump(mode="python", by_alias=True)
    mismatch["detail-type"] = "ModelTrainingRequested"

    with pytest.raises(ValidationError):
        EventBridgeEnvelope.model_validate(unknown, strict=True)
    with pytest.raises(ValidationError):
        EventBridgeEnvelope.model_validate(mismatch, strict=True)


def test_policy_loader_rejects_duplicate_keys_and_aliases(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.yaml"
    duplicate.write_text("schema_version: one\nschema_version: two\n", encoding="utf-8")
    alias = tmp_path / "alias.yaml"
    alias.write_text("schema_version: &value one\ncopy: *value\n", encoding="utf-8")

    with pytest.raises(OrchestrationValidationError):
        load_workflow_policy(duplicate)
    with pytest.raises(OrchestrationValidationError):
        load_workflow_policy(alias)
