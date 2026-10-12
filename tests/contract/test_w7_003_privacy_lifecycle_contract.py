"""Contract coverage for strict W7-003 configuration and schemas."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from enterprise_ai_platform.ingestion.governance import GovernanceContractError
from enterprise_ai_platform.ingestion.privacy_lifecycle import (
    LifecyclePlan,
    load_privacy_lifecycle_config,
)
from tests.fakes.w7_003_privacy_lifecycle import config, plan


def test_config_is_exact_source_only_and_has_stable_identity() -> None:
    first = config()
    second = config()
    assert first.identity == second.identity
    assert first.retention_days.model_dump() == {
        "raw": 7,
        "quarantine": 7,
        "processed": 30,
        "evidence": 30,
    }
    assert first.lifecycle.destructive_retry == "disabled"
    assert first.lifecycle.live_cloud_execution == "separate_owner_approval_required"


def test_duplicate_config_key_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "duplicate.yaml"
    path.write_text("schema_version: one\nschema_version: two\n", encoding="utf-8")
    with pytest.raises(GovernanceContractError):
        load_privacy_lifecycle_config(path)


def test_unknown_plan_field_and_missing_kms_retention_fail_closed() -> None:
    raw = plan().model_dump(mode="python")
    raw["unexpected"] = "not-approved"
    with pytest.raises(ValidationError):
        LifecyclePlan.model_validate(raw)
    raw.pop("unexpected")
    raw["retained_resources"] = raw["retained_resources"][:2]
    with pytest.raises(ValidationError, match="KMS"):
        LifecyclePlan.model_validate(raw)
