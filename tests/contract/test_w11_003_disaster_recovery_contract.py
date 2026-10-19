"""W11-003 policy, schema, ordering and identity rejection contract."""

from pathlib import Path

import pytest
import yaml

from enterprise_ai_platform.disaster_recovery import (
    DEFAULT_RECOVERY_POLICY_PATH,
    RECOVERY_SCOPE_ORDER,
    SOURCE_PATHS,
    STOP_CONDITIONS,
    RecoveryAssetIdentity,
    RecoveryScope,
    load_recovery_policy,
)
from enterprise_ai_platform.retrieval.models import Classification
from tests.fakes.w11_003_disaster_recovery import NOW, digest

ROOT = Path(__file__).resolve().parents[2]


def _copied_root(tmp_path: Path) -> Path:
    for relative in (DEFAULT_RECOVERY_POLICY_PATH, *SOURCE_PATHS.values()):
        destination = tmp_path / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes((ROOT / relative).read_bytes())
    return tmp_path


def test_exact_policy_binds_objectives_scopes_and_unready_status() -> None:
    policy = load_recovery_policy(ROOT / DEFAULT_RECOVERY_POLICY_PATH, repository_root=ROOT)
    assert policy.feature_ids == ("DR-001", "RPO-001")
    assert policy.recovery_scopes == RECOVERY_SCOPE_ORDER
    assert policy.stop_conditions == STOP_CONDITIONS
    assert policy.objectives.target_rpo_seconds == 86400
    assert policy.objectives.target_rto_seconds == 28800
    assert policy.secondary_region is None
    assert policy.multi_region_readiness == "NOT_ESTABLISHED"


@pytest.mark.parametrize(
    "change",
    ["reordered", "missing", "unknown", "live", "secondary", "retry", "feature"],
)
def test_modified_policy_fails_closed(tmp_path: Path, change: str) -> None:
    root = _copied_root(tmp_path)
    path = root / DEFAULT_RECOVERY_POLICY_PATH
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if change == "reordered":
        data["recovery_scopes"][0], data["recovery_scopes"][1] = (
            data["recovery_scopes"][1],
            data["recovery_scopes"][0],
        )
    elif change == "missing":
        del data["objectives"]
    elif change == "unknown":
        data["unexpected"] = True
    elif change == "live":
        data["live_execution_status"] = "PASS"
    elif change == "secondary":
        data["secondary_region"] = "ap-southeast-2"
    elif change == "retry":
        data["execution"]["mutation_retry_count"] = 1
    else:
        data["feature_ids"] = ["DR-001"]
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    with pytest.raises(ValueError):
        load_recovery_policy(path, repository_root=root)


@pytest.mark.parametrize("invalid", ["duplicate", "alias", "utf16", "oversized"])
def test_ambiguous_or_oversized_yaml_fails_closed(tmp_path: Path, invalid: str) -> None:
    root = _copied_root(tmp_path)
    path = root / DEFAULT_RECOVERY_POLICY_PATH
    source = path.read_text(encoding="utf-8")
    if invalid == "duplicate":
        path.write_text(source + "\nprompt_id: W11-003\n", encoding="utf-8")
    elif invalid == "alias":
        path.write_text(source + "\nx: &alias value\ny: *alias\n", encoding="utf-8")
    elif invalid == "utf16":
        path.write_bytes(source.encode("utf-16"))
    else:
        path.write_bytes(b"a" * 131_073)
    with pytest.raises(ValueError):
        load_recovery_policy(path, repository_root=root)


def test_upstream_substitution_and_wrong_policy_path_fail_closed(
    tmp_path: Path,
) -> None:
    root = _copied_root(tmp_path)
    (root / SOURCE_PATHS["storage_module_sha256"]).write_bytes(b"changed")
    with pytest.raises(ValueError, match="upstream source identity"):
        load_recovery_policy(root / DEFAULT_RECOVERY_POLICY_PATH, repository_root=root)
    with pytest.raises(ValueError, match="authoritative path"):
        load_recovery_policy(ROOT / DEFAULT_RECOVERY_POLICY_PATH, repository_root=root)


def test_scope_specific_identity_fields_are_not_interchangeable() -> None:
    common = {
        "scope": RecoveryScope.TERRAFORM_STATE,
        "tenant_id": "tenant-a",
        "classification": Classification.INTERNAL,
        "account_id": "526338061652",
        "region": "ap-southeast-1",
        "source_identity_sha256": digest("source"),
        "artifact_identity_sha256": digest("state"),
        "kms_identity_sha256": digest("kms"),
        "iam_identity_sha256": digest("iam"),
        "recovery_point_at": NOW,
    }
    with pytest.raises(ValueError, match="lineage and serial"):
        RecoveryAssetIdentity.model_validate(common)
    with pytest.raises(ValueError, match="only for Terraform"):
        RecoveryAssetIdentity.model_validate(
            {
                **common,
                "scope": RecoveryScope.OPENSEARCH_INDEX,
                "collection_spec_sha256": digest("collection"),
                "state_lineage": "wrong",
                "state_serial": 12,
            }
        )
