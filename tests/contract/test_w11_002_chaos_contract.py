"""W11-002 schema, ordering and upstream identity rejection contract."""

from pathlib import Path

import pytest
import yaml

from enterprise_ai_platform.chaos import (
    DEFAULT_CHAOS_POLICY_PATH,
    SCENARIO_CONTRACT,
    SOURCE_PATHS,
    STOP_CONDITIONS,
    load_chaos_policy,
)

ROOT = Path(__file__).resolve().parents[2]


def _copied_root(tmp_path: Path) -> Path:
    paths = (
        DEFAULT_CHAOS_POLICY_PATH,
        *SOURCE_PATHS.values(),
        Path("observability/alerts.yml"),
    )
    for relative in paths:
        destination = tmp_path / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes((ROOT / relative).read_bytes())
    return tmp_path


def test_exact_yaml_policy_has_one_ordered_synthetic_inventory() -> None:
    policy = load_chaos_policy(ROOT / DEFAULT_CHAOS_POLICY_PATH, repository_root=ROOT)
    assert policy.stop_conditions == STOP_CONDITIONS
    assert tuple(item.id for item in policy.scenarios) == tuple(
        item[0] for item in SCENARIO_CONTRACT
    )
    assert policy.blast_radius.maximum_targets == 1
    assert policy.blast_radius.retry_count == 0
    assert policy.live_execution_status == "NOT RUN"


@pytest.mark.parametrize(
    "change",
    ["reordered", "missing", "unknown", "live", "unbounded", "wrong_feature"],
)
def test_modified_schema_or_blast_radius_fails_closed(tmp_path: Path, change: str) -> None:
    root = _copied_root(tmp_path)
    path = root / DEFAULT_CHAOS_POLICY_PATH
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if change == "reordered":
        data["scenarios"][0], data["scenarios"][1] = data["scenarios"][1], data["scenarios"][0]
    elif change == "missing":
        del data["stop_conditions"]
    elif change == "unknown":
        data["unexpected"] = True
    elif change == "live":
        data["execution_mode"] = "aws-fis"
    elif change == "unbounded":
        data["blast_radius"]["maximum_targets"] = 2
    else:
        data["feature_ids"] = ["FIS-002"]
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    with pytest.raises(ValueError):
        load_chaos_policy(path, repository_root=root)


@pytest.mark.parametrize("invalid", ["duplicate", "alias", "utf16", "oversized"])
def test_ambiguous_or_oversized_yaml_fails_closed(tmp_path: Path, invalid: str) -> None:
    root = _copied_root(tmp_path)
    path = root / DEFAULT_CHAOS_POLICY_PATH
    source = path.read_text(encoding="utf-8")
    if invalid == "duplicate":
        path.write_text(source + "\nprompt_id: W11-002\n", encoding="utf-8")
    elif invalid == "alias":
        path.write_text(source + "\nx: &alias value\ny: *alias\n", encoding="utf-8")
    elif invalid == "utf16":
        path.write_bytes(source.encode("utf-16"))
    else:
        path.write_bytes(b"a" * 131_073)
    with pytest.raises(ValueError):
        load_chaos_policy(path, repository_root=root)


def test_upstream_substitution_and_wrong_policy_path_fail_closed(tmp_path: Path) -> None:
    root = _copied_root(tmp_path)
    (root / SOURCE_PATHS["fis_plan_sha256"]).write_bytes(b"changed")
    with pytest.raises(ValueError, match="upstream source identity"):
        load_chaos_policy(root / DEFAULT_CHAOS_POLICY_PATH, repository_root=root)
    with pytest.raises(ValueError, match="authoritative path"):
        load_chaos_policy(ROOT / DEFAULT_CHAOS_POLICY_PATH, repository_root=root)
