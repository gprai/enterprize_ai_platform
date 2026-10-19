"""W11-002 composes existing FIS, SLO and alert sources without live calls."""

from pathlib import Path

from enterprise_ai_platform.chaos import (
    DEFAULT_CHAOS_POLICY_PATH,
    SCENARIO_CONTRACT,
    SOURCE_PATHS,
    load_chaos_policy,
)
from enterprise_ai_platform.telemetry.ai_reliability import load_ai_reliability_policy

ROOT = Path(__file__).resolve().parents[2]


def test_all_scenarios_bind_existing_w11_slis() -> None:
    policy = load_chaos_policy(ROOT / DEFAULT_CHAOS_POLICY_PATH, repository_root=ROOT)
    reliability = load_ai_reliability_policy(ROOT / SOURCE_PATHS["slo_policy_sha256"])
    sli_ids = {item.sli_id for item in reliability.slis}
    assert len(reliability.slis) == 17
    assert len(policy.scenarios) == len(SCENARIO_CONTRACT) == 13
    assert all(item.sli_id in sli_ids for item in policy.scenarios)


def test_pinned_fis_boundary_is_one_pod_and_not_node_execution() -> None:
    policy = load_chaos_policy(ROOT / DEFAULT_CHAOS_POLICY_PATH, repository_root=ROOT)
    fis = (ROOT / SOURCE_PATHS["fis_template_sha256"]).read_text(encoding="utf-8")
    iam = (ROOT / SOURCE_PATHS["fis_iam_sha256"]).read_text(encoding="utf-8")
    assert 'selection_mode = "COUNT(1)"' in fis
    assert 'action_id = "aws:eks:pod-delete"' in fis
    assert fis.count("stop_condition {") == 2
    assert "ec2:TerminateInstances" not in iam
    assert policy.scenarios[1].fault == "node_loss_simulated"
