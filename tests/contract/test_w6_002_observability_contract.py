from pathlib import Path

from tools.w6_002_observability import EXPECTED_ALERTS, PASS_STATUS, validate

ROOT = Path(__file__).resolve().parents[2]


def test_complete_observability_artifact_contract() -> None:
    assert validate(ROOT) == PASS_STATUS
    assert len(EXPECTED_ALERTS) == 10


def test_cloud_artifacts_are_explicitly_non_executing() -> None:
    fis = (ROOT / "configs/chaos/fis-plan.yaml").read_text(encoding="utf-8")
    collector = (ROOT / "configs/observability/otel-collector.aws.yaml").read_text(encoding="utf-8")
    assert "plan-only-not-authorized-for-execution" in fis
    assert "W6-004-owner-approval-required" in fis
    assert "W6-004 owns deployment and live validation" in collector
