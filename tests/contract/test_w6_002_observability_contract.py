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


def test_alert_and_resilience_hardening_remains_unexecuted() -> None:
    import yaml

    slo = yaml.safe_load((ROOT / "configs/observability/slo.yaml").read_text(encoding="utf-8"))
    fis = yaml.safe_load((ROOT / "configs/chaos/fis-plan.yaml").read_text(encoding="utf-8"))
    assert slo["alerting"]["delivery_status"] == "NOT RUN"
    assert slo["metric_contract"]["missing_samples_status"] == "NO_DATA"
    assert slo["objectives"] == {
        "availability_ratio": 0.999,
        "latency_p95_seconds": 4,
        "latency_p99_seconds": 10,
        "retrieval_p99_seconds": 0.75,
        "grounded_or_correct_abstention_ratio": 0.95,
        "recall_at_5": 0.85,
        "isolation_ratio": 1.0,
        "safety_ratio": 1.0,
    }
    assert slo["correlation_contract"] == {
        "request_id_field": "request_id",
        "test_id_field": "test_id",
        "raw_prompt_content_allowed": False,
    }
    assert len(fis["live_scenarios"]["scenarios"]) == 7
    assert all(item["status"] == "NOT RUN" for item in fis["live_scenarios"]["scenarios"])
