"""Acceptance coverage for privacy-safe AI operations correlation."""

from enterprise_ai_platform.telemetry.ai_operations import (
    AdmissionReason,
    record_admission_state,
    record_rag_result,
)
from tests.fakes.w10_004_ai_operations import RecordingAIOperationsRuntime


def test_quality_cost_and_resilience_signals_share_one_bounded_contract() -> None:
    runtime = RecordingAIOperationsRuntime()
    record_admission_state(
        runtime,
        reason=AdmissionReason.ADMITTED,
        allowed=True,
        queue_depth=0,
    )
    record_rag_result(
        runtime,
        retrieval_quality=0.75,
        groundedness_proxy=1.0,
        citation_coverage=1.0,
        abstained=False,
    )
    assert len(runtime.observations) == 6
    assert {item.signal for item in runtime.observations} == {
        "admission_decision",
        "queue_depth",
        "retrieval_quality",
        "groundedness",
        "citation_coverage",
        "abstention",
    }
    assert all("prompt" not in item.model_dump() for item in runtime.observations)
