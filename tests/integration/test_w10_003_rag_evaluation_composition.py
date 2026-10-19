"""Composition coverage for W3 quality plus W10 safety report construction."""

from __future__ import annotations

from enterprise_ai_platform.evaluation.rag_safety import canonical_json_bytes
from tests.fakes.w10_003_rag_evaluation import report


def test_report_composes_quality_safety_privacy_and_configuration_identity() -> None:
    result = report("CANDIDATE")
    payload = canonical_json_bytes(result.model_dump(mode="json"))

    assert result.quality_gate_status == "PASS"
    assert result.safety_gate_status == "PASS"
    assert result.overall_status == "PASS"
    assert result.release_eligible is True
    assert result.metrics.provider_requests == 29
    assert b"question" not in payload
    assert b"untrusted_content" not in payload
