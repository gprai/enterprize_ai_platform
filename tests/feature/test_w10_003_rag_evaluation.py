"""Feature coverage for repeated control-versus-candidate governance."""

from __future__ import annotations

from enterprise_ai_platform.evaluation.rag_safety import (
    compare_rag_safety_reports,
    write_exclusive_json,
)
from tests.fakes.w10_003_rag_evaluation import report


def test_exact_repeats_and_changed_retrieval_identity_can_pass(tmp_path) -> None:  # type: ignore[no-untyped-def]
    paths = {
        "control": tmp_path / "control.json",
        "control_repeat": tmp_path / "control-repeat.json",
        "candidate": tmp_path / "candidate.json",
        "candidate_repeat": tmp_path / "candidate-repeat.json",
    }
    write_exclusive_json(paths["control"], report("CONTROL"))
    write_exclusive_json(paths["control_repeat"], report("CONTROL"))
    write_exclusive_json(paths["candidate"], report("CANDIDATE"))
    write_exclusive_json(paths["candidate_repeat"], report("CANDIDATE"))

    comparison = compare_rag_safety_reports(
        control_path=paths["control"],
        control_repeat_path=paths["control_repeat"],
        candidate_path=paths["candidate"],
        candidate_repeat_path=paths["candidate_repeat"],
    )

    assert comparison.status == "PASS"
    assert comparison.release_eligible is True
    assert "retrieval_mode" in comparison.version_dimensions_changed
    assert "reranker_enabled" in comparison.version_dimensions_changed
    assert comparison.blocked_configuration_sha256 is None
