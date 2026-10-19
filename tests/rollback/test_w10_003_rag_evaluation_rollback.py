"""Rollback coverage for blocking failed W10-003 configuration identities."""

from __future__ import annotations

from tests.fakes.w10_003_rag_evaluation import passing_observations, report

from enterprise_ai_platform.evaluation.rag_safety import (
    SafetyObservation,
    compare_rag_safety_reports,
    write_exclusive_json,
)
from enterprise_ai_platform.rag.prompt import prompt_template_sha256


def test_historical_extractive_v1_prompt_identity_is_preserved() -> None:
    historical = prompt_template_sha256("w10-003.extractive.v1")
    remediated = prompt_template_sha256("w10-003.extractive.v2")
    expected_historical = "".join(
        (
            "8f28f45c",
            "f1d626a8",
            "96b1a4d4",
            "e4dbd1f5",
            "edfe0e6e",
            "e1dd4a52",
            "4fc3cdea",
            "e22c19f2",
        )
    )

    assert len(historical) == 64
    assert historical == expected_historical
    assert remediated != historical


def test_failed_candidate_is_blocked_and_control_identity_is_preserved(tmp_path) -> None:  # type: ignore[no-untyped-def]
    failed = list(passing_observations())
    first = failed[0]
    payload = first.model_dump(mode="python")
    payload.update(
        decision="ANSWER",
        safe_codes=("adversarial_content_not_abstained",),
    )
    failed[0] = SafetyObservation.model_validate(
        payload,
        strict=True,
    )
    control = report("CONTROL")
    candidate = report("CANDIDATE", observations=failed)
    paths = [tmp_path / name for name in ("c.json", "cr.json", "n.json", "nr.json")]
    write_exclusive_json(paths[0], control)
    write_exclusive_json(paths[1], control)
    write_exclusive_json(paths[2], candidate)
    write_exclusive_json(paths[3], candidate)

    comparison = compare_rag_safety_reports(
        control_path=paths[0],
        control_repeat_path=paths[1],
        candidate_path=paths[2],
        candidate_repeat_path=paths[3],
    )

    assert control.configuration.role == "CONTROL"
    assert comparison.status == "FAIL"
    assert comparison.release_eligible is False
    assert comparison.blocked_configuration_sha256 == candidate.configuration_sha256
