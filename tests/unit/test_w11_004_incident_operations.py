from __future__ import annotations

from datetime import datetime

import pytest
from pydantic import ValidationError

from enterprise_ai_platform.incident_operations import (
    CommandClassification,
    GameDayEvidence,
    IncidentStatus,
    NativeVerification,
    classify_command,
    evaluate_game_day_status,
    redact_output,
)
from tests.fakes.w11_004_incident_operations import evidence, failed_command, policy


def test_policy_has_complete_incident_contract() -> None:
    value = policy()
    assert value.feature_ids == ("INC-001", "RUNNER-001")
    assert len(value.roles) == 7
    assert [item.scenario_id for item in value.scenarios] == [
        "CAPACITY",
        "SATURATION",
        "DEPENDENCY_FAILURE",
    ]
    assert value.execution_bounds.maximum_mutation_concurrency == 1
    assert value.execution_bounds.mutation_retries == 0


def test_nonzero_exit_cannot_be_successful() -> None:
    value = evidence()
    data = value.command_evidence[0].model_dump(mode="python")
    data["exit_code"] = 9
    with pytest.raises(ValidationError, match="non-zero command cannot be successful"):
        type(value.command_evidence[0]).model_validate(data)


@pytest.mark.parametrize(
    ("timed_out", "cancelled", "expected"),
    [
        (True, False, CommandClassification.TIMED_OUT),
        (False, True, CommandClassification.CANCELLED),
    ],
)
def test_timeout_and_cancel_are_exact(
    timed_out: bool, cancelled: bool, expected: CommandClassification
) -> None:
    native = NativeVerification(
        verifier="fake",
        expected_identity="a" * 64,
        observed_identity="a" * 64,
        identity_match=True,
        integrity_ok=True,
        health_ok=True,
        expected_absence=False,
        native_absent=False,
        residue_count=0,
        details="local",
    )
    assert (
        classify_command(
            exit_code=-1,
            stderr="",
            timed_out=timed_out,
            cancelled=cancelled,
            expected_absence=False,
            expected_identity="a" * 64,
            native_verification=native,
        )
        is expected
    )


def test_not_found_requires_expected_exact_native_absence() -> None:
    native = NativeVerification(
        verifier="fake",
        expected_identity="a" * 64,
        observed_identity="a" * 64,
        identity_match=True,
        integrity_ok=True,
        health_ok=True,
        expected_absence=True,
        native_absent=True,
        residue_count=0,
        details="local",
    )
    assert (
        classify_command(
            exit_code=1,
            stderr="Resource NotFound",
            timed_out=False,
            cancelled=False,
            expected_absence=True,
            expected_identity="a" * 64,
            native_verification=native,
        )
        is CommandClassification.EXPECTED_ABSENT
    )
    assert (
        classify_command(
            exit_code=1,
            stderr="Resource NotFound",
            timed_out=False,
            cancelled=False,
            expected_absence=False,
            expected_identity="a" * 64,
            native_verification=native,
        )
        is CommandClassification.FAILED
    )


def test_game_day_fails_when_any_command_fails() -> None:
    value = evidence()
    data = value.model_dump(mode="python")
    data["command_evidence"] = (failed_command(value.command_evidence[0]),)
    data["status"] = IncidentStatus.FAIL
    failed = GameDayEvidence.model_validate(data)
    assert evaluate_game_day_status(failed) is IncidentStatus.FAIL


def test_output_redaction_removes_credentials() -> None:
    access_key = "AKIA" + "ABCDEFGHIJKLMNOP"
    value = redact_output(f"Authorization=Bearer-value token=secret-value {access_key}")
    assert "Bearer-value" not in value
    assert "secret-value" not in value
    assert access_key not in value
    assert value.count("[REDACTED]") == 3


def test_naive_evidence_time_is_rejected() -> None:
    value = evidence()
    data = value.model_dump(mode="python")
    data["started_at"] = datetime(2026, 10, 20)
    with pytest.raises(ValidationError, match="timezone-aware"):
        GameDayEvidence.model_validate(data)
