"""Unit tests for deterministic evidence metadata and fake providers."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from tools.record_test_evidence import build_evidence_record, redact_command

from tests.fakes import (
    FakeAnswerProvider,
    FakeEnvironmentProvider,
    FakeGitMetadataProvider,
    FixedClock,
)


def test_uncommitted_record_is_deterministic() -> None:
    git_provider = FakeGitMetadataProvider()
    git_sha, git_state = git_provider.metadata()
    record = build_evidence_record(
        command="python -B -m pytest",
        git_sha=git_sha,
        git_state=git_state,
        environment=FakeEnvironmentProvider().name(),
        result="PASS",
        report_path="docs/test-evidence/W1-003.md",
        clock=FixedClock(),
    )

    assert record.timestamp_utc == "2026-01-01T00:00:00Z"
    assert record.git_sha == "UNCOMMITTED"
    assert record.git_state == "UNCOMMITTED"
    assert record.command == "python -B -m pytest"


def test_fake_answer_provider_is_repeatable() -> None:
    provider = FakeAnswerProvider(answer_text="fixed")
    assert provider.answer("first") == "fixed"
    assert provider.answer("second") == "fixed"


@pytest.mark.parametrize("result", ["PASS", "FAIL", "NOT_RUN", "INDETERMINATE"])
def test_approved_results_are_accepted(result: str) -> None:
    record = build_evidence_record(
        command="pytest",
        git_sha="UNCOMMITTED",
        git_state="UNCOMMITTED",
        environment="sandbox",
        result=result,
        report_path="docs/test-evidence/W1-003.md",
        clock=FixedClock(),
    )
    assert record.result == result


def test_unapproved_result_is_rejected() -> None:
    with pytest.raises(ValueError, match="approved evidence value"):
        build_evidence_record(
            command="pytest",
            git_sha="UNCOMMITTED",
            git_state="UNCOMMITTED",
            environment="sandbox",
            result="SUCCESS",
            report_path="docs/test-evidence/W1-003.md",
            clock=FixedClock(),
        )


def test_non_utc_clock_is_rejected() -> None:
    non_utc_clock = FixedClock(
        datetime(2026, 1, 1, tzinfo=timezone(timedelta(hours=1)))
    )
    with pytest.raises(ValueError, match="UTC timestamp"):
        build_evidence_record(
            command="pytest",
            git_sha="UNCOMMITTED",
            git_state="UNCOMMITTED",
            environment="sandbox",
            result="PASS",
            report_path="docs/test-evidence/W1-003.md",
            clock=non_utc_clock,
        )


def test_redaction_preserves_command_shape() -> None:
    redacted = redact_command("pytest --token synthetic-value tests/security")
    assert redacted == "pytest --token [REDACTED] tests/security"
