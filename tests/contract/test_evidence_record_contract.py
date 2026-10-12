"""Contract tests for the stdout evidence metadata schema."""

from __future__ import annotations

import json

import pytest
from tools.record_test_evidence import build_evidence_record

from tests.fakes import FixedClock

EXPECTED_KEYS = {
    "command",
    "environment",
    "git_sha",
    "git_state",
    "report_path",
    "result",
    "schema_version",
    "timestamp_utc",
}


def test_contract_directory_marker_is_automatic(request: pytest.FixtureRequest) -> None:
    assert request.node.get_closest_marker("contract") is not None


def test_serialized_record_has_exact_approved_keys() -> None:
    record = build_evidence_record(
        command="python -B -m pytest",
        git_sha="UNCOMMITTED",
        git_state="UNCOMMITTED",
        environment="sandbox",
        result="PASS",
        report_path="docs/test-evidence/W1/W1-003.md",
        clock=FixedClock(),
    )
    payload = json.loads(record.to_json())

    assert set(payload) == EXPECTED_KEYS
    assert payload["schema_version"] == "1.0"


def test_uncommitted_sha_requires_matching_state() -> None:
    with pytest.raises(ValueError, match="requires UNCOMMITTED"):
        build_evidence_record(
            command="pytest",
            git_sha="UNCOMMITTED",
            git_state="DIRTY",
            environment="sandbox",
            result="PASS",
            report_path="docs/test-evidence/W1/W1-003.md",
            clock=FixedClock(),
        )


def test_committed_sha_requires_dirty_state() -> None:
    record = build_evidence_record(
        command="pytest",
        git_sha="A" * 40,
        git_state="DIRTY",
        environment="sandbox",
        result="PASS",
        report_path="docs/test-evidence/W1/W1-003.md",
        clock=FixedClock(),
    )
    assert record.git_sha == "a" * 40
    assert record.git_state == "DIRTY"
