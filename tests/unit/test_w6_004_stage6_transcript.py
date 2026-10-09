"""Tests for bounded synthetic Stage 6 transcript evidence."""

from __future__ import annotations

from pathlib import Path

import pytest
from tools.w6_004_stage6_transcript import (
    TranscriptError,
    build_package,
    synthetic_questions,
    validate_transcript,
)

IMAGE = (
    "526338061652.dkr.ecr.ap-southeast-1.amazonaws.com/enterprise-ai/sandbox/api@sha256:" + "a" * 64
)
OPERATION = "stage6-transcript-001"


def _transcript() -> dict[str, object]:
    questions = synthetic_questions(OPERATION)
    return {
        "schema_version": "w6-004.stage6-transcript.v1",
        "operation_identity": OPERATION,
        "model_id": "global.amazon.nova-2-lite-v1:0",
        "application_image": IMAGE,
        "started_at": "2026-10-09T00:00:00Z",
        "completed_at": "2026-10-09T00:00:01Z",
        "tests": [
            {
                "test_id": "grounded",
                "question": questions["grounded"],
                "response": {
                    "request_id": "4d90e3d2-512c-448b-a168-98a146151159",
                    "outcome": "answered",
                    "answer": "Synthetic grounded answer.",
                    "citations": [{"source_id": "W6-004-STAGE6-ACCESSIBLE"}],
                    "prompt_version": "w3-001.v1",
                    "usage": {"input_tokens": 4, "output_tokens": 3, "total_tokens": 7},
                },
            },
            {
                "test_id": "abstention",
                "question": questions["abstention"],
                "response": {
                    "request_id": "897a77bf-fd79-4030-a553-98bcd37de620",
                    "outcome": "abstained",
                    "reason": "insufficient_evidence",
                    "prompt_version": "w3-001.v1",
                },
            },
        ],
    }


def test_transcript_preserves_exact_synthetic_questions_and_responses() -> None:
    transcript = _transcript()
    assert validate_transcript(transcript, operation_identity=OPERATION) == transcript


@pytest.mark.parametrize("protected", ["Authorization", "Bearer token", "access_key"])
def test_transcript_rejects_protected_material(protected: str) -> None:
    transcript = _transcript()
    transcript["tests"][0]["response"]["answer"] = protected  # type: ignore[index]
    with pytest.raises(TranscriptError, match="protected"):
        validate_transcript(transcript, operation_identity=OPERATION)


def test_transcript_rejects_unapproved_question() -> None:
    transcript = _transcript()
    transcript["tests"][0]["question"] = "real tenant question"  # type: ignore[index]
    with pytest.raises(TranscriptError, match="question"):
        validate_transcript(transcript, operation_identity=OPERATION)


def test_package_is_immutable_network_bounded_and_contains_tracked_source() -> None:
    package = build_package(
        operation_identity=OPERATION,
        application_image=IMAGE,
        mutation_deadline="2026-10-09T12:00:00Z",
        service_cluster_ip="172.20.164.11",
    )
    items = package["items"]
    assert items[0]["immutable"] is True  # type: ignore[index]
    assert "w6_004_stage6_transcript.py" in items[0]["data"]  # type: ignore[index]
    assert items[1]["spec"]["egress"][1]["to"][0]["ipBlock"]["cidr"] == (  # type: ignore[index]
        "172.20.164.11/32"
    )
    container = items[2]["spec"]["template"]["spec"]["containers"][0]  # type: ignore[index]
    assert container["image"] == IMAGE
    assert all(item["name"] != "Authorization" for item in container["env"])
    assert Path("tools/w6_004_stage6_transcript.py").is_file()
