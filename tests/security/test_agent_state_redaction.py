"""Sentinel-based proof that agent control records retain no content."""

from __future__ import annotations

from uuid import uuid4

import pytest
from pydantic import ValidationError

from enterprise_ai_platform.agent.models import AgentNode, AgentState, AuditDecision
from enterprise_ai_platform.agent.serialization import canonical_bytes, hash_identifier

SENTINELS = (
    "RAW_QUERY_SENTINEL",
    "PROMPT_SENTINEL",
    "CHUNK_SENTINEL",
    "ANSWER_SENTINEL",
    "SECRET_SENTINEL",
    "PII_SENTINEL",
)


def test_serialized_state_contains_hashes_but_no_sensitive_sentinels() -> None:
    state = AgentState(
        request_id=uuid4(),
        run_id=uuid4(),
        tenant_reference_sha256=hash_identifier(SENTINELS[5]),
        subject_reference_sha256=hash_identifier(SENTINELS[4]),
        authorization_reference_sha256="a" * 64,
        current_node=AgentNode.SAFE_TERMINAL,
        result_reference_sha256=hash_identifier(SENTINELS[3]),
    )
    payload = canonical_bytes(state).decode("utf-8")
    assert all(sentinel not in payload for sentinel in SENTINELS)


def test_evidence_and_audit_collection_bounds_are_strict() -> None:
    base = {
        "request_id": uuid4(),
        "run_id": uuid4(),
        "tenant_reference_sha256": "a" * 64,
        "subject_reference_sha256": "b" * 64,
        "authorization_reference_sha256": "c" * 64,
        "current_node": AgentNode.SAFE_TERMINAL,
    }
    with pytest.raises(ValidationError):
        AgentState.model_validate(
            {
                **base,
                "evidence_reference_sha256": tuple(str(index) * 64 for index in range(6)),
            },
            strict=True,
        )
    with pytest.raises(ValidationError):
        AgentState.model_validate(
            {
                **base,
                "audit_decisions": tuple(
                    AuditDecision(
                        sequence=index,
                        node=AgentNode.SAFE_TERMINAL,
                        decision="bounded",
                    )
                    for index in range(1, 10)
                ),
            },
            strict=True,
        )
