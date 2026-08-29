"""Strict W4-002 state, approval, and canonical-byte contracts."""

from __future__ import annotations

from uuid import uuid4

import pytest
from pydantic import ValidationError

from enterprise_ai_platform.agent.errors import AgentStateValidationError
from enterprise_ai_platform.agent.models import AgentNode, AgentState
from enterprise_ai_platform.agent.serialization import (
    canonical_bytes,
    fingerprint,
    load_canonical_model,
)


def _state() -> AgentState:
    return AgentState(
        request_id=uuid4(),
        run_id=uuid4(),
        tenant_reference_sha256="a" * 64,
        subject_reference_sha256="b" * 64,
        authorization_reference_sha256="c" * 64,
        current_node=AgentNode.VALIDATE_INPUT,
    )


def test_persisted_state_contains_only_the_approved_allowlist() -> None:
    properties = set(AgentState.model_json_schema()["properties"])
    assert not properties.intersection(
        {
            "query",
            "prompt",
            "evidence",
            "chunks",
            "answer",
            "tool_output",
            "credentials",
            "headers",
            "pii",
            "provider_envelope",
            "exception",
            "stack_trace",
            "chain_of_thought",
        }
    )
    assert AgentState.model_config["extra"] == "forbid"
    assert AgentState.model_config["frozen"] is True


def test_canonical_bytes_are_sorted_utf8_and_have_one_newline() -> None:
    payload = canonical_bytes({"z": "é", "a": 1})
    assert payload == '{"a":1,"z":"é"}\n'.encode()
    assert fingerprint({"b": 2, "a": 1}) == fingerprint({"a": 1, "b": 2})
    assert fingerprint({"a": 2}) != fingerprint({"a": 1})


@pytest.mark.parametrize(
    "payload",
    [
        b'{"schema_version":"w4-002.agent-state.v1","schema_version":"x"}\n',
        b'{"value":NaN}\n',
        b"\xff\n",
        b"{}\n\n",
    ],
)
def test_duplicate_nonfinite_invalid_utf8_and_noncanonical_data_fail_closed(
    payload: bytes,
) -> None:
    with pytest.raises(AgentStateValidationError):
        load_canonical_model(AgentState, payload, maximum_bytes=16_384)


def test_invalid_version_unknown_field_and_oversize_are_rejected() -> None:
    state = _state()
    values = state.model_dump(mode="python")
    values["schema_version"] = "unknown"
    with pytest.raises(ValidationError):
        AgentState.model_validate(values, strict=True)
    values = state.model_dump(mode="python")
    values["raw_query"] = "must-not-persist"
    with pytest.raises(ValidationError):
        AgentState.model_validate(values, strict=True)
    with pytest.raises(AgentStateValidationError):
        load_canonical_model(
            AgentState,
            canonical_bytes(state),
            maximum_bytes=10,
        )
