"""Feature proof for safe N+1 rejection and exact N restoration."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from enterprise_ai_platform.release_rollback import state as state_module
from enterprise_ai_platform.release_rollback.identity import (
    APPROVED_ARTIFACT_COUNT,
    APPROVED_COMPOSITION_SHA256,
    load_release_descriptor,
)
from enterprise_ai_platform.release_rollback.service import rollback_release
from tests.fakes.release_rollback import (
    DeterministicReleaseProbe,
    isolate_release_runtime,
)


def test_n_plus_one_fails_safely_and_exact_n_is_restored_under_deadline(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    isolate_release_runtime(monkeypatch, tmp_path)

    result = asyncio.run(rollback_release(DeterministicReleaseProbe()))
    active = state_module.require_active_state("w4-known-good-v1")

    assert result.regression.probe.http_status == 501
    assert result.regression.probe.safe_error_code == "agent_disabled"
    assert result.regression.probe.rag_calls == 0
    assert result.regression.probe.retrieval_calls == 0
    assert result.regression.probe.embedding_calls == 0
    assert result.regression.probe.provider_calls == 0
    assert result.regression.probe.graph_calls == 0
    assert result.regression.probe.approval_calls == 0
    assert result.regression.probe.tool_calls == 0
    assert result.rollback.rollback_duration_ms <= 30_000
    assert result.rollback.composition_sha256 == APPROVED_COMPOSITION_SHA256
    assert active.active_release == "w4-known-good-v1"
    assert active.agent_route_allowed is False


def test_release_pair_has_identical_99_artifacts_and_only_approved_delta() -> None:
    known_good = load_release_descriptor("w4-known-good-v1")
    candidate = load_release_descriptor("w4-synthetic-regression-v1")

    assert known_good.artifact_count == candidate.artifact_count == (
        APPROVED_ARTIFACT_COUNT
    )
    assert known_good.artifacts == candidate.artifacts
    assert known_good.composition_sha256 == candidate.composition_sha256 == (
        APPROVED_COMPOSITION_SHA256
    )
    serialized = json.dumps(candidate.model_dump(mode="json"), sort_keys=True)
    assert "w4-011.agent-route-disabled.v1" in serialized
    assert "agent_disabled" in serialized
    assert "PROMPT_SECRET_W4_011" not in serialized
    assert "ANSWER_PII_W4_011" not in serialized
