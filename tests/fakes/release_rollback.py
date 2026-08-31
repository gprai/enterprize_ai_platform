"""Deterministic local collaborators for W4-11 rollback tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from enterprise_ai_platform.release_rollback import state as state_module
from enterprise_ai_platform.release_rollback.identity import validate_release_pair
from enterprise_ai_platform.release_rollback.models import (
    CandidateProbeResult,
    ReleaseDescriptor,
    RestoredProbeResult,
)


def candidate_probe_result() -> CandidateProbeResult:
    return CandidateProbeResult(
        status="EXPECTED_REGRESSION_DETECTED",
        http_status=501,
        safe_error_code="agent_disabled",
        rag_calls=0,
        retrieval_calls=0,
        embedding_calls=0,
        provider_calls=0,
        graph_calls=0,
        approval_calls=0,
        tool_calls=0,
        network_activity=False,
    )


def restored_probe_result() -> RestoredProbeResult:
    return RestoredProbeResult(
        status="RESTORED_RELEASE_VERIFIED",
        health_http_status=200,
        health_status="ok",
        service="enterprise-ai-platform",
        environment="sandbox",
        agent_route_http_status=422,
        agent_route_safe_error_code="api_request_invalid",
        agent_disabled_observed=False,
        network_activity=False,
    )


class DeterministicReleaseProbe:
    def __init__(
        self,
        *,
        candidate: CandidateProbeResult | BaseException | None = None,
        restored: RestoredProbeResult | BaseException | None = None,
    ) -> None:
        self.candidate = candidate or candidate_probe_result()
        self.restored = restored or restored_probe_result()
        self.candidate_calls = 0
        self.restored_calls = 0

    async def probe_candidate(
        self,
        descriptor: ReleaseDescriptor,
    ) -> CandidateProbeResult:
        self.candidate_calls += 1
        if descriptor.release_version != "w4-synthetic-regression-v1":
            raise AssertionError("candidate probe received the wrong release")
        if isinstance(self.candidate, BaseException):
            raise self.candidate
        return self.candidate.model_copy(deep=True)

    async def probe_restored(
        self,
        descriptor: ReleaseDescriptor,
    ) -> RestoredProbeResult:
        self.restored_calls += 1
        if descriptor.release_version != "w4-known-good-v1":
            raise AssertionError("restored probe received the wrong release")
        if isinstance(self.restored, BaseException):
            raise self.restored
        return self.restored.model_copy(deep=True)


def isolate_release_runtime(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Move only mutable runtime state; immutable descriptors remain real."""

    known_good, regression = validate_release_pair()
    (tmp_path / "reports").mkdir()
    monkeypatch.setattr(state_module, "REPOSITORY_ROOT", tmp_path)
    monkeypatch.setattr(
        state_module,
        "load_release_descriptor",
        lambda version: known_good if version == "w4-known-good-v1" else regression,
    )
