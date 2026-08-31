"""Fail-closed orchestration for the owner-controlled W4-11 rollback drill."""

from __future__ import annotations

import time

from pydantic import ValidationError

from enterprise_ai_platform.json_contracts import strict_json_loads

from .errors import (
    ReleaseCleanupError,
    ReleaseDeadlineError,
    ReleaseRollbackError,
    ReleaseStateConflictError,
    ReleaseStateError,
)
from .identity import (
    APPROVED_ARTIFACT_COUNT,
    APPROVED_COMPOSITION_SHA256,
    canonical_json_bytes,
    descriptor_sha256,
    load_release_descriptor,
    validate_release_pair,
)
from .models import (
    APPROVED_SMOKE_GATES,
    CleanlinessResult,
    RegressionReport,
    ReleaseLifecycleResult,
    ReleaseValidationResult,
    RollbackReport,
    SmokeReport,
)
from .probe import LocalASGIReleaseProbe, ReleaseProbe
from .state import (
    REGRESSION_REPORT_PATH,
    ROLLBACK_REPORT_PATH,
    SMOKE_REPORT_PATH,
    activate_release,
    cleanup_complete_lifecycle,
    load_report_bytes,
    publish_report,
    publish_smoke_and_enable,
    read_active_state,
    require_active_state,
    verify_runtime_inventory,
)
from .state import verify_zero_residue as verify_state_zero_residue

ROLLBACK_DEADLINE_MILLISECONDS = 30_000


def validate() -> ReleaseValidationResult:
    """Rehash immutable releases and fail closed on inconsistent runtime state."""

    known_good, regression = validate_release_pair()
    state = read_active_state()
    artifact_count = verify_runtime_inventory(require_complete=False)
    if (state is None and artifact_count != 0) or (state is not None and artifact_count == 0):
        raise ReleaseStateError
    if state is not None:
        expected = known_good if state.active_release == "w4-known-good-v1" else regression
        if (
            state.descriptor_sha256 != descriptor_sha256(expected)
            or state.composition_sha256 != APPROVED_COMPOSITION_SHA256
            or (state.agent_route_allowed and state.active_release != "w4-known-good-v1")
        ):
            raise ReleaseStateError
        if state.agent_route_allowed:
            if artifact_count != 4:
                raise ReleaseStateError
            smoke_report = _load_smoke_report()
            if (
                smoke_report.generation != state.generation
                or smoke_report.descriptor_sha256 != state.descriptor_sha256
            ):
                raise ReleaseStateError
    return ReleaseValidationResult(
        status="VALIDATED",
        known_good_descriptor_sha256=descriptor_sha256(known_good),
        regression_descriptor_sha256=descriptor_sha256(regression),
        composition_sha256=APPROVED_COMPOSITION_SHA256,
        artifact_count=APPROVED_ARTIFACT_COUNT,
    )


async def rollback_release(
    probe: ReleaseProbe | None = None,
) -> ReleaseLifecycleResult:
    """Activate N+1, prove its safe regression, and restore exact release N."""

    validate()
    current = read_active_state()
    if current is None:
        activate_release("w4-known-good-v1", expected_current="absent")
        current = require_active_state("w4-known-good-v1")
    if (
        current.active_release != "w4-known-good-v1"
        or current.agent_route_allowed
        or verify_runtime_inventory(require_complete=False) != 1
    ):
        raise ReleaseStateConflictError

    candidate_descriptor = load_release_descriptor("w4-synthetic-regression-v1")
    activate_release(
        "w4-synthetic-regression-v1",
        expected_current="w4-known-good-v1",
    )
    candidate_state = require_active_state("w4-synthetic-regression-v1")
    selected_probe = probe or LocalASGIReleaseProbe()
    candidate_probe = await selected_probe.probe_candidate(candidate_descriptor)
    regression = RegressionReport(
        schema_version="w4-011.regression-report.v1",
        task_id="W4-ROLLBACK-001",
        release_version="w4-synthetic-regression-v1",
        descriptor_sha256=descriptor_sha256(candidate_descriptor),
        composition_sha256=candidate_descriptor.composition_sha256,
        generation=candidate_state.generation,
        gate_status="FAIL",
        probe=candidate_probe,
        agent_route_allowed=False,
    )
    publish_report(
        REGRESSION_REPORT_PATH,
        regression,
        expected_state=candidate_state,
    )

    rollback_started = time.monotonic_ns()
    known_good_descriptor = load_release_descriptor("w4-known-good-v1")
    activate_release(
        "w4-known-good-v1",
        expected_current="w4-synthetic-regression-v1",
    )
    restored_state = require_active_state("w4-known-good-v1")
    restored_descriptor = load_release_descriptor("w4-known-good-v1")
    duration_ms = (time.monotonic_ns() - rollback_started) // 1_000_000
    if (
        restored_descriptor != known_good_descriptor
        or restored_state.descriptor_sha256 != descriptor_sha256(known_good_descriptor)
        or restored_state.agent_route_allowed
        or duration_ms > ROLLBACK_DEADLINE_MILLISECONDS
    ):
        if duration_ms > ROLLBACK_DEADLINE_MILLISECONDS:
            raise ReleaseDeadlineError
        raise ReleaseStateError
    rollback = RollbackReport(
        schema_version="w4-011.rollback-report.v1",
        task_id="W4-ROLLBACK-001",
        from_release="w4-synthetic-regression-v1",
        restored_release="w4-known-good-v1",
        restored_descriptor_sha256=descriptor_sha256(known_good_descriptor),
        composition_sha256=known_good_descriptor.composition_sha256,
        generation=restored_state.generation,
        rollback_duration_ms=duration_ms,
        rollback_status="PASS",
        agent_route_allowed=False,
        network_activity=False,
    )
    publish_report(
        ROLLBACK_REPORT_PATH,
        rollback,
        expected_state=restored_state,
    )
    return ReleaseLifecycleResult(
        status="RESTORED_KNOWN_GOOD",
        regression=regression,
        rollback=rollback,
    )


def _load_rollback_report() -> RollbackReport:
    try:
        payload = load_report_bytes(ROLLBACK_REPORT_PATH)
        text = payload.decode("utf-8", errors="strict")
        strict_json_loads(text)
        report = RollbackReport.model_validate_json(text, strict=True)
    except ReleaseRollbackError:
        raise
    except (UnicodeError, TypeError, ValueError, ValidationError):
        raise ReleaseStateError from None
    if payload != canonical_json_bytes(report.model_dump(mode="json")):
        raise ReleaseStateError
    return report


def _load_regression_report() -> RegressionReport:
    try:
        payload = load_report_bytes(REGRESSION_REPORT_PATH)
        text = payload.decode("utf-8", errors="strict")
        strict_json_loads(text)
        report = RegressionReport.model_validate_json(text, strict=True)
    except ReleaseRollbackError:
        raise
    except (UnicodeError, TypeError, ValueError, ValidationError):
        raise ReleaseStateError from None
    if payload != canonical_json_bytes(report.model_dump(mode="json")):
        raise ReleaseStateError
    return report


def _load_smoke_report() -> SmokeReport:
    try:
        payload = load_report_bytes(SMOKE_REPORT_PATH)
        text = payload.decode("utf-8", errors="strict")
        strict_json_loads(text)
        report = SmokeReport.model_validate_json(text, strict=True)
    except ReleaseRollbackError:
        raise
    except (UnicodeError, TypeError, ValueError, ValidationError):
        raise ReleaseStateError from None
    if payload != canonical_json_bytes(report.model_dump(mode="json")):
        raise ReleaseStateError
    return report


async def smoke(probe: ReleaseProbe | None = None) -> SmokeReport:
    """Verify restored N and open its latch only after every Make gate passed."""

    smoke_started = time.monotonic_ns()
    validate()
    state = require_active_state("w4-known-good-v1")
    if state.agent_route_allowed or verify_runtime_inventory(require_complete=False) != 3:
        raise ReleaseStateConflictError
    rollback = _load_rollback_report()
    regression = _load_regression_report()
    descriptor = load_release_descriptor("w4-known-good-v1")
    if (
        rollback.restored_descriptor_sha256 != descriptor_sha256(descriptor)
        or rollback.generation != state.generation
        or regression.composition_sha256 != descriptor.composition_sha256
        or regression.generation + 1 != rollback.generation
    ):
        raise ReleaseStateError
    restored_probe = await (probe or LocalASGIReleaseProbe()).probe_restored(descriptor)
    duration_ms = (time.monotonic_ns() - smoke_started) // 1_000_000
    report = SmokeReport(
        schema_version="w4-011.smoke-report.v1",
        task_id="W4-ROLLBACK-001",
        release_version="w4-known-good-v1",
        descriptor_sha256=descriptor_sha256(descriptor),
        composition_sha256=descriptor.composition_sha256,
        generation=state.generation,
        smoke_duration_ms=duration_ms,
        passed_gates=APPROVED_SMOKE_GATES,
        restored_probe=restored_probe,
        smoke_status="PASS",
        agent_route_allowed_after_publish=True,
        network_activity=False,
    )
    publish_smoke_and_enable(report, expected_state=state)
    return report


def verify_clean() -> CleanlinessResult:
    validate_release_pair()
    state = require_active_state("w4-known-good-v1")
    if not state.agent_route_allowed:
        raise ReleaseCleanupError
    count = verify_runtime_inventory(require_complete=True)
    return CleanlinessResult(
        status="CLEAN",
        approved_artifact_count=count,
        unexpected_residue_count=0,
    )


def cleanup(*, owner_output_captured: bool) -> CleanlinessResult:
    validate_release_pair()
    cleanup_complete_lifecycle(owner_output_captured=owner_output_captured)
    verify_state_zero_residue()
    validate_release_pair()
    return CleanlinessResult(
        status="ZERO_RESIDUE",
        approved_artifact_count=0,
        unexpected_residue_count=0,
    )


def verify_zero_residue() -> CleanlinessResult:
    verify_state_zero_residue()
    validate_release_pair()
    return CleanlinessResult(
        status="ZERO_RESIDUE",
        approved_artifact_count=0,
        unexpected_residue_count=0,
    )
