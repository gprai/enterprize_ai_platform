"""Local deterministic W3-004 rollback-drill orchestration."""

from __future__ import annotations

import hashlib
import json
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from enterprise_ai_platform.evaluation.baseline import (
    compare_with_baseline,
    load_approved_baseline,
)
from enterprise_ai_platform.evaluation.config import load_evaluation_config
from enterprise_ai_platform.evaluation.dataset import load_golden_dataset
from enterprise_ai_platform.evaluation.evaluator import (
    CaseFixtureFactory,
    DeterministicRAGEvaluator,
)
from enterprise_ai_platform.evaluation.fixtures import (
    CaseFixture,
    ControlledProvider,
    fixture_for,
)
from enterprise_ai_platform.evaluation.metrics import (
    aggregate_metrics,
    apply_absolute_gates,
    assess_case,
)
from enterprise_ai_platform.evaluation.models import EvaluationReport, GoldenCase
from enterprise_ai_platform.evaluation.report import (
    build_report,
    canonical_report_bytes,
    load_evaluation_report,
)
from enterprise_ai_platform.json_contracts import strict_json_loads
from enterprise_ai_platform.llm.models import ChatResponse, Usage
from enterprise_ai_platform.rag.config import load_rag_policy

from . import identity as identity_module
from .errors import (
    RAGRollbackError,
    RollbackEvaluationError,
    RollbackStateError,
)
from .identity import (
    canonical_json_bytes,
    identity_sha256,
    validate_identity_pair,
)
from .models import (
    ActivationOutcome,
    CleanlinessResult,
    EvaluationOutcome,
    IdentityAlias,
    IdentityValidationResult,
    RAGIdentityDescriptor,
    RollbackRecord,
)
from .state import (
    REGRESSION_REPORT_PATH,
    RESTORED_REPORT_PATH,
    ROLLBACK_RECORD_PATH,
    activate_identity,
    cleanup_complete_drill,
    load_artifact_bytes,
    publish_artifact,
    read_activation_state,
    require_activation_state,
    verify_runtime_inventory,
)
from .state import (
    verify_zero_residue as verify_state_zero_residue,
)

_SYNTHETIC_REGRESSION_RESPONSE = ChatResponse(
    text=json.dumps(
        {
            "answer": "controlled synthetic regression output",
            "citations": [],
        },
        separators=(",", ":"),
        sort_keys=True,
    ),
    usage=Usage(
        input_tokens=10,
        output_tokens=5,
        total_tokens=15,
        estimated_cost_usd=0.0,
    ),
    stop_reason="end_turn",
)


def _repository_path(relative: str) -> Path:
    return identity_module.REPOSITORY_ROOT / relative


def validate() -> IdentityValidationResult:
    """Validate both immutable identities and all approved transitive inputs."""

    known_good, regression = validate_identity_pair()
    state = read_activation_state()
    artifact_count = verify_runtime_inventory(require_complete=False)
    if (state is None and artifact_count != 0) or (
        state is not None and artifact_count == 0
    ):
        raise RollbackStateError
    if state is not None:
        expected = known_good if state.active_identity == "known-good" else regression
        if state.identity_sha256 != identity_sha256(expected):
            raise RollbackEvaluationError
    return IdentityValidationResult(
        status="VALIDATED",
        known_good_identity_sha256=identity_sha256(known_good),
        regression_identity_sha256=identity_sha256(regression),
    )


def initialize() -> ActivationOutcome:
    validate()
    return activate_identity("known-good", expected_current="absent")


def activate_regression() -> ActivationOutcome:
    validate()
    return activate_identity(
        "synthetic-regression",
        expected_current="known-good",
    )


def rollback() -> ActivationOutcome:
    validate()
    return activate_identity(
        "known-good",
        expected_current="synthetic-regression",
    )


def _regression_fixture(case: GoldenCase) -> CaseFixture:
    ordinary = fixture_for(case)
    if case.case_id not in {"Q1", "Q2"}:
        return ordinary
    return CaseFixture(
        retrieval=ordinary.retrieval,
        provider=ControlledProvider(_SYNTHETIC_REGRESSION_RESPONSE),
        auth_context=ordinary.auth_context,
        query=ordinary.query,
    )


def _require_expected_report(
    report: EvaluationReport,
    identity: RAGIdentityDescriptor,
) -> None:
    expectation = identity.expectation
    failed_cases = tuple(item.case_id for item in report.cases if not item.passed)
    if (
        report.gates.absolute_gate_status != expectation.absolute_gate_status
        or report.baseline_comparison_status
        != expectation.baseline_comparison_status
        or report.overall_status != expectation.overall_status
        or report.release_eligible != expectation.release_eligible
        or report.metrics.answered_correctness.numerator
        != expectation.answered_correct_numerator
        or report.metrics.answered_correctness.denominator
        != expectation.answered_correct_denominator
        or report.metrics.combined_correctness.numerator
        != expectation.combined_correct_numerator
        or report.metrics.combined_correctness.denominator
        != expectation.combined_correct_denominator
        or failed_cases != expectation.invalid_citation_cases
    ):
        raise RollbackEvaluationError
    if identity.identity_alias == "synthetic-regression":
        for item in report.cases[:2]:
            if (
                item.actual_outcome != "ABSTAINED"
                or item.abstention_reason != "invalid_generated_citation"
                or item.returned_citation_count != 0
                or item.valid_citation_count != 0
                or item.provider_calls != 1
                or item.usage is None
            ):
                raise RollbackEvaluationError


async def _evaluate_active_identity(
    alias: IdentityAlias,
    target: Path,
) -> EvaluationOutcome:
    verify_runtime_inventory(require_complete=False)
    state = require_activation_state(alias)
    known_good, regression = validate_identity_pair()
    identity = known_good if alias == "known-good" else regression
    try:
        config, config_checksum = load_evaluation_config(
            _repository_path(identity.evaluation.config_path)
        )
        dataset = load_golden_dataset(
            _repository_path(identity.evidence.dataset_path)
        )
        policy = load_rag_policy(
            _repository_path(identity.rag_configuration.path)
        )
        baseline = load_approved_baseline(
            _repository_path(identity.baseline.path)
        )
        if baseline is None:
            raise RollbackEvaluationError
        fixture_factory: CaseFixtureFactory = (
            fixture_for if alias == "known-good" else _regression_fixture
        )
        started = time.perf_counter_ns()
        executions = await DeterministicRAGEvaluator(
            fixture_factory=fixture_factory
        ).evaluate(dataset, policy)
        assessments = tuple(
            assess_case(case, execution)
            for case, execution in zip(
                dataset.cases,
                executions,
                strict=True,
            )
        )
        metrics = aggregate_metrics(dataset, assessments)
        gates = apply_absolute_gates(metrics, config)
        comparison = compare_with_baseline(
            candidate=metrics,
            config=config,
            dataset_checksum=dataset.checksum_sha256,
            configuration_checksum=config_checksum,
            baseline=baseline,
        )
        report = build_report(
            executions=executions,
            assessments=assessments,
            metrics=metrics,
            gates=gates,
            dataset_checksum=dataset.checksum_sha256,
            configuration_checksum=config_checksum,
            baseline_status=comparison.status,
            generated_at_utc=datetime.now(UTC).isoformat(),
            runtime_duration_ms=(time.perf_counter_ns() - started) // 1_000_000,
        )
        _require_expected_report(report, identity)
        payload = canonical_report_bytes(report)
        publish_artifact(target, payload, expected_state=state)
    except RAGRollbackError:
        raise
    except Exception:
        raise RollbackEvaluationError from None
    outcome_status: Literal[
        "EXPECTED_REGRESSION_DETECTED", "RESTORED_BASELINE_PASS"
    ] = (
        "RESTORED_BASELINE_PASS"
        if alias == "known-good"
        else "EXPECTED_REGRESSION_DETECTED"
    )
    report_path: Literal[
        "reports/w3-004/regression.json", "reports/w3-004/restored.json"
    ] = (
        "reports/w3-004/restored.json"
        if alias == "known-good"
        else "reports/w3-004/regression.json"
    )
    return EvaluationOutcome(
        status=outcome_status,
        report_path=report_path,
        report_sha256=hashlib.sha256(payload).hexdigest(),
        active_identity=alias,
        absolute_gate_status=identity.expectation.absolute_gate_status,
        baseline_comparison_status=(
            identity.expectation.baseline_comparison_status
        ),
        overall_status=identity.expectation.overall_status,
        release_eligible=identity.expectation.release_eligible,
    )


async def evaluate_regression() -> EvaluationOutcome:
    return await _evaluate_active_identity(
        "synthetic-regression",
        REGRESSION_REPORT_PATH,
    )


async def evaluate_restored() -> EvaluationOutcome:
    return await _evaluate_active_identity(
        "known-good",
        RESTORED_REPORT_PATH,
    )


def _load_drill_report(relative: Path) -> tuple[EvaluationReport, str]:
    payload = load_artifact_bytes(relative)
    try:
        report = load_evaluation_report(
            identity_module.REPOSITORY_ROOT / relative
        )
    except Exception:
        raise RollbackEvaluationError from None
    return report, hashlib.sha256(payload).hexdigest()


def finalize() -> RollbackRecord:
    """Write one redacted record after regression detection and restored PASS."""

    verify_runtime_inventory(require_complete=False)
    state = require_activation_state("known-good")
    known_good, regression = validate_identity_pair()
    regression_report, regression_hash = _load_drill_report(
        REGRESSION_REPORT_PATH
    )
    restored_report, restored_hash = _load_drill_report(RESTORED_REPORT_PATH)
    _require_expected_report(regression_report, regression)
    _require_expected_report(restored_report, known_good)
    record = RollbackRecord(
        schema_version="w3-004.rollback-record.v1",
        task_id="W3-ROLLBACK-001",
        finalized_at_utc=datetime.now(UTC).isoformat(),
        known_good_identity_sha256=identity_sha256(known_good),
        regression_identity_sha256=identity_sha256(regression),
        baseline_sha256=known_good.baseline.sha256,
        candidate_sha256=known_good.evaluation.candidate_sha256,
        repeat_sha256=known_good.evaluation.repeat_sha256,
        regression_report_sha256=regression_hash,
        restored_report_sha256=restored_hash,
        regression_status="FAIL",
        restored_status="PASS",
        active_identity="known-good",
        final_status="PASS",
        unexpected_residue_count=0,
        network_activity=False,
        provider_cost_usd=0.0,
        external_archive_retention_days=180,
        warnings=("local_deterministic_scope_only",),
    )
    publish_artifact(
        ROLLBACK_RECORD_PATH,
        canonical_json_bytes(record.model_dump(mode="json")),
        expected_state=state,
    )
    return record


def verify_clean() -> CleanlinessResult:
    validate_identity_pair()
    require_activation_state("known-good")
    count = verify_runtime_inventory(require_complete=True)
    return CleanlinessResult(
        status="CLEAN",
        approved_artifact_count=count,
        unexpected_residue_count=0,
    )


def cleanup(*, external_archive_verified: bool) -> CleanlinessResult:
    validate_identity_pair()
    cleanup_complete_drill(
        external_archive_verified=external_archive_verified
    )
    verify_state_zero_residue()
    validate_identity_pair()
    return CleanlinessResult(
        status="ZERO_RESIDUE",
        approved_artifact_count=0,
        unexpected_residue_count=0,
    )


def verify_zero_residue() -> CleanlinessResult:
    verify_state_zero_residue()
    validate_identity_pair()
    return CleanlinessResult(
        status="ZERO_RESIDUE",
        approved_artifact_count=0,
        unexpected_residue_count=0,
    )


def load_rollback_record() -> RollbackRecord:
    """Load the strict redacted record without exposing evaluation content."""

    try:
        payload = load_artifact_bytes(ROLLBACK_RECORD_PATH)
        text = payload.decode("utf-8", errors="strict")
        strict_json_loads(text)
        return RollbackRecord.model_validate_json(text, strict=True)
    except RAGRollbackError:
        raise
    except (UnicodeError, TypeError, ValueError):
        raise RollbackEvaluationError from None


def active_identity() -> IdentityAlias | None:
    state = read_activation_state()
    return None if state is None else state.active_identity
