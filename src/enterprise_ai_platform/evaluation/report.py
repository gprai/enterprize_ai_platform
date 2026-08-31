"""Redacted canonical report construction and atomic no-overwrite writing."""

from __future__ import annotations

import hashlib
import json
import os
import threading
from pathlib import Path

from pydantic import ValidationError

from enterprise_ai_platform.json_contracts import strict_json_loads

from .errors import EvaluationReportExistsError, EvaluationReportWriteError
from .models import (
    BaselineStatus,
    CaseAssessment,
    CaseExecution,
    EvaluationMetrics,
    EvaluationReport,
    EvaluationUsageSummary,
    GateResults,
    RedactedCaseResult,
)

_APPROVED_REPORT_NAMES = frozenset({"eval.json", "eval-repeat.json"})


def _canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _atomic_write_no_overwrite(path: Path, payload: bytes) -> None:
    """Publish complete bytes by an exclusive hard link and always remove the sibling."""

    if path.exists():
        raise EvaluationReportExistsError
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
        if temporary.exists():
            raise EvaluationReportWriteError
        try:
            with temporary.open("xb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.link(temporary, path)
            except FileExistsError:
                raise EvaluationReportExistsError from None
        finally:
            temporary.unlink(missing_ok=True)
    except EvaluationReportExistsError:
        raise
    except OSError:
        raise EvaluationReportWriteError from None


def _summarize_usage(
    executions: tuple[CaseExecution, ...],
) -> EvaluationUsageSummary:
    usages = tuple(execution.usage for execution in executions if execution.usage is not None)
    costs = tuple(usage.estimated_cost_usd for usage in usages)
    estimated_cost = (
        sum(cost for cost in costs if cost is not None)
        if costs and all(cost is not None for cost in costs)
        else None
    )
    return EvaluationUsageSummary(
        provider_calls=sum(execution.provider_calls for execution in executions),
        cases_with_usage=len(usages),
        input_tokens=sum(usage.input_tokens for usage in usages),
        output_tokens=sum(usage.output_tokens for usage in usages),
        total_tokens=sum(usage.total_tokens for usage in usages),
        estimated_cost_usd=estimated_cost,
    )


def build_report(
    *,
    executions: tuple[CaseExecution, ...],
    assessments: tuple[CaseAssessment, ...],
    metrics: EvaluationMetrics,
    gates: GateResults,
    dataset_checksum: str,
    configuration_checksum: str,
    baseline_status: BaselineStatus,
    generated_at_utc: str,
    runtime_duration_ms: int,
) -> EvaluationReport:
    """Build a redacted report whose deterministic payload excludes two runtime fields."""

    if len(executions) != len(assessments):
        raise EvaluationReportWriteError
    redacted = tuple(
        RedactedCaseResult(
            case_id=execution.case_id,
            expected_outcome=execution.expected_outcome,
            release_blocking=execution.release_blocking,
            actual_outcome=execution.actual_outcome,
            passed=assessment.passed,
            abstention_reason=execution.abstention_reason,
            error_code=execution.error_code,
            provider_calls=execution.provider_calls,
            usage=execution.usage,
            retrieved_source_count=len(execution.retrieved_source_ids),
            retrieval_recall_numerator=assessment.retrieval_recall_numerator,
            retrieval_recall_denominator=assessment.retrieval_recall_denominator,
            reciprocal_rank=assessment.reciprocal_rank,
            returned_citation_count=len(execution.citations),
            valid_citation_count=assessment.valid_citations,
            security_violation_count=len(execution.security_violations),
            exposed_invalid_citation_count=execution.exposed_invalid_citations,
        )
        for execution, assessment in zip(executions, assessments, strict=True)
    )
    absolute_status = gates.absolute_gate_status
    if absolute_status == "FAIL":
        overall = "FAIL"
    elif baseline_status == "NO_APPROVED_BASELINE":
        overall = "NO_APPROVED_BASELINE"
    elif baseline_status == "INCOMPATIBLE_BASELINE":
        overall = "INCOMPATIBLE_BASELINE"
    else:
        overall = baseline_status
    deterministic = {
        "schema_version": "w3-002.report.v1",
        "evaluator_version": "w3-002.v1",
        "metric_version": "w3-002.metrics.v1",
        "dataset_version": "w3-002.v1",
        "dataset_checksum_sha256": dataset_checksum,
        "configuration_checksum_sha256": configuration_checksum,
        "runtime_duration_classification": "LOCAL_INFORMATIONAL",
        "fake_provider_only": True,
        "network_activity": False,
        "candidate_status": absolute_status,
        "baseline_comparison_status": baseline_status,
        "overall_status": overall,
        "release_eligible": absolute_status == "PASS" and baseline_status == "PASS",
        "candidate_generation_exit": int(
            absolute_status != "PASS" or baseline_status in {"FAIL", "INCOMPATIBLE_BASELINE"}
        ),
        "metrics": metrics.model_dump(mode="json"),
        "usage_summary": _summarize_usage(executions).model_dump(mode="json"),
        "gates": gates.model_dump(mode="json"),
        "cases": tuple(item.model_dump(mode="json") for item in redacted),
    }
    payload_hash = hashlib.sha256(_canonical_json_bytes(deterministic)).hexdigest()
    try:
        return EvaluationReport.model_validate(
            {
                **deterministic,
                "generated_at_utc": generated_at_utc,
                "runtime_duration_ms": runtime_duration_ms,
                "deterministic_payload_sha256": payload_hash,
            },
            strict=True,
        )
    except ValidationError:
        raise EvaluationReportWriteError from None


def write_candidate_report(path: Path, report: EvaluationReport) -> None:
    """Write only one approved report filename without exposing internal case content."""

    if path.name not in _APPROVED_REPORT_NAMES:
        raise EvaluationReportWriteError
    _atomic_write_no_overwrite(path, _canonical_json_bytes(report.model_dump(mode="json")))


def load_evaluation_report(path: Path) -> EvaluationReport:
    """Load a strict redacted report for repeatability or promotion checks."""

    try:
        text = path.read_text(encoding="utf-8", errors="strict")
        strict_json_loads(text)
        report = EvaluationReport.model_validate_json(text, strict=True)
    except (OSError, UnicodeError, TypeError, ValueError, ValidationError):
        raise EvaluationReportWriteError from None
    deterministic = report.model_dump(mode="json")
    deterministic.pop("generated_at_utc")
    deterministic.pop("runtime_duration_ms")
    supplied_hash = deterministic.pop("deterministic_payload_sha256")
    calculated_hash = hashlib.sha256(_canonical_json_bytes(deterministic)).hexdigest()
    if supplied_hash != calculated_hash:
        raise EvaluationReportWriteError
    return report


def canonical_report_bytes(report: EvaluationReport) -> bytes:
    return _canonical_json_bytes(report.model_dump(mode="json"))
