"""Read-only compatible-baseline comparison with owner-approved tolerances."""

from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
from pathlib import Path

from pydantic import ValidationError

from enterprise_ai_platform.json_contracts import strict_json_loads

from .config import EvaluationConfig
from .errors import IncompatibleBaselineError
from .models import ApprovedBaseline, BaselineStatus, EvaluationMetrics


@dataclass(frozen=True, slots=True)
class BaselineComparison:
    status: BaselineStatus
    baseline: ApprovedBaseline | None


def load_approved_baseline(path: Path) -> ApprovedBaseline | None:
    """Load one immutable approved baseline or return none when it is absent."""

    if not path.exists():
        return None
    try:
        text = path.read_text(encoding="utf-8", errors="strict")
        strict_json_loads(text)
        return ApprovedBaseline.model_validate_json(text, strict=True)
    except (OSError, UnicodeError, TypeError, ValueError, ValidationError):
        raise IncompatibleBaselineError from None


def _fraction(metrics: EvaluationMetrics, field: str) -> Fraction:
    metric = getattr(metrics, field)
    if metric.denominator == 0:
        raise IncompatibleBaselineError
    return Fraction(metric.numerator, metric.denominator)


def compare_with_baseline(
    *,
    candidate: EvaluationMetrics,
    config: EvaluationConfig,
    dataset_checksum: str,
    configuration_checksum: str,
    baseline: ApprovedBaseline | None,
) -> BaselineComparison:
    """Apply compatibility and regression gates after absolute gates are known."""

    if baseline is None:
        return BaselineComparison(status="NO_APPROVED_BASELINE", baseline=None)
    if (
        baseline.dataset_version != config.dataset_version
        or baseline.dataset_checksum_sha256 != dataset_checksum
        or baseline.evaluator_version != config.evaluator_version
        or baseline.metric_version != config.metric_version
        or baseline.configuration_checksum_sha256 != configuration_checksum
        or baseline.gates.absolute_gate_status != "PASS"
        or baseline.metrics.release_blocking_failures != 0
        or baseline.metrics.security_violations != 0
        or baseline.metrics.exposed_invalid_citations != 0
    ):
        return BaselineComparison(status="INCOMPATIBLE_BASELINE", baseline=baseline)
    tolerance = config.regression_tolerances
    checks = (
        _fraction(candidate, "recall_at_5")
        + Fraction(str(tolerance.recall_at_5))
        >= _fraction(baseline.metrics, "recall_at_5"),
        _fraction(candidate, "citation_precision")
        + Fraction(str(tolerance.citation_precision))
        >= _fraction(baseline.metrics, "citation_precision"),
        _fraction(candidate, "answered_correctness")
        + Fraction(str(tolerance.answered_correctness))
        >= _fraction(baseline.metrics, "answered_correctness"),
        _fraction(candidate, "abstention_correctness")
        + Fraction(str(tolerance.abstention_correctness))
        >= _fraction(baseline.metrics, "abstention_correctness"),
        _fraction(candidate, "combined_correctness")
        + Fraction(str(tolerance.combined_correctness))
        >= _fraction(baseline.metrics, "combined_correctness"),
        _fraction(candidate, "expected_error_correctness")
        + Fraction(str(tolerance.expected_error_correctness))
        >= _fraction(baseline.metrics, "expected_error_correctness"),
        candidate.security_violations == 0,
        candidate.exposed_invalid_citations == 0,
        candidate.release_blocking_failures == 0,
    )
    return BaselineComparison(status="PASS" if all(checks) else "FAIL", baseline=baseline)
