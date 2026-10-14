"""Content-free parameter, artifact, and evaluation-metric admission for W9-002."""

from __future__ import annotations

from decimal import Decimal

from enterprise_ai_platform.evaluation.models import EvaluationReport

from .errors import ExperimentValidationError
from .models import ExperimentInput, ExperimentMetric, MetricUnit

SECRET_KEY_PARTS = (
    "access_key",
    "api_key",
    "authorization",
    "credential",
    "password",
    "private_key",
    "secret",
    "session_token",
    "token",
)
RAW_CONTENT_KEY_PARTS = (
    "answer",
    "chain_of_thought",
    "content",
    "evidence",
    "expected_fact",
    "prompt",
    "question",
    "reasoning",
    "response",
)


def validate_privacy_safe_input(experiment_input: ExperimentInput) -> None:
    """Reject secret-like names and raw-content fields before store access."""

    for parameter in experiment_input.parameters:
        folded = parameter.key.casefold()
        if any(part in folded for part in (*SECRET_KEY_PARTS, *RAW_CONTENT_KEY_PARTS)):
            raise ExperimentValidationError("unsafe experiment parameter name")
    for artifact in experiment_input.artifacts:
        folded = f"{artifact.kind}/{artifact.path}".casefold()
        if any(part in folded for part in (*SECRET_KEY_PARTS, *RAW_CONTENT_KEY_PARTS)):
            raise ExperimentValidationError("unsafe experiment artifact reference")


def _ratio(value: float | None, *, name: str, derivation: str) -> ExperimentMetric:
    if value is None:
        raise ExperimentValidationError(f"{name} is not applicable")
    return ExperimentMetric(
        name=name,
        value=Decimal(str(value)),
        unit=MetricUnit.RATIO,
        derivation=derivation,
    )


def metrics_from_evaluation_report(report: EvaluationReport) -> tuple[ExperimentMetric, ...]:
    """Map only approved aggregate W3-002 report values into lineage metrics."""

    values = [
        _ratio(
            report.metrics.abstention_correctness.value,
            name="abstention_correctness",
            derivation=report.metric_version,
        ),
        _ratio(
            report.metrics.citation_precision.value,
            name="citation_precision",
            derivation=report.metric_version,
        ),
        _ratio(
            report.metrics.combined_correctness.value,
            name="groundedness",
            derivation=report.metric_version,
        ),
        ExperimentMetric(
            name="input_tokens",
            value=Decimal(report.usage_summary.input_tokens),
            unit=MetricUnit.TOKENS,
            derivation=report.metric_version,
        ),
        ExperimentMetric(
            name="latency_ms",
            value=Decimal(report.runtime_duration_ms),
            unit=MetricUnit.MILLISECONDS,
            derivation=report.evaluator_version,
        ),
        ExperimentMetric(
            name="output_tokens",
            value=Decimal(report.usage_summary.output_tokens),
            unit=MetricUnit.TOKENS,
            derivation=report.metric_version,
        ),
        ExperimentMetric(
            name="safety",
            value=Decimal(
                int(
                    report.metrics.security_violations == 0
                    and report.metrics.exposed_invalid_citations == 0
                )
            ),
            unit=MetricUnit.BOOLEAN,
            derivation=report.metric_version,
        ),
        ExperimentMetric(
            name="total_tokens",
            value=Decimal(report.usage_summary.total_tokens),
            unit=MetricUnit.TOKENS,
            derivation=report.metric_version,
        ),
    ]
    if report.usage_summary.estimated_cost_usd is not None:
        values.append(
            ExperimentMetric(
                name="estimated_cost_usd",
                value=Decimal(str(report.usage_summary.estimated_cost_usd)),
                unit=MetricUnit.USD,
                derivation=report.metric_version,
            )
        )
    return tuple(sorted(values, key=lambda metric: metric.name))
