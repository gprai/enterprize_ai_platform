"""Strict models for the W3-002 dataset, results, reports, and baselines."""

from __future__ import annotations

import math
from datetime import datetime, timedelta
from decimal import ROUND_HALF_UP, Decimal
from fractions import Fraction
from typing import Annotated, Literal, TypeAlias

from pydantic import BaseModel, ConfigDict, Field, model_validator

from enterprise_ai_platform.llm.models import Usage

HexDigest: TypeAlias = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
GitSha: TypeAlias = Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
CaseId: TypeAlias = Annotated[str, Field(pattern=r"^Q(?:[1-9]|[1-3][0-9])$")]
ExpectedOutcome: TypeAlias = Literal["ANSWERED", "ABSTAINED", "ERROR"]
ActualOutcome: TypeAlias = Literal["ANSWERED", "ABSTAINED", "ERROR"]
ExpectedAbstentionReason: TypeAlias = Literal[
    "insufficient_evidence",
    "no_authorized_evidence",
    "conflicting_evidence",
    "malformed_evidence",
    "invalid_generated_citation",
]
ExpectedErrorCode: TypeAlias = Literal[
    "rag_output_validation_error",
    "llm_malformed_response_error",
]
GateStatus: TypeAlias = Literal["PASS", "FAIL", "INDETERMINATE"]
BaselineStatus: TypeAlias = Literal[
    "PASS",
    "FAIL",
    "NO_APPROVED_BASELINE",
    "INCOMPATIBLE_BASELINE",
]


class StrictEvaluationModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        validate_default=True,
    )


class EvaluationAuthorizationContext(StrictEvaluationModel):
    roles: tuple[Literal["reader", "reviewer", "ingestor", "admin"], ...] = Field(min_length=1)
    clearance: Literal["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"]
    groups: tuple[str, ...]


class GoldenCase(StrictEvaluationModel):
    dataset_version: Literal["w3-002.v1"]
    case_id: CaseId
    question: str = Field(min_length=1, max_length=10_000)
    tenant_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]*$")
    authorization_context: EvaluationAuthorizationContext
    execution_mode: str = Field(min_length=1, max_length=128)
    controlled_fixture_ids: tuple[str, ...]
    supplied_source_ids: tuple[str, ...]
    retrieval_metric_eligible: bool
    expected_outcome: ExpectedOutcome
    expected_abstention_reason: ExpectedAbstentionReason | None
    expected_error_code: ExpectedErrorCode | None
    expected_facts: tuple[str, ...] = Field(min_length=1)
    expected_source_ids: tuple[str, ...]
    expected_document_ids: tuple[HexDigest, ...]
    expected_document_versions: tuple[HexDigest, ...]
    expected_chunk_ids: tuple[HexDigest, ...]
    classification_expectation: Literal[
        "AUTHORIZED",
        "DENIED",
        "NO_EVIDENCE",
        "CONFLICTING_VERSIONS",
        "MALFORMED",
    ]
    acl_expectation: Literal[
        "ALLOWED",
        "DENIED_CLEARANCE",
        "DENIED_TENANT",
        "DENIED_ROLE",
        "NOT_APPLICABLE",
    ]
    expected_provider_calls: int = Field(ge=0, le=1)
    expected_usage_retained: bool
    safety_tags: tuple[str, ...] = Field(min_length=1)
    release_blocking: bool

    @model_validator(mode="after")
    def validate_expected_result_shape(self) -> GoldenCase:
        if self.expected_outcome == "ANSWERED":
            if self.expected_abstention_reason is not None or self.expected_error_code is not None:
                raise ValueError("answered cases cannot define a reason or error")
            if not self.expected_source_ids or not self.expected_chunk_ids:
                raise ValueError("answered cases require expected provenance")
        elif self.expected_outcome == "ABSTAINED":
            if self.expected_abstention_reason is None or self.expected_error_code is not None:
                raise ValueError("abstained cases require only an abstention reason")
        elif self.expected_error_code is None or self.expected_abstention_reason is not None:
            raise ValueError("error cases require only an error code")
        if self.expected_chunk_ids:
            expected_width = len(self.expected_chunk_ids)
            for values in (
                self.expected_source_ids,
                self.expected_document_ids,
                self.expected_document_versions,
            ):
                if len(values) not in {1, expected_width}:
                    raise ValueError("expected provenance arrays do not align")
        elif any(
            (
                self.expected_source_ids,
                self.expected_document_ids,
                self.expected_document_versions,
            )
        ):
            raise ValueError("expected provenance requires an expected chunk")
        expected_provider_usage = (
            (1, True)
            if self.expected_outcome == "ANSWERED"
            or self.expected_abstention_reason == "invalid_generated_citation"
            else (1, False)
            if self.expected_outcome == "ERROR"
            else (0, False)
        )
        if (
            self.expected_provider_calls,
            self.expected_usage_retained,
        ) != expected_provider_usage:
            raise ValueError("provider-call or usage expectation is inconsistent")
        if self.retrieval_metric_eligible and self.expected_outcome != "ANSWERED":
            raise ValueError("retrieval metrics are limited to answered cases")
        if len(set(self.expected_source_ids)) != len(self.expected_source_ids):
            raise ValueError("expected source IDs must be unique")
        if not set(self.expected_source_ids).issubset(self.supplied_source_ids):
            raise ValueError("expected sources must be supplied to the controlled case")
        return self


class GoldenDataset(StrictEvaluationModel):
    version: Literal["w3-002.v1"]
    checksum_sha256: HexDigest
    cases: tuple[GoldenCase, ...] = Field(min_length=39, max_length=39)


class Provenance(StrictEvaluationModel):
    source_id: str
    document_id: HexDigest
    document_version: HexDigest
    chunk_id: HexDigest


class CaseExecution(StrictEvaluationModel):
    case_id: CaseId
    expected_outcome: ExpectedOutcome
    release_blocking: bool
    actual_outcome: ActualOutcome
    answer_text: str | None = None
    abstention_reason: ExpectedAbstentionReason | None = None
    error_code: ExpectedErrorCode | None = None
    retrieved_source_ids: tuple[str, ...] = ()
    citations: tuple[Provenance, ...] = ()
    provider_calls: int = Field(ge=0)
    usage: Usage | None = None
    security_violations: tuple[str, ...] = ()
    exposed_invalid_citations: int = Field(default=0, ge=0)


class CaseAssessment(StrictEvaluationModel):
    case_id: CaseId
    outcome_correct: bool
    provider_calls_correct: bool
    usage_correct: bool
    facts_correct: bool
    citations_valid: bool
    abstention_correct: bool
    error_correct: bool
    retrieval_recall_numerator: int = Field(ge=0)
    retrieval_recall_denominator: int = Field(ge=0)
    reciprocal_rank: float = Field(ge=0.0, le=1.0)
    returned_citations: int = Field(ge=0)
    valid_citations: int = Field(ge=0)
    security_violations: int = Field(ge=0)
    exposed_invalid_citations: int = Field(ge=0)
    passed: bool

    @model_validator(mode="after")
    def validate_retrieval_credit(self) -> CaseAssessment:
        if self.retrieval_recall_denominator == 0:
            if self.retrieval_recall_numerator != 0:
                raise ValueError("ineligible retrieval case has recall credit")
            if self.reciprocal_rank != 0.0:
                raise ValueError("ineligible retrieval case has reciprocal-rank credit")
        elif self.retrieval_recall_numerator > self.retrieval_recall_denominator:
            raise ValueError("retrieval recall count exceeds its denominator")
        return self


class MetricValue(StrictEvaluationModel):
    numerator: int = Field(ge=0)
    denominator: int = Field(ge=0)
    value: float | None
    display: str

    @model_validator(mode="after")
    def validate_value(self) -> MetricValue:
        if self.value is not None and not math.isfinite(self.value):
            raise ValueError("metric value must be finite")
        if self.denominator == 0:
            if self.numerator != 0 or self.value is not None:
                raise ValueError("zero-denominator metrics must be null")
            if self.display != "NOT_APPLICABLE":
                raise ValueError("zero-denominator display must be NOT_APPLICABLE")
            return self
        if self.numerator > self.denominator or self.value is None:
            raise ValueError("metric ratio is outside its exact bounds")
        expected_value = self.numerator / self.denominator
        if not math.isclose(self.value, expected_value, rel_tol=0.0, abs_tol=1e-15):
            raise ValueError("metric value differs from its exact ratio")
        expected_display = (Decimal(self.numerator) / Decimal(self.denominator)).quantize(
            Decimal("0.000001"), rounding=ROUND_HALF_UP
        )
        if self.display != f"{expected_display:.6f}":
            raise ValueError("metric display differs from decimal half-up")
        return self


class EvaluationMetrics(StrictEvaluationModel):
    recall_at_5: MetricValue
    mrr: MetricValue
    citation_precision: MetricValue
    answered_correctness: MetricValue
    abstention_correctness: MetricValue
    combined_correctness: MetricValue
    expected_error_correctness: MetricValue
    release_blocking_failures: int = Field(ge=0)
    security_violations: int = Field(ge=0)
    exposed_invalid_citations: int = Field(ge=0)


class GateResults(StrictEvaluationModel):
    recall_at_5: GateStatus
    citation_precision: GateStatus
    answered_correctness: GateStatus
    abstention_correctness: GateStatus
    combined_correctness: GateStatus
    expected_error_correctness: GateStatus
    release_blocking_cases: GateStatus
    security: GateStatus
    absolute_gate_status: GateStatus


class EvaluationUsageSummary(StrictEvaluationModel):
    provider_calls: int = Field(ge=0)
    cases_with_usage: int = Field(ge=0)
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    total_tokens: int = Field(ge=0)
    estimated_cost_usd: float | None = Field(default=None, ge=0.0)

    @model_validator(mode="after")
    def validate_usage_totals(self) -> EvaluationUsageSummary:
        if self.total_tokens != self.input_tokens + self.output_tokens:
            raise ValueError("evaluation token totals are inconsistent")
        if self.cases_with_usage > self.provider_calls:
            raise ValueError("usage cannot exist without a provider call")
        if self.estimated_cost_usd is not None and not math.isfinite(self.estimated_cost_usd):
            raise ValueError("evaluation cost must be finite")
        return self


class RedactedCaseResult(StrictEvaluationModel):
    case_id: CaseId
    expected_outcome: ExpectedOutcome
    release_blocking: bool
    actual_outcome: ActualOutcome
    passed: bool
    abstention_reason: ExpectedAbstentionReason | None = None
    error_code: ExpectedErrorCode | None = None
    provider_calls: int = Field(ge=0)
    usage: Usage | None = None
    retrieved_source_count: int = Field(ge=0)
    retrieval_recall_numerator: int = Field(ge=0)
    retrieval_recall_denominator: int = Field(ge=0)
    reciprocal_rank: float = Field(ge=0.0, le=1.0)
    returned_citation_count: int = Field(ge=0)
    valid_citation_count: int = Field(ge=0)
    security_violation_count: int = Field(ge=0)
    exposed_invalid_citation_count: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_redacted_counts(self) -> RedactedCaseResult:
        if self.retrieval_recall_numerator > self.retrieval_recall_denominator:
            raise ValueError("retrieval recall count exceeds its denominator")
        if self.valid_citation_count > self.returned_citation_count:
            raise ValueError("valid citation count exceeds returned citations")
        if self.retrieval_recall_denominator == 0 and self.reciprocal_rank != 0.0:
            raise ValueError("ineligible retrieval case has reciprocal-rank credit")
        return self


class EvaluationReport(StrictEvaluationModel):
    schema_version: Literal["w3-002.report.v1"]
    evaluator_version: Literal["w3-002.v1"]
    metric_version: Literal["w3-002.metrics.v1"]
    dataset_version: Literal["w3-002.v1"]
    dataset_checksum_sha256: HexDigest
    configuration_checksum_sha256: HexDigest
    generated_at_utc: str
    runtime_duration_ms: int = Field(ge=0)
    runtime_duration_classification: Literal["LOCAL_INFORMATIONAL"]
    fake_provider_only: Literal[True]
    network_activity: Literal[False]
    candidate_status: GateStatus
    baseline_comparison_status: BaselineStatus
    overall_status: GateStatus | Literal["NO_APPROVED_BASELINE", "INCOMPATIBLE_BASELINE"]
    release_eligible: bool
    candidate_generation_exit: Literal[0, 1]
    deterministic_payload_sha256: HexDigest
    metrics: EvaluationMetrics
    usage_summary: EvaluationUsageSummary
    gates: GateResults
    cases: tuple[RedactedCaseResult, ...] = Field(min_length=39, max_length=39)

    @model_validator(mode="after")
    def require_ordered_unique_inventory(self) -> EvaluationReport:
        try:
            generated_at = datetime.fromisoformat(self.generated_at_utc)
        except ValueError:
            raise ValueError("report timestamp is invalid") from None
        if generated_at.utcoffset() != timedelta(0):
            raise ValueError("report timestamp must use UTC")
        expected = tuple(f"Q{index}" for index in range(1, 40))
        if tuple(case.case_id for case in self.cases) != expected:
            raise ValueError("report cases must be ordered Q1 through Q39")
        gated_metrics = (
            self.metrics.recall_at_5,
            self.metrics.citation_precision,
            self.metrics.answered_correctness,
            self.metrics.abstention_correctness,
            self.metrics.combined_correctness,
            self.metrics.expected_error_correctness,
        )
        if any(metric.denominator == 0 for metric in gated_metrics):
            raise ValueError("report gated metrics require denominators")
        threshold_checks = {
            "recall_at_5": Fraction(
                self.metrics.recall_at_5.numerator,
                self.metrics.recall_at_5.denominator,
            )
            >= Fraction(85, 100),
            "citation_precision": Fraction(
                self.metrics.citation_precision.numerator,
                self.metrics.citation_precision.denominator,
            )
            >= Fraction(1, 1),
            "answered_correctness": Fraction(
                self.metrics.answered_correctness.numerator,
                self.metrics.answered_correctness.denominator,
            )
            >= Fraction(95, 100),
            "abstention_correctness": Fraction(
                self.metrics.abstention_correctness.numerator,
                self.metrics.abstention_correctness.denominator,
            )
            >= Fraction(95, 100),
            "combined_correctness": Fraction(
                self.metrics.combined_correctness.numerator,
                self.metrics.combined_correctness.denominator,
            )
            >= Fraction(95, 100),
            "expected_error_correctness": Fraction(
                self.metrics.expected_error_correctness.numerator,
                self.metrics.expected_error_correctness.denominator,
            )
            >= Fraction(1, 1),
            "release_blocking_cases": self.metrics.release_blocking_failures == 0,
            "security": self.metrics.security_violations == 0
            and self.metrics.exposed_invalid_citations == 0,
        }
        if any(
            getattr(self.gates, name) != ("PASS" if passed else "FAIL")
            for name, passed in threshold_checks.items()
        ) or self.gates.absolute_gate_status != (
            "PASS" if all(threshold_checks.values()) else "FAIL"
        ):
            raise ValueError("report gates differ from exact owner thresholds")
        if self.candidate_status != self.gates.absolute_gate_status:
            raise ValueError("candidate status differs from absolute gates")
        expected_overall = (
            self.candidate_status
            if self.candidate_status != "PASS"
            else self.baseline_comparison_status
        )
        if self.overall_status != expected_overall:
            raise ValueError("overall status differs from gate precedence")
        expected_release = (
            self.candidate_status == "PASS" and self.baseline_comparison_status == "PASS"
        )
        if self.release_eligible != expected_release:
            raise ValueError("release eligibility differs from gate results")
        expected_exit = int(
            self.candidate_status != "PASS"
            or self.baseline_comparison_status in {"FAIL", "INCOMPATIBLE_BASELINE"}
        )
        if self.candidate_generation_exit != expected_exit:
            raise ValueError("candidate exit differs from gate results")
        answered = tuple(case for case in self.cases if case.expected_outcome == "ANSWERED")
        abstained = tuple(case for case in self.cases if case.expected_outcome == "ABSTAINED")
        errors = tuple(case for case in self.cases if case.expected_outcome == "ERROR")
        if (len(answered), len(abstained), len(errors)) != (24, 12, 3):
            raise ValueError("report outcome distribution differs from owner approval")
        exact_counts = (
            (
                self.metrics.answered_correctness,
                sum(case.passed for case in answered),
                24,
            ),
            (
                self.metrics.abstention_correctness,
                sum(case.passed for case in abstained),
                12,
            ),
            (
                self.metrics.combined_correctness,
                sum(case.passed for case in (*answered, *abstained)),
                36,
            ),
            (
                self.metrics.expected_error_correctness,
                sum(case.passed for case in errors),
                3,
            ),
        )
        if any(
            (metric.numerator, metric.denominator) != (numerator, denominator)
            for metric, numerator, denominator in exact_counts
        ):
            raise ValueError("report correctness metrics differ from case results")
        eligible = tuple(case for case in self.cases if case.retrieval_recall_denominator > 0)
        if len(eligible) != 24:
            raise ValueError("report retrieval eligibility count differs from approval")
        recall = sum(
            (
                Fraction(
                    case.retrieval_recall_numerator,
                    case.retrieval_recall_denominator,
                )
                for case in eligible
            ),
            Fraction(),
        ) / len(eligible)
        mrr = sum(
            (Fraction(case.reciprocal_rank).limit_denominator(5) for case in eligible),
            Fraction(),
        ) / len(eligible)
        if self.metrics.recall_at_5.denominator == 0 or self.metrics.mrr.denominator == 0:
            raise ValueError("report retrieval metrics require denominators")
        if (
            Fraction(
                self.metrics.recall_at_5.numerator,
                self.metrics.recall_at_5.denominator,
            )
            != recall
            or Fraction(
                self.metrics.mrr.numerator,
                self.metrics.mrr.denominator,
            )
            != mrr
        ):
            raise ValueError("report retrieval metrics differ from case results")
        returned = sum(case.returned_citation_count for case in answered)
        valid = sum(case.valid_citation_count for case in answered)
        if (
            returned == 0
            or self.metrics.citation_precision.denominator == 0
            or (
                Fraction(
                    self.metrics.citation_precision.numerator,
                    self.metrics.citation_precision.denominator,
                )
                != Fraction(valid, returned)
            )
        ):
            raise ValueError("report citation precision differs from case results")
        if self.metrics.security_violations != sum(
            case.security_violation_count for case in self.cases
        ) or self.metrics.exposed_invalid_citations != sum(
            case.exposed_invalid_citation_count for case in self.cases
        ):
            raise ValueError("report hard-blocker counts differ from case results")
        if self.metrics.release_blocking_failures != sum(
            case.release_blocking and not case.passed for case in self.cases
        ):
            raise ValueError("report release-blocking count differs from case results")
        usages = tuple(case.usage for case in self.cases if case.usage is not None)
        usage_values = (
            sum(case.provider_calls for case in self.cases),
            len(usages),
            sum(usage.input_tokens for usage in usages),
            sum(usage.output_tokens for usage in usages),
            sum(usage.total_tokens for usage in usages),
        )
        summary_values = (
            self.usage_summary.provider_calls,
            self.usage_summary.cases_with_usage,
            self.usage_summary.input_tokens,
            self.usage_summary.output_tokens,
            self.usage_summary.total_tokens,
        )
        if usage_values != summary_values:
            raise ValueError("report usage summary differs from case results")
        costs = tuple(usage.estimated_cost_usd for usage in usages)
        expected_cost = (
            sum(cost for cost in costs if cost is not None)
            if costs and all(cost is not None for cost in costs)
            else None
        )
        if expected_cost is None:
            if self.usage_summary.estimated_cost_usd is not None:
                raise ValueError("report cost must remain unknown")
        elif self.usage_summary.estimated_cost_usd is None or not math.isclose(
            self.usage_summary.estimated_cost_usd,
            expected_cost,
            rel_tol=0.0,
            abs_tol=1e-15,
        ):
            raise ValueError("report cost differs from case usage")
        return self


class ApprovedBaseline(StrictEvaluationModel):
    schema_version: Literal["w3-002.baseline.v1"]
    repository_sha: GitSha
    dataset_version: Literal["w3-002.v1"]
    dataset_checksum_sha256: HexDigest
    evaluator_version: Literal["w3-002.v1"]
    metric_version: Literal["w3-002.metrics.v1"]
    configuration_checksum_sha256: HexDigest
    candidate_sha256: HexDigest
    repeat_report_sha256: HexDigest
    deterministic_payload_sha256: HexDigest
    reviewer: str
    decision: Literal["APPROVED"]
    approved_at: str
    metrics: EvaluationMetrics
    gates: GateResults

    @model_validator(mode="after")
    def require_owner_approval_identity(self) -> ApprovedBaseline:
        if self.reviewer != "Gyan Prakash Rai":
            raise ValueError("baseline reviewer differs from owner approval")
        try:
            approved_at = datetime.fromisoformat(self.approved_at)
        except ValueError:
            raise ValueError("baseline approval timestamp is invalid") from None
        if approved_at.tzinfo is None or approved_at.utcoffset() is None:
            raise ValueError("baseline approval timestamp requires an offset")
        return self
