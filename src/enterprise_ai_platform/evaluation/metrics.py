"""Pure deterministic W3-002 metric, fact-matching, and release-gate calculations."""

from __future__ import annotations

import unicodedata
from decimal import ROUND_HALF_UP, Decimal
from fractions import Fraction

from .config import EvaluationConfig
from .errors import EvaluationResultError
from .models import (
    CaseAssessment,
    CaseExecution,
    EvaluationMetrics,
    GateResults,
    GateStatus,
    GoldenCase,
    GoldenDataset,
    MetricValue,
    Provenance,
)


def normalize_fact_tokens(value: str) -> tuple[str, ...]:
    """Apply the exact owner-approved NFKC/case-fold/punctuation normalization."""

    normalized = unicodedata.normalize("NFKC", value).casefold()
    normalized = "".join(
        " " if unicodedata.category(character).startswith("P") else character
        for character in normalized
    )
    collapsed = " ".join(normalized.split())
    return () if not collapsed else tuple(collapsed.split(" "))


def contains_contiguous_tokens(answer: str, expected_fact: str) -> bool:
    answer_tokens = normalize_fact_tokens(answer)
    expected_tokens = normalize_fact_tokens(expected_fact)
    if not expected_tokens or len(expected_tokens) > len(answer_tokens):
        return False
    width = len(expected_tokens)
    return any(
        answer_tokens[index : index + width] == expected_tokens
        for index in range(len(answer_tokens) - width + 1)
    )


def _expected_provenance(case: GoldenCase) -> frozenset[Provenance]:
    values: list[Provenance] = []
    for index, chunk_id in enumerate(case.expected_chunk_ids):
        source_id = (
            case.expected_source_ids[index]
            if len(case.expected_source_ids) > 1
            else case.expected_source_ids[0]
        )
        document_id = (
            case.expected_document_ids[index]
            if len(case.expected_document_ids) > 1
            else case.expected_document_ids[0]
        )
        version = (
            case.expected_document_versions[index]
            if len(case.expected_document_versions) > 1
            else case.expected_document_versions[0]
        )
        values.append(
            Provenance(
                source_id=source_id,
                document_id=document_id,
                document_version=version,
                chunk_id=chunk_id,
            )
        )
    return frozenset(values)


def assess_case(case: GoldenCase, execution: CaseExecution) -> CaseAssessment:
    """Assess one case without semantic inference or aggregate compensation."""

    if case.case_id != execution.case_id:
        raise EvaluationResultError
    expected_provenance = _expected_provenance(case) if case.expected_chunk_ids else frozenset()
    valid_citations = sum(item in expected_provenance for item in execution.citations)
    returned_provenance = frozenset(execution.citations)
    citations_valid = bool(execution.citations) and (
        len(returned_provenance) == len(execution.citations)
        and returned_provenance == expected_provenance
    )
    provider_calls_correct = execution.provider_calls == case.expected_provider_calls
    usage_correct = (execution.usage is not None) == case.expected_usage_retained
    facts_correct = bool(
        execution.actual_outcome == "ANSWERED"
        and execution.answer_text is not None
        and citations_valid
        and all(
            contains_contiguous_tokens(execution.answer_text, fact)
            for fact in case.expected_facts
        )
    )
    abstention_correct = bool(
        case.expected_outcome == "ABSTAINED"
        and execution.actual_outcome == "ABSTAINED"
        and execution.abstention_reason == case.expected_abstention_reason
        and not execution.citations
        and execution.answer_text is None
    )
    error_correct = bool(
        case.expected_outcome == "ERROR"
        and execution.actual_outcome == "ERROR"
        and execution.error_code == case.expected_error_code
        and not execution.citations
        and execution.answer_text is None
    )
    found = 0
    retrieval_denominator = 0
    reciprocal_rank = 0.0
    if case.retrieval_metric_eligible:
        expected_sources = frozenset(case.expected_source_ids)
        retrieved = tuple(execution.retrieved_source_ids[:5])
        found = len(expected_sources.intersection(retrieved))
        retrieval_denominator = len(expected_sources)
        for index, source_id in enumerate(retrieved, start=1):
            if source_id in expected_sources:
                reciprocal_rank = 1.0 / index
                break
    outcome_correct = execution.actual_outcome == case.expected_outcome
    passed = (
        outcome_correct and facts_correct and citations_valid
        if case.expected_outcome == "ANSWERED"
        else abstention_correct
        if case.expected_outcome == "ABSTAINED"
        else error_correct
    )
    if execution.security_violations or execution.exposed_invalid_citations:
        passed = False
    if not provider_calls_correct or not usage_correct:
        passed = False
    return CaseAssessment(
        case_id=case.case_id,
        outcome_correct=outcome_correct,
        provider_calls_correct=provider_calls_correct,
        usage_correct=usage_correct,
        facts_correct=facts_correct,
        citations_valid=citations_valid,
        abstention_correct=abstention_correct,
        error_correct=error_correct,
        retrieval_recall_numerator=found,
        retrieval_recall_denominator=retrieval_denominator,
        reciprocal_rank=reciprocal_rank,
        returned_citations=len(execution.citations),
        valid_citations=valid_citations,
        security_violations=len(execution.security_violations),
        exposed_invalid_citations=execution.exposed_invalid_citations,
        passed=passed,
    )


def _metric(numerator: int, denominator: int) -> MetricValue:
    if denominator == 0:
        return MetricValue(
            numerator=0,
            denominator=0,
            value=None,
            display="NOT_APPLICABLE",
        )

    ratio = Fraction(numerator, denominator)
    display = (Decimal(numerator) / Decimal(denominator)).quantize(
        Decimal("0.000001"), rounding=ROUND_HALF_UP
    )
    return MetricValue(
        numerator=numerator,
        denominator=denominator,
        value=float(ratio),
        display=f"{display:.6f}",
    )


def _macro_metric(values: tuple[Fraction, ...]) -> MetricValue:
    if not values:
        return _metric(0, 0)

    total = sum(values, Fraction())
    return _metric(total.numerator, total.denominator * len(values))


def aggregate_metrics(
    dataset: GoldenDataset,
    assessments: tuple[CaseAssessment, ...],
) -> EvaluationMetrics:
    if len(assessments) != 39 or tuple(
        item.case_id for item in assessments
    ) != tuple(case.case_id for case in dataset.cases):
        raise EvaluationResultError
    pairs = tuple(zip(dataset.cases, assessments, strict=True))
    eligible = tuple(item for case, item in pairs if case.retrieval_metric_eligible)
    recall_values = tuple(
        Fraction(
            item.retrieval_recall_numerator,
            item.retrieval_recall_denominator,
        )
        for item in eligible
    )
    mrr_values = tuple(
        Fraction(item.reciprocal_rank).limit_denominator(5) for item in eligible
    )
    answered = tuple(item for case, item in pairs if case.expected_outcome == "ANSWERED")
    abstained = tuple(item for case, item in pairs if case.expected_outcome == "ABSTAINED")
    errors = tuple(item for case, item in pairs if case.expected_outcome == "ERROR")
    result_bearing = answered + abstained
    returned = sum(item.returned_citations for item in answered)
    valid = sum(item.valid_citations for item in answered)
    return EvaluationMetrics(
        recall_at_5=_macro_metric(recall_values),
        mrr=_macro_metric(mrr_values),
        citation_precision=_metric(valid, returned),
        answered_correctness=_metric(sum(item.passed for item in answered), len(answered)),
        abstention_correctness=_metric(
            sum(item.passed for item in abstained), len(abstained)
        ),
        combined_correctness=_metric(
            sum(item.passed for item in result_bearing), len(result_bearing)
        ),
        expected_error_correctness=_metric(
            sum(item.passed for item in errors), len(errors)
        ),
        release_blocking_failures=sum(
            case.release_blocking and not item.passed for case, item in pairs
        ),
        security_violations=sum(item.security_violations for item in assessments),
        exposed_invalid_citations=sum(item.exposed_invalid_citations for item in assessments),
    )


def _passes(metric: MetricValue, threshold: float) -> bool:
    return metric.value is not None and Fraction(
        metric.numerator, metric.denominator
    ) >= Fraction(str(threshold))


def _gate_status(passed: bool) -> GateStatus:
    return "PASS" if passed else "FAIL"


def apply_absolute_gates(metrics: EvaluationMetrics, config: EvaluationConfig) -> GateResults:
    threshold = config.thresholds
    statuses = {
        "recall_at_5": _passes(metrics.recall_at_5, threshold.recall_at_5),
        "citation_precision": _passes(metrics.citation_precision, threshold.citation_precision),
        "answered_correctness": _passes(
            metrics.answered_correctness, threshold.answered_correctness
        ),
        "abstention_correctness": _passes(
            metrics.abstention_correctness, threshold.abstention_correctness
        ),
        "combined_correctness": _passes(
            metrics.combined_correctness, threshold.combined_correctness
        ),
        "expected_error_correctness": _passes(
            metrics.expected_error_correctness,
            threshold.expected_error_correctness,
        ),
        "release_blocking_cases": metrics.release_blocking_failures == 0,
        "security": metrics.security_violations == 0 and metrics.exposed_invalid_citations == 0,
    }
    absolute = all(statuses.values())
    return GateResults(
        recall_at_5=_gate_status(statuses["recall_at_5"]),
        citation_precision=_gate_status(statuses["citation_precision"]),
        answered_correctness=_gate_status(statuses["answered_correctness"]),
        abstention_correctness=_gate_status(statuses["abstention_correctness"]),
        combined_correctness=_gate_status(statuses["combined_correctness"]),
        expected_error_correctness=_gate_status(
            statuses["expected_error_correctness"]
        ),
        release_blocking_cases=_gate_status(statuses["release_blocking_cases"]),
        security=_gate_status(statuses["security"]),
        absolute_gate_status=_gate_status(absolute),
    )
