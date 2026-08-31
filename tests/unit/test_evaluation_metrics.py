from __future__ import annotations

from pathlib import Path

import pytest

from enterprise_ai_platform.evaluation.config import load_evaluation_config
from enterprise_ai_platform.evaluation.dataset import load_golden_dataset
from enterprise_ai_platform.evaluation.metrics import (
    aggregate_metrics,
    apply_absolute_gates,
    assess_case,
    contains_contiguous_tokens,
    normalize_fact_tokens,
)
from enterprise_ai_platform.evaluation.models import (
    CaseAssessment,
    CaseExecution,
    Provenance,
)
from enterprise_ai_platform.llm.models import Usage

ROOT = Path(__file__).resolve().parents[2]
USAGE = Usage(
    input_tokens=10,
    output_tokens=5,
    total_tokens=15,
    estimated_cost_usd=0.0,
)


def _provenance(case: object) -> tuple[Provenance, ...]:
    values: list[Provenance] = []
    for index, chunk_id in enumerate(case.expected_chunk_ids):  # type: ignore[attr-defined]
        source_ids = case.expected_source_ids  # type: ignore[attr-defined]
        document_ids = case.expected_document_ids  # type: ignore[attr-defined]
        versions = case.expected_document_versions  # type: ignore[attr-defined]
        values.append(
            Provenance(
                source_id=source_ids[index] if len(source_ids) > 1 else source_ids[0],
                document_id=document_ids[index] if len(document_ids) > 1 else document_ids[0],
                document_version=versions[index] if len(versions) > 1 else versions[0],
                chunk_id=chunk_id,
            )
        )
    return tuple(values)


def _perfect_execution(case: object) -> CaseExecution:
    expected = case.expected_outcome  # type: ignore[attr-defined]
    if expected == "ANSWERED":
        return CaseExecution(
            case_id=case.case_id,  # type: ignore[attr-defined]
            expected_outcome=expected,
            release_blocking=case.release_blocking,  # type: ignore[attr-defined]
            actual_outcome="ANSWERED",
            answer_text=" ".join(case.expected_facts),  # type: ignore[attr-defined]
            retrieved_source_ids=case.expected_source_ids,  # type: ignore[attr-defined]
            citations=_provenance(case),
            provider_calls=case.expected_provider_calls,  # type: ignore[attr-defined]
            usage=USAGE,
        )
    if expected == "ABSTAINED":
        return CaseExecution(
            case_id=case.case_id,  # type: ignore[attr-defined]
            expected_outcome=expected,
            release_blocking=case.release_blocking,  # type: ignore[attr-defined]
            actual_outcome="ABSTAINED",
            abstention_reason=case.expected_abstention_reason,  # type: ignore[attr-defined]
            provider_calls=case.expected_provider_calls,  # type: ignore[attr-defined]
            usage=(
                USAGE if case.expected_usage_retained else None  # type: ignore[attr-defined]
            ),
        )
    return CaseExecution(
        case_id=case.case_id,  # type: ignore[attr-defined]
        expected_outcome=expected,
        release_blocking=case.release_blocking,  # type: ignore[attr-defined]
        actual_outcome="ERROR",
        error_code=case.expected_error_code,  # type: ignore[attr-defined]
        provider_calls=case.expected_provider_calls,  # type: ignore[attr-defined]
    )


def test_fact_normalization_and_contiguous_whole_tokens_are_exact() -> None:
    assert normalize_fact_tokens("Ａ—B,  C") == ("a", "b", "c")
    assert contains_contiguous_tokens("Alpha, beta gamma.", "BETA—gamma")
    assert not contains_contiguous_tokens("alphabet soup", "alpha")
    assert not contains_contiguous_tokens("alpha middle beta", "alpha beta")


def test_perfect_inventory_passes_exact_gates_and_macro_metrics() -> None:
    dataset = load_golden_dataset(ROOT / "configs" / "eval" / "golden.jsonl")
    config, _ = load_evaluation_config(ROOT / "configs" / "eval" / "w3-002.yaml")
    executions = tuple(_perfect_execution(case) for case in dataset.cases)
    assessments = tuple(
        assess_case(case, execution)
        for case, execution in zip(dataset.cases, executions, strict=True)
    )
    metrics = aggregate_metrics(dataset, assessments)
    gates = apply_absolute_gates(metrics, config)
    returned_citations = sum(
        len(execution.citations)
        for case, execution in zip(dataset.cases, executions, strict=True)
        if case.expected_outcome == "ANSWERED"
    )
    assert (metrics.recall_at_5.numerator, metrics.recall_at_5.denominator) == (
        24,
        24,
    )
    assert metrics.recall_at_5.display == "1.000000"
    assert (metrics.mrr.numerator, metrics.mrr.denominator) == (24, 24)
    assert metrics.mrr.display == "1.000000"
    assert (
        metrics.citation_precision.numerator,
        metrics.citation_precision.denominator,
    ) == (returned_citations, returned_citations)
    assert (
        metrics.answered_correctness.numerator,
        metrics.answered_correctness.denominator,
    ) == (24, 24)
    assert (
        metrics.abstention_correctness.numerator,
        metrics.abstention_correctness.denominator,
    ) == (12, 12)
    assert (
        metrics.combined_correctness.numerator,
        metrics.combined_correctness.denominator,
    ) == (36, 36)
    assert (
        metrics.expected_error_correctness.numerator,
        metrics.expected_error_correctness.denominator,
    ) == (3, 3)
    assert gates.absolute_gate_status == "PASS"


def test_missing_required_fact_or_supporting_citation_fails_answer() -> None:
    dataset = load_golden_dataset(ROOT / "configs" / "eval" / "golden.jsonl")
    case = dataset.cases[0]
    missing_fact = _perfect_execution(case).model_copy(update={"answer_text": "unrelated"})
    missing_citation = _perfect_execution(case).model_copy(update={"citations": ()})
    assert not assess_case(case, missing_fact).passed
    assert not assess_case(case, missing_citation).passed


def test_duplicate_sources_do_not_add_recall_credit() -> None:
    dataset = load_golden_dataset(ROOT / "configs" / "eval" / "golden.jsonl")
    case = dataset.cases[20]
    execution = _perfect_execution(case).model_copy(
        update={"retrieved_source_ids": (case.expected_source_ids[0],) * 5}
    )
    assessment = assess_case(case, execution)
    assert assessment.retrieval_recall_numerator == 1
    assert assessment.retrieval_recall_denominator == 2


def test_macro_recall_preserves_one_half_credit_as_47_of_48() -> None:
    dataset = load_golden_dataset(ROOT / "configs" / "eval" / "golden.jsonl")
    executions = [_perfect_execution(case) for case in dataset.cases]
    case = dataset.cases[20]
    executions[20] = executions[20].model_copy(
        update={"retrieved_source_ids": (case.expected_source_ids[0],)}
    )
    assessments = tuple(
        assess_case(case, execution)
        for case, execution in zip(dataset.cases, executions, strict=True)
    )

    recall = aggregate_metrics(dataset, assessments).recall_at_5

    assert (recall.numerator, recall.denominator) == (47, 48)
    assert recall.value == 47 / 48
    assert recall.display == "0.979167"


def test_ineligible_q28_receives_no_retrieval_credit() -> None:
    dataset = load_golden_dataset(ROOT / "configs" / "eval" / "golden.jsonl")
    case = dataset.cases[27]
    execution = _perfect_execution(case).model_copy(
        update={"retrieved_source_ids": case.expected_source_ids}
    )

    assessment = assess_case(case, execution)

    assert not case.retrieval_metric_eligible
    assert assessment.retrieval_recall_numerator == 0
    assert assessment.retrieval_recall_denominator == 0
    assert assessment.reciprocal_rank == 0.0


@pytest.mark.parametrize(
    "retrieval_values",
    (
        {
            "retrieval_recall_numerator": 2,
            "retrieval_recall_denominator": 1,
            "reciprocal_rank": 0.0,
        },
        {
            "retrieval_recall_numerator": 1,
            "retrieval_recall_denominator": 0,
            "reciprocal_rank": 0.0,
        },
        {
            "retrieval_recall_numerator": 0,
            "retrieval_recall_denominator": 0,
            "reciprocal_rank": 1.0,
        },
    ),
)
def test_case_assessment_rejects_inconsistent_retrieval_credit(
    retrieval_values: dict[str, int | float],
) -> None:
    valid = CaseAssessment(
        case_id="Q1",
        outcome_correct=True,
        provider_calls_correct=True,
        usage_correct=True,
        facts_correct=True,
        citations_valid=True,
        abstention_correct=False,
        error_correct=False,
        retrieval_recall_numerator=1,
        retrieval_recall_denominator=1,
        reciprocal_rank=1.0,
        returned_citations=1,
        valid_citations=1,
        security_violations=0,
        exposed_invalid_citations=0,
        passed=True,
    )

    with pytest.raises(ValueError):
        CaseAssessment.model_validate(
            {**valid.model_dump(), **retrieval_values},
            strict=True,
        )


def test_exact_case_thresholds_and_mandatory_gates_do_not_compensate() -> None:
    dataset = load_golden_dataset(ROOT / "configs" / "eval" / "golden.jsonl")
    config, _ = load_evaluation_config(ROOT / "configs" / "eval" / "w3-002.yaml")
    perfect = [_perfect_execution(case) for case in dataset.cases]

    one_answer_failure = list(perfect)
    one_answer_failure[0] = one_answer_failure[0].model_copy(
        update={
            "actual_outcome": "ERROR",
            "answer_text": None,
            "citations": (),
            "error_code": "rag_output_validation_error",
        }
    )
    assessments = tuple(
        assess_case(case, execution)
        for case, execution in zip(dataset.cases, one_answer_failure, strict=True)
    )
    gates = apply_absolute_gates(aggregate_metrics(dataset, assessments), config)
    assert gates.answered_correctness == "PASS"
    assert gates.combined_correctness == "PASS"

    one_abstention_failure = list(perfect)
    abstention_index = next(
        index for index, case in enumerate(dataset.cases) if case.expected_outcome == "ABSTAINED"
    )
    one_abstention_failure[abstention_index] = one_abstention_failure[abstention_index].model_copy(
        update={"abstention_reason": "wrong_reason"}
    )
    assessments = tuple(
        assess_case(case, execution)
        for case, execution in zip(dataset.cases, one_abstention_failure, strict=True)
    )
    gates = apply_absolute_gates(aggregate_metrics(dataset, assessments), config)
    assert gates.combined_correctness == "PASS"
    assert gates.abstention_correctness == "FAIL"
    assert gates.absolute_gate_status == "FAIL"


def test_missing_or_unauthorized_source_has_zero_recall_and_mrr_credit() -> None:
    dataset = load_golden_dataset(ROOT / "configs" / "eval" / "golden.jsonl")
    case = dataset.cases[0]
    execution = _perfect_execution(case).model_copy(
        update={"retrieved_source_ids": ("UNAUTHORIZED-SOURCE",)}
    )
    assessment = assess_case(case, execution)
    assert assessment.retrieval_recall_numerator == 0
    assert assessment.reciprocal_rank == 0.0


def test_exposed_invalid_citation_is_a_non_compensable_hard_blocker() -> None:
    dataset = load_golden_dataset(ROOT / "configs" / "eval" / "golden.jsonl")
    config, _ = load_evaluation_config(ROOT / "configs" / "eval" / "w3-002.yaml")
    executions = [_perfect_execution(case) for case in dataset.cases]
    executions[0] = executions[0].model_copy(
        update={
            "citations": (
                Provenance(
                    source_id="FABRICATED",
                    document_id="f" * 64,
                    document_version="f" * 64,
                    chunk_id="f" * 64,
                ),
            ),
            "exposed_invalid_citations": 1,
        }
    )
    assessments = tuple(
        assess_case(case, execution)
        for case, execution in zip(dataset.cases, executions, strict=True)
    )
    metrics = aggregate_metrics(dataset, assessments)
    gates = apply_absolute_gates(metrics, config)
    assert metrics.exposed_invalid_citations == 1
    assert gates.security == "FAIL"
    assert gates.absolute_gate_status == "FAIL"


def test_one_expected_error_mismatch_fails_the_three_of_three_gate() -> None:
    dataset = load_golden_dataset(ROOT / "configs" / "eval" / "golden.jsonl")
    config, _ = load_evaluation_config(ROOT / "configs" / "eval" / "w3-002.yaml")
    executions = [_perfect_execution(case) for case in dataset.cases]
    error_index = next(
        index for index, case in enumerate(dataset.cases) if case.expected_outcome == "ERROR"
    )
    executions[error_index] = executions[error_index].model_copy(
        update={"error_code": "wrong_error"}
    )
    assessments = tuple(
        assess_case(case, execution)
        for case, execution in zip(dataset.cases, executions, strict=True)
    )
    gates = apply_absolute_gates(aggregate_metrics(dataset, assessments), config)
    assert gates.combined_correctness == "PASS"
    assert gates.expected_error_correctness == "FAIL"
    assert gates.absolute_gate_status == "FAIL"


def test_release_blocking_answer_failure_cannot_use_the_one_case_tolerance() -> None:
    dataset = load_golden_dataset(ROOT / "configs" / "eval" / "golden.jsonl")
    config, _ = load_evaluation_config(ROOT / "configs" / "eval" / "w3-002.yaml")
    executions = [_perfect_execution(case) for case in dataset.cases]
    q39_index = next(index for index, case in enumerate(dataset.cases) if case.case_id == "Q39")
    executions[q39_index] = executions[q39_index].model_copy(
        update={"answer_text": "wrong deterministic answer"}
    )
    assessments = tuple(
        assess_case(case, execution)
        for case, execution in zip(dataset.cases, executions, strict=True)
    )
    metrics = aggregate_metrics(dataset, assessments)
    gates = apply_absolute_gates(metrics, config)
    assert gates.answered_correctness == "PASS"
    assert gates.combined_correctness == "PASS"
    assert metrics.release_blocking_failures == 1
    assert gates.release_blocking_cases == "FAIL"
    assert gates.absolute_gate_status == "FAIL"
