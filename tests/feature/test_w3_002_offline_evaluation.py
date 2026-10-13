from __future__ import annotations

import asyncio
from pathlib import Path

from enterprise_ai_platform.evaluation.baseline import compare_with_baseline
from enterprise_ai_platform.evaluation.config import load_evaluation_config
from enterprise_ai_platform.evaluation.dataset import load_golden_dataset
from enterprise_ai_platform.evaluation.evaluator import DeterministicRAGEvaluator
from enterprise_ai_platform.evaluation.metrics import (
    aggregate_metrics,
    apply_absolute_gates,
    assess_case,
)
from enterprise_ai_platform.evaluation.report import build_report
from enterprise_ai_platform.rag.config import load_rag_policy

ROOT = Path(__file__).resolve().parents[2]


def _evaluate() -> tuple[object, ...]:
    dataset = load_golden_dataset(ROOT / "configs" / "eval" / "golden.jsonl")
    config, config_checksum = load_evaluation_config(
        ROOT / "configs" / "eval" / "cited-rag-evaluation-policy.yaml"
    )
    policy = load_rag_policy(ROOT / "configs" / "rag.yaml")
    executions = asyncio.run(DeterministicRAGEvaluator().evaluate(dataset, policy))
    assessments = tuple(
        assess_case(case, execution)
        for case, execution in zip(dataset.cases, executions, strict=True)
    )
    metrics = aggregate_metrics(dataset, assessments)
    gates = apply_absolute_gates(metrics, config)
    return dataset, config, config_checksum, executions, assessments, metrics, gates


def test_all_39_controlled_cases_pass_the_absolute_contract() -> None:
    dataset, _, _, executions, assessments, metrics, gates = _evaluate()

    assert [case.case_id for case in dataset.cases] == [f"Q{index}" for index in range(1, 40)]
    assert all(assessment.passed for assessment in assessments)
    assert all(assessment.provider_calls_correct for assessment in assessments)
    assert all(assessment.usage_correct for assessment in assessments)
    assert metrics.recall_at_5.numerator == 24
    assert metrics.recall_at_5.denominator == 24
    assert metrics.citation_precision.display == "1.000000"
    assert metrics.answered_correctness.numerator == 24
    assert metrics.abstention_correctness.numerator == 12
    assert metrics.combined_correctness.numerator == 36
    assert metrics.expected_error_correctness.numerator == 3
    assert metrics.release_blocking_failures == 0
    assert metrics.security_violations == 0
    assert metrics.exposed_invalid_citations == 0
    assert gates.absolute_gate_status == "PASS"
    assert gates.release_blocking_cases == "PASS"
    assert len(executions) == 39


def test_q24_through_q39_have_exact_fail_closed_results() -> None:
    dataset, _, _, executions, assessments, _, _ = _evaluate()
    by_id = {execution.case_id: execution for execution in executions}
    assessments_by_id = {assessment.case_id: assessment for assessment in assessments}

    for case_id in ("Q24", "Q25", "Q26"):
        result = by_id[case_id]
        assert result.actual_outcome == "ABSTAINED"
        assert result.abstention_reason == "no_authorized_evidence"
        assert result.provider_calls == 0
        assert result.usage is None
    q28 = by_id["Q28"]
    q28_assessment = assessments_by_id["Q28"]
    retrieval_eligible_ids = {
        case.case_id for case in dataset.cases if case.retrieval_metric_eligible
    }
    assert "Q28" not in retrieval_eligible_ids
    assert q28.actual_outcome == "ABSTAINED"
    assert q28.abstention_reason == "conflicting_evidence"
    assert q28.provider_calls == 0
    assert q28_assessment.retrieval_recall_numerator == 0
    assert q28_assessment.retrieval_recall_denominator == 0
    assert q28_assessment.reciprocal_rank == 0.0
    for case_id in ("Q30", "Q32", "Q33", "Q34", "Q35"):
        result = by_id[case_id]
        assert result.actual_outcome == "ABSTAINED"
        assert result.abstention_reason == "invalid_generated_citation"
        assert result.answer_text is None
        assert result.citations == ()
        assert result.provider_calls == 1
        assert result.usage is not None
    assert by_id["Q31"].abstention_reason == "malformed_evidence"
    assert by_id["Q31"].provider_calls == 0
    assert by_id["Q36"].error_code == "rag_output_validation_error"
    assert by_id["Q37"].error_code == "rag_output_validation_error"
    assert by_id["Q38"].error_code == "llm_malformed_response_error"
    q39_chunk_ids = tuple(citation.chunk_id for citation in by_id["Q39"].citations)
    assert q39_chunk_ids == tuple(sorted(q39_chunk_ids))


def test_repeat_execution_and_first_run_report_are_deterministic() -> None:
    dataset, config, config_checksum, first, assessments, metrics, gates = _evaluate()
    policy = load_rag_policy(ROOT / "configs" / "rag.yaml")
    second = asyncio.run(DeterministicRAGEvaluator().evaluate(dataset, policy))
    assert first == second

    comparison = compare_with_baseline(
        candidate=metrics,
        config=config,
        dataset_checksum=dataset.checksum_sha256,
        configuration_checksum=config_checksum,
        baseline=None,
    )
    assert comparison.status == "NO_APPROVED_BASELINE"
    first_report = build_report(
        executions=first,
        assessments=assessments,
        metrics=metrics,
        gates=gates,
        dataset_checksum=dataset.checksum_sha256,
        configuration_checksum=config_checksum,
        baseline_status=comparison.status,
        generated_at_utc="2026-08-26T00:00:00+00:00",
        runtime_duration_ms=1,
    )
    second_report = first_report.model_copy(
        update={
            "generated_at_utc": "2026-08-26T00:00:01+00:00",
            "runtime_duration_ms": 2,
        }
    )
    assert first_report.candidate_status == "PASS"
    assert first_report.baseline_comparison_status == "NO_APPROVED_BASELINE"
    assert first_report.overall_status == "NO_APPROVED_BASELINE"
    assert not first_report.release_eligible
    assert first_report.candidate_generation_exit == 0
    assert first_report.usage_summary.provider_calls == 32
    assert first_report.usage_summary.cases_with_usage == 29
    assert first_report.usage_summary.total_tokens == 435
    assert first_report.usage_summary.estimated_cost_usd == 0.0
    first_values = first_report.model_dump(mode="json")
    second_values = second_report.model_dump(mode="json")
    for field in ("generated_at_utc", "runtime_duration_ms"):
        first_values.pop(field)
        second_values.pop(field)
    assert first_values == second_values
