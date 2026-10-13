from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from enterprise_ai_platform.evaluation import promotion
from enterprise_ai_platform.evaluation.baseline import compare_with_baseline
from enterprise_ai_platform.evaluation.config import load_evaluation_config
from enterprise_ai_platform.evaluation.errors import (
    PromotionChecksumError,
    PromotionTargetExistsError,
)
from enterprise_ai_platform.evaluation.models import (
    ApprovedBaseline,
    EvaluationMetrics,
    GateResults,
    MetricValue,
)

ROOT = Path(__file__).resolve().parents[2]


def _metric(numerator: int, denominator: int) -> MetricValue:
    value = numerator / denominator
    return MetricValue(
        numerator=numerator,
        denominator=denominator,
        value=value,
        display=f"{value:.6f}",
    )


def _metrics(recall: MetricValue) -> EvaluationMetrics:
    perfect = _metric(1, 1)
    return EvaluationMetrics(
        recall_at_5=recall,
        mrr=perfect,
        citation_precision=perfect,
        answered_correctness=perfect,
        abstention_correctness=perfect,
        combined_correctness=perfect,
        expected_error_correctness=perfect,
        release_blocking_failures=0,
        security_violations=0,
        exposed_invalid_citations=0,
    )


def _gates() -> GateResults:
    return GateResults(
        recall_at_5="PASS",
        citation_precision="PASS",
        answered_correctness="PASS",
        abstention_correctness="PASS",
        combined_correctness="PASS",
        expected_error_correctness="PASS",
        release_blocking_cases="PASS",
        security="PASS",
        absolute_gate_status="PASS",
    )


def _baseline(metrics: EvaluationMetrics) -> ApprovedBaseline:
    return ApprovedBaseline(
        schema_version="w3-002.baseline.v1",
        repository_sha="a" * 40,
        dataset_version="w3-002.v1",
        dataset_checksum_sha256="b" * 64,
        evaluator_version="w3-002.v1",
        metric_version="w3-002.metrics.v1",
        configuration_checksum_sha256="c" * 64,
        candidate_sha256="d" * 64,
        repeat_report_sha256="e" * 64,
        deterministic_payload_sha256="f" * 64,
        reviewer="Gyan Prakash Rai",
        decision="APPROVED",
        approved_at="2026-08-26T11:11:21+08:00",
        metrics=metrics,
        gates=_gates(),
    )


def test_recall_tolerance_and_incompatible_baseline_fail_closed() -> None:
    config, config_checksum = load_evaluation_config(
        ROOT / "configs" / "eval" / "cited-rag-evaluation-policy.yaml"
    )
    baseline = _baseline(_metrics(_metric(18, 20)))
    within_tolerance = compare_with_baseline(
        candidate=_metrics(_metric(17, 20)),
        config=config,
        dataset_checksum="b" * 64,
        configuration_checksum="c" * 64,
        baseline=baseline,
    )
    assert within_tolerance.status == "PASS"
    regressed = compare_with_baseline(
        candidate=_metrics(_metric(16, 20)),
        config=config,
        dataset_checksum="b" * 64,
        configuration_checksum="c" * 64,
        baseline=baseline,
    )
    assert regressed.status == "FAIL"
    incompatible = compare_with_baseline(
        candidate=_metrics(_metric(18, 20)),
        config=config,
        dataset_checksum="0" * 64,
        configuration_checksum=config_checksum,
        baseline=baseline,
    )
    assert incompatible.status == "INCOMPATIBLE_BASELINE"


def _promotion_arguments(target: Path) -> argparse.Namespace:
    return argparse.Namespace(
        repository_sha="a" * 40,
        dataset=Path("configs/eval/golden.jsonl"),
        dataset_sha256="0" * 64,
        config=Path("configs/eval/cited-rag-evaluation-policy.yaml"),
        candidate=Path("reports/eval.json"),
        candidate_sha256="1" * 64,
        repeat_report=Path("reports/eval-repeat.json"),
        repeat_sha256="2" * 64,
        reviewer="Gyan Prakash Rai",
        decision="APPROVED",
        approved_at="2026-08-26T11:11:21+08:00",
        target=target,
    )


def test_failed_or_existing_promotion_target_is_never_modified(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "w3-002-v1.json"
    monkeypatch.setattr(promotion, "_APPROVED_TARGET", target)
    with pytest.raises(PromotionChecksumError):
        promotion.promote(_promotion_arguments(target))
    assert not target.exists()

    target.write_text("retained", encoding="utf-8")
    with pytest.raises(PromotionTargetExistsError):
        promotion.promote(_promotion_arguments(target))
    assert target.read_text(encoding="utf-8") == "retained"
