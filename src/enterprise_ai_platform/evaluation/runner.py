"""Windows-compatible deterministic W3-002 candidate runner."""

from __future__ import annotations

import argparse
import asyncio
import json
import time
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from enterprise_ai_platform.rag.config import load_rag_policy

from .baseline import compare_with_baseline, load_approved_baseline
from .config import load_evaluation_config
from .dataset import load_golden_dataset
from .errors import (
    EvaluationConfigurationError,
    EvaluationError,
    EvaluationReportExistsError,
    MissingApprovedBaselineError,
)
from .evaluator import DeterministicRAGEvaluator
from .metrics import aggregate_metrics, apply_absolute_gates, assess_case
from .report import build_report, write_candidate_report

_APPROVED_CONFIG = Path("configs/eval/cited-rag-evaluation-policy.yaml")
_APPROVED_DATASET = Path("configs/eval/golden.jsonl")
_APPROVED_BASELINE = Path("configs/eval/baselines/w3-002-v1.json")
_APPROVED_REPORTS = frozenset({Path("reports/eval.json"), Path("reports/eval-repeat.json")})


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run deterministic offline RAG evaluation")
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--dataset", required=True, type=Path)
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--enforce-release", action="store_true")
    return parser


def require_release_baseline(enforce_release: bool, baseline_status: str) -> None:
    """Fail release enforcement when no approved compatible baseline exists."""

    if enforce_release and baseline_status == "NO_APPROVED_BASELINE":
        raise MissingApprovedBaselineError


async def _run(arguments: argparse.Namespace) -> int:
    if (
        arguments.config != _APPROVED_CONFIG
        or arguments.dataset != _APPROVED_DATASET
        or arguments.baseline != _APPROVED_BASELINE
        or arguments.out not in _APPROVED_REPORTS
    ):
        raise EvaluationConfigurationError
    if arguments.out.exists():
        raise EvaluationReportExistsError
    started = time.perf_counter_ns()
    config, config_checksum = load_evaluation_config(arguments.config)
    dataset = load_golden_dataset(arguments.dataset)
    root = Path(__file__).resolve().parents[3]
    policy = load_rag_policy(root / "configs" / "rag.yaml")
    executions = await DeterministicRAGEvaluator().evaluate(dataset, policy)
    assessments = tuple(
        assess_case(case, execution)
        for case, execution in zip(dataset.cases, executions, strict=True)
    )
    metrics = aggregate_metrics(dataset, assessments)
    gates = apply_absolute_gates(metrics, config)
    baseline = load_approved_baseline(arguments.baseline)
    comparison = compare_with_baseline(
        candidate=metrics,
        config=config,
        dataset_checksum=dataset.checksum_sha256,
        configuration_checksum=config_checksum,
        baseline=baseline,
    )
    require_release_baseline(arguments.enforce_release, comparison.status)
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
    write_candidate_report(arguments.out, report)
    print(
        json.dumps(
            {
                "absolute_gate_status": report.gates.absolute_gate_status,
                "baseline_comparison_status": report.baseline_comparison_status,
                "overall_status": report.overall_status,
                "release_eligible": report.release_eligible,
                "candidate_generation_exit": report.candidate_generation_exit,
                "dataset_checksum_sha256": report.dataset_checksum_sha256,
                "deterministic_payload_sha256": report.deterministic_payload_sha256,
            },
            sort_keys=True,
        )
    )
    return report.candidate_generation_exit


def main(argv: Sequence[str] | None = None) -> int:
    try:
        return asyncio.run(_run(build_parser().parse_args(argv)))
    except EvaluationError as exc:
        print(json.dumps({"status": "ERROR", "error_code": exc.code}, sort_keys=True))
        return 1
    except Exception:
        print(
            json.dumps(
                {"status": "ERROR", "error_code": "evaluation_error"},
                sort_keys=True,
            )
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
