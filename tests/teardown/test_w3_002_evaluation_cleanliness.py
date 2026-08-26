from __future__ import annotations

import asyncio
from pathlib import Path

from enterprise_ai_platform.evaluation.dataset import load_golden_dataset
from enterprise_ai_platform.evaluation.evaluator import DeterministicRAGEvaluator
from enterprise_ai_platform.rag.config import load_rag_policy

ROOT = Path(__file__).resolve().parents[2]
REPORTS = (
    ROOT / "reports" / "eval.json",
    ROOT / "reports" / "eval-repeat.json",
)
BASELINE = ROOT / "configs" / "eval" / "baselines" / "w3-002-v1.json"


def _runtime_artifacts() -> set[Path]:
    report_root = ROOT / "reports"
    temporary = (
        set(report_root.glob(".eval.json.*.tmp"))
        | set(report_root.glob(".eval-repeat.json.*.tmp"))
        if report_root.exists()
        else set()
    )
    return {path for path in (*REPORTS, BASELINE) if path.exists()} | temporary


def test_offline_evaluation_leaves_no_report_baseline_or_temporary_file() -> None:
    assert _runtime_artifacts() == set()
    dataset = load_golden_dataset(ROOT / "configs" / "eval" / "golden.jsonl")
    policy = load_rag_policy(ROOT / "configs" / "rag.yaml")
    executions = asyncio.run(DeterministicRAGEvaluator().evaluate(dataset, policy))
    assert len(executions) == 39
    assert _runtime_artifacts() == set()


def test_column_l_has_no_evaluation_cache_or_broad_report_ignore() -> None:
    assert not (
        ROOT / "src" / "enterprise_ai_platform" / "evaluation" / "__pycache__"
    ).exists()
    ignore_lines = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert "reports/" not in ignore_lines
    assert "reports/eval.json" in ignore_lines
    assert "reports/eval-repeat.json" in ignore_lines
    assert "reports/.eval.json.*.tmp" in ignore_lines
    assert "reports/.eval-repeat.json.*.tmp" in ignore_lines
