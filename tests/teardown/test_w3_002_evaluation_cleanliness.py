from __future__ import annotations

import asyncio
import hashlib
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


def _report_hashes() -> dict[Path, str]:
    return {
        path: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in REPORTS
        if path.exists()
    }


def _unexpected_runtime_artifacts() -> set[Path]:
    report_root = ROOT / "reports"
    temporary = (
        set(report_root.glob(".eval.json.*.tmp"))
        | set(report_root.glob(".eval-repeat.json.*.tmp"))
        if report_root.exists()
        else set()
    )
    unexpected_reports = (
        {path for path in report_root.iterdir() if path not in REPORTS}
        if report_root.exists()
        else set()
    )
    baseline = {BASELINE} if BASELINE.exists() else set()
    return baseline | temporary | unexpected_reports


def test_offline_evaluation_leaves_no_report_baseline_or_temporary_file() -> None:
    report_hashes_before = _report_hashes()
    assert _unexpected_runtime_artifacts() == set()
    dataset = load_golden_dataset(ROOT / "configs" / "eval" / "golden.jsonl")
    policy = load_rag_policy(ROOT / "configs" / "rag.yaml")
    executions = asyncio.run(DeterministicRAGEvaluator().evaluate(dataset, policy))
    assert len(executions) == 39
    assert _report_hashes() == report_hashes_before
    assert _unexpected_runtime_artifacts() == set()


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
