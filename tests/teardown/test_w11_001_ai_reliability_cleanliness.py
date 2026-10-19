"""Zero-residue checks for source-only W11-001 evaluation."""

from __future__ import annotations

from pathlib import Path

from enterprise_ai_platform.telemetry.ai_reliability import (
    evaluate_batch,
    load_ai_reliability_policy,
)
from tests.fakes.w11_001_ai_reliability import passing_batch


def _residue(root: Path) -> set[Path]:
    return {
        path.relative_to(root)
        for pattern in ("*.tmp", "*.temp", "w11-001-*.json")
        for path in root.rglob(pattern)
        if path.is_file()
    }


def test_policy_and_decision_create_no_repository_residue() -> None:
    root = Path(__file__).resolve().parents[2]
    before = _residue(root)
    policy = load_ai_reliability_policy(root / "configs/observability/slo.yaml")
    evaluate_batch(policy, passing_batch(policy))
    assert _residue(root) == before
