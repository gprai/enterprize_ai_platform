"""Rollback boundary for W5-002 workflow-only Phase A changes."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_phase_a_rollback_is_workflow_disable_or_candidate_rejection_only() -> None:
    workflows = "\n".join(
        path.read_text(encoding="utf-8") for path in (ROOT / ".github/workflows").glob("*.yml")
    )
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")

    for prohibited in (
        "terraform apply",
        "terraform destroy",
        "docker push",
        "kubectl",
        "aws ecr",
    ):
        assert prohibited not in workflows.casefold()
        assert prohibited not in makefile.casefold()
    assert "eligible_for_owner_approval" in (ROOT / "tools/w5_002_ci.py").read_text(
        encoding="utf-8"
    )


def test_cancellation_is_bounded_to_duplicate_task_work() -> None:
    ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    plan = (ROOT / ".github/workflows/plan-sandbox.yml").read_text(encoding="utf-8")
    supply = (ROOT / ".github/workflows/security-scan.yml").read_text(encoding="utf-8")

    assert "w5-002-pr-${{ github.event.pull_request.number }}" in ci
    assert "group: w5-002-plan-sandbox" in plan
    assert "w5-002-supply-chain-${{ github.sha }}" in supply
    assert all("cancel-in-progress: true" in text for text in (ci, plan, supply))
