"""Rollback contract for disabling W7-002 while preserving W7-001."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_last_approved_w7_001_runner_contract_remains_unchanged_and_available() -> None:
    workflow = (ROOT / "src/enterprise_ai_platform/ingestion/workflow.py").read_text(
        encoding="utf-8"
    )
    config = (ROOT / "configs/ingestion/w7-001.yaml").read_text(encoding="utf-8")

    assert "async def run(self, eligibility: EmbeddingEligibility) -> object" in workflow
    assert "raw:" in config
    assert "quarantine:" in config
    assert "processed:" in config
    assert "evidence:" in config


def test_rollback_preserves_checkpoint_and_quarantine_contracts() -> None:
    pipeline = (ROOT / "src/enterprise_ai_platform/processing/pipeline.py").read_text(
        encoding="utf-8"
    )

    assert "CHECKPOINT_REPLAY_SKIPPED" in pipeline
    assert "ProcessingState.QUARANTINED" in pipeline
    assert "Remove-Item" not in pipeline
