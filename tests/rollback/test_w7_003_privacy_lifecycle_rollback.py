"""Rollback contract for W7-003 source-only controls."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_rollback_preserves_prior_ingestion_and_processing_contracts() -> None:
    ingestion = (ROOT / "src/enterprise_ai_platform/ingestion/workflow.py").read_text(
        encoding="utf-8"
    )
    processing = (ROOT / "src/enterprise_ai_platform/processing/pipeline.py").read_text(
        encoding="utf-8"
    )
    assert "async def run(self, eligibility: EmbeddingEligibility) -> object" in ingestion
    assert "CHECKPOINT_REPLAY_SKIPPED" in processing


def test_partial_deletion_contract_preserves_evidence_and_blocks_source_deletion() -> None:
    lifecycle = (ROOT / "src/enterprise_ai_platform/ingestion/privacy_lifecycle.py").read_text(
        encoding="utf-8"
    )
    coordinator = lifecycle[
        lifecycle.index("class LifecycleCoordinator") : lifecycle.index("class ReindexRequest")
    ]
    assert coordinator.index("archive_redacted_metadata") < coordinator.index(
        "delete_by_document_version"
    )
    assert coordinator.index("if count_after != 0") < coordinator.index(
        "await self._objects.delete_exact_version"
    )
    assert "schedule_key_deletion" not in coordinator
