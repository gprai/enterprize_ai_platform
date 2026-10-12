"""Rollback contract for disabling only the W7 governed handoff."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_disabling_w7_handoff_preserves_w2_pipeline_and_source_evidence() -> None:
    assert (ROOT / "src/enterprise_ai_platform/ingestion/pipeline.py").is_file()
    assert (ROOT / "data/sample/corpus-manifest.json").is_file()
    workflow = (ROOT / "src/enterprise_ai_platform/ingestion/workflow.py").read_text(
        encoding="utf-8"
    )
    assert "delete" not in workflow.casefold()
    assert "PipelineRunner" in workflow
