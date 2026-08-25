"""Static cleanliness contract for W2-003 repository and retained cache boundaries."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_no_repository_local_manifest_quarantine_or_model_cache_exists() -> None:
    forbidden = (
        ROOT / "manifest",
        ROOT / "manifests",
        ROOT / "quarantine",
        ROOT / ".cache",
        ROOT / ".model-cache",
        ROOT / "models--sentence-transformers--all-MiniLM-L6-v2",
    )

    assert all(not path.exists() for path in forbidden)


def test_ingestion_code_never_declares_repository_output_cache_directories() -> None:
    pipeline = (ROOT / "src" / "enterprise_ai_platform" / "ingestion" / "pipeline.py").read_text(
        encoding="utf-8"
    )
    tokenizer = (ROOT / "src" / "enterprise_ai_platform" / "ingestion" / "tokenizer.py").read_text(
        encoding="utf-8"
    )

    assert "mkdir(" not in pipeline
    assert "snapshot_download" not in tokenizer
    assert "from_pretrained" not in tokenizer
    assert "sentence_transformers" not in tokenizer


def test_retained_w2_002_cache_is_outside_repository_when_present() -> None:
    retained = Path(
        r"E:\AI\.model-cache\enterprise_ai_platform\W2-002"
    )
    resolved_root = ROOT.resolve()

    if retained.exists():
        assert not retained.resolve().is_relative_to(resolved_root)


def test_approved_source_files_are_inputs_not_runtime_residue() -> None:
    approved = (
        ROOT / "data" / "sample" / "corpus-manifest.json",
        ROOT / "data" / "sample" / "approved" / "source-of-truth-v1.1.md",
        ROOT / "data" / "sample" / "approved" / "coaching-blueprint.md",
        ROOT / "data" / "sample" / "restricted-fixtures" / "restricted-test.txt",
        ROOT / "configs" / "pii-policy.yaml",
        ROOT / "configs" / "eval" / "w2-starter.jsonl",
    )

    assert all(path.is_file() for path in approved)
