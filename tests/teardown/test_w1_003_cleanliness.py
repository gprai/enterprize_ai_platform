"""Teardown checks for W1-003 caches, residue, and premature evidence files."""

from __future__ import annotations

from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def test_no_test_tool_cache_or_deepeval_residue_exists() -> None:
    forbidden_paths = (
        REPOSITORY_ROOT / ".deepeval",
        REPOSITORY_ROOT / ".mypy_cache",
        REPOSITORY_ROOT / ".pytest_cache",
        REPOSITORY_ROOT / ".ruff_cache",
    )
    findings = [
        str(path.relative_to(REPOSITORY_ROOT))
        for path in forbidden_paths
        if path.exists()
    ]
    assert findings == []


def test_no_w1_003_evidence_file_exists_before_column_m() -> None:
    evidence_paths = (
        REPOSITORY_ROOT / "docs" / "test-evidence" / "README.md",
        REPOSITORY_ROOT / "docs" / "test-evidence" / "W1-003.md",
        REPOSITORY_ROOT / "docs" / "test-evidence" / "W1-003.json",
    )
    assert [str(path) for path in evidence_paths if path.exists()] == []


def test_recorder_defines_no_managed_resource_or_service_artifact() -> None:
    forbidden_paths = (
        REPOSITORY_ROOT / "terraform.tfstate",
        REPOSITORY_ROOT / ".terraform",
        REPOSITORY_ROOT / "qdrant_storage",
        REPOSITORY_ROOT / "opensearch-data",
    )
    assert [str(path) for path in forbidden_paths if path.exists()] == []
