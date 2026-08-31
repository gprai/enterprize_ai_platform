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
    findings = [str(path.relative_to(REPOSITORY_ROOT)) for path in forbidden_paths if path.exists()]
    assert findings == []


def test_approved_w1_003_documents_exist_without_json_evidence() -> None:
    approved_documents = (
        REPOSITORY_ROOT / "docs" / "test-evidence" / "README.md",
        REPOSITORY_ROOT / "docs" / "test-evidence" / "W1-003.md",
    )
    missing_documents = [
        path.relative_to(REPOSITORY_ROOT).as_posix()
        for path in approved_documents
        if not path.exists()
    ]
    unapproved_json_evidence = REPOSITORY_ROOT / "docs" / "test-evidence" / "W1-003.json"

    assert missing_documents == []
    assert not unapproved_json_evidence.exists()


def test_recorder_defines_no_managed_resource_or_service_artifact() -> None:
    forbidden_paths = (
        REPOSITORY_ROOT / "terraform.tfstate",
        REPOSITORY_ROOT / ".terraform",
        REPOSITORY_ROOT / "qdrant_storage",
        REPOSITORY_ROOT / "opensearch-data",
    )
    assert [str(path) for path in forbidden_paths if path.exists()] == []
