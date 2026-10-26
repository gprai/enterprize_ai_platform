"""Cleanliness tests for the W1-002 local-only foundation."""

from __future__ import annotations

from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def test_no_runtime_or_model_storage_was_created() -> None:
    forbidden_paths = (
        REPOSITORY_ROOT / ".env",
        REPOSITORY_ROOT / ".pytest_cache",
        REPOSITORY_ROOT / ".ruff_cache",
        REPOSITORY_ROOT / ".mypy_cache",
        REPOSITORY_ROOT / "models",
        REPOSITORY_ROOT / "qdrant_storage",
        REPOSITORY_ROOT / "opensearch-data",
        REPOSITORY_ROOT / ".terraform",
        REPOSITORY_ROOT / "terraform.tfstate",
    )

    assert [
        str(path.relative_to(REPOSITORY_ROOT)) for path in forbidden_paths if path.exists()
    ] == []


def test_no_downloaded_model_artifact_exists_in_source_or_tests() -> None:
    model_suffixes = {".bin", ".onnx", ".pt", ".safetensors"}
    findings = [
        str(path.relative_to(REPOSITORY_ROOT))
        for root in (REPOSITORY_ROOT / "src", REPOSITORY_ROOT / "tests")
        for path in root.rglob("*")
        if path.is_file() and path.suffix.casefold() in model_suffixes
    ]

    assert findings == []


def test_only_approved_w5_001_infrastructure_manifest_exists() -> None:
    expected_files = {
        "infra/bootstrap/main.tf",
        "infra/bootstrap/outputs.tf",
        "infra/bootstrap/variables.tf",
        "infra/bootstrap/versions.tf",
        "infra/environments/sandbox/main.tf",
        "infra/environments/sandbox/outputs.tf",
        "infra/environments/sandbox/variables.tf",
        "infra/environments/sandbox/versions.tf",
        "infra/environments/sandbox/w12_prerequisite_images.tf",
        "infra/environments/sandbox/w12_prerequisite_outputs.tf",
        "infra/modules/ecr/main.tf",
        "infra/modules/ecr/outputs.tf",
        "infra/modules/ecr/variables.tf",
        "infra/modules/eks/main.tf",
        "infra/modules/eks/outputs.tf",
        "infra/modules/eks/variables.tf",
        "infra/modules/iam/main.tf",
        "infra/modules/iam/outputs.tf",
        "infra/modules/iam/variables.tf",
        "infra/modules/iam/w12_prerequisite_images.tf",
        "infra/modules/iam/w12_prerequisite_outputs.tf",
        "infra/modules/kms/main.tf",
        "infra/modules/kms/outputs.tf",
        "infra/modules/kms/variables.tf",
        "infra/modules/network/main.tf",
        "infra/modules/network/outputs.tf",
        "infra/modules/network/variables.tf",
        "infra/modules/opensearch/main.tf",
        "infra/modules/opensearch/outputs.tf",
        "infra/modules/opensearch/variables.tf",
        "infra/modules/observability/main.tf",
        "infra/modules/observability/outputs.tf",
        "infra/modules/observability/variables.tf",
        "infra/modules/secrets/main.tf",
        "infra/modules/secrets/outputs.tf",
        "infra/modules/secrets/variables.tf",
        "infra/modules/storage/main.tf",
        "infra/modules/storage/outputs.tf",
        "infra/modules/storage/variables.tf",
    }
    infrastructure_files = {
        path.relative_to(REPOSITORY_ROOT).as_posix()
        for path in (REPOSITORY_ROOT / "infra").rglob("*.tf")
    }
    assert infrastructure_files == expected_files
