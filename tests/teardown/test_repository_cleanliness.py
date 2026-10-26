"""Checks that the skeleton leaves no managed-resource residue."""

from __future__ import annotations

import unittest
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
OWNER_PROTECTED_STATE = Path("infra/bootstrap/terraform.tfstate")


class RepositoryCleanlinessTests(unittest.TestCase):
    def test_no_infrastructure_state_or_tool_cache_exists(self) -> None:
        approved_provider_locks = {
            Path("infra/bootstrap/.terraform.lock.hcl"),
            Path("infra/environments/sandbox/.terraform.lock.hcl"),
        }
        forbidden_names = {
            ".coverage",
            ".mypy_cache",
            ".pytest_cache",
            ".ruff_cache",
            ".terraform",
            ".terraform.lock.hcl",
            ".tflint.d",
            ".venv",
            "__pycache__",
            "htmlcov",
            "terraform.tfstate",
            "terraform.tfstate.backup",
        }
        findings: list[str] = []
        for path in REPOSITORY_ROOT.rglob("*"):
            relative_path = path.relative_to(REPOSITORY_ROOT)
            if ".git" in relative_path.parts:
                continue
            if relative_path in approved_provider_locks and path.is_file():
                continue
            if relative_path == OWNER_PROTECTED_STATE and path.is_file():
                continue
            if path.name in forbidden_names or (
                path.is_file() and path.suffix.casefold() in {".pyc", ".pyo"}
            ):
                findings.append(str(relative_path))
        self.assertEqual([], findings)

    def test_no_plan_environment_or_private_key_artifacts_exist(self) -> None:
        findings: list[str] = []
        for pattern in ("*.tfplan", "*.pem", "*.key"):
            for path in REPOSITORY_ROOT.rglob(pattern):
                relative_path = path.relative_to(REPOSITORY_ROOT)
                if ".git" not in relative_path.parts:
                    findings.append(str(relative_path))
        environment_file = REPOSITORY_ROOT / ".env"
        if environment_file.exists():
            findings.append(".env")
        self.assertEqual([], findings)

    def test_only_approved_w5_001_terraform_manifest_exists(self) -> None:
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
        terraform_files = {
            path.relative_to(REPOSITORY_ROOT).as_posix()
            for path in (REPOSITORY_ROOT / "infra").rglob("*.tf")
        }
        self.assertEqual(expected_files, terraform_files)


if __name__ == "__main__":
    unittest.main()
