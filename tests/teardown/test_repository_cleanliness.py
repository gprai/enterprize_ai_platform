"""Checks that the skeleton leaves no managed-resource residue."""

from __future__ import annotations

import unittest
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


class RepositoryCleanlinessTests(unittest.TestCase):
    def test_no_infrastructure_state_or_tool_cache_exists(self) -> None:
        forbidden_names = {
            ".coverage",
            ".mypy_cache",
            ".pytest_cache",
            ".ruff_cache",
            ".terraform",
            ".venv",
            "htmlcov",
            "terraform.tfstate",
            "terraform.tfstate.backup",
        }
        findings = [
            str(path.relative_to(REPOSITORY_ROOT))
            for path in REPOSITORY_ROOT.rglob("*")
            if path.name in forbidden_names
        ]
        self.assertEqual([], findings)

    def test_no_plan_environment_or_private_key_artifacts_exist(self) -> None:
        findings: list[str] = []
        for pattern in ("*.tfplan", "*.pem", "*.key"):
            findings.extend(
                str(path.relative_to(REPOSITORY_ROOT))
                for path in REPOSITORY_ROOT.rglob(pattern)
            )
        environment_file = REPOSITORY_ROOT / ".env"
        if environment_file.exists():
            findings.append(".env")
        self.assertEqual([], findings)

    def test_only_approved_w1_004_terraform_skeleton_exists(self) -> None:
        expected_files = {
            "infra/bootstrap/main.tf",
            "infra/bootstrap/versions.tf",
            "infra/environments/sandbox/main.tf",
            "infra/environments/sandbox/versions.tf",
        }
        terraform_files = {
            path.relative_to(REPOSITORY_ROOT).as_posix()
            for path in (REPOSITORY_ROOT / "infra").rglob("*.tf")
        }
        self.assertEqual(expected_files, terraform_files)


if __name__ == "__main__":
    unittest.main()
