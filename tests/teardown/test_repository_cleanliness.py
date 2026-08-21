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

    def test_no_terraform_implementation_exists_yet(self) -> None:
        terraform_files = [
            str(path.relative_to(REPOSITORY_ROOT))
            for path in (REPOSITORY_ROOT / "infra").rglob("*.tf")
        ]
        self.assertEqual([], terraform_files)


if __name__ == "__main__":
    unittest.main()
