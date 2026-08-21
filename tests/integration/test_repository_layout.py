"""Integration tests for the approved repository structure."""

from __future__ import annotations

import unittest
from pathlib import Path

from tools.platformctl.cli import (
    REQUIRED_DIRECTORIES,
    REQUIRED_FILES,
    validate_repository,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


class RepositoryLayoutIntegrationTests(unittest.TestCase):
    def test_required_directories_exist(self) -> None:
        missing = [
            path
            for path in REQUIRED_DIRECTORIES
            if not (REPOSITORY_ROOT / path).is_dir()
        ]
        self.assertEqual([], missing)

    def test_required_code_stage_files_exist(self) -> None:
        missing = [
            path for path in REQUIRED_FILES if not (REPOSITORY_ROOT / path).is_file()
        ]
        self.assertEqual([], missing)

    def test_full_code_stage_contract_is_valid(self) -> None:
        errors = validate_repository(REPOSITORY_ROOT)
        self.assertEqual([], errors, "\n".join(errors))


if __name__ == "__main__":
    unittest.main()
