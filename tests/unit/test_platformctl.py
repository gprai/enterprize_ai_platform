"""Unit tests for the read-only platformctl contract."""

from __future__ import annotations

import unittest
from pathlib import Path

from tools.platformctl import __version__
from tools.platformctl.cli import (
    EXPECTED_FEATURE,
    EXPECTED_PROJECT,
    EXPECTED_SCHEMA_VERSION,
    PERMITTED_STATUSES,
    build_parser,
    validate_feature_matrix,
    validate_repository,
)


def approved_matrix() -> dict[str, object]:
    return {
        "schema_version": EXPECTED_SCHEMA_VERSION,
        "project": dict(EXPECTED_PROJECT),
        "permitted_statuses": list(PERMITTED_STATUSES),
        "features": [
            {
                "id": EXPECTED_FEATURE["id"],
                "status": EXPECTED_FEATURE["status"],
                "linked_tracker_steps": list(
                    EXPECTED_FEATURE["linked_tracker_steps"]
                ),
            }
        ],
    }


class PlatformCtlUnitTests(unittest.TestCase):
    def test_version_is_an_explicit_pre_release_version(self) -> None:
        self.assertEqual("0.1.0", __version__)

    def test_parser_exposes_w1_004_lifecycle_subcommands(self) -> None:
        parser = build_parser()
        arguments = parser.parse_args(["validate"])
        self.assertEqual("validate", arguments.command)
        help_text = parser.format_help()
        for command in (
            "bootstrap",
            "plan",
            "deploy",
            "validate",
            "rollback",
            "destroy",
            "verify-clean",
        ):
            self.assertIn(command, help_text)
        self.assertNotIn("--execute", help_text)

    def test_approved_matrix_has_no_errors(self) -> None:
        self.assertEqual([], validate_feature_matrix(approved_matrix()))

    def test_unapproved_status_is_rejected(self) -> None:
        matrix = approved_matrix()
        matrix["features"][0]["status"] = "Complete"  # type: ignore[index]
        errors = validate_feature_matrix(matrix)
        self.assertTrue(any("MVP-001" in error for error in errors))

    def test_additional_feature_is_rejected(self) -> None:
        matrix = approved_matrix()
        matrix["features"].append(  # type: ignore[union-attr]
            {
                "id": "W1-03",
                "status": "Not Started",
                "linked_tracker_steps": [],
            }
        )
        errors = validate_feature_matrix(matrix)
        self.assertTrue(any("only MVP-001" in error for error in errors))

    def test_missing_repository_reports_errors_without_creating_paths(self) -> None:
        missing_root = Path("definitely-not-an-enterprise-ai-platform-root")
        errors = validate_repository(missing_root)
        self.assertTrue(errors)
        self.assertFalse(missing_root.exists())


if __name__ == "__main__":
    unittest.main()
