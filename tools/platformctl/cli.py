"""A dependency-free, read-only repository validator."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

from . import __version__

EXPECTED_SCHEMA_VERSION = "1.0"
EXPECTED_PROJECT = {
    "name": "enterprise-ai-platform",
    "owner": "Gyan Prakash Rai",
    "default_environment": "sandbox",
    "cost_center": "ai_platform_learn",
    "repository": "https://github.com/gprai/enterprize_ai_platform",
    "expires_at": "31/12/2026",
}
PERMITTED_STATUSES = (
    "Not Started",
    "In Progress",
    "Blocked",
    "Ready for Review",
    "Done",
    "Deferred",
)
EXPECTED_FEATURE = {
    "id": "MVP-001",
    "status": "Not Started",
    "linked_tracker_steps": ["W1-03", "W1-04", "W1-07"],
}

REQUIRED_DIRECTORIES = (
    "docs/architecture",
    "docs/adr",
    "docs/features",
    "docs/test-evidence",
    "docs/deployment-records",
    "docs/rollback-records",
    "docs/cost-estimates",
    "docs/resource-cleanliness",
    "tools/platformctl",
    "infra/bootstrap",
    "infra/modules",
    "infra/environments/sandbox",
    "tests/unit",
    "tests/integration",
    "tests/feature",
    "tests/smoke",
    "tests/security",
    "tests/teardown",
    "policies",
)

REQUIRED_FILES = (
    "Makefile",
    "feature-matrix.yaml",
    "tools/__init__.py",
    "tools/platformctl/__init__.py",
    "tools/platformctl/__main__.py",
    "tools/platformctl/cli.py",
    "tests/__init__.py",
    "tests/unit/__init__.py",
    "tests/unit/test_platformctl.py",
    "tests/integration/__init__.py",
    "tests/integration/test_repository_layout.py",
    "tests/feature/__init__.py",
    "tests/feature/test_feature_matrix.py",
    "tests/smoke/__init__.py",
    "tests/smoke/test_platformctl_help.py",
    "tests/security/__init__.py",
    "tests/security/test_repository_security.py",
    "tests/teardown/__init__.py",
    "tests/teardown/test_repository_cleanliness.py",
)


class MatrixValidationError(ValueError):
    """Raised when feature-matrix.yaml violates the approved contract."""


def validate_feature_matrix(data: object) -> list[str]:
    """Return all deviations from the owner-approved feature matrix contract."""
    if not isinstance(data, dict):
        return ["feature matrix must contain a top-level object"]

    errors: list[str] = []
    expected_top_level = {
        "schema_version",
        "project",
        "permitted_statuses",
        "features",
    }
    actual_top_level = set(data)
    if actual_top_level != expected_top_level:
        errors.append(
            "top-level keys must be exactly: "
            + ", ".join(sorted(expected_top_level))
        )

    if data.get("schema_version") != EXPECTED_SCHEMA_VERSION:
        errors.append(f"schema_version must be {EXPECTED_SCHEMA_VERSION!r}")

    if data.get("project") != EXPECTED_PROJECT:
        errors.append("project metadata does not match the owner-approved values")

    statuses = data.get("permitted_statuses")
    if statuses != list(PERMITTED_STATUSES):
        errors.append("permitted_statuses do not match the exact approved labels")

    features = data.get("features")
    if not isinstance(features, list):
        errors.append("features must be a list")
    elif features != [EXPECTED_FEATURE]:
        errors.append(
            "features must contain only MVP-001 with status 'Not Started' "
            "and the approved linked tracker steps"
        )

    return errors


def load_feature_matrix(path: Path) -> dict[str, object]:
    """Load JSON-compatible YAML and enforce the approved contract."""
    try:
        raw_data = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise MatrixValidationError(f"cannot read {path}: {exc}") from exc

    try:
        data = json.loads(raw_data)
    except json.JSONDecodeError as exc:
        raise MatrixValidationError(
            f"feature matrix must be valid JSON-compatible YAML: {exc}"
        ) from exc

    errors = validate_feature_matrix(data)
    if errors:
        raise MatrixValidationError("; ".join(errors))
    return data


def repository_root() -> Path:
    """Return the repository root without consulting external state."""
    return Path(__file__).resolve().parents[2]


def validate_repository(root: Path | None = None) -> list[str]:
    """Read repository state and return code-stage validation errors."""
    target = (root or repository_root()).resolve()
    errors: list[str] = []

    for relative_path in REQUIRED_DIRECTORIES:
        if not (target / relative_path).is_dir():
            errors.append(f"missing required directory: {relative_path}")

    for relative_path in REQUIRED_FILES:
        if not (target / relative_path).is_file():
            errors.append(f"missing required file: {relative_path}")

    matrix_path = target / "feature-matrix.yaml"
    if matrix_path.is_file():
        try:
            load_feature_matrix(matrix_path)
        except MatrixValidationError as exc:
            errors.append(str(exc))

    return errors


def build_parser() -> argparse.ArgumentParser:
    """Build the intentionally small platformctl command contract."""
    parser = argparse.ArgumentParser(
        prog="platformctl",
        description="Read-only enterprise AI platform repository validation.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    subcommands = parser.add_subparsers(dest="command")
    subcommands.add_parser(
        "validate",
        help="validate the approved code-stage repository contract",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run platformctl without mutating repository or external state."""
    parser = build_parser()
    arguments = parser.parse_args(argv)

    if arguments.command is None:
        parser.print_help()
        return 0

    errors = validate_repository()
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1

    print("CODE-STAGE VALIDATION PASS: approved repository contract is present")
    return 0
