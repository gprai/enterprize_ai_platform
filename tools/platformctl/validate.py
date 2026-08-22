"""Read-only validation of the approved repository contract."""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

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
    "tests/contract",
    "tests/feature",
    "tests/fakes",
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
    "tools/platformctl/contracts.py",
    "tools/platformctl/aws_inventory.py",
    "tools/platformctl/bootstrap.py",
    "tools/platformctl/plan.py",
    "tools/platformctl/deploy.py",
    "tools/platformctl/validate.py",
    "tools/platformctl/rollback.py",
    "tools/platformctl/destroy.py",
    "tools/platformctl/verify_clean.py",
    "infra/bootstrap/versions.tf",
    "infra/bootstrap/main.tf",
    "infra/environments/sandbox/versions.tf",
    "infra/environments/sandbox/main.tf",
    "tests/__init__.py",
    "tests/unit/__init__.py",
    "tests/unit/test_platformctl.py",
    "tests/unit/test_platformctl_lifecycle.py",
    "tests/unit/test_platformctl_verify_clean.py",
    "tests/integration/__init__.py",
    "tests/integration/test_repository_layout.py",
    "tests/integration/test_platformctl_dry_run.py",
    "tests/contract/test_platformctl_cli_contract.py",
    "tests/feature/__init__.py",
    "tests/feature/test_feature_matrix.py",
    "tests/feature/test_mvp_001_platformctl.py",
    "tests/fakes/aws_inventory.py",
    "tests/smoke/__init__.py",
    "tests/smoke/test_platformctl_help.py",
    "tests/security/__init__.py",
    "tests/security/test_platformctl_approval_gates.py",
    "tests/teardown/__init__.py",
    "tests/teardown/test_platformctl_cleanup.py",
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
        data = cast(object, json.loads(raw_data))
    except json.JSONDecodeError as exc:
        raise MatrixValidationError(
            f"feature matrix must be valid JSON-compatible YAML: {exc}"
        ) from exc

    errors = validate_feature_matrix(data)
    if errors:
        raise MatrixValidationError("; ".join(errors))
    if not isinstance(data, dict) or any(not isinstance(key, str) for key in data):
        raise MatrixValidationError("feature matrix keys must be strings")
    return cast(dict[str, object], data)


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
