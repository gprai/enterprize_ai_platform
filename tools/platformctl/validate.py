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
EXPECTED_RAG_IMPLEMENTATION_PATHS = (
    "docker-compose.yml",
    "docker/qdrant-test-runner.Dockerfile",
    "docker/qdrant-test-runner.Dockerfile.dockerignore",
    "docker/qdrant-test-runner.requirements.txt",
    "src/enterprise_ai_platform/retrieval/__init__.py",
    "src/enterprise_ai_platform/retrieval/authorization.py",
    "src/enterprise_ai_platform/retrieval/errors.py",
    "src/enterprise_ai_platform/retrieval/models.py",
    "src/enterprise_ai_platform/retrieval/vector_store.py",
    "src/enterprise_ai_platform/retrieval/adapters/__init__.py",
    "src/enterprise_ai_platform/retrieval/adapters/fake.py",
    "src/enterprise_ai_platform/retrieval/adapters/opensearch.py",
    "src/enterprise_ai_platform/retrieval/adapters/qdrant.py",
    "tests/unit/test_models.py",
    "tests/contract/test_vector_store.py",
    "tests/integration/test_opensearch.py",
    "tests/integration/test_qdrant.py",
    "tests/feature/test_w2_001_retrieval_contract.py",
    "tests/security/test_tenant_isolation.py",
    "tests/teardown/test_w2_001_qdrant_lifecycle.py",
    "src/enterprise_ai_platform/embeddings/__init__.py",
    "src/enterprise_ai_platform/embeddings/base.py",
    "src/enterprise_ai_platform/embeddings/errors.py",
    "src/enterprise_ai_platform/embeddings/fake.py",
    "src/enterprise_ai_platform/embeddings/sentence_transformer.py",
    "tests/unit/test_embedder.py",
    "tests/contract/test_embedder.py",
    "tests/integration/test_sentence_transformer_embedder.py",
    "tests/feature/test_w2_002_embedder_contract.py",
    "tests/security/test_embedder_security.py",
    "tests/teardown/test_w2_002_embedder_cleanliness.py",
    "requirements.txt",
    "configs/pii-policy.yaml",
    "configs/eval/w2-starter.jsonl",
    "data/sample/corpus-manifest.json",
    "data/sample/approved/source-of-truth-v1.1.md",
    "data/sample/approved/coaching-blueprint.md",
    "data/sample/restricted-fixtures/restricted-test.txt",
    "src/enterprise_ai_platform/ingestion/__init__.py",
    "src/enterprise_ai_platform/ingestion/errors.py",
    "src/enterprise_ai_platform/ingestion/models.py",
    "src/enterprise_ai_platform/ingestion/identity.py",
    "src/enterprise_ai_platform/ingestion/normalization.py",
    "src/enterprise_ai_platform/ingestion/loaders.py",
    "src/enterprise_ai_platform/ingestion/pii.py",
    "src/enterprise_ai_platform/ingestion/tokenizer.py",
    "src/enterprise_ai_platform/ingestion/chunking.py",
    "src/enterprise_ai_platform/ingestion/pipeline.py",
    "tests/unit/test_chunking.py",
    "tests/unit/test_ingestion.py",
    "tests/contract/test_ingestion_manifest.py",
    "tests/contract/test_pii_policy.py",
    "tests/integration/test_ingestion_pdf.py",
    "tests/integration/test_ingestion_tokenizer.py",
    "tests/integration/test_dependency_contract.py",
    "tests/feature/test_w2_003_ingestion_contract.py",
    "tests/security/test_pii.py",
    "tests/security/test_ingestion_paths.py",
    "tests/smoke/test_ingestion_cli.py",
    "tests/rollback/test_w2_003_ingestion_rollback.py",
    "tests/teardown/test_w2_003_ingestion_cleanliness.py",
    "docker-compose.w2-004.yml",
    "docker/local-retrieval-runner.Dockerfile",
    "docker/local-retrieval-runner.Dockerfile.dockerignore",
    "docker/local-retrieval-runner.requirements.txt",
    "Makefile",
    "src/enterprise_ai_platform/retrieval/service.py",
    "tools/verify_w2_004_local.py",
    "tests/unit/test_retrieval_service.py",
    "tests/unit/test_verify_w2_004_local.py",
    "tests/contract/test_retrieval_service.py",
    "tests/feature/test_local_retrieval.py",
    "tests/security/test_w2_004_retrieval_security.py",
    "tests/rollback/test_w2_004_local_rollback.py",
    "tests/teardown/test_w2_004_retrieval_cleanliness.py",
)
EXPECTED_RAG_LINKED_TRACKER_STEPS = (
    "W2-03",
    "W2-01",
    "W2-02",
    "W2-04",
    "W2-08",
    "W2-05",
    "W2-06",
    "W2-07",
    "W2-09",
    "W2-10",
)
EXPECTED_RAG_FEATURE = {
    "id": "RAG-001",
    "implementation_paths": list(EXPECTED_RAG_IMPLEMENTATION_PATHS),
    "status": "In Progress",
    "linked_tracker_steps": list(EXPECTED_RAG_LINKED_TRACKER_STEPS),
}
EXPECTED_FEATURES = (
    EXPECTED_FEATURE,
    EXPECTED_RAG_FEATURE,
)

REQUIRED_DIRECTORIES = (
    "configs",
    "configs/eval",
    "data/sample",
    "data/sample/approved",
    "data/sample/restricted-fixtures",
    "docker",
    "src/enterprise_ai_platform/ingestion",
    "src/enterprise_ai_platform/retrieval",
    "src/enterprise_ai_platform/retrieval/adapters",
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
    "tests/rollback",
    "tests/teardown",
    "policies",
)

REQUIRED_FILES = (
    "Makefile",
    "docker-compose.yml",
    "docker/qdrant-test-runner.Dockerfile",
    "docker/qdrant-test-runner.Dockerfile.dockerignore",
    "docker/qdrant-test-runner.requirements.txt",
    "feature-matrix.yaml",
    "src/enterprise_ai_platform/retrieval/__init__.py",
    "src/enterprise_ai_platform/retrieval/authorization.py",
    "src/enterprise_ai_platform/retrieval/errors.py",
    "src/enterprise_ai_platform/retrieval/models.py",
    "src/enterprise_ai_platform/retrieval/vector_store.py",
    "src/enterprise_ai_platform/retrieval/adapters/__init__.py",
    "src/enterprise_ai_platform/retrieval/adapters/fake.py",
    "src/enterprise_ai_platform/retrieval/adapters/opensearch.py",
    "src/enterprise_ai_platform/retrieval/adapters/qdrant.py",
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
    "tests/unit/test_models.py",
    "tests/integration/__init__.py",
    "tests/integration/test_opensearch.py",
    "tests/integration/test_repository_layout.py",
    "tests/integration/test_platformctl_dry_run.py",
    "tests/integration/test_qdrant.py",
    "tests/contract/test_platformctl_cli_contract.py",
    "tests/contract/test_vector_store.py",
    "tests/feature/__init__.py",
    "tests/feature/test_feature_matrix.py",
    "tests/feature/test_mvp_001_platformctl.py",
    "tests/feature/test_w2_001_retrieval_contract.py",
    "tests/fakes/aws_inventory.py",
    "tests/smoke/__init__.py",
    "tests/smoke/test_platformctl_help.py",
    "tests/security/__init__.py",
    "tests/security/test_platformctl_approval_gates.py",
    "tests/security/test_tenant_isolation.py",
    *EXPECTED_RAG_IMPLEMENTATION_PATHS,
    "tests/teardown/__init__.py",
    "tests/teardown/test_platformctl_cleanup.py",
    "tests/teardown/test_w2_001_qdrant_lifecycle.py",
)


class MatrixValidationError(ValueError):
    """Raised when feature-matrix.yaml violates the approved contract."""


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise MatrixValidationError("feature matrix must not contain duplicate keys")
        result[key] = value
    return result


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
    elif features != list(EXPECTED_FEATURES):
        errors.append(
            "features must exactly match the owner-approved ordered feature set: "
            "MVP-001, RAG-001"
        )

    return errors


def load_feature_matrix(path: Path) -> dict[str, object]:
    """Load JSON-compatible YAML and enforce the approved contract."""
    try:
        raw_data = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise MatrixValidationError(f"cannot read {path}: {exc}") from exc

    try:
        data = cast(
            object,
            json.loads(raw_data, object_pairs_hook=_reject_duplicate_keys),
        )
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
