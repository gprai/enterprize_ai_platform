"""Canonical W4-11 historical identity and explicit checkout verification."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Final

from pydantic import ValidationError

from enterprise_ai_platform import __version__
from enterprise_ai_platform.json_contracts import strict_json_loads

from .errors import (
    ReleaseConfigurationError,
    ReleaseIdentityError,
    ReleaseUnsafePathError,
)
from .models import ReleaseDescriptor, ReleaseVersion

REPOSITORY_ROOT: Final[Path] = Path(__file__).resolve().parents[3]
KNOWN_GOOD_DESCRIPTOR_PATH: Final[Path] = Path("configs/releases/versions/w4-known-good-v1.json")
REGRESSION_DESCRIPTOR_PATH: Final[Path] = Path(
    "configs/releases/versions/w4-synthetic-regression-v1.json"
)
APPROVED_REPOSITORY_SHA: Final = "bd7a82039ee1d8b3a789b9e0db9dd893d1c36745"
APPROVED_COMPOSITION_SHA256: Final = (
    "2bd002d111dbfae4390254d077acafd0623f42fac945f608a32bf685b3053b14"
)
APPROVED_ARTIFACT_COUNT: Final = 99

DESCRIPTOR_PATHS: Final[dict[ReleaseVersion, Path]] = {
    "w4-known-good-v1": KNOWN_GOOD_DESCRIPTOR_PATH,
    "w4-synthetic-regression-v1": REGRESSION_DESCRIPTOR_PATH,
}

APPROVED_ARTIFACT_PATHS: Final[tuple[str, ...]] = (
    "configs/eval/baselines/w3-002-v1.json",
    "configs/eval/golden.jsonl",
    "configs/eval/w2-starter.jsonl",
    "configs/eval/w3-002.yaml",
    "configs/observability/otel-collector.local.yaml",
    "configs/pii-policy.yaml",
    "configs/rag.yaml",
    "configs/rag/versions/w3-002-v1.json",
    "configs/rag/versions/w3-004-synthetic-regression-v1.json",
    "data/sample/approved/coaching-blueprint.md",
    "data/sample/approved/source-of-truth-v1.1.md",
    "data/sample/corpus-manifest.json",
    "data/sample/restricted-fixtures/restricted-test.txt",
    "requirements.txt",
    "src/enterprise_ai_platform/__init__.py",
    "src/enterprise_ai_platform/agent/__init__.py",
    "src/enterprise_ai_platform/agent/authorization.py",
    "src/enterprise_ai_platform/agent/contracts.py",
    "src/enterprise_ai_platform/agent/controller.py",
    "src/enterprise_ai_platform/agent/errors.py",
    "src/enterprise_ai_platform/agent/graph.py",
    "src/enterprise_ai_platform/agent/models.py",
    "src/enterprise_ai_platform/agent/persistence.py",
    "src/enterprise_ai_platform/agent/runtime.py",
    "src/enterprise_ai_platform/agent/serialization.py",
    "src/enterprise_ai_platform/agent/tools.py",
    "src/enterprise_ai_platform/api/__init__.py",
    "src/enterprise_ai_platform/api/dependencies.py",
    "src/enterprise_ai_platform/api/errors.py",
    "src/enterprise_ai_platform/api/models.py",
    "src/enterprise_ai_platform/api/routes.py",
    "src/enterprise_ai_platform/api/runtime.py",
    "src/enterprise_ai_platform/app.py",
    "src/enterprise_ai_platform/config.py",
    "src/enterprise_ai_platform/embeddings/__init__.py",
    "src/enterprise_ai_platform/embeddings/base.py",
    "src/enterprise_ai_platform/embeddings/errors.py",
    "src/enterprise_ai_platform/embeddings/fake.py",
    "src/enterprise_ai_platform/embeddings/sentence_transformer.py",
    "src/enterprise_ai_platform/evaluation/__init__.py",
    "src/enterprise_ai_platform/evaluation/baseline.py",
    "src/enterprise_ai_platform/evaluation/config.py",
    "src/enterprise_ai_platform/evaluation/dataset.py",
    "src/enterprise_ai_platform/evaluation/errors.py",
    "src/enterprise_ai_platform/evaluation/evaluator.py",
    "src/enterprise_ai_platform/evaluation/fixtures.py",
    "src/enterprise_ai_platform/evaluation/metrics.py",
    "src/enterprise_ai_platform/evaluation/models.py",
    "src/enterprise_ai_platform/evaluation/promotion.py",
    "src/enterprise_ai_platform/evaluation/report.py",
    "src/enterprise_ai_platform/evaluation/runner.py",
    "src/enterprise_ai_platform/guardrails/__init__.py",
    "src/enterprise_ai_platform/guardrails/adapter.py",
    "src/enterprise_ai_platform/guardrails/errors.py",
    "src/enterprise_ai_platform/guardrails/models.py",
    "src/enterprise_ai_platform/guardrails/policy.py",
    "src/enterprise_ai_platform/ingestion/__init__.py",
    "src/enterprise_ai_platform/ingestion/chunking.py",
    "src/enterprise_ai_platform/ingestion/errors.py",
    "src/enterprise_ai_platform/ingestion/identity.py",
    "src/enterprise_ai_platform/ingestion/loaders.py",
    "src/enterprise_ai_platform/ingestion/models.py",
    "src/enterprise_ai_platform/ingestion/normalization.py",
    "src/enterprise_ai_platform/ingestion/pii.py",
    "src/enterprise_ai_platform/ingestion/pipeline.py",
    "src/enterprise_ai_platform/ingestion/tokenizer.py",
    "src/enterprise_ai_platform/json_contracts.py",
    "src/enterprise_ai_platform/llm/__init__.py",
    "src/enterprise_ai_platform/llm/bedrock.py",
    "src/enterprise_ai_platform/llm/errors.py",
    "src/enterprise_ai_platform/llm/factory.py",
    "src/enterprise_ai_platform/llm/fake.py",
    "src/enterprise_ai_platform/llm/models.py",
    "src/enterprise_ai_platform/llm/provider.py",
    "src/enterprise_ai_platform/rag_rollback/__init__.py",
    "src/enterprise_ai_platform/rag_rollback/errors.py",
    "src/enterprise_ai_platform/rag_rollback/identity.py",
    "src/enterprise_ai_platform/rag_rollback/models.py",
    "src/enterprise_ai_platform/rag_rollback/service.py",
    "src/enterprise_ai_platform/rag_rollback/state.py",
    "src/enterprise_ai_platform/rag/__init__.py",
    "src/enterprise_ai_platform/rag/config.py",
    "src/enterprise_ai_platform/rag/errors.py",
    "src/enterprise_ai_platform/rag/models.py",
    "src/enterprise_ai_platform/rag/prompt.py",
    "src/enterprise_ai_platform/rag/service.py",
    "src/enterprise_ai_platform/retrieval/__init__.py",
    "src/enterprise_ai_platform/retrieval/adapters/__init__.py",
    "src/enterprise_ai_platform/retrieval/adapters/fake.py",
    "src/enterprise_ai_platform/retrieval/adapters/opensearch.py",
    "src/enterprise_ai_platform/retrieval/adapters/qdrant.py",
    "src/enterprise_ai_platform/retrieval/authorization.py",
    "src/enterprise_ai_platform/retrieval/errors.py",
    "src/enterprise_ai_platform/retrieval/models.py",
    "src/enterprise_ai_platform/retrieval/service.py",
    "src/enterprise_ai_platform/retrieval/vector_store.py",
    "src/enterprise_ai_platform/telemetry/__init__.py",
    "src/enterprise_ai_platform/telemetry/models.py",
    "src/enterprise_ai_platform/telemetry/runtime.py",
)


def canonical_json_bytes(value: object) -> bytes:
    """Return the exact approved canonical JSON representation."""

    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def hash_file(path: Path) -> str:
    try:
        return sha256_bytes(path.read_bytes())
    except OSError:
        raise ReleaseConfigurationError from None


def descriptor_sha256(descriptor: ReleaseDescriptor) -> str:
    return sha256_bytes(canonical_json_bytes(descriptor.model_dump(mode="json")))


def artifact_composition_sha256(descriptor: ReleaseDescriptor) -> str:
    values = [item.model_dump(mode="json") for item in descriptor.artifacts]
    return sha256_bytes(canonical_json_bytes(values))


def _validate_relative_path(value: str) -> PurePosixPath:
    relative = PurePosixPath(value)
    if (
        not value
        or "\\" in value
        or ":" in value
        or relative.is_absolute()
        or relative.as_posix() != value
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise ReleaseUnsafePathError
    return relative


def _repository_root() -> Path:
    try:
        root = REPOSITORY_ROOT.resolve(strict=True)
    except OSError:
        raise ReleaseUnsafePathError from None
    if REPOSITORY_ROOT.is_symlink() or not root.is_dir():
        raise ReleaseUnsafePathError
    return root


def _exact_repository_file(value: str) -> Path:
    relative = _validate_relative_path(value)
    root = _repository_root()
    current = root
    try:
        for part in relative.parts:
            names = tuple(item.name for item in current.iterdir())
            case_matches = tuple(name for name in names if name.casefold() == part.casefold())
            if part not in names or case_matches != (part,):
                raise ReleaseUnsafePathError
            current = current / part
            if current.is_symlink():
                raise ReleaseUnsafePathError
        resolved = current.resolve(strict=True)
    except ReleaseUnsafePathError:
        raise
    except OSError:
        raise ReleaseConfigurationError from None
    if resolved != root / Path(*relative.parts) or not resolved.is_file():
        raise ReleaseUnsafePathError
    return resolved


def _load_descriptor_file(
    relative: Path,
    expected_version: ReleaseVersion,
) -> ReleaseDescriptor:
    path = _exact_repository_file(relative.as_posix())
    try:
        payload = path.read_bytes()
        text = payload.decode("utf-8", errors="strict")
        strict_json_loads(text)
        descriptor = ReleaseDescriptor.model_validate_json(text, strict=True)
    except (OSError, UnicodeError, TypeError, ValueError, ValidationError):
        raise ReleaseConfigurationError from None
    if descriptor.release_version != expected_version or payload != canonical_json_bytes(
        descriptor.model_dump(mode="json")
    ):
        raise ReleaseIdentityError
    return descriptor


def _validate_descriptor(descriptor: ReleaseDescriptor) -> None:
    paths = tuple(item.path for item in descriptor.artifacts)
    if (
        descriptor.repository_commit_sha != APPROVED_REPOSITORY_SHA
        or descriptor.package_version != __version__
        or descriptor.artifact_count != APPROVED_ARTIFACT_COUNT
        or descriptor.composition_sha256 != APPROVED_COMPOSITION_SHA256
        or paths != APPROVED_ARTIFACT_PATHS
        or artifact_composition_sha256(descriptor) != APPROVED_COMPOSITION_SHA256
    ):
        raise ReleaseIdentityError


def validate_current_checkout(descriptor: ReleaseDescriptor) -> None:
    """Fail unless the current checkout still contains the historical payload."""

    _validate_descriptor(descriptor)
    for artifact in descriptor.artifacts:
        if hash_file(_exact_repository_file(artifact.path)) != artifact.sha256:
            raise ReleaseIdentityError


def load_release_descriptor(version: ReleaseVersion) -> ReleaseDescriptor:
    """Load one fixed historical descriptor without relabeling the current checkout."""

    descriptor = _load_descriptor_file(DESCRIPTOR_PATHS[version], version)
    _validate_descriptor(descriptor)
    return descriptor


def validate_release_pair() -> tuple[ReleaseDescriptor, ReleaseDescriptor]:
    """Validate N and N+1 and permit only their approved behavioral delta."""

    known_good = load_release_descriptor("w4-known-good-v1")
    regression = load_release_descriptor("w4-synthetic-regression-v1")
    known_values = known_good.model_dump(mode="python")
    regression_values = regression.model_dump(mode="python")
    for field in (
        "release_version",
        "agent_enabled",
        "regression_profile",
        "expected_gate",
        "expected_safe_error_code",
    ):
        known_values.pop(field)
        regression_values.pop(field)
    if known_values != regression_values:
        raise ReleaseIdentityError
    return known_good, regression
