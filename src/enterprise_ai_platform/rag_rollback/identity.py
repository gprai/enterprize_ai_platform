"""Canonical identity loading and transitive W3-002 compatibility checks."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Final

from pydantic import ValidationError

from enterprise_ai_platform.evaluation.baseline import load_approved_baseline
from enterprise_ai_platform.evaluation.config import load_evaluation_config
from enterprise_ai_platform.evaluation.dataset import load_golden_dataset
from enterprise_ai_platform.evaluation.report import load_evaluation_report
from enterprise_ai_platform.guardrails.policy import (
    ALLOWED_RAG_CONTENT_TYPE,
    MAX_RAG_INPUT_CHARACTERS,
)
from enterprise_ai_platform.json_contracts import strict_json_loads
from enterprise_ai_platform.rag.config import load_rag_policy
from enterprise_ai_platform.rag.prompt import prompt_template_sha256

from .errors import (
    RollbackBaselineError,
    RollbackConfigurationError,
    RollbackIdentityError,
    RollbackUnsafePathError,
)
from .models import IdentityAlias, RAGIdentityDescriptor

REPOSITORY_ROOT: Final[Path] = Path(__file__).resolve().parents[3]
KNOWN_GOOD_PATH: Final[Path] = Path("configs/rag/versions/w3-002-v1.json")
REGRESSION_PATH: Final[Path] = Path("configs/rag/versions/w3-004-synthetic-regression-v1.json")

_IDENTITY_PATHS: Final[dict[IdentityAlias, Path]] = {
    "known-good": KNOWN_GOOD_PATH,
    "synthetic-regression": REGRESSION_PATH,
}
_BASELINE_SHA256 = "4bbc8f24af911ba09356196e9285d261549926c713110f9549929e1e4ac9086f"
_BASELINE_REPOSITORY_SHA = "b9f596118c2a75c75f20af1a2c9a19c2234b65ad"
_CANDIDATE_SHA256 = "f259784666c180145c4dbb0f4757fbac2505eba059c6ee06510c6906cb3546cf"
_REPEAT_SHA256 = "d35c1ee13a54cda78e7514a84cd9af6e6086236a4095f7824f52cdbc46d2da1a"
_DETERMINISTIC_PAYLOAD_SHA256 = "7e9368c3e29252f21af6398aa39873151536e42df53619f156cc6ce38450743e"
_GOLDEN_RAW_SHA256 = "809aac88f84dd44aeb96c676f3bad229164a0767c6fc9d0ebeeb01b6823c06c2"
_GOLDEN_CANONICAL_SHA256 = "e3ff344d9904ea0e9cff722441bbe8237105e6131e1f57d0ca42d35ddad410f9"
_EVALUATION_CONFIG_SHA256 = "4564b1935c1c072281f90a63c1ac80315709e35e6aab8e0803d0a9abf5c189df"
_RAG_SOURCE_SHA256 = "5cb62932bbc0a0c11e494912bdcc5b4b48bd4195e3ca58bda2df27227070b27e"
_RAG_SEMANTIC_SHA256 = "447bda9713f661db5e8e47f5991528fad0820544cc184da4a232b190408ec8d5"
_PROMPT_SEMANTIC_SHA256 = "f1b9583bd8e8dd3abfa066c1e03e3979a118bad56565a99930e387ea2ccba927"
_FIXTURE_SOURCE_SHA256 = "c1a3285fad8235f3624c21da60b3f16233bf2f7203bbfc382b39599830608932"
_GUARDRAIL_SOURCE_SHA256 = "4a3a93584569e90d31beda4280d242bee54e10f8f8b5c732152d7b3c1bb6e3c7"
_GUARDRAIL_SEMANTIC_SHA256 = "cad252519c820639fac4f1b4c796465122e914d87bb7168c1da713644558b74c"


def canonical_json_bytes(value: object) -> bytes:
    """Return the approved formatting-independent canonical JSON bytes."""

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
        raise RollbackConfigurationError from None


def identity_sha256(identity: RAGIdentityDescriptor) -> str:
    return sha256_bytes(canonical_json_bytes(identity.model_dump(mode="json")))


def _fixed_file(relative: Path) -> Path:
    candidate = REPOSITORY_ROOT / relative
    try:
        resolved_root = REPOSITORY_ROOT.resolve(strict=True)
        resolved = candidate.resolve(strict=True)
    except OSError:
        raise RollbackConfigurationError from None
    if candidate.is_symlink() or resolved_root not in resolved.parents:
        raise RollbackUnsafePathError
    if resolved != resolved_root / relative or not resolved.is_file():
        raise RollbackUnsafePathError
    return resolved


def _require_hash(relative: Path, expected: str) -> Path:
    path = _fixed_file(relative)
    if hash_file(path) != expected:
        raise RollbackIdentityError
    return path


def _require_exact_references(identity: RAGIdentityDescriptor) -> None:
    expected = {
        "baseline": (
            "configs/eval/baselines/w3-002-v1.json",
            _BASELINE_SHA256,
        ),
        "repository": _BASELINE_REPOSITORY_SHA,
        "prompt": ("w3-001.v1", _PROMPT_SEMANTIC_SHA256),
        "rag": (
            "configs/rag.yaml",
            _RAG_SOURCE_SHA256,
            _RAG_SEMANTIC_SHA256,
        ),
        "evidence": (
            "configs/eval/golden.jsonl",
            _GOLDEN_RAW_SHA256,
            _GOLDEN_CANONICAL_SHA256,
            "src/enterprise_ai_platform/evaluation/fixtures.py",
            _FIXTURE_SOURCE_SHA256,
        ),
        "evaluation": (
            "configs/eval/w3-002.yaml",
            _EVALUATION_CONFIG_SHA256,
            "w3-002.v1",
            "w3-002.metrics.v1",
            "reports/eval.json",
            _CANDIDATE_SHA256,
            "reports/eval-repeat.json",
            _REPEAT_SHA256,
            _DETERMINISTIC_PAYLOAD_SHA256,
        ),
        "guardrail": (
            "src/enterprise_ai_platform/guardrails/policy.py",
            _GUARDRAIL_SOURCE_SHA256,
            _GUARDRAIL_SEMANTIC_SHA256,
            "text/plain",
            10_000,
        ),
    }
    actual = {
        "baseline": (identity.baseline.path, identity.baseline.sha256),
        "repository": identity.repository.approved_behavior_sha,
        "prompt": (identity.prompt.version, identity.prompt.semantic_sha256),
        "rag": (
            identity.rag_configuration.path,
            identity.rag_configuration.source_sha256,
            identity.rag_configuration.semantic_sha256,
        ),
        "evidence": (
            identity.evidence.dataset_path,
            identity.evidence.dataset_raw_sha256,
            identity.evidence.dataset_canonical_sha256,
            identity.evidence.fixture_source_path,
            identity.evidence.fixture_source_sha256,
        ),
        "evaluation": (
            identity.evaluation.config_path,
            identity.evaluation.config_sha256,
            identity.evaluation.evaluator_version,
            identity.evaluation.metric_version,
            identity.evaluation.candidate_path,
            identity.evaluation.candidate_sha256,
            identity.evaluation.repeat_path,
            identity.evaluation.repeat_sha256,
            identity.evaluation.deterministic_payload_sha256,
        ),
        "guardrail": (
            identity.guardrail.source_path,
            identity.guardrail.source_sha256,
            identity.guardrail.semantic_sha256,
            identity.guardrail.allowed_content_type,
            identity.guardrail.max_input_characters,
        ),
    }
    if actual != expected:
        raise RollbackIdentityError


def _validate_transitive_authorities(identity: RAGIdentityDescriptor) -> None:
    baseline_path = _require_hash(Path(identity.baseline.path), _BASELINE_SHA256)
    try:
        baseline = load_approved_baseline(baseline_path)
    except Exception:
        raise RollbackBaselineError from None
    if (
        baseline is None
        or baseline.repository_sha != _BASELINE_REPOSITORY_SHA
        or baseline.dataset_checksum_sha256 != _GOLDEN_CANONICAL_SHA256
        or baseline.configuration_checksum_sha256 != _EVALUATION_CONFIG_SHA256
        or baseline.candidate_sha256 != _CANDIDATE_SHA256
        or baseline.repeat_report_sha256 != _REPEAT_SHA256
        or baseline.deterministic_payload_sha256 != _DETERMINISTIC_PAYLOAD_SHA256
        or baseline.gates.absolute_gate_status != "PASS"
    ):
        raise RollbackBaselineError

    candidate_path = _require_hash(Path(identity.evaluation.candidate_path), _CANDIDATE_SHA256)
    repeat_path = _require_hash(Path(identity.evaluation.repeat_path), _REPEAT_SHA256)
    try:
        candidate = load_evaluation_report(candidate_path)
        repeat = load_evaluation_report(repeat_path)
    except Exception:
        raise RollbackBaselineError from None
    for report in (candidate, repeat):
        if (
            report.baseline_comparison_status != "NO_APPROVED_BASELINE"
            or report.overall_status != "NO_APPROVED_BASELINE"
            or report.release_eligible
            or report.deterministic_payload_sha256 != _DETERMINISTIC_PAYLOAD_SHA256
        ):
            raise RollbackBaselineError

    dataset_path = _require_hash(Path(identity.evidence.dataset_path), _GOLDEN_RAW_SHA256)
    try:
        dataset = load_golden_dataset(dataset_path)
    except Exception:
        raise RollbackConfigurationError from None
    if dataset.checksum_sha256 != _GOLDEN_CANONICAL_SHA256:
        raise RollbackIdentityError

    config_path = _require_hash(Path(identity.evaluation.config_path), _EVALUATION_CONFIG_SHA256)
    try:
        config, config_hash = load_evaluation_config(config_path)
    except Exception:
        raise RollbackConfigurationError from None
    if (
        config_hash != _EVALUATION_CONFIG_SHA256
        or config.evaluator_version != identity.evaluation.evaluator_version
        or config.metric_version != identity.evaluation.metric_version
    ):
        raise RollbackIdentityError

    rag_path = _require_hash(Path(identity.rag_configuration.path), _RAG_SOURCE_SHA256)
    try:
        policy = load_rag_policy(rag_path)
    except Exception:
        raise RollbackConfigurationError from None
    rag_semantic = sha256_bytes(canonical_json_bytes(policy.model_dump(mode="json")))
    if rag_semantic != _RAG_SEMANTIC_SHA256:
        raise RollbackIdentityError

    _require_hash(Path(identity.evidence.fixture_source_path), _FIXTURE_SOURCE_SHA256)
    _require_hash(Path(identity.guardrail.source_path), _GUARDRAIL_SOURCE_SHA256)
    guardrail_semantic = sha256_bytes(
        canonical_json_bytes(
            {
                "allowed_content_type": ALLOWED_RAG_CONTENT_TYPE,
                "max_input_characters": MAX_RAG_INPUT_CHARACTERS,
            }
        )
    )
    if (
        prompt_template_sha256() != _PROMPT_SEMANTIC_SHA256
        or guardrail_semantic != _GUARDRAIL_SEMANTIC_SHA256
    ):
        raise RollbackIdentityError


def load_identity(alias: IdentityAlias) -> RAGIdentityDescriptor:
    """Load and validate one fixed immutable descriptor and all its authorities."""

    relative = _IDENTITY_PATHS[alias]
    path = _fixed_file(relative)
    try:
        text = path.read_text(encoding="utf-8", errors="strict")
        strict_json_loads(text)
        identity = RAGIdentityDescriptor.model_validate_json(text, strict=True)
    except (OSError, UnicodeError, TypeError, ValueError, ValidationError):
        raise RollbackConfigurationError from None
    if identity.identity_alias != alias:
        raise RollbackIdentityError
    _require_exact_references(identity)
    _validate_transitive_authorities(identity)
    return identity


def validate_identity_pair() -> tuple[RAGIdentityDescriptor, RAGIdentityDescriptor]:
    """Require N and N+1 to differ only in approved profile and expectation metadata."""

    known_good = load_identity("known-good")
    regression = load_identity("synthetic-regression")
    common_fields = (
        "baseline",
        "repository",
        "prompt",
        "rag_configuration",
        "retriever",
        "evidence",
        "evaluation",
        "guardrail",
    )
    if any(getattr(known_good, field) != getattr(regression, field) for field in common_fields):
        raise RollbackIdentityError
    return known_good, regression
