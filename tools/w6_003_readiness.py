"""Offline W6-003 integrated-readiness and W6-004 handover validation."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path, PureWindowsPath
from typing import Any, cast

import yaml  # type: ignore[import-untyped]

CONFIG_SCHEMA = "w6-003.readiness-config.v1"
LOCAL_PROOF_SCHEMA = "w6-003.local-proof.v1"
LOCAL_ROLLBACK_SCHEMA = "w6-003.local-rollback.v1"
APPLICATION_SCHEMA = "w6-003.known-good-application.v1"
INFRASTRUCTURE_SCHEMA = "w6-003.known-good-infrastructure.v1"
HANDOVER_SCHEMA = "w6-003.w6-004-handover.v1"
VALIDATION_MESSAGE = "W6-003 INTEGRATED READINESS CONTRACT VALID — NOT DEPLOYED"
APPROVED_BASELINE = "ad943842cd0448a0d3db991707a1c2f1181a79c7"
ALLOWED_OUTPUT_ROOT = r"E:\AI\.runtime\enterprise_ai_platform\w6-003\owner-test-01"
TEMPORARY_ROOT = r"E:\AI\.tmp\enterprise-ai-platform-w6-003\owner-test-01"
VALIDITY_HOURS = 24
EVIDENCE_STATUSES = frozenset({"PASS", "FAIL", "NOT RUN", "INDETERMINATE", "NO_DATA"})
EVIDENCE_STATUS_ORDER = ("PASS", "FAIL", "NOT RUN", "INDETERMINATE", "NO_DATA")
RETAINED_FILES = (
    "local-proof.json",
    "local-rollback-rehearsal.json",
    "w6-004-readiness-manifest.json",
)
LIFECYCLE = (
    "bootstrap/state",
    "network/security",
    "data/services",
    "ECR/image",
    "EKS/identity",
    "application composition",
    "observability",
    "live tests",
    "rollback",
    "complete teardown",
    "residue/cost verification",
)
OWNER_DECISIONS = (
    "deterministic in-memory providers only",
    "no Docker, Qdrant, telemetry service, Kubernetes or cloud-service startup",
    "retain only the three approved W6-003 evidence files until W6-004 closure",
    "evidence expires after 24 hours",
    "W6-004 Stage A establishes the first live known-good identities",
    "historical AWS account and Region require W6-004 reapproval",
    "preserve historical warnings, limitations and NOT RUN activities",
    "MVP-001 remains In Progress until W6-004 completion",
)
LIMITATIONS = (
    "W5 Bedrock live verification limitations remain open",
    "W5 cost coverage remains accepted risk and not current W6 approval",
    "W5 KMS pending-deletion follow-up requires fresh native verification",
    "W5 delayed billing reconciliation remains open",
    "W6-001 source template is valid but not deployable",
    "W6-001 Stage B immutable release binding is NOT RUN",
    "W6-002 cloud exporters, live alerts and FIS execution are NOT RUN",
    "local and injected evidence does not prove cloud or production readiness",
)
NOT_RUN_ACTIVITIES = (
    "ECR publication and registry-returned digest verification",
    "W6-001 Stage B immutable release binding",
    "AWS infrastructure creation",
    "EKS server-side validation and deployment",
    "live OpenSearch and Bedrock integration",
    "live CloudWatch and X-Ray integration",
    "live FIS execution",
    "cloud rollback and complete teardown",
    "native residue and delayed-cost verification",
)
STOP_CONDITIONS = (
    "handover manifest absent, expired or changed",
    "nested evidence hash mismatch",
    "mandatory local gate not PASS",
    "owner cloud target, profile, expiry or cost approval absent",
    "fresh Terraform plan and matching current state absent",
    "ECR registry-returned immutable digest absent",
    "W6-001 Stage B immutable release binding absent",
    "policy, security, pricing, rollback or teardown coverage incomplete",
    "rollback target is not an independently verified immutable identity",
)
REQUIRED_REPOSITORY_PATHS = (
    "src/enterprise_ai_platform/app.py",
    "src/enterprise_ai_platform/api/dependencies.py",
    "src/enterprise_ai_platform/retrieval/service.py",
    "src/enterprise_ai_platform/rag/service.py",
    "src/enterprise_ai_platform/guardrails/policy.py",
    "src/enterprise_ai_platform/agent/controller.py",
    "src/enterprise_ai_platform/evaluation/evaluator.py",
    "src/enterprise_ai_platform/telemetry/runtime.py",
    "src/enterprise_ai_platform/release_rollback/service.py",
    "configs/releases/versions/w4-known-good-v1.json",
    "configs/releases/versions/w4-synthetic-regression-v1.json",
    "tools/w6_001_k8s.py",
    "tools/w6_002_observability.py",
    "configs/readiness/local-integrated-readiness.yaml",
    "tools/w6_003_readiness.py",
)
COMPOSITION_PATHS = tuple(
    dict.fromkeys(
        (
            *REQUIRED_REPOSITORY_PATHS,
            "Makefile",
            "pyproject.toml",
            "feature-matrix.yaml",
            "tools/platformctl/validate.py",
            ".github/workflows/ci.yml",
            "tests/fakes/readiness.py",
            "tests/unit/test_w6_003_readiness.py",
            "tests/unit/test_platformctl.py",
            "tests/contract/test_w6_003_readiness_contract.py",
            "tests/integration/test_w6_003_platform_composition.py",
            "tests/integration/test_dependency_contract.py",
            "tests/integration/test_w5_002_ci_composition.py",
            "tests/feature/test_w6_003_integrated_readiness.py",
            "tests/feature/test_feature_matrix.py",
            "tests/smoke/test_w6_003_local_smoke.py",
            "tests/security/test_w6_003_readiness_security.py",
            "tests/rollback/test_w6_003_local_rollback.py",
            "tests/teardown/test_w6_003_readiness_cleanliness.py",
        )
    )
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SENSITIVE_KEY_RE = re.compile(
    r"(?i)(password|secret|token|credential|private.?key|access.?key|"
    r"prompt|content|tenant|customer)"
)


class W6003Error(ValueError):
    """Raised when W6-003 evidence or configuration fails closed."""


class UniqueSafeLoader(yaml.SafeLoader):  # type: ignore[misc]
    """Safe YAML loader that rejects duplicate mapping keys."""


def _construct_mapping(loader: UniqueSafeLoader, node: yaml.Node, deep: bool = False) -> Any:
    result: dict[object, object] = {}
    for key_node, value_node in cast(yaml.MappingNode, node).value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise W6003Error(f"duplicate YAML key: {key!r}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


UniqueSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping,
)


def canonical_json_bytes(value: object) -> bytes:
    """Return the only accepted deterministic JSON representation."""

    try:
        serialized = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise W6003Error("evidence is not canonical JSON data") from exc
    return f"{serialized}\n".encode()


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def repository_composition_sha256(root: Path) -> str:
    """Hash the exact W6-003 producer, consumer and control composition."""

    repository = root.resolve(strict=True)
    digest = hashlib.sha256()
    for relative_path in sorted(COMPOSITION_PATHS):
        path = repository / relative_path
        if path.is_symlink() or not path.is_file():
            raise W6003Error(f"missing or unsafe composition path: {relative_path}")
        digest.update(relative_path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _reject_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise W6003Error(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> object:
    raise W6003Error(f"non-finite JSON value is prohibited: {value}")


def load_strict_json(path: Path) -> tuple[dict[str, object], bytes]:
    """Load one canonical UTF-8 JSON object without accepting duplicate keys."""

    try:
        payload = path.read_bytes()
        text = payload.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_reject_pairs,
            parse_constant=_reject_constant,
        )
    except W6003Error:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise W6003Error(f"invalid strict JSON evidence: {path.name}") from exc
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise W6003Error("evidence must contain one JSON object")
    result = cast(dict[str, object], value)
    if payload != canonical_json_bytes(result):
        raise W6003Error("evidence must use canonical JSON with one final newline")
    return result, payload


def load_config(path: Path) -> dict[str, object]:
    try:
        text = path.read_text(encoding="utf-8")
        loader = UniqueSafeLoader(text)
        try:
            value = loader.get_single_data()
        finally:
            loader.dispose()
    except W6003Error:
        raise
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise W6003Error("readiness configuration must be strict UTF-8 YAML") from exc
    return _mapping(value, "readiness configuration")


def _mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise W6003Error(f"{label} must be an object")
    return cast(dict[str, object], value)


def _list(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        raise W6003Error(f"{label} must be a list")
    return value


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise W6003Error(f"{label} must be a non-empty string")
    return value


def _strings(value: object, label: str) -> tuple[str, ...]:
    values = _list(value, label)
    if any(not isinstance(item, str) or not item for item in values):
        raise W6003Error(f"{label} must contain only non-empty strings")
    return tuple(cast(list[str], values))


def _exact_keys(value: Mapping[str, object], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise W6003Error(f"{label} fields differ from the closed schema")


def _sha256(value: object, label: str) -> str:
    text = _text(value, label)
    if SHA256_RE.fullmatch(text) is None:
        raise W6003Error(f"{label} must be 64 lowercase hexadecimal characters")
    return text


def _timestamp(value: object, label: str) -> datetime:
    text = _text(value, label)
    if not text.endswith("Z"):
        raise W6003Error(f"{label} must be UTC and end in Z")
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as exc:
        raise W6003Error(f"{label} is invalid") from exc
    if parsed.tzinfo != UTC:
        raise W6003Error(f"{label} must be UTC")
    return parsed


def _validate_window(
    value: Mapping[str, object],
    *,
    now: datetime | None,
) -> None:
    generated = _timestamp(value.get("generated_at"), "generated_at")
    expires = _timestamp(value.get("expires_at"), "expires_at")
    if expires - generated != timedelta(hours=VALIDITY_HOURS):
        raise W6003Error("evidence validity must be exactly 24 hours")
    current = (now or datetime.now(UTC)).astimezone(UTC)
    if generated > current or current >= expires:
        raise W6003Error("evidence is future-dated or expired")


def _validate_roots(value: Mapping[str, object]) -> None:
    allowed = _text(value.get("allowed_output_root"), "allowed_output_root")
    output = _text(value.get("output_root"), "output_root")
    if PureWindowsPath(allowed) != PureWindowsPath(ALLOWED_OUTPUT_ROOT):
        raise W6003Error("allowed output root differs")
    if PureWindowsPath(output) != PureWindowsPath(ALLOWED_OUTPUT_ROOT):
        raise W6003Error("output root must equal the approved private evidence root")


def _validate_safe_keys(value: object) -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            if not isinstance(key, str) or SENSITIVE_KEY_RE.search(key):
                raise W6003Error("evidence contains a prohibited sensitive or narrative field")
            _validate_safe_keys(nested)
    elif isinstance(value, list):
        for nested in value:
            _validate_safe_keys(nested)


def validate_config_values(value: dict[str, object]) -> None:
    """Validate the exact owner-approved W6-003 configuration values."""

    _exact_keys(
        value,
        {
            "schema_version",
            "classification",
            "owner",
            "approved_source_baseline",
            "execution",
            "evidence",
            "schemas",
            "evidence_statuses",
            "historical_cloud_target",
            "known_good",
            "lifecycle",
            "owner_decisions",
            "limitations",
            "not_run_activities",
            "stop_conditions",
            "required_repository_paths",
        },
        "readiness configuration",
    )
    if value.get("schema_version") != CONFIG_SCHEMA:
        raise W6003Error("configuration schema differs")
    if value.get("classification") != "local-integrated-readiness-only-not-deployed":
        raise W6003Error("configuration classification differs")
    if value.get("owner") != "Gyan Prakash Rai":
        raise W6003Error("configuration owner differs")
    if value.get("approved_source_baseline") != APPROVED_BASELINE:
        raise W6003Error("approved source baseline differs")
    if _mapping(value.get("execution"), "execution") != {
        "provider_mode": "deterministic-in-memory",
        "network_activity": "prohibited",
        "subprocess_activity": "prohibited",
        "docker_activity": "prohibited",
        "cloud_activity": "NOT RUN",
    }:
        raise W6003Error("execution boundary differs")
    if _mapping(value.get("evidence"), "evidence") != {
        "allowed_output_root": ALLOWED_OUTPUT_ROOT,
        "temporary_root": TEMPORARY_ROOT,
        "validity_hours": VALIDITY_HOURS,
        "retained_files": list(RETAINED_FILES),
    }:
        raise W6003Error("evidence boundary differs")
    if _mapping(value.get("schemas"), "schemas") != {
        "local_proof": LOCAL_PROOF_SCHEMA,
        "local_rollback": LOCAL_ROLLBACK_SCHEMA,
        "known_good_application": APPLICATION_SCHEMA,
        "known_good_infrastructure": INFRASTRUCTURE_SCHEMA,
        "handover": HANDOVER_SCHEMA,
    }:
        raise W6003Error("schema inventory differs")
    statuses = _strings(value.get("evidence_statuses"), "evidence_statuses")
    if statuses != EVIDENCE_STATUS_ORDER:
        raise W6003Error("evidence status vocabulary differs")
    if _mapping(value.get("historical_cloud_target"), "historical_cloud_target") != {
        "classification": "historical-proposed-not-approved-for-w6-004",
        "aws_account_id": "526338061652",
        "aws_region": "ap-southeast-1",
    }:
        raise W6003Error("historical cloud target differs")
    known_good = _mapping(value.get("known_good"), "known_good")
    if known_good != {
        "application": {
            "deployable_identity_status": "MISSING",
            "ecr_repository_uri": None,
            "registry_digest": None,
            "release_binding_status": "NOT RUN",
            "promotion_mode": "w6-004-stage-a",
        },
        "infrastructure": {
            "deployable_identity_status": "MISSING",
            "backend_identity": None,
            "state_lineage": None,
            "state_serial": None,
            "saved_plan_sha256": None,
            "policy_status": "NOT RUN",
            "cost_status": "NOT RUN",
            "promotion_mode": "w6-004-stage-a",
        },
    }:
        raise W6003Error("known-good bootstrap boundary differs")
    exact_sequences = (
        ("lifecycle", LIFECYCLE),
        ("owner_decisions", OWNER_DECISIONS),
        ("limitations", LIMITATIONS),
        ("not_run_activities", NOT_RUN_ACTIVITIES),
        ("stop_conditions", STOP_CONDITIONS),
        ("required_repository_paths", REQUIRED_REPOSITORY_PATHS),
    )
    for key, expected in exact_sequences:
        if _strings(value.get(key), key) != expected:
            raise W6003Error(f"{key} differs")


def validate_config(root: Path, config_path: Path) -> str:
    """Validate the repository-local config and required producer/consumer paths."""

    repository = root.resolve(strict=True)
    resolved_config = config_path.resolve(strict=True)
    try:
        resolved_config.relative_to(repository)
    except ValueError as exc:
        raise W6003Error("readiness configuration must be inside the repository") from exc
    if config_path.is_symlink() or not resolved_config.is_file():
        raise W6003Error("readiness configuration must be a regular file")
    values = load_config(resolved_config)
    validate_config_values(values)
    for relative_path in REQUIRED_REPOSITORY_PATHS:
        path = repository / relative_path
        if path.is_symlink() or not path.is_file():
            raise W6003Error(f"missing or unsafe readiness dependency: {relative_path}")
    return VALIDATION_MESSAGE


def _validate_results(value: object) -> None:
    results = _list(value, "test_results")
    if not results:
        raise W6003Error("test_results must not be empty")
    mandatory_statuses: list[str] = []
    for index, item in enumerate(results):
        result = _mapping(item, f"test_results[{index}]")
        _exact_keys(result, {"check_name", "status", "scope"}, f"test_results[{index}]")
        _text(result.get("check_name"), "check_name")
        scope = _text(result.get("scope"), "scope")
        status = _text(result.get("status"), "test result status")
        if status not in EVIDENCE_STATUSES:
            raise W6003Error("test result status differs")
        if scope == "mandatory-local":
            mandatory_statuses.append(status)
    if not mandatory_statuses or any(status != "PASS" for status in mandatory_statuses):
        raise W6003Error("every mandatory local gate must be present and PASS")


def validate_local_proof(value: dict[str, object], *, now: datetime | None = None) -> None:
    _exact_keys(
        value,
        {
            "schema_version",
            "source_identity",
            "configuration_identity",
            "component_identities",
            "provider_mode",
            "test_results",
            "warnings",
            "exclusions",
            "limitations",
            "deferrals",
            "cloud_deployment_status",
            "generated_at",
            "expires_at",
            "allowed_output_root",
            "output_root",
        },
        "local proof",
    )
    if value.get("schema_version") != LOCAL_PROOF_SCHEMA:
        raise W6003Error("local proof schema differs")
    _sha256(value.get("source_identity"), "source_identity")
    _sha256(value.get("configuration_identity"), "configuration_identity")
    components = _mapping(value.get("component_identities"), "component_identities")
    if not components:
        raise W6003Error("component identities must not be empty")
    for name, identity in components.items():
        _text(name, "component name")
        _sha256(identity, f"component identity {name}")
    if value.get("provider_mode") != "deterministic-in-memory":
        raise W6003Error("local proof provider mode differs")
    _validate_results(value.get("test_results"))
    for key in ("warnings", "exclusions", "limitations", "deferrals"):
        _strings(value.get(key), key)
    if value.get("cloud_deployment_status") != "NOT RUN":
        raise W6003Error("cloud deployment status must remain NOT RUN")
    _validate_window(value, now=now)
    _validate_roots(value)
    _validate_safe_keys(value)


def validate_local_rollback(value: dict[str, object], *, now: datetime | None = None) -> None:
    _exact_keys(
        value,
        {
            "schema_version",
            "known_good_release",
            "candidate_release",
            "rollback_trigger",
            "candidate_status",
            "restored_application_identity",
            "smoke_status",
            "security_status",
            "evaluation_status",
            "elapsed_seconds",
            "cleanup_status",
            "residue_status",
            "eks_rollback_status",
            "terraform_rollback_status",
            "generated_at",
            "expires_at",
            "allowed_output_root",
            "output_root",
        },
        "local rollback",
    )
    expected = {
        "schema_version": LOCAL_ROLLBACK_SCHEMA,
        "known_good_release": "w4-known-good-v1",
        "candidate_release": "w4-synthetic-regression-v1",
        "rollback_trigger": "expected-local-regression",
        "candidate_status": "FAIL",
        "smoke_status": "PASS",
        "security_status": "PASS",
        "evaluation_status": "PASS",
        "cleanup_status": "PASS",
        "residue_status": "PASS",
        "eks_rollback_status": "NOT RUN",
        "terraform_rollback_status": "NOT RUN",
    }
    if any(value.get(key) != expected_value for key, expected_value in expected.items()):
        raise W6003Error("local rollback result differs")
    _sha256(value.get("restored_application_identity"), "restored_application_identity")
    elapsed = value.get("elapsed_seconds")
    if isinstance(elapsed, bool) or not isinstance(elapsed, int | float) or not 0 <= elapsed <= 30:
        raise W6003Error("local rollback elapsed_seconds must be bounded to 30 seconds")
    _validate_window(value, now=now)
    _validate_roots(value)
    _validate_safe_keys(value)


def _validate_application(value: object) -> dict[str, object]:
    application = _mapping(value, "known_good_application")
    _exact_keys(
        application,
        {
            "schema_version",
            "source_composition_sha256",
            "historical_w4_proof_sha256",
            "ecr_repository_uri",
            "registry_digest",
            "release_binding_status",
            "promotion_mode",
            "deployable_identity_status",
        },
        "known_good_application",
    )
    _sha256(application.get("source_composition_sha256"), "source_composition_sha256")
    _sha256(application.get("historical_w4_proof_sha256"), "historical_w4_proof_sha256")
    if application.get("schema_version") != APPLICATION_SCHEMA or any(
        application.get(key) != expected
        for key, expected in {
            "ecr_repository_uri": None,
            "registry_digest": None,
            "release_binding_status": "NOT RUN",
            "promotion_mode": "w6-004-stage-a",
            "deployable_identity_status": "MISSING",
        }.items()
    ):
        raise W6003Error("application known-good identity must remain absent until W6-004 Stage A")
    return application


def _validate_infrastructure(value: object) -> dict[str, object]:
    infrastructure = _mapping(value, "known_good_infrastructure")
    _exact_keys(
        infrastructure,
        {
            "schema_version",
            "terraform_composition_sha256",
            "provider_lock_sha256",
            "backend_identity",
            "state_lineage",
            "state_serial",
            "saved_plan_sha256",
            "policy_status",
            "cost_status",
            "promotion_mode",
            "deployable_identity_status",
        },
        "known_good_infrastructure",
    )
    _sha256(infrastructure.get("terraform_composition_sha256"), "terraform composition")
    _sha256(infrastructure.get("provider_lock_sha256"), "provider lock")
    if infrastructure.get("schema_version") != INFRASTRUCTURE_SCHEMA or any(
        infrastructure.get(key) != expected
        for key, expected in {
            "backend_identity": None,
            "state_lineage": None,
            "state_serial": None,
            "saved_plan_sha256": None,
            "policy_status": "NOT RUN",
            "cost_status": "NOT RUN",
            "promotion_mode": "w6-004-stage-a",
            "deployable_identity_status": "MISSING",
        }.items()
    ):
        raise W6003Error(
            "infrastructure known-good identity must remain absent until W6-004 Stage A"
        )
    return infrastructure


def _validate_reference(
    value: object,
    *,
    expected_schema: str,
    expected_sha256: str,
    label: str,
) -> None:
    reference = _mapping(value, label)
    _exact_keys(reference, {"schema_version", "sha256"}, label)
    if reference.get("schema_version") != expected_schema:
        raise W6003Error(f"{label} schema differs")
    if _sha256(reference.get("sha256"), f"{label}.sha256") != expected_sha256:
        raise W6003Error(f"{label} hash differs")


def validate_handover(
    value: dict[str, object],
    *,
    local_proof_sha256: str,
    local_rollback_sha256: str,
    now: datetime | None = None,
) -> None:
    _exact_keys(
        value,
        {
            "schema_version",
            "source_identity",
            "local_proof",
            "local_rollback",
            "known_good_application",
            "known_good_infrastructure",
            "owner_decisions",
            "warnings",
            "risks",
            "limitations",
            "not_run_activities",
            "indeterminate_activities",
            "retained_artifacts",
            "deferred_cleanup",
            "lifecycle",
            "generated_at",
            "expires_at",
            "w6_004_entry_decision",
            "stop_reasons",
            "stage_a_known_good_promotion_required",
            "allowed_output_root",
            "output_root",
        },
        "W6-004 handover",
    )
    if value.get("schema_version") != HANDOVER_SCHEMA:
        raise W6003Error("handover schema differs")
    _sha256(value.get("source_identity"), "source_identity")
    _validate_reference(
        value.get("local_proof"),
        expected_schema=LOCAL_PROOF_SCHEMA,
        expected_sha256=local_proof_sha256,
        label="local_proof",
    )
    _validate_reference(
        value.get("local_rollback"),
        expected_schema=LOCAL_ROLLBACK_SCHEMA,
        expected_sha256=local_rollback_sha256,
        label="local_rollback",
    )
    _validate_application(value.get("known_good_application"))
    _validate_infrastructure(value.get("known_good_infrastructure"))
    if _strings(value.get("owner_decisions"), "owner_decisions") != OWNER_DECISIONS:
        raise W6003Error("owner decisions differ")
    for key in ("warnings", "risks", "indeterminate_activities", "deferred_cleanup"):
        _strings(value.get(key), key)
    if _strings(value.get("limitations"), "limitations") != LIMITATIONS:
        raise W6003Error("historical limitations differ")
    if _strings(value.get("not_run_activities"), "not_run_activities") != NOT_RUN_ACTIVITIES:
        raise W6003Error("NOT RUN activities differ")
    if _strings(value.get("retained_artifacts"), "retained_artifacts") != RETAINED_FILES:
        raise W6003Error("retained artifact inventory differs")
    if _strings(value.get("lifecycle"), "lifecycle") != LIFECYCLE:
        raise W6003Error("W6-004 lifecycle differs")
    if value.get("w6_004_entry_decision") != "BLOCKED_PENDING_W6_004_STAGE_A":
        raise W6003Error("W6-004 entry must remain blocked pending Stage A")
    if _strings(value.get("stop_reasons"), "stop_reasons") != STOP_CONDITIONS:
        raise W6003Error("W6-004 stop reasons differ")
    if value.get("stage_a_known_good_promotion_required") is not True:
        raise W6003Error("W6-004 Stage A promotion must remain mandatory")
    _validate_window(value, now=now)
    _validate_roots(value)
    _validate_safe_keys(value)


def validate_evidence_files(
    *,
    local_proof_path: Path,
    local_rollback_path: Path,
    handover_path: Path,
    now: datetime | None = None,
) -> str:
    """Validate all three retained files and their nested immutable identities."""

    expected_names = tuple(
        path.name for path in (local_proof_path, local_rollback_path, handover_path)
    )
    if expected_names != RETAINED_FILES:
        raise W6003Error("evidence filenames differ from the approved retained inventory")
    expected_parent = PureWindowsPath(ALLOWED_OUTPUT_ROOT)
    resolved_parents: set[Path] = set()
    for path in (local_proof_path, local_rollback_path, handover_path):
        try:
            resolved_parent = path.parent.resolve(strict=True)
            resolved_path = path.resolve(strict=True)
        except OSError as exc:
            raise W6003Error("evidence file or private output root is missing") from exc
        if (
            PureWindowsPath(str(path.parent)) != expected_parent
            or path.parent.is_symlink()
            or path.is_symlink()
            or not resolved_path.is_file()
            or resolved_path.parent != resolved_parent
        ):
            raise W6003Error("evidence path is outside the approved private output root")
        resolved_parents.add(resolved_parent)
    if len(resolved_parents) != 1:
        raise W6003Error("evidence files must share one approved private output root")
    output_root = next(iter(resolved_parents))
    if sorted(item.name for item in output_root.iterdir()) != sorted(RETAINED_FILES):
        raise W6003Error("private output root contains missing or unexpected residue")
    local_proof, local_proof_payload = load_strict_json(local_proof_path)
    local_rollback, local_rollback_payload = load_strict_json(local_rollback_path)
    handover, _ = load_strict_json(handover_path)
    validate_local_proof(local_proof, now=now)
    validate_local_rollback(local_rollback, now=now)
    validate_handover(
        handover,
        local_proof_sha256=sha256_bytes(local_proof_payload),
        local_rollback_sha256=sha256_bytes(local_rollback_payload),
        now=now,
    )
    if handover.get("source_identity") != local_proof.get("source_identity"):
        raise W6003Error("handover and local proof source identities differ")
    application = _mapping(handover.get("known_good_application"), "known_good_application")
    if application.get("source_composition_sha256") != local_proof.get("source_identity"):
        raise W6003Error("application and local proof source identities differ")
    if application.get("historical_w4_proof_sha256") != local_rollback.get(
        "restored_application_identity"
    ):
        raise W6003Error("application and rollback known-good identities differ")
    return VALIDATION_MESSAGE


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    config = subparsers.add_parser("validate-config")
    config.add_argument("--root", type=Path, default=Path.cwd())
    config.add_argument("--config", type=Path, required=True)
    source = subparsers.add_parser("source-identity")
    source.add_argument("--root", type=Path, default=Path.cwd())
    evidence = subparsers.add_parser("validate-evidence")
    evidence.add_argument("--local-proof", type=Path, required=True)
    evidence.add_argument("--local-rollback", type=Path, required=True)
    evidence.add_argument("--handover", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "validate-config":
        print(validate_config(args.root, args.config))
    elif args.command == "source-identity":
        print(repository_composition_sha256(args.root))
    elif args.command == "validate-evidence":
        print(
            validate_evidence_files(
                local_proof_path=args.local_proof,
                local_rollback_path=args.local_rollback,
                handover_path=args.handover,
            )
        )
    else:  # pragma: no cover - argparse enforces the closed command set
        raise W6003Error("unsupported command")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
