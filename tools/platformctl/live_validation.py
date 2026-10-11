"""Offline W6-004 lifecycle source and evidence validation."""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from decimal import Decimal, InvalidOperation
from ipaddress import IPv4Network, ip_network
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .lifecycle_models import BedrockLoggingContract

SOURCE_SCHEMA = "w6-004.source-contract.v1"
SOURCE_STATUS = "W6-004 LIFECYCLE SOURCE CONTRACT VALID - NOT EXECUTED"
OWNER_SENTINEL = "OWNER_BINDING_REQUIRED"
HISTORICAL_AUTHORIZATION_FAILURE = "AUTHORIZATION FAILURE OBSERVED — ROOT CAUSE UNRESOLVED"
EVIDENCE_ROOT = Path("E:/AI/.runtime/enterprise_ai_platform/w6-004/owner-test-01")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
OPERATION_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{7,63}$")
STATUS_VALUES = frozenset({"PASS", "FAIL", "NOT RUN", "INDETERMINATE", "NO_DATA"})
PROTECTED_KEY_PATTERN = re.compile(
    r"(?i)(credential|password|private.?key|secret|session.?token|access.?key|kubeconfig|content|prompt|embedding)"
)
LIFECYCLE_ORDER = (
    "bootstrap_state",
    "network_security",
    "data_services",
    "ecr_image",
    "eks_identity",
    "application_composition",
    "observability",
    "live_tests",
    "application_rollback",
    "infrastructure_rollback",
    "complete_teardown",
    "residue_cost_verification",
)
APPROVED_EVIDENCE_SCOPES = frozenset(
    {
        "discovery",
        "bootstrap-plan",
        "bootstrap-apply",
        "platform-plan",
        "platform-apply",
        "image",
        "release",
        "deployment",
        "live-tests",
        "application-rollback",
        "infrastructure-regression",
        "infrastructure-rollback",
        "platform-destroy",
        "bootstrap-destroy",
        "residue",
        "cost",
        "closure",
    }
)
COMMON_EVIDENCE_FIELDS = frozenset(
    {
        "schema_version",
        "task_id",
        "operation_id",
        "operation_type",
        "source_sha256",
        "input_sha256",
        "account_id",
        "region",
        "principal_arn",
        "environment",
        "created_at",
        "expires_at",
        "approval_sha256",
        "evidence_scope",
        "output_root",
        "evidence_sha256",
        "status",
    }
)
SCHEMA_FIELDS: dict[str, frozenset[str]] = {
    "w6-004.discovery.v1": frozenset(
        {"native_inventory_sha256", "kms_tail_status", "billing_status"}
    ),
    "w6-004.inputs.v1": frozenset(
        {"owner_bindings_sha256", "cost_ceiling_usd", "stage_limits_sha256"}
    ),
    "w6-004.plan.v1": frozenset(
        {
            "terraform_version",
            "provider_lock_sha256",
            "state_lineage",
            "state_serial",
            "saved_plan_sha256",
        }
    ),
    "w6-004.normalized-plan.v1": frozenset(
        {"plan_sha256", "normalized_plan_sha256", "resource_change_count"}
    ),
    "w6-004.opa.v1": frozenset({"normalized_plan_sha256", "policy_bundle_sha256", "decision"}),
    "w6-004.cost.v1": frozenset(
        {
            "normalized_plan_sha256",
            "pricing_sha256",
            "estimated_usd",
            "cost_ceiling_usd",
            "coverage",
            "planned_resource_count",
            "priced_resource_count",
            "embedded_errors",
        }
    ),
    "w6-004.approval.v1": frozenset(
        {"plan_sha256", "opa_sha256", "cost_sha256", "approval_id", "consumed"}
    ),
    "w6-004.apply.v1": frozenset(
        {"saved_plan_sha256", "approval_id", "state_lineage", "state_serial", "apply_status"}
    ),
    "w6-004.partial-apply.v1": frozenset(
        {"saved_plan_sha256", "state_sha256", "inventory_sha256", "mutation_frozen"}
    ),
    "w6-004.image.v1": frozenset(
        {
            "dependency_lock_sha256",
            "dockerfile_sha256",
            "base_image_digest",
            "oci_digest",
            "registry_digest",
            "scan_sha256",
            "sbom_sha256",
            "provenance_sha256",
            "repository_uri",
            "image_composition_sha256",
            "embedding_snapshot_sha256",
        }
    ),
    "w6-004.vulnerability-scan.v1": frozenset(
        {
            "image_digest",
            "scanner",
            "scanner_version",
            "database_sha256",
            "report_sha256",
            "critical",
            "high",
            "waiver_sha256",
        }
    ),
    "w6-004.sbom.v1": frozenset({"image_digest", "format", "document_sha256"}),
    "w6-004.provenance.v1": frozenset({"source_sha256_bound", "image_digest", "statement_sha256"}),
    "w6-004.release-binding.v1": frozenset(
        {"application_digest", "collector_digest", "runtime_sha256", "manifest_sha256"}
    ),
    "w6-004.deployment.v1": frozenset(
        {
            "cluster_arn",
            "kubernetes_version",
            "namespace",
            "service_account",
            "pod_identity_arn",
            "workload_sha256",
            "running_digests",
        }
    ),
    "w6-004.live-test.v1": frozenset({"deployment_sha256", "checks", "slo_classification"}),
    "w6-004.application-rollback.v1": frozenset(
        {"known_good_digest", "regression_digest", "running_digest", "health_sha256"}
    ),
    "w6-004.infrastructure-rollback.v1": frozenset(
        {
            "known_good_state_sha256",
            "regression_plan_sha256",
            "restore_plan_sha256",
            "restored_state_sha256",
        }
    ),
    "w6-004.destroy.v1": frozenset(
        {
            "target",
            "destroy_plan_sha256",
            "state_before_sha256",
            "state_after_sha256",
            "shared_exclusions_sha256",
        }
    ),
    "w6-004.residue.v1": frozenset(
        {"native_inventory_sha256", "expected_residuals", "unexpected_residuals", "kms_status"}
    ),
    "w6-004.billing.v1": frozenset({"cost_explorer_sha256", "observed_usd", "billing_lag_status"}),
    "w6-004.closure.v1": frozenset(
        {"stage_evidence_sha256", "residue_sha256", "billing_sha256", "deferred_followups"}
    ),
}


SCHEMA_SCOPES: dict[str, frozenset[str]] = {
    "w6-004.discovery.v1": frozenset({"discovery"}),
    "w6-004.inputs.v1": frozenset({"discovery"}),
    "w6-004.plan.v1": frozenset(
        {
            "bootstrap-plan",
            "platform-plan",
            "infrastructure-regression",
            "infrastructure-rollback",
            "platform-destroy",
            "bootstrap-destroy",
        }
    ),
    "w6-004.normalized-plan.v1": frozenset(
        {
            "bootstrap-plan",
            "platform-plan",
            "infrastructure-regression",
            "infrastructure-rollback",
            "platform-destroy",
            "bootstrap-destroy",
        }
    ),
    "w6-004.opa.v1": frozenset({"bootstrap-plan", "platform-plan"}),
    "w6-004.cost.v1": frozenset({"cost"}),
    "w6-004.approval.v1": frozenset(
        {
            "bootstrap-plan",
            "platform-plan",
            "image",
            "release",
            "deployment",
            "application-rollback",
            "infrastructure-regression",
            "infrastructure-rollback",
            "platform-destroy",
            "bootstrap-destroy",
        }
    ),
    "w6-004.apply.v1": frozenset({"bootstrap-apply", "platform-apply"}),
    "w6-004.partial-apply.v1": frozenset({"bootstrap-apply", "platform-apply"}),
    "w6-004.image.v1": frozenset({"image"}),
    "w6-004.vulnerability-scan.v1": frozenset({"image"}),
    "w6-004.sbom.v1": frozenset({"image"}),
    "w6-004.provenance.v1": frozenset({"image"}),
    "w6-004.release-binding.v1": frozenset({"release"}),
    "w6-004.deployment.v1": frozenset({"deployment"}),
    "w6-004.live-test.v1": frozenset({"live-tests"}),
    "w6-004.application-rollback.v1": frozenset({"application-rollback"}),
    "w6-004.infrastructure-rollback.v1": frozenset({"infrastructure-rollback"}),
    "w6-004.destroy.v1": frozenset({"platform-destroy", "bootstrap-destroy"}),
    "w6-004.residue.v1": frozenset({"residue"}),
    "w6-004.billing.v1": frozenset({"cost"}),
    "w6-004.closure.v1": frozenset({"closure"}),
}
MUTATION_SCHEMAS = frozenset(
    {
        "w6-004.apply.v1",
        "w6-004.partial-apply.v1",
        "w6-004.release-binding.v1",
        "w6-004.deployment.v1",
        "w6-004.application-rollback.v1",
        "w6-004.infrastructure-rollback.v1",
        "w6-004.destroy.v1",
    }
)
OWNER_BINDING_KEYS = frozenset(
    {
        "aws_cli_profile",
        "federated_principal_arn",
        "administrator_role_arn",
        "owner_api_cidr",
        "deployment_start",
        "approval_issued_at",
        "approval_expires_at",
        "cost_ceiling_usd",
        "stage_stop_limits_usd",
        "eks_kubernetes_version",
        "eks_node_instance_types",
        "addon_versions",
        "metrics_server_image",
        "otel_collector_image",
        "kubectl_version",
        "kustomize_version",
        "bedrock_inference_profile",
        "bedrock_model_id",
        "alert_recipients",
        "trivy_version",
        "trivy_database_sha256",
        "grype_version",
        "grype_database_sha256",
        "application_image_digest",
        "collector_image_digest",
        "known_good_application_digest",
        "known_good_infrastructure_identity",
        "bootstrap_state_lineage",
        "bootstrap_state_serial",
        "platform_state_lineage",
        "platform_state_serial",
        "plan_policy_cost_approval_hashes",
    }
)
STAGE_LIMIT_KEYS = frozenset(
    {
        "bootstrap",
        "platform",
        "image",
        "eks",
        "opensearch",
        "observability",
        "resilience",
        "teardown",
    }
)
ADDON_VERSION_KEYS = frozenset({"vpc-cni", "coredns", "kube-proxy", "eks-pod-identity-agent"})
IMAGE_REFERENCE_PATTERN = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")


class W6004Error(ValueError):
    """Raised when a W6-004 source or evidence contract fails closed."""


def canonical_sha256(value: object) -> str:
    _validate_json_tree(value)
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )
    return hashlib.sha256(f"{payload}\n".encode()).hexdigest()


def _validate_json_tree(value: object, *, key_path: tuple[str, ...] = ()) -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise W6004Error("non-finite evidence number")
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise W6004Error("evidence keys must be strings")
            if PROTECTED_KEY_PATTERN.search(key) and not key.endswith("_sha256"):
                location = ".".join((*key_path, key))
                raise W6004Error(f"protected evidence field is prohibited: {location}")
            _validate_json_tree(item, key_path=(*key_path, key))
    elif isinstance(value, Sequence) and not isinstance(value, str | bytes):
        for item in value:
            _validate_json_tree(item, key_path=key_path)


def _parse_utc(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise W6004Error(f"{field} must be UTC ISO-8601")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise W6004Error(f"{field} must be UTC ISO-8601") from exc
    if parsed.utcoffset() != timedelta(0):
        raise W6004Error(f"{field} must be UTC")
    return parsed


def _sha(value: object, field: str) -> str:
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise W6004Error(f"{field} must be lowercase SHA-256")
    return value


def _digest(value: object, field: str) -> str:
    if not isinstance(value, str) or DIGEST_PATTERN.fullmatch(value) is None:
        raise W6004Error(f"{field} must be an immutable SHA-256 digest")
    return value


def canonical_evidence_sha256(value: Mapping[str, object]) -> str:
    return canonical_sha256({key: item for key, item in value.items() if key != "evidence_sha256"})


def validate_evidence_record(
    value: object,
    *,
    expected_schema: str,
    now: datetime | None = None,
    consumed_approvals: Sequence[str] = (),
) -> Mapping[str, object]:
    """Validate one closed, metadata-only, operation-bound W6-004 record."""

    if expected_schema not in SCHEMA_FIELDS or not isinstance(value, Mapping):
        raise W6004Error("unknown W6-004 schema or non-object evidence")
    if any(not isinstance(key, str) for key in value):
        raise W6004Error("evidence keys must be strings")
    expected_fields = COMMON_EVIDENCE_FIELDS | SCHEMA_FIELDS[expected_schema]
    if set(value) != expected_fields or value.get("schema_version") != expected_schema:
        raise W6004Error("evidence fields or schema differ")
    _validate_json_tree({key: item for key, item in value.items() if key not in {"principal_arn"}})
    if value.get("task_id") != "W6-004" or value.get("environment") != "sandbox":
        raise W6004Error("task or environment differs")
    if value.get("account_id") != "526338061652" or value.get("region") != "ap-southeast-1":
        raise W6004Error("AWS authority differs")
    operation_id = value.get("operation_id")
    if not isinstance(operation_id, str) or OPERATION_ID_PATTERN.fullmatch(operation_id) is None:
        raise W6004Error("operation_id is malformed")
    principal = value.get("principal_arn")
    if (
        not isinstance(principal, str)
        or not principal.startswith("arn:aws:iam::526338061652:role/")
        or "finopsinfra" in principal.casefold()
    ):
        raise W6004Error("principal is not the approved federated role boundary")
    for field in (
        "source_sha256",
        "input_sha256",
        "approval_sha256",
        "evidence_sha256",
    ):
        _sha(value.get(field), field)
    for field, item in value.items():
        if field.endswith("_sha256") and not (field == "waiver_sha256" and item is None):
            _sha(item, field)
        if field.endswith("_digest"):
            _digest(item, field)
    if "source_sha256_bound" in value:
        _sha(value.get("source_sha256_bound"), "source_sha256_bound")
    running_digests = value.get("running_digests")
    if running_digests is not None:
        if (
            not isinstance(running_digests, Sequence)
            or isinstance(running_digests, str | bytes)
            or len(running_digests) != 2
        ):
            raise W6004Error("running_digests must contain both immutable images")
        for digest in running_digests:
            _digest(digest, "running_digests")
    created = _parse_utc(value.get("created_at"), "created_at")
    expires = _parse_utc(value.get("expires_at"), "expires_at")
    observed_now = now or datetime.now(UTC)
    if created > observed_now or expires <= created or expires - created > timedelta(hours=24):
        raise W6004Error("evidence validity window differs")
    if expires <= observed_now:
        raise W6004Error("evidence has expired")
    operation_type = value.get("operation_type")
    if not isinstance(operation_type, str) or not operation_type.strip():
        raise W6004Error("operation_type is required")
    if (
        operation_type in {"apply", "deploy", "rollback", "destroy", "fis"}
        or expected_schema in MUTATION_SCHEMAS
    ) and expires - created > timedelta(hours=8):
        raise W6004Error("mutation window exceeds eight hours")
    evidence_scope = value.get("evidence_scope")
    if (
        not isinstance(evidence_scope, str)
        or evidence_scope not in APPROVED_EVIDENCE_SCOPES
        or evidence_scope not in SCHEMA_SCOPES[expected_schema]
    ):
        raise W6004Error("evidence scope differs from the approved schema boundary")
    output_root = value.get("output_root")
    expected_root = EVIDENCE_ROOT / evidence_scope / operation_id
    if not isinstance(output_root, str) or Path(output_root).resolve(strict=False) != expected_root:
        raise W6004Error("output_root is outside the approved single-use operation root")
    if value.get("status") not in STATUS_VALUES:
        raise W6004Error("evidence status differs")
    if value.get("evidence_sha256") != canonical_evidence_sha256(value):
        raise W6004Error("evidence hash differs")
    approval_id = value.get("approval_id")
    if isinstance(approval_id, str) and approval_id in consumed_approvals:
        raise W6004Error("approval has already been consumed")
    if expected_schema == "w6-004.approval.v1" and value.get("consumed") is not False:
        raise W6004Error("new approval evidence must be unconsumed")
    if expected_schema == "w6-004.apply.v1":
        serial = value.get("state_serial")
        if (
            not isinstance(value.get("approval_id"), str)
            or not value["approval_id"]
            or not isinstance(value.get("state_lineage"), str)
            or not value["state_lineage"]
            or isinstance(serial, bool)
            or not isinstance(serial, int)
            or serial < 0
            or value.get("apply_status") not in STATUS_VALUES
        ):
            raise W6004Error("apply identity or status differs")
    if expected_schema == "w6-004.plan.v1":
        serial = value.get("state_serial")
        if (
            value.get("terraform_version") != "1.16.1"
            or not isinstance(value.get("state_lineage"), str)
            or not value["state_lineage"]
            or isinstance(serial, bool)
            or not isinstance(serial, int)
            or serial < 0
        ):
            raise W6004Error("Terraform plan identity differs")
    if expected_schema == "w6-004.normalized-plan.v1":
        count = value.get("resource_change_count")
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise W6004Error("normalized plan resource count is malformed")
    if expected_schema == "w6-004.partial-apply.v1" and value.get("mutation_frozen") is not True:
        raise W6004Error("partial apply must freeze affected mutation")
    if expected_schema == "w6-004.image.v1" and value.get("repository_uri") != (
        "526338061652.dkr.ecr.ap-southeast-1.amazonaws.com/enterprise-ai/sandbox/api"
    ):
        raise W6004Error("image repository differs")
    if expected_schema == "w6-004.vulnerability-scan.v1":
        critical, high = value.get("critical"), value.get("high")
        if any(
            isinstance(item, bool) or not isinstance(item, int) or item < 0
            for item in (critical, high)
        ):
            raise W6004Error("vulnerability counts are malformed")
        if critical != 0:
            raise W6004Error("Critical findings are prohibited")
        if high and value.get("waiver_sha256") is None:
            raise W6004Error("High findings require explicit waiver evidence")
        if (
            value.get("scanner") not in {"trivy", "grype"}
            or not isinstance(value.get("scanner_version"), str)
            or value.get("scanner_version") in {"", OWNER_SENTINEL, "owner-pinned"}
        ):
            raise W6004Error("scanner identity is unresolved")
    if expected_schema == "w6-004.sbom.v1" and value.get("format") not in {
        "SPDX",
        "CycloneDX",
    }:
        raise W6004Error("SBOM format differs")
    if expected_schema == "w6-004.deployment.v1":
        if (
            value.get("cluster_arn")
            != "arn:aws:eks:ap-southeast-1:526338061652:cluster/enterprise-ai-sandbox"
            or not isinstance(value.get("kubernetes_version"), str)
            or re.fullmatch(r"[0-9]+\.[0-9]+", value["kubernetes_version"]) is None
            or value.get("namespace") != "enterprise-ai-sandbox"
            or value.get("service_account") != "enterprise-ai-runtime"
            or value.get("pod_identity_arn")
            != "arn:aws:iam::526338061652:role/enterprise-ai-sandbox-runtime"
        ):
            raise W6004Error("deployment identity differs")
    if expected_schema == "w6-004.live-test.v1":
        checks = value.get("checks")
        if (
            not isinstance(checks, Sequence)
            or isinstance(checks, str | bytes)
            or not checks
            or value.get("slo_classification") not in STATUS_VALUES
        ):
            raise W6004Error("live-test checks or SLO classification differ")
    if expected_schema == "w6-004.application-rollback.v1" and (
        value.get("known_good_digest") == value.get("regression_digest")
        or value.get("running_digest") != value.get("known_good_digest")
    ):
        raise W6004Error("application rollback identity differs")
    if expected_schema == "w6-004.infrastructure-rollback.v1" and (
        value.get("regression_plan_sha256") == value.get("restore_plan_sha256")
        or value.get("known_good_state_sha256") != value.get("restored_state_sha256")
    ):
        raise W6004Error("infrastructure rollback identity differs")
    if expected_schema == "w6-004.destroy.v1":
        target = value.get("target")
        if target not in {"platform", "bootstrap"} or evidence_scope != f"{target}-destroy":
            raise W6004Error("destroy target and evidence scope differ")
    if expected_schema == "w6-004.residue.v1" and (
        value.get("status") == "PASS" and value.get("unexpected_residuals") != []
    ):
        raise W6004Error("PASS residue evidence contains unexpected resources")
    if expected_schema == "w6-004.cost.v1":
        if value.get("coverage") != "COMPLETE" or value.get("embedded_errors") != []:
            raise W6004Error("cost evidence is incomplete or contains embedded errors")
        planned = value.get("planned_resource_count")
        priced = value.get("priced_resource_count")
        if (
            isinstance(planned, bool)
            or not isinstance(planned, int)
            or planned < 0
            or isinstance(priced, bool)
            or not isinstance(priced, int)
            or priced < 0
            or priced > planned
            or (planned > 0 and priced == 0)
        ):
            raise W6004Error("cost resource coverage differs")
        try:
            estimate = Decimal(str(value.get("estimated_usd")))
            ceiling = Decimal(str(value.get("cost_ceiling_usd")))
        except InvalidOperation as exc:
            raise W6004Error("cost values are malformed") from exc
        if not estimate.is_finite() or not ceiling.is_finite() or estimate < 0 or ceiling <= 0:
            raise W6004Error("cost values are invalid")
        if estimate > ceiling:
            raise W6004Error("owner lifecycle cost ceiling is breached")
    return value


def validate_operation_exclusivity(
    operation_id: str,
    *,
    active_operation_ids: Sequence[str],
    completed_operation_ids: Sequence[str],
) -> None:
    """Reject concurrent, duplicate or replayed W6-004 operations."""

    if OPERATION_ID_PATTERN.fullmatch(operation_id) is None:
        raise W6004Error("operation_id is malformed")
    if operation_id in active_operation_ids or operation_id in completed_operation_ids:
        raise W6004Error("operation ID is active, completed, or already consumed")
    if active_operation_ids:
        raise W6004Error("another lifecycle operation is active")


def load_strict_json(path: Path) -> dict[str, object]:
    def pairs(values: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in values:
            if key in result:
                raise W6004Error(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=pairs,
            parse_constant=lambda token: (_ for _ in ()).throw(
                W6004Error(f"non-finite JSON constant: {token}")
            ),
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise W6004Error("W6-004 input must be strict UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise W6004Error("W6-004 input must be an object")
    return value


def validate_source_contract(path: Path) -> str:
    value = load_strict_json(path)
    required = {
        "schema_version",
        "task_id",
        "classification",
        "account_id",
        "region",
        "environment",
        "historical_authorization_failure",
        "validity_hours",
        "maximum_mutation_hours",
        "evidence_root",
        "temporary_root",
        "lifecycle_order",
        "network",
        "data",
        "eks",
        "image_gate",
        "observability",
        "rollback",
        "teardown",
        "expected_residuals",
        "owner_bindings",
    }
    if set(value) != required:
        raise W6004Error("source contract fields differ")
    if value.get("schema_version") != SOURCE_SCHEMA or value.get("task_id") != "W6-004":
        raise W6004Error("source contract identity differs")
    if (
        value.get("classification") != "SOURCE CONTRACT VALID - NOT EXECUTABLE"
        or value.get("environment") != "sandbox"
        or value.get("evidence_root") != EVIDENCE_ROOT.as_posix()
        or value.get("temporary_root") != "E:/AI/.tmp/enterprise-ai-platform-w6-004/owner-test-01"
    ):
        raise W6004Error("source contract classification or path boundary differs")
    if value.get("account_id") != "526338061652" or value.get("region") != "ap-southeast-1":
        raise W6004Error("AWS boundary differs")
    if value.get("historical_authorization_failure") != HISTORICAL_AUTHORIZATION_FAILURE:
        raise W6004Error("historical authorization failure classification differs")
    lifecycle_order = value.get("lifecycle_order")
    if (
        not isinstance(lifecycle_order, Sequence)
        or isinstance(lifecycle_order, str | bytes)
        or tuple(lifecycle_order) != LIFECYCLE_ORDER
    ):
        raise W6004Error("lifecycle order differs")
    if value.get("validity_hours") != 24 or value.get("maximum_mutation_hours") != 8:
        raise W6004Error("approval or mutation duration differs")
    network = value.get("network")
    if not isinstance(network, Mapping) or network != {
        "vpc_cidr": "10.60.0.0/16",
        "private_subnet_cidrs": ["10.60.10.0/24", "10.60.11.0/24"],
        "nat_gateway": False,
        "public_application_ingress": False,
        "endpoint_services": [
            "s3",
            "dynamodb",
            "ecr.api",
            "ecr.dkr",
            "eks",
            "eks-auth",
            "sts",
            "ec2",
            "kms",
            "secretsmanager",
            "logs",
            "monitoring",
            "xray",
            "bedrock-runtime",
        ],
    }:
        raise W6004Error("network contract differs")
    if value.get("data") != {
        "classifications": ["PUBLIC", "INTERNAL"],
        "customer_data_allowed": False,
        "synthetic_only": True,
    }:
        raise W6004Error("data classification contract differs")
    if value.get("eks") != {
        "private_nodes": True,
        "node_group": {
            "minimum": 2,
            "desired": 2,
            "maximum": 3,
            "capacity_type": "ON_DEMAND",
        },
        "required_addons": [
            "vpc-cni",
            "coredns",
            "kube-proxy",
            "eks-pod-identity-agent",
            "metrics-server",
        ],
    }:
        raise W6004Error("EKS contract differs")
    if value.get("image_gate") != {
        "critical_findings": 0,
        "high_findings_require_owner_waiver": True,
        "required_sboms": ["SPDX", "CycloneDX"],
        "provenance_required": True,
        "registry_digest_required": True,
        "signature_required": False,
    }:
        raise W6004Error("image gate contract differs")
    if value.get("observability") != {
        "otlp_ingress": "pod-local-grpc-4317",
        "trace_destination": "AWS X-Ray",
        "metric_log_destination": "CloudWatch",
        "retention_days": 14,
    }:
        raise W6004Error("observability contract differs")
    if value.get("rollback") != {
        "application": "verified-known-good-digest",
        "infrastructure": "distinct-saved-restore-plan",
        "safe_regression_required": True,
    }:
        raise W6004Error("rollback contract differs")
    teardown = value.get("teardown")
    if not isinstance(teardown, Mapping) or teardown != {
        "order": ["kubernetes", "platform", "versioned_state_objects", "bootstrap"],
        "remove_project_ecr_images": True,
        "remove_synthetic_s3_objects": True,
        "remove_opensearch_indexes": True,
        "shared_resources_excluded": True,
    }:
        raise W6004Error("teardown order or ownership boundary differs")
    if value.get("expected_residuals") != [
        "final_evidence",
        "shared_external_service_linked_roles",
        "kms_keys_pending_deletion",
        "delayed_billing_records",
    ]:
        raise W6004Error("expected residual contract differs")
    bindings = value.get("owner_bindings")
    if not isinstance(bindings, Mapping) or not bindings:
        raise W6004Error("owner bindings are missing")
    if any(item != OWNER_SENTINEL for item in bindings.values()):
        raise W6004Error("source contract must retain non-executable owner sentinels")
    if set(bindings) != OWNER_BINDING_KEYS:
        raise W6004Error("owner-binding inventory differs")
    return SOURCE_STATUS


def validate_runtime_bindings(
    bindings: object,
    *,
    now: datetime | None = None,
) -> Mapping[str, object]:
    """Validate the external owner-bound package without mutating source configuration."""

    if not isinstance(bindings, Mapping) or set(bindings) != OWNER_BINDING_KEYS:
        raise W6004Error("runtime owner-binding inventory differs")
    if any(value == OWNER_SENTINEL for value in bindings.values()):
        raise W6004Error("runtime package contains unresolved owner sentinel")

    for field in ("aws_cli_profile", "bedrock_inference_profile", "bedrock_model_id"):
        value = bindings[field]
        if not isinstance(value, str) or not value.strip() or "finopsinfra" in value.casefold():
            raise W6004Error(f"{field} is unresolved or prohibited")

    for field in ("federated_principal_arn", "administrator_role_arn"):
        value = bindings[field]
        if (
            not isinstance(value, str)
            or not value.startswith("arn:aws:iam::526338061652:role/")
            or "finopsinfra" in value.casefold()
        ):
            raise W6004Error(f"{field} differs from the approved account role boundary")

    cidr = bindings["owner_api_cidr"]
    try:
        network = ip_network(cidr, strict=True) if isinstance(cidr, str) else None
    except ValueError as exc:
        raise W6004Error("owner_api_cidr must be one public IPv4 /32") from exc
    if (
        not isinstance(network, IPv4Network)
        or network.prefixlen != 32
        or not network.network_address.is_global
    ):
        raise W6004Error("owner_api_cidr must be one public IPv4 /32")

    issued = _parse_utc(bindings["approval_issued_at"], "approval_issued_at")
    deployment = _parse_utc(bindings["deployment_start"], "deployment_start")
    expires = _parse_utc(bindings["approval_expires_at"], "approval_expires_at")
    observed_now = now or datetime.now(UTC)
    if (
        issued > observed_now
        or expires <= observed_now
        or not issued <= deployment < expires
        or expires - issued > timedelta(hours=24)
        or expires - deployment > timedelta(hours=8)
    ):
        raise W6004Error("owner approval or mutation window differs")

    try:
        ceiling = Decimal(str(bindings["cost_ceiling_usd"]))
    except InvalidOperation as exc:
        raise W6004Error("owner cost ceiling is malformed") from exc
    if not ceiling.is_finite() or ceiling <= 0:
        raise W6004Error("owner cost ceiling must be positive")
    stage_limits = bindings["stage_stop_limits_usd"]
    if not isinstance(stage_limits, Mapping) or set(stage_limits) != STAGE_LIMIT_KEYS:
        raise W6004Error("stage cost-limit inventory differs")
    for field, value in stage_limits.items():
        try:
            limit = Decimal(str(value))
        except InvalidOperation as exc:
            raise W6004Error(f"{field} stage cost limit is malformed") from exc
        if not limit.is_finite() or limit <= 0 or limit > ceiling:
            raise W6004Error(f"{field} stage cost limit exceeds the approved boundary")

    version = bindings["eks_kubernetes_version"]
    if not isinstance(version, str) or re.fullmatch(r"[0-9]+\.[0-9]+", version) is None:
        raise W6004Error("EKS Kubernetes version is malformed")
    instance_types = bindings["eks_node_instance_types"]
    if (
        not isinstance(instance_types, Sequence)
        or isinstance(instance_types, str | bytes)
        or len(instance_types) != 1
        or not isinstance(instance_types[0], str)
        or not instance_types[0]
    ):
        raise W6004Error("one exact managed-node instance type is required")
    addon_versions = bindings["addon_versions"]
    if not isinstance(addon_versions, Mapping) or set(addon_versions) != ADDON_VERSION_KEYS:
        raise W6004Error("managed add-on version inventory differs")
    if any(
        not isinstance(item, str) or not item or OWNER_SENTINEL in item
        for item in addon_versions.values()
    ):
        raise W6004Error("managed add-on versions must be owner-bound")

    for field in ("metrics_server_image", "otel_collector_image"):
        value = bindings[field]
        if not isinstance(value, str) or IMAGE_REFERENCE_PATTERN.fullmatch(value) is None:
            raise W6004Error(f"{field} must be an immutable image reference")
    for field in (
        "application_image_digest",
        "collector_image_digest",
        "known_good_application_digest",
    ):
        _digest(bindings[field], field)
    _sha(bindings["known_good_infrastructure_identity"], "known_good_infrastructure_identity")

    for field in ("kubectl_version", "kustomize_version", "trivy_version", "grype_version"):
        value = bindings[field]
        if (
            not isinstance(value, str)
            or re.fullmatch(r"v?[0-9]+\.[0-9]+(?:\.[0-9]+)?", value) is None
        ):
            raise W6004Error(f"{field} must be an exact version")
    for field in ("trivy_database_sha256", "grype_database_sha256"):
        _sha(bindings[field], field)

    recipients = bindings["alert_recipients"]
    if (
        not isinstance(recipients, Sequence)
        or isinstance(recipients, str | bytes)
        or len(recipients) != 2
        or any(not isinstance(item, str) or "@" not in item for item in recipients)
        or len(set(recipients)) != 2
    ):
        raise W6004Error("two distinct alert recipients are required")

    for field in ("bootstrap_state_lineage", "platform_state_lineage"):
        value = bindings[field]
        if not isinstance(value, str) or not value:
            raise W6004Error(f"{field} is required")
    for field in ("bootstrap_state_serial", "platform_state_serial"):
        value = bindings[field]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise W6004Error(f"{field} must be a non-negative integer")

    approval_hashes = bindings["plan_policy_cost_approval_hashes"]
    if not isinstance(approval_hashes, Mapping) or not approval_hashes:
        raise W6004Error("plan, policy, cost and approval hashes are required")
    for field, value in approval_hashes.items():
        if not isinstance(field, str) or not field:
            raise W6004Error("approval hash names must be non-empty strings")
        _sha(value, field)
    return bindings


def validate_stage_sequence(stages: Sequence[str]) -> None:
    if tuple(stages) != LIFECYCLE_ORDER:
        raise W6004Error("lifecycle evidence is incomplete or out of order")


def validate_residue(actual: Sequence[str], expected: Sequence[str]) -> None:
    if sorted(actual) != sorted(expected):
        raise W6004Error("unexpected lifecycle residue")


def validate_bedrock_logging_contract(value: BedrockLoggingContract) -> BedrockLoggingContract:
    """Validate default-off, synthetic-only logging metadata without enabling logging."""
    from .contracts import APPROVED_AWS_ACCOUNT_ID, APPROVED_AWS_REGION, validate_sha256
    from .lifecycle_models import W7_001_SCHEMA_VERSION, ControlResult

    if value.schema_version != W7_001_SCHEMA_VERSION:
        raise W6004Error("Bedrock logging schema differs")
    if value.account_id != APPROVED_AWS_ACCOUNT_ID or value.region != APPROVED_AWS_REGION:
        raise W6004Error("Bedrock logging authority differs")
    if value.retention_days < 1 or value.retention_days > 7:
        raise W6004Error("Bedrock logging retention is outside the approved boundary")
    if not value.encryption_identity:
        raise W6004Error("Bedrock logging encryption identity is required")
    for digest in (value.access_identity_sha256, value.before_state_sha256):
        validate_sha256(digest)
    if value.after_state_sha256 is not None:
        validate_sha256(value.after_state_sha256)
    if value.raw_protected_content_allowed or not value.synthetic_only:
        raise W6004Error("Bedrock logging must be synthetic-only and content-safe")
    if value.enabled:
        if not value.approval_id or not value.operation_id:
            raise W6004Error("enabled logging requires exact approval and operation identity")
        if value.disablement_status is ControlResult.PASS:
            raise W6004Error("enabled logging cannot claim disablement PASS")
    elif value.disablement_status is ControlResult.PASS:
        if value.after_state_sha256 is None:
            raise W6004Error("logging disablement PASS requires after-state identity")
    return value


def require_non_pass_for_limited_evidence(
    *,
    status: str,
    disposition: str,
    scanner_disagreement: bool = False,
) -> None:
    """Prevent partial, waived, limited or disputed evidence from becoming PASS."""
    limited = {"FAILED", "PARTIAL", "WAIVED", "LIMITED", "CLOSURE_TAIL"}
    if status == "PASS" and (disposition in limited or scanner_disagreement):
        raise W6004Error("limited or disputed evidence cannot be PASS")
