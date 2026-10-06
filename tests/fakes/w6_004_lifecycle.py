"""Deterministic W6-004 lifecycle evidence builders; never call AWS."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from tools.platformctl.live_validation import SCHEMA_SCOPES, canonical_evidence_sha256

SHA = "a" * 64
DIGEST = "sha256:" + SHA

SCHEMA_DEFAULTS: dict[str, dict[str, Any]] = {
    "w6-004.discovery.v1": {
        "native_inventory_sha256": SHA,
        "kms_tail_status": "ABSENT",
        "billing_status": "INDETERMINATE",
    },
    "w6-004.inputs.v1": {
        "owner_bindings_sha256": SHA,
        "cost_ceiling_usd": "100.00",
        "stage_limits_sha256": SHA,
    },
    "w6-004.plan.v1": {
        "terraform_version": "1.16.1",
        "provider_lock_sha256": SHA,
        "state_lineage": "fixture-lineage",
        "state_serial": 0,
        "saved_plan_sha256": SHA,
    },
    "w6-004.normalized-plan.v1": {
        "plan_sha256": SHA,
        "normalized_plan_sha256": SHA,
        "resource_change_count": 1,
    },
    "w6-004.opa.v1": {
        "normalized_plan_sha256": SHA,
        "policy_bundle_sha256": SHA,
        "decision": "PASS",
    },
    "w6-004.cost.v1": {
        "normalized_plan_sha256": SHA,
        "pricing_sha256": SHA,
        "estimated_usd": "1.00",
        "cost_ceiling_usd": "2.00",
        "coverage": "COMPLETE",
        "planned_resource_count": 1,
        "priced_resource_count": 1,
        "embedded_errors": [],
    },
    "w6-004.approval.v1": {
        "plan_sha256": SHA,
        "opa_sha256": SHA,
        "cost_sha256": SHA,
        "approval_id": "approval-fixture-0001",
        "consumed": False,
    },
    "w6-004.apply.v1": {
        "saved_plan_sha256": SHA,
        "approval_id": "approval-fixture-0001",
        "state_lineage": "fixture-lineage",
        "state_serial": 1,
        "apply_status": "PASS",
    },
    "w6-004.partial-apply.v1": {
        "saved_plan_sha256": SHA,
        "state_sha256": SHA,
        "inventory_sha256": SHA,
        "mutation_frozen": True,
    },
    "w6-004.image.v1": {
        "dependency_lock_sha256": SHA,
        "dockerfile_sha256": SHA,
        "base_image_digest": DIGEST,
        "oci_digest": DIGEST,
        "registry_digest": DIGEST,
        "scan_sha256": SHA,
        "sbom_sha256": SHA,
        "provenance_sha256": SHA,
        "repository_uri": (
            "526338061652.dkr.ecr.ap-southeast-1.amazonaws.com/enterprise-ai/sandbox/api"
        ),
        "image_composition_sha256": SHA,
        "embedding_snapshot_sha256": SHA,
    },
    "w6-004.vulnerability-scan.v1": {
        "image_digest": DIGEST,
        "scanner": "trivy",
        "scanner_version": "1.0.0",
        "database_sha256": SHA,
        "report_sha256": SHA,
        "critical": 0,
        "high": 0,
        "waiver_sha256": None,
    },
    "w6-004.sbom.v1": {
        "image_digest": DIGEST,
        "format": "SPDX",
        "document_sha256": SHA,
    },
    "w6-004.provenance.v1": {
        "source_sha256_bound": SHA,
        "image_digest": DIGEST,
        "statement_sha256": SHA,
    },
    "w6-004.release-binding.v1": {
        "application_digest": DIGEST,
        "collector_digest": "sha256:" + "b" * 64,
        "runtime_sha256": SHA,
        "manifest_sha256": SHA,
    },
    "w6-004.deployment.v1": {
        "cluster_arn": ("arn:aws:eks:ap-southeast-1:526338061652:cluster/enterprise-ai-sandbox"),
        "kubernetes_version": "1.32",
        "namespace": "enterprise-ai-sandbox",
        "service_account": "enterprise-ai-runtime",
        "pod_identity_arn": "arn:aws:iam::526338061652:role/enterprise-ai-sandbox-runtime",
        "workload_sha256": SHA,
        "running_digests": [DIGEST, "sha256:" + "b" * 64],
    },
    "w6-004.live-test.v1": {
        "deployment_sha256": SHA,
        "checks": ["health", "identity", "network-policy"],
        "slo_classification": "NO_DATA",
    },
    "w6-004.application-rollback.v1": {
        "known_good_digest": DIGEST,
        "regression_digest": "sha256:" + "c" * 64,
        "running_digest": DIGEST,
        "health_sha256": SHA,
    },
    "w6-004.infrastructure-rollback.v1": {
        "known_good_state_sha256": SHA,
        "regression_plan_sha256": "b" * 64,
        "restore_plan_sha256": "c" * 64,
        "restored_state_sha256": SHA,
    },
    "w6-004.destroy.v1": {
        "target": "platform",
        "destroy_plan_sha256": SHA,
        "state_before_sha256": SHA,
        "state_after_sha256": SHA,
        "shared_exclusions_sha256": SHA,
    },
    "w6-004.residue.v1": {
        "native_inventory_sha256": SHA,
        "expected_residuals": ["kms_keys_pending_deletion"],
        "unexpected_residuals": [],
        "kms_status": "PendingDeletion",
    },
    "w6-004.billing.v1": {
        "cost_explorer_sha256": SHA,
        "observed_usd": "1.25",
        "billing_lag_status": "INDETERMINATE",
    },
    "w6-004.closure.v1": {
        "stage_evidence_sha256": SHA,
        "residue_sha256": SHA,
        "billing_sha256": SHA,
        "deferred_followups": ["kms-deletion-date", "billing-24h"],
    },
}


def evidence_record(schema: str) -> dict[str, Any]:
    """Return one complete metadata-only fixture for a closed evidence schema."""

    created = datetime.now(UTC).replace(microsecond=0)
    operation_id = "fixture-" + schema.removeprefix("w6-004.").removesuffix(".v1")
    evidence_scope = (
        f"{SCHEMA_DEFAULTS[schema]['target']}-destroy"
        if schema == "w6-004.destroy.v1"
        else sorted(SCHEMA_SCOPES[schema])[0]
    )
    value: dict[str, Any] = {
        "schema_version": schema,
        "task_id": "W6-004",
        "operation_id": operation_id,
        "operation_type": "validation",
        "source_sha256": SHA,
        "input_sha256": SHA,
        "account_id": "526338061652",
        "region": "ap-southeast-1",
        "principal_arn": "arn:aws:iam::526338061652:role/owner-test-role",
        "environment": "sandbox",
        "created_at": created.isoformat().replace("+00:00", "Z"),
        "expires_at": (created + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
        "approval_sha256": SHA,
        "evidence_scope": evidence_scope,
        "output_root": (
            "E:/AI/.runtime/enterprise_ai_platform/w6-004/owner-test-01/"
            f"{evidence_scope}/{operation_id}"
        ),
        "evidence_sha256": "",
        "status": "PASS",
        **SCHEMA_DEFAULTS[schema],
    }
    value["evidence_sha256"] = canonical_evidence_sha256(value)
    return value


def image_evidence() -> dict[str, Any]:
    return evidence_record("w6-004.image.v1")


def vulnerability_evidence(*, critical: int = 0, high: int = 0) -> dict[str, Any]:
    value = evidence_record("w6-004.vulnerability-scan.v1")
    value["critical"] = critical
    value["high"] = high
    value["waiver_sha256"] = SHA if high else None
    value["evidence_sha256"] = canonical_evidence_sha256(value)
    return value


def kubernetes_evidence(stage: str = "live_verify") -> dict[str, Any]:
    return {
        "schema_version": "w6-004.kubernetes-evidence.v1",
        "stage": stage,
        "namespace": "enterprise-ai-sandbox",
        "cluster_arn": "arn:aws:eks:ap-southeast-1:526338061652:cluster/enterprise-ai-sandbox",
        "application_digest": DIGEST,
        "collector_digest": "sha256:" + "b" * 64,
        "manifest_sha256": SHA,
        "observed": ["health", "identity", "network-policy"],
        "status": "PASS",
    }


def runtime_bindings() -> dict[str, Any]:
    """Return a complete owner-runtime fixture with no executable credentials."""

    return {
        "aws_cli_profile": "sandbox-owner-federated",
        "federated_principal_arn": "arn:aws:iam::526338061652:role/owner-federated",
        "administrator_role_arn": "arn:aws:iam::526338061652:role/owner-administrator",
        "owner_api_cidr": "8.8.8.8/32",
        "deployment_start": "2026-10-03T01:00:00Z",
        "approval_issued_at": "2026-10-03T00:00:00Z",
        "approval_expires_at": "2026-10-03T09:00:00Z",
        "cost_ceiling_usd": "100.00",
        "stage_stop_limits_usd": {
            "bootstrap": "10.00",
            "platform": "50.00",
            "image": "10.00",
            "eks": "50.00",
            "opensearch": "50.00",
            "observability": "20.00",
            "resilience": "10.00",
            "teardown": "10.00",
        },
        "eks_kubernetes_version": "1.32",
        "eks_node_instance_types": ["m6i.large"],
        "addon_versions": {
            "vpc-cni": "v1.20.0-eksbuild.1",
            "coredns": "v1.11.4-eksbuild.1",
            "kube-proxy": "v1.32.0-eksbuild.1",
            "eks-pod-identity-agent": "v1.3.7-eksbuild.2",
        },
        "metrics_server_image": "registry.k8s.io/metrics-server/metrics-server@sha256:" + SHA,
        "otel_collector_image": "public.ecr.aws/aws-observability/aws-otel-collector@sha256:" + SHA,
        "kubectl_version": "v1.32.2",
        "kustomize_version": "v5.6.0",
        "bedrock_inference_profile": "apac.amazon.nova-lite-v1:0",
        "bedrock_model_id": "amazon.nova-lite-v1:0",
        "alert_recipients": ["primary@example.invalid", "backup@example.invalid"],
        "trivy_version": "0.59.1",
        "trivy_database_sha256": SHA,
        "grype_version": "0.87.0",
        "grype_database_sha256": SHA,
        "application_image_digest": DIGEST,
        "collector_image_digest": "sha256:" + "b" * 64,
        "known_good_application_digest": DIGEST,
        "known_good_infrastructure_identity": SHA,
        "bootstrap_state_lineage": "bootstrap-lineage-fixture",
        "bootstrap_state_serial": 1,
        "platform_state_lineage": "platform-lineage-fixture",
        "platform_state_serial": 1,
        "plan_policy_cost_approval_hashes": {
            "plan": SHA,
            "policy": "b" * 64,
            "cost": "c" * 64,
            "approval": "d" * 64,
        },
    }
