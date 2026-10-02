"""Deterministic W6-003 evidence fixtures without external activity."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from tools import w6_003_readiness

NOW = datetime(2026, 10, 2, 0, 0, tzinfo=UTC)
GENERATED_AT = NOW.isoformat().replace("+00:00", "Z")
EXPIRES_AT = (NOW + timedelta(hours=24)).isoformat().replace("+00:00", "Z")


def local_proof() -> dict[str, object]:
    return {
        "schema_version": w6_003_readiness.LOCAL_PROOF_SCHEMA,
        "source_identity": "a" * 64,
        "configuration_identity": "b" * 64,
        "component_identities": {
            "api": "c" * 64,
            "rag": "d" * 64,
            "agent": "e" * 64,
            "telemetry": "f" * 64,
        },
        "provider_mode": "deterministic-in-memory",
        "test_results": [
            {
                "check_name": "local-integration",
                "status": "PASS",
                "scope": "mandatory-local",
            },
            {"check_name": "live-aws", "status": "NOT RUN", "scope": "cloud"},
            {"check_name": "minimum-slo-population", "status": "NO_DATA", "scope": "local"},
        ],
        "warnings": ["one retained dependency deprecation warning"],
        "exclusions": ["live AWS and EKS activity"],
        "limitations": list(w6_003_readiness.LIMITATIONS),
        "deferrals": ["W6-004 owns the live lifecycle"],
        "cloud_deployment_status": "NOT RUN",
        "generated_at": GENERATED_AT,
        "expires_at": EXPIRES_AT,
        "allowed_output_root": w6_003_readiness.ALLOWED_OUTPUT_ROOT,
        "output_root": w6_003_readiness.ALLOWED_OUTPUT_ROOT,
    }


def local_rollback() -> dict[str, object]:
    return {
        "schema_version": w6_003_readiness.LOCAL_ROLLBACK_SCHEMA,
        "known_good_release": "w4-known-good-v1",
        "candidate_release": "w4-synthetic-regression-v1",
        "rollback_trigger": "expected-local-regression",
        "candidate_status": "FAIL",
        "restored_application_identity": "1" * 64,
        "smoke_status": "PASS",
        "security_status": "PASS",
        "evaluation_status": "PASS",
        "elapsed_seconds": 1.0,
        "cleanup_status": "PASS",
        "residue_status": "PASS",
        "eks_rollback_status": "NOT RUN",
        "terraform_rollback_status": "NOT RUN",
        "generated_at": GENERATED_AT,
        "expires_at": EXPIRES_AT,
        "allowed_output_root": w6_003_readiness.ALLOWED_OUTPUT_ROOT,
        "output_root": w6_003_readiness.ALLOWED_OUTPUT_ROOT,
    }


def handover(
    proof: dict[str, object] | None = None,
    rollback: dict[str, object] | None = None,
) -> dict[str, object]:
    proof_value = proof or local_proof()
    rollback_value = rollback or local_rollback()
    return {
        "schema_version": w6_003_readiness.HANDOVER_SCHEMA,
        "source_identity": "a" * 64,
        "local_proof": {
            "schema_version": w6_003_readiness.LOCAL_PROOF_SCHEMA,
            "sha256": w6_003_readiness.sha256_bytes(
                w6_003_readiness.canonical_json_bytes(proof_value)
            ),
        },
        "local_rollback": {
            "schema_version": w6_003_readiness.LOCAL_ROLLBACK_SCHEMA,
            "sha256": w6_003_readiness.sha256_bytes(
                w6_003_readiness.canonical_json_bytes(rollback_value)
            ),
        },
        "known_good_application": {
            "schema_version": w6_003_readiness.APPLICATION_SCHEMA,
            "source_composition_sha256": "a" * 64,
            "historical_w4_proof_sha256": "1" * 64,
            "ecr_repository_uri": None,
            "registry_digest": None,
            "release_binding_status": "NOT RUN",
            "promotion_mode": "w6-004-stage-a",
            "deployable_identity_status": "MISSING",
        },
        "known_good_infrastructure": {
            "schema_version": w6_003_readiness.INFRASTRUCTURE_SCHEMA,
            "terraform_composition_sha256": "4" * 64,
            "provider_lock_sha256": "5" * 64,
            "backend_identity": None,
            "state_lineage": None,
            "state_serial": None,
            "saved_plan_sha256": None,
            "policy_status": "NOT RUN",
            "cost_status": "NOT RUN",
            "promotion_mode": "w6-004-stage-a",
            "deployable_identity_status": "MISSING",
        },
        "owner_decisions": list(w6_003_readiness.OWNER_DECISIONS),
        "warnings": ["one retained dependency deprecation warning"],
        "risks": ["live cloud behavior remains unproved"],
        "limitations": list(w6_003_readiness.LIMITATIONS),
        "not_run_activities": list(w6_003_readiness.NOT_RUN_ACTIVITIES),
        "indeterminate_activities": [],
        "retained_artifacts": list(w6_003_readiness.RETAINED_FILES),
        "deferred_cleanup": ["retain approved evidence until W6-004 closure"],
        "lifecycle": list(w6_003_readiness.LIFECYCLE),
        "generated_at": GENERATED_AT,
        "expires_at": EXPIRES_AT,
        "w6_004_entry_decision": "BLOCKED_PENDING_W6_004_STAGE_A",
        "stop_reasons": list(w6_003_readiness.STOP_CONDITIONS),
        "stage_a_known_good_promotion_required": True,
        "allowed_output_root": w6_003_readiness.ALLOWED_OUTPUT_ROOT,
        "output_root": w6_003_readiness.ALLOWED_OUTPUT_ROOT,
    }
