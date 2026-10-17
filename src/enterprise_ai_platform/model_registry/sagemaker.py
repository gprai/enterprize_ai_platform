"""Deterministic SageMaker-compatible request rendering without submission."""

from __future__ import annotations

from enterprise_ai_platform.json_contracts import JSONValue

from .errors import RegistryValidationError
from .models import ApprovalState, RegistryRecord
from .policy import RegistryPolicy


def render_register_model_package_request(
    record: RegistryRecord,
    policy: RegistryPolicy,
) -> dict[str, JSONValue]:
    if record.package.policy_sha256 != policy.identity_sha256:
        raise RegistryValidationError("package and registry policy identities differ")
    package = record.package
    return {
        "model_package_group_name": policy.bindings.model_package_group_name,
        "model_approval_status": "PendingManualApproval",
        "inference_specification": {
            "container_image": package.container.registry_uri,
            "container_image_digest": package.container.image_digest,
            "model_data_url": package.artifact.source_uri,
            "model_data_object_version": package.artifact.object_version_id,
            "supported_content_types": ["application/json"],
            "supported_response_mime_types": ["application/json"],
        },
        "customer_metadata": {
            "artifact_sha256": package.artifact.sha256,
            "code_commit": package.code.git_commit,
            "evaluation_sha256": (
                package.experiment_run.experiment_input.evaluation.deterministic_payload_sha256
            ),
            "model_card_sha256": package.model_card.evaluation_report_sha256,
            "package_identity_sha256": record.package_identity_sha256,
            "policy_sha256": package.policy_sha256,
            "supply_chain_eligibility_sha256": (
                package.supply_chain_eligibility.opa_decision.decision_sha256
            ),
            "supply_chain_policy_sha256": package.supply_chain_eligibility.policy_sha256,
            "supply_chain_status": package.supply_chain_eligibility.status.value,
        },
        "submission_status": "NOT_AUTHORIZED",
        "deployment_approval": "NOT_AUTHORIZED",
    }


def render_update_model_package_request(record: RegistryRecord) -> dict[str, JSONValue]:
    if record.approval_state not in {ApprovalState.APPROVED, ApprovalState.REJECTED}:
        raise RegistryValidationError("only a reviewed package can render an approval update")
    status = "Approved" if record.approval_state is ApprovalState.APPROVED else "Rejected"
    return {
        "model_package_identity_sha256": record.package_identity_sha256,
        "model_approval_status": status,
        "approval_identity_sha256": record.latest_approval_identity_sha256,
        "submission_status": "NOT_AUTHORIZED",
        "deployment_approval": "NOT_AUTHORIZED",
    }
