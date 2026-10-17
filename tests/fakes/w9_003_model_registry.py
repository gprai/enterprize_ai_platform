"""Deterministic W9-003 fixtures with no registry, model, file, or network access."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

from enterprise_ai_platform.agent.authorization import authorization_reference
from enterprise_ai_platform.agent.serialization import hash_identifier
from enterprise_ai_platform.experiment_tracking.models import (
    ExperimentRun,
    RunEnvelope,
    RunStatus,
)
from enterprise_ai_platform.model_registry import (
    ApprovalDecision,
    InMemoryModelRegistry,
    KnownGoodReference,
    ModelArtifactIdentity,
    ModelCard,
    ModelPackageManifest,
    ModelRegistryService,
    PackageApproval,
    PromotionApproval,
    PromotionRequest,
    PromotionResult,
    PromotionStage,
    RegistryRecord,
    RollbackApproval,
    RollbackRequest,
    TenantRegistryAuthorizer,
    fingerprint,
    load_registry_policy,
)
from enterprise_ai_platform.model_supply_chain import load_supply_chain_policy
from enterprise_ai_platform.retrieval.models import AuthContext, Classification, Role
from enterprise_ai_platform.training import (
    TrainingCodeIdentity,
    TrainingContainerIdentity,
    TrainingOutcome,
    TrainingResult,
)
from tests.fakes.w9_002_experiment_tracking import make_input
from tests.fakes.w9_004_model_supply_chain import make_eligibility

NOW = datetime(2026, 10, 14, 0, 0, tzinfo=UTC)


def make_auth(
    *,
    role: Role = Role.ADMIN,
    tenant_id: str = "tenant-a",
    subject_id: str = "registry-owner-a",
) -> AuthContext:
    return AuthContext(
        subject_id=subject_id,
        tenant_id=tenant_id,
        roles=frozenset({role}),
        clearance=Classification.INTERNAL,
        groups=frozenset(),
        issuer="https://identity.example.invalid",
        audience="enterprise-ai-platform",
        expires_at=NOW + timedelta(hours=4),
        request_id="w9-003-request",
    )


def make_package(
    *,
    auth: AuthContext | None = None,
    package_number: int = 1,
    artifact_character: str = "d",
    model_version: str | None = None,
    idempotency_key: str | None = None,
) -> ModelPackageManifest:
    auth = auth or make_auth()
    policy = load_registry_policy()
    experiment_input = make_input(
        model_revision=model_version or f"model-v{package_number}",
        code_sha256="5" * 64,
    )
    experiment_input = experiment_input.model_copy(
        update={
            "model": experiment_input.model.model_copy(
                update={"artifact_sha256": artifact_character * 64}
            )
        }
    )
    experiment_input = type(experiment_input).model_validate(
        experiment_input.model_dump(mode="python"), strict=True
    )
    envelope = RunEnvelope(
        run_id=str(UUID(f"00000000-0000-4000-8001-{package_number:012d}")),
        correlation_id=str(UUID("00000000-0000-4000-8001-000000000903")),
        idempotency_key=f"{package_number:x}" * 64,
        tenant_reference_sha256=hash_identifier(auth.tenant_id),
        subject_reference_sha256=hash_identifier(auth.subject_id),
        authorization_reference_sha256=authorization_reference(auth),
        classification=Classification.INTERNAL,
        policy_sha256="e" * 64,
        requested_at=NOW - timedelta(minutes=5),
        deadline_at=NOW + timedelta(minutes=10),
    )
    run = ExperimentRun(
        envelope=envelope,
        input_identity_sha256=fingerprint(experiment_input),
        experiment_input=experiment_input,
        status=RunStatus.COMPLETED,
        completed_at=NOW - timedelta(minutes=1),
    )
    training_request_identity = "a" * 64
    experiment_run_identity = fingerprint(run)
    container_digest = f"sha256:{'6' * 64}"
    artifact_source_uri = f"s3://approved-model-artifacts/model-{package_number}.tar.gz"
    return ModelPackageManifest(
        package_id=str(UUID(f"00000000-0000-4000-8002-{package_number:012d}")),
        correlation_id=str(UUID("00000000-0000-4000-8002-000000000903")),
        idempotency_key=idempotency_key or f"{package_number + 3:x}" * 64,
        tenant_reference_sha256=hash_identifier(auth.tenant_id),
        registrant_reference_sha256=hash_identifier(auth.subject_id),
        authorization_reference_sha256=authorization_reference(auth),
        classification=Classification.INTERNAL,
        artifact=ModelArtifactIdentity(
            source_uri=artifact_source_uri,
            object_version_id=f"object-version-{package_number}",
            sha256=artifact_character * 64,
            size_bytes=1024,
        ),
        code=TrainingCodeIdentity(git_commit="1" * 40, source_sha256="5" * 64),
        container=TrainingContainerIdentity(
            registry_uri=(
                f"000000000000.dkr.ecr.ap-southeast-1.amazonaws.com/training@sha256:{'6' * 64}"
            ),
            image_digest=container_digest,
        ),
        training_request_identity_sha256=training_request_identity,
        training_result=TrainingResult(
            request_identity_sha256=training_request_identity,
            outcome=TrainingOutcome.CANDIDATE_READY,
            provider_request_sha256="b" * 64,
            candidate_artifact_sha256=artifact_character * 64,
            safe_reason_code="CANDIDATE_READY",
        ),
        experiment_run_identity_sha256=experiment_run_identity,
        experiment_run=run,
        lineage_export_identity_sha256="f" * 64,
        model_card=ModelCard(
            model_name="owner/approved-model",
            model_version=model_version or f"model-v{package_number}",
            intended_uses=("approved synthetic evaluation",),
            limitations=("not production validated",),
            prohibited_uses=("autonomous deployment",),
            training_data_provenance_sha256="1" * 64,
            evaluation_report_sha256="c" * 64,
            owner_reference_sha256=hash_identifier(auth.subject_id),
            license="Apache-2.0",
        ),
        supply_chain_eligibility=make_eligibility(
            artifact_character=artifact_character,
            tenant_reference_sha256=hash_identifier(auth.tenant_id),
            container_image_digest=container_digest,
            training_request_identity_sha256=training_request_identity,
            experiment_run_identity_sha256=experiment_run_identity,
            evaluation_report_sha256="c" * 64,
            generated_at=NOW - timedelta(minutes=3),
            artifact_source_uri=artifact_source_uri,
        ),
        policy_sha256=policy.identity_sha256,
        requested_at=NOW - timedelta(minutes=2),
        deadline_at=NOW + timedelta(minutes=13),
    )


def make_service() -> tuple[ModelRegistryService, InMemoryModelRegistry]:
    policy = load_registry_policy()
    store = InMemoryModelRegistry()
    return (
        ModelRegistryService(
            policy=policy,
            supply_chain_policy=load_supply_chain_policy(),
            authorizer=TenantRegistryAuthorizer(),
            store=store,
        ),
        store,
    )


def make_package_approval(
    record: RegistryRecord,
    *,
    reviewer: AuthContext | None = None,
    decision: ApprovalDecision = ApprovalDecision.APPROVED,
) -> PackageApproval:
    reviewer = reviewer or make_auth(role=Role.REVIEWER, subject_id="registry-reviewer-a")
    return PackageApproval(
        approval_reference_sha256="2" * 64,
        tenant_reference_sha256=record.package.tenant_reference_sha256,
        authorization_reference_sha256=authorization_reference(reviewer),
        package_identity_sha256=record.package_identity_sha256,
        policy_sha256=record.package.policy_sha256,
        requester_reference_sha256=record.package.registrant_reference_sha256,
        approver_reference_sha256=hash_identifier(reviewer.subject_id),
        decision=decision,
        decided_at=NOW,
        expires_at=NOW + timedelta(hours=1),
    )


def make_promotion_request(
    record: RegistryRecord,
    *,
    auth: AuthContext | None = None,
    request_number: int = 1,
    source_stage: PromotionStage = PromotionStage.CANDIDATE,
    target_stage: PromotionStage = PromotionStage.STAGING,
    expected_target: str | None = None,
) -> PromotionRequest:
    auth = auth or make_auth()
    assert record.latest_approval_identity_sha256 is not None
    return PromotionRequest(
        request_id=str(UUID(f"00000000-0000-4000-8003-{request_number:012d}")),
        idempotency_key=f"{request_number + 6:x}" * 64,
        tenant_reference_sha256=record.package.tenant_reference_sha256,
        executor_reference_sha256=hash_identifier(auth.subject_id),
        authorization_reference_sha256=authorization_reference(auth),
        package_identity_sha256=record.package_identity_sha256,
        package_approval_identity_sha256=record.latest_approval_identity_sha256,
        source_stage=source_stage,
        target_stage=target_stage,
        expected_target_package_sha256=expected_target,
        policy_sha256=record.package.policy_sha256,
        requested_at=NOW,
        deadline_at=NOW + timedelta(minutes=15),
    )


def make_promotion_approval(
    request: PromotionRequest,
    *,
    reviewer: AuthContext | None = None,
) -> PromotionApproval:
    reviewer = reviewer or make_auth(role=Role.REVIEWER, subject_id="registry-reviewer-a")
    return PromotionApproval(
        approval_reference_sha256="3" * 64,
        promotion_request_identity_sha256=fingerprint(request),
        package_identity_sha256=request.package_identity_sha256,
        target_stage=request.target_stage,
        requester_reference_sha256=request.executor_reference_sha256,
        approver_reference_sha256=hash_identifier(reviewer.subject_id),
        decided_at=NOW,
        expires_at=NOW + timedelta(hours=1),
    )


def make_known_good(
    promotion: PromotionResult,
    *,
    tenant_reference_sha256: str,
    reviewer: AuthContext | None = None,
) -> KnownGoodReference:
    reviewer = reviewer or make_auth(role=Role.REVIEWER, subject_id="registry-reviewer-a")
    return KnownGoodReference(
        tenant_reference_sha256=tenant_reference_sha256,
        authorization_reference_sha256=authorization_reference(reviewer),
        stage=promotion.target_stage,
        package_identity_sha256=promotion.package_identity_sha256,
        promotion_event_sha256=promotion.audit_event_sha256,
        reviewer_reference_sha256=hash_identifier(reviewer.subject_id),
        evidence_identity_sha256="4" * 64,
        marked_at=NOW,
    )


def make_rollback_request(
    *,
    current: RegistryRecord,
    known_good: KnownGoodReference,
    auth: AuthContext | None = None,
) -> RollbackRequest:
    auth = auth or make_auth()
    return RollbackRequest(
        request_id=str(UUID("00000000-0000-4000-8004-000000000001")),
        idempotency_key="e" * 64,
        tenant_reference_sha256=current.package.tenant_reference_sha256,
        executor_reference_sha256=hash_identifier(auth.subject_id),
        authorization_reference_sha256=authorization_reference(auth),
        stage=known_good.stage,
        expected_current_package_sha256=current.package_identity_sha256,
        known_good_package_sha256=known_good.package_identity_sha256,
        known_good_reference_sha256=fingerprint(known_good),
        policy_sha256=current.package.policy_sha256,
        requested_at=NOW,
        deadline_at=NOW + timedelta(minutes=15),
    )


def make_rollback_approval(
    request: RollbackRequest,
    *,
    reviewer: AuthContext | None = None,
) -> RollbackApproval:
    reviewer = reviewer or make_auth(role=Role.REVIEWER, subject_id="registry-reviewer-a")
    return RollbackApproval(
        approval_reference_sha256="5" * 64,
        rollback_request_identity_sha256=fingerprint(request),
        current_package_sha256=request.expected_current_package_sha256,
        known_good_package_sha256=request.known_good_package_sha256,
        requester_reference_sha256=request.executor_reference_sha256,
        approver_reference_sha256=hash_identifier(reviewer.subject_id),
        decided_at=NOW,
        expires_at=NOW + timedelta(hours=1),
    )
