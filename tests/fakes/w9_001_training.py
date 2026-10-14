"""Deterministic W9-001 training fixtures with no model, GPU, or network access."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from uuid import UUID

from enterprise_ai_platform.agent.authorization import authorization_reference
from enterprise_ai_platform.agent.serialization import hash_identifier
from enterprise_ai_platform.retrieval.models import AuthContext, Classification, Role
from enterprise_ai_platform.training import (
    Accelerator,
    CacheEntry,
    Hyperparameter,
    ModelSourceIdentity,
    PeftRequest,
    ResourceRequest,
    TrainingApproval,
    TrainingCacheManifest,
    TrainingCodeIdentity,
    TrainingContainerIdentity,
    TrainingDataIdentity,
    TrainingRequest,
    fingerprint,
    load_training_policy,
)

NOW = datetime(2026, 10, 14, 0, 0, tzinfo=UTC)


class FakeTorchRuntime:
    def __init__(self, *, gpu: bool = False, count: int = 0) -> None:
        self._gpu = gpu
        self._count = count

    @property
    def version(self) -> str:
        return "2.13.0+cpu"

    def cuda_available(self) -> bool:
        return self._gpu

    def cuda_device_count(self) -> int:
        return self._count


def make_auth(*, tenant_id: str = "tenant-a", subject_id: str = "owner-a") -> AuthContext:
    return AuthContext(
        subject_id=subject_id,
        tenant_id=tenant_id,
        roles=frozenset({Role.ADMIN}),
        clearance=Classification.RESTRICTED,
        groups=frozenset(),
        issuer="https://identity.example.invalid",
        audience="enterprise-ai-platform",
        expires_at=NOW + timedelta(hours=1),
        request_id="w9-001-request",
    )


def make_request(
    *,
    auth: AuthContext | None = None,
    accelerator: Accelerator = Accelerator.CPU,
    peft: PeftRequest | None = None,
    idempotency_key: str = "9" * 64,
) -> TrainingRequest:
    auth = auth or make_auth()
    policy = load_training_policy()
    return TrainingRequest(
        request_id=str(UUID("00000000-0000-4000-8000-000000000901")),
        correlation_id=str(UUID("00000000-0000-4000-8000-000000000902")),
        idempotency_key=idempotency_key,
        tenant_reference_sha256=hash_identifier(auth.tenant_id),
        subject_reference_sha256=hash_identifier(auth.subject_id),
        authorization_reference_sha256=authorization_reference(auth),
        classification=Classification.INTERNAL,
        model=ModelSourceIdentity(
            repository_id="owner/approved-model",
            revision="1" * 40,
            manifest_sha256="2" * 64,
            license="Apache-2.0",
        ),
        data=TrainingDataIdentity(
            uri="s3://approved-training-input/dataset.jsonl",
            version_id="version-1",
            manifest_sha256="3" * 64,
            tenant_reference_sha256=hash_identifier(auth.tenant_id),
            classification=Classification.INTERNAL,
        ),
        code=TrainingCodeIdentity(git_commit="4" * 40, source_sha256="5" * 64),
        container=TrainingContainerIdentity(
            registry_uri=(
                f"000000000000.dkr.ecr.ap-southeast-1.amazonaws.com/training@sha256:{'6' * 64}"
            ),
            image_digest=f"sha256:{'6' * 64}",
        ),
        hyperparameters=(Hyperparameter(key="epochs", value="1"),),
        cache=TrainingCacheManifest(
            entries=(CacheEntry(path="model/config.json", size_bytes=128, sha256="7" * 64),)
        ),
        resources=ResourceRequest(
            accelerator=accelerator,
            instance_type="OWNER_BINDING_REQUIRED",
            runtime_seconds=3600,
            volume_gib=100,
        ),
        peft=peft or PeftRequest(),
        policy_sha256=policy.identity_sha256,
        budget_reference_sha256="8" * 64,
        approval_reference_sha256="b" * 64,
        requested_at=NOW,
        deadline_at=NOW + timedelta(hours=1),
    )


def make_approval(
    request: TrainingRequest,
    *,
    peft_approved: bool = False,
    expires_at: datetime = NOW + timedelta(hours=2),
) -> TrainingApproval:
    return TrainingApproval(
        approval_reference_sha256=request.approval_reference_sha256,
        request_identity_sha256=fingerprint(request),
        tenant_reference_sha256=request.tenant_reference_sha256,
        requester_reference_sha256=request.subject_reference_sha256,
        approver_reference_sha256="c" * 64,
        cost_ceiling_usd=Decimal("1.00"),
        peft_approved=peft_approved,
        decided_at=NOW - timedelta(minutes=1),
        expires_at=expires_at,
    )
