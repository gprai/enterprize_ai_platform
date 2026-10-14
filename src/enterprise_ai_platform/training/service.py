"""Ordered authorization, approval, capability, and cost gates for W9-001."""

from __future__ import annotations

from datetime import UTC, datetime

from enterprise_ai_platform.agent.authorization import authorization_reference
from enterprise_ai_platform.agent.serialization import hash_identifier
from enterprise_ai_platform.retrieval.models import CLASSIFICATION_RANK, AuthContext, Role

from .capabilities import detect_capability
from .contracts import TorchRuntime, TrainingAuthorizer, TrainingProvider
from .errors import TrainingAdmissionError, TrainingAuthorizationError, TrainingValidationError
from .models import TrainingApproval, TrainingRequest, TrainingResult
from .policy import TrainingPolicy
from .serialization import fingerprint


class TrainingService:
    def __init__(
        self,
        *,
        policy: TrainingPolicy,
        runtime: TorchRuntime,
        authorizer: TrainingAuthorizer,
        provider: TrainingProvider,
    ) -> None:
        self._policy = policy
        self._runtime = runtime
        self._authorizer = authorizer
        self._provider = provider
        self._active_global = 0
        self._active_by_tenant: dict[str, int] = {}
        self._completed: dict[str, tuple[str, TrainingResult]] = {}

    def prepare(
        self,
        request: TrainingRequest,
        approval: TrainingApproval,
        auth_context: AuthContext,
        *,
        now: datetime,
    ) -> TrainingResult:
        if now.tzinfo is None or now.utcoffset() != UTC.utcoffset(now):
            raise TrainingValidationError("service time must be UTC")
        if not auth_context.is_active(now) or Role.ADMIN not in auth_context.roles:
            raise TrainingAuthorizationError("active administrator authorization is required")
        self._authorizer.authorize(request, auth_context)
        if request.policy_sha256 != self._policy.identity_sha256:
            raise TrainingValidationError("training policy identity differs")
        request_identity = fingerprint(request)
        if (
            approval.request_identity_sha256 != request_identity
            or approval.approval_reference_sha256 != request.approval_reference_sha256
            or approval.tenant_reference_sha256 != request.tenant_reference_sha256
            or approval.expires_at <= now
            or approval.cost_ceiling_usd <= 0
        ):
            raise TrainingAdmissionError("training approval is invalid or expired")
        if request.peft.enabled and not approval.peft_approved:
            raise TrainingAdmissionError("PEFT requires explicit approval")
        if request.resources.instance_type != self._policy.bindings.instance_type:
            raise TrainingAdmissionError("instance type remains owner-bound")
        if request.resources.instance_count > self._policy.limits.maximum_instance_count:
            raise TrainingAdmissionError("instance-count ceiling exceeded")
        if request.resources.runtime_seconds > self._policy.limits.maximum_runtime_seconds:
            raise TrainingAdmissionError("runtime ceiling exceeded")
        if request.resources.volume_gib > self._policy.limits.maximum_volume_gib:
            raise TrainingAdmissionError("storage ceiling exceeded")
        prior = self._completed.get(request.idempotency_key)
        if prior is not None:
            prior_identity, prior_result = prior
            if prior_identity != request_identity:
                raise TrainingAdmissionError("idempotency key conflicts with another request")
            return prior_result
        tenant = request.tenant_reference_sha256
        if self._active_global >= self._policy.limits.global_active_training_jobs:
            raise TrainingAdmissionError("global training concurrency exceeded")
        if (
            self._active_by_tenant.get(tenant, 0)
            >= self._policy.limits.per_tenant_active_training_jobs
        ):
            raise TrainingAdmissionError("tenant training concurrency exceeded")
        capability = detect_capability(self._runtime, request.resources.accelerator)
        self._active_global += 1
        self._active_by_tenant[tenant] = self._active_by_tenant.get(tenant, 0) + 1
        try:
            result = self._provider.prepare(request, capability)
            if result.request_identity_sha256 != request_identity:
                raise TrainingValidationError("provider result is not bound to the request")
            self._completed[request.idempotency_key] = (request_identity, result)
            return result
        finally:
            self._active_global -= 1
            self._active_by_tenant[tenant] -= 1


class TenantTrainingAuthorizer:
    """Fail closed unless hashed tenant and subject identities match the auth context."""

    def authorize(self, request: TrainingRequest, auth_context: AuthContext) -> None:
        if hash_identifier(auth_context.tenant_id) != request.tenant_reference_sha256:
            raise TrainingAuthorizationError("tenant authorization failed")
        if hash_identifier(auth_context.subject_id) != request.subject_reference_sha256:
            raise TrainingAuthorizationError("subject authorization failed")
        if authorization_reference(auth_context) != request.authorization_reference_sha256:
            raise TrainingAuthorizationError("authorization context differs")
        if (
            CLASSIFICATION_RANK[auth_context.clearance]
            < CLASSIFICATION_RANK[request.classification]
        ):
            raise TrainingAuthorizationError("classification clearance is insufficient")
