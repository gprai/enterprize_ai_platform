"""Authorization-first orchestration for bounded W9-002 experiment lineage."""

from __future__ import annotations

from datetime import UTC, datetime
from threading import RLock

from enterprise_ai_platform.agent.authorization import authorization_reference
from enterprise_ai_platform.agent.serialization import hash_identifier
from enterprise_ai_platform.retrieval.models import CLASSIFICATION_RANK, AuthContext, Role

from .contracts import ExperimentAuthorizer, ExperimentStore
from .errors import (
    ExperimentAdmissionError,
    ExperimentAuthorizationError,
    ExperimentStateError,
    ExperimentValidationError,
)
from .models import (
    CleanupPlan,
    ExperimentComparison,
    ExperimentInput,
    ExperimentMetric,
    ExperimentRun,
    MetricDelta,
    RedactedLineageExport,
    RunEnvelope,
    RunStatus,
)
from .policy import ExperimentPolicy
from .redaction import validate_privacy_safe_input
from .serialization import fingerprint


class TenantExperimentAuthorizer:
    """Require an active same-tenant administrator before tracking-store access."""

    def authorize(self, envelope: RunEnvelope, auth_context: AuthContext, *, now: datetime) -> None:
        if not auth_context.is_active(now) or Role.ADMIN not in auth_context.roles:
            raise ExperimentAuthorizationError("active administrator authorization is required")
        if hash_identifier(auth_context.tenant_id) != envelope.tenant_reference_sha256:
            raise ExperimentAuthorizationError("tenant authorization failed")
        if hash_identifier(auth_context.subject_id) != envelope.subject_reference_sha256:
            raise ExperimentAuthorizationError("subject authorization failed")
        if authorization_reference(auth_context) != envelope.authorization_reference_sha256:
            raise ExperimentAuthorizationError("authorization context differs")
        if (
            CLASSIFICATION_RANK[auth_context.clearance]
            < CLASSIFICATION_RANK[envelope.classification]
        ):
            raise ExperimentAuthorizationError("classification clearance is insufficient")


class ExperimentTrackingService:
    def __init__(
        self,
        *,
        policy: ExperimentPolicy,
        authorizer: ExperimentAuthorizer,
        store: ExperimentStore,
    ) -> None:
        self._policy = policy
        self._authorizer = authorizer
        self._store = store
        self._active_global = 0
        self._active_by_tenant: dict[str, int] = {}
        self._completed: dict[str, tuple[str, ExperimentRun]] = {}
        self._lock = RLock()

    def record(
        self,
        envelope: RunEnvelope,
        experiment_input: ExperimentInput,
        auth_context: AuthContext,
        *,
        now: datetime,
    ) -> ExperimentRun:
        if now.tzinfo is None or now.utcoffset() != UTC.utcoffset(now):
            raise ExperimentValidationError("service time must use UTC")
        self._authorizer.authorize(envelope, auth_context, now=now)
        validate_privacy_safe_input(experiment_input)
        if envelope.policy_sha256 != self._policy.identity_sha256:
            raise ExperimentValidationError("experiment policy identity differs")
        if envelope.classification != experiment_input.dataset.classification:
            raise ExperimentValidationError("run and dataset classifications differ")
        if now >= envelope.deadline_at:
            raise ExperimentAdmissionError("run deadline has expired")
        idempotency_identity = fingerprint(
            {
                "authorization_reference_sha256": envelope.authorization_reference_sha256,
                "classification": envelope.classification.value,
                "experiment_input": experiment_input,
                "policy_sha256": envelope.policy_sha256,
                "subject_reference_sha256": envelope.subject_reference_sha256,
                "tenant_reference_sha256": envelope.tenant_reference_sha256,
            }
        )
        with self._lock:
            prior = self._completed.get(envelope.idempotency_key)
            if prior is not None:
                prior_identity, prior_result = prior
                if prior_identity != idempotency_identity:
                    raise ExperimentAdmissionError("idempotency key conflicts with another input")
                return prior_result
            tenant = envelope.tenant_reference_sha256
            if self._active_global >= self._policy.limits.global_active_runs:
                raise ExperimentAdmissionError("global experiment concurrency exceeded")
            if self._active_by_tenant.get(tenant, 0) >= self._policy.limits.per_tenant_active_runs:
                raise ExperimentAdmissionError("tenant experiment concurrency exceeded")
            self._active_global += 1
            self._active_by_tenant[tenant] = self._active_by_tenant.get(tenant, 0) + 1
        created = False
        try:
            self._store.create(envelope, experiment_input)
            created = True
            result = self._store.terminate(
                envelope.run_id,
                RunStatus.COMPLETED,
                completed_at=now,
            )
            with self._lock:
                self._completed[envelope.idempotency_key] = (idempotency_identity, result)
            return result
        except Exception:
            if created:
                try:
                    self._store.terminate(
                        envelope.run_id,
                        RunStatus.INVALIDATED,
                        completed_at=now,
                        safe_reason_code="RUN_RECORD_INVALIDATED",
                    )
                except ExperimentStateError:
                    pass
            raise
        finally:
            with self._lock:
                self._active_global -= 1
                self._active_by_tenant[tenant] -= 1

    def cancel(self, run_id: str, *, now: datetime) -> ExperimentRun:
        return self._store.terminate(
            run_id,
            RunStatus.CANCELLED,
            completed_at=now,
            safe_reason_code="OWNER_CANCELLED",
        )

    def compare(
        self,
        baseline_run_id: str,
        candidate_run_id: str,
        auth_context: AuthContext,
        *,
        now: datetime,
        tenant_reference_sha256: str,
    ) -> ExperimentComparison:
        if now.tzinfo is None or now.utcoffset() != UTC.utcoffset(now):
            raise ExperimentValidationError("comparison time must use UTC")
        if not auth_context.is_active(now) or not auth_context.roles.intersection(
            {Role.REVIEWER, Role.ADMIN}
        ):
            raise ExperimentAuthorizationError("active reviewer authorization is required")
        if hash_identifier(auth_context.tenant_id) != tenant_reference_sha256:
            raise ExperimentAuthorizationError("comparison tenant authorization failed")
        baseline = self._store.get(baseline_run_id)
        candidate = self._store.get(candidate_run_id)
        if any(
            run.envelope.tenant_reference_sha256 != tenant_reference_sha256
            or CLASSIFICATION_RANK[auth_context.clearance]
            < CLASSIFICATION_RANK[run.envelope.classification]
            for run in (baseline, candidate)
        ):
            raise ExperimentAuthorizationError("comparison run authorization failed")
        if (
            baseline.status is not RunStatus.COMPLETED
            or candidate.status is not RunStatus.COMPLETED
        ):
            raise ExperimentStateError("only completed runs can be compared")
        baseline_context = _comparison_context(baseline)
        candidate_context = _comparison_context(candidate)
        if baseline_context != candidate_context:
            raise ExperimentValidationError("experiment comparison contexts differ")
        baseline_metrics = _metric_map(baseline.experiment_input.metrics)
        candidate_metrics = _metric_map(candidate.experiment_input.metrics)
        if baseline_metrics.keys() != candidate_metrics.keys():
            raise ExperimentValidationError("experiment metric inventories differ")
        deltas: list[MetricDelta] = []
        for name in sorted(baseline_metrics):
            left = baseline_metrics[name]
            right = candidate_metrics[name]
            if left.unit != right.unit:
                raise ExperimentValidationError("experiment metric units differ")
            deltas.append(
                MetricDelta(
                    name=name,
                    unit=left.unit,
                    baseline=left.value,
                    candidate=right.value,
                    delta=right.value - left.value,
                )
            )
        return ExperimentComparison(
            baseline_run_id=baseline_run_id,
            candidate_run_id=candidate_run_id,
            compatible_context_sha256=fingerprint(baseline_context),
            metric_deltas=tuple(deltas),
        )

    def disable(self) -> None:
        self._store.disable()

    def export(self, *, now: datetime) -> RedactedLineageExport:
        return self._store.export(policy_sha256=self._policy.identity_sha256, exported_at=now)

    def cleanup_plan(self) -> CleanupPlan:
        return CleanupPlan(
            policy_sha256=self._policy.identity_sha256,
            exact_run_ids=tuple(sorted(record.envelope.run_id for record in self._store.list())),
        )


def _metric_map(metrics: tuple[ExperimentMetric, ...]) -> dict[str, ExperimentMetric]:
    return {metric.name: metric for metric in metrics}


def _comparison_context(run: ExperimentRun) -> dict[str, object]:
    item = run.experiment_input
    evaluation_contract = {
        "baseline_comparison_status": item.evaluation.baseline_comparison_status,
        "configuration_checksum_sha256": item.evaluation.configuration_checksum_sha256,
        "dataset_checksum_sha256": item.evaluation.dataset_checksum_sha256,
        "evaluator_version": item.evaluation.evaluator_version,
        "metric_version": item.evaluation.metric_version,
        "report_schema": item.evaluation.report_schema,
    }
    return {
        "classification": run.envelope.classification.value,
        "tenant_reference_sha256": run.envelope.tenant_reference_sha256,
        "dataset": item.dataset,
        "code": item.code,
        "prompt": item.prompt,
        "embedding": item.embedding,
        "retrieval": item.retrieval,
        "evaluation_contract": evaluation_contract,
    }
