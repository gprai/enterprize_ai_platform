"""Composition checks for authorization through bounded local lineage storage."""

from datetime import timedelta
from threading import Event, Thread

import pytest

from enterprise_ai_platform.experiment_tracking import (
    ExperimentAdmissionError,
    ExperimentTrackingService,
    ExperimentValidationError,
    InMemoryMlflowStore,
    RunStatus,
    TenantExperimentAuthorizer,
    load_experiment_policy,
)
from enterprise_ai_platform.experiment_tracking.models import (
    ExperimentInput,
    ExperimentRun,
    RunEnvelope,
)
from tests.fakes.w9_002_experiment_tracking import (
    NOW,
    make_auth,
    make_envelope,
    make_input,
)


def make_service() -> ExperimentTrackingService:
    return ExperimentTrackingService(
        policy=load_experiment_policy(),
        authorizer=TenantExperimentAuthorizer(),
        store=InMemoryMlflowStore(),
    )


class FailingCompletionStore(InMemoryMlflowStore):
    def __init__(self) -> None:
        super().__init__()
        self.fail_completion = True

    def terminate(self, *args: object, **kwargs: object) -> ExperimentRun:
        if self.fail_completion:
            self.fail_completion = False
            raise ExperimentValidationError("malformed admitted metric")
        return super().terminate(*args, **kwargs)  # type: ignore[arg-type]


class BlockingStore(InMemoryMlflowStore):
    def __init__(self) -> None:
        super().__init__()
        self.entered = Event()
        self.release = Event()

    def create(self, envelope: RunEnvelope, experiment_input: ExperimentInput) -> ExperimentRun:
        record = super().create(envelope, experiment_input)
        self.entered.set()
        assert self.release.wait(timeout=5)
        return record


def test_authorized_run_is_completed_without_deployment_or_promotion_approval() -> None:
    auth = make_auth()
    result = make_service().record(make_envelope(auth=auth), make_input(), auth, now=NOW)

    assert result.status is RunStatus.COMPLETED
    assert result.deployment_approval == "NOT_AUTHORIZED"
    assert result.promotion_approval == "NOT_AUTHORIZED"


def test_idempotent_replay_returns_the_same_record() -> None:
    auth = make_auth()
    envelope = make_envelope(auth=auth)
    service = make_service()

    first = service.record(envelope, make_input(), auth, now=NOW)
    second = service.record(envelope, make_input(), auth, now=NOW)

    assert first == second


def test_comparison_allows_visible_model_change_but_rejects_context_change() -> None:
    auth = make_auth()
    service = make_service()
    baseline = service.record(make_envelope(auth=auth, run_number=1), make_input(), auth, now=NOW)
    candidate = service.record(
        make_envelope(auth=auth, run_number=2),
        make_input(model_revision="model-v2", groundedness="0.970000"),
        auth,
        now=NOW,
    )

    comparison = service.compare(
        baseline.envelope.run_id,
        candidate.envelope.run_id,
        auth,
        now=NOW,
        tenant_reference_sha256=baseline.envelope.tenant_reference_sha256,
    )
    assert comparison.deployment_approval == "NOT_AUTHORIZED"
    assert next(item for item in comparison.metric_deltas if item.name == "groundedness").delta > 0

    incompatible = service.record(
        make_envelope(auth=auth, run_number=3),
        make_input(model_revision="model-v3", code_sha256="0" * 64),
        auth,
        now=NOW,
    )
    with pytest.raises(ExperimentValidationError, match="contexts differ"):
        service.compare(
            baseline.envelope.run_id,
            incompatible.envelope.run_id,
            auth,
            now=NOW,
            tenant_reference_sha256=baseline.envelope.tenant_reference_sha256,
        )


def test_failure_after_admission_retains_only_an_invalidated_safe_record() -> None:
    auth = make_auth()
    store = FailingCompletionStore()
    service = ExperimentTrackingService(
        policy=load_experiment_policy(),
        authorizer=TenantExperimentAuthorizer(),
        store=store,
    )

    with pytest.raises(ExperimentValidationError, match="malformed admitted metric"):
        service.record(make_envelope(auth=auth), make_input(), auth, now=NOW)

    record = store.list()[0]
    assert record.status is RunStatus.INVALIDATED
    assert record.safe_reason_code == "RUN_RECORD_INVALIDATED"
    assert record.deployment_approval == "NOT_AUTHORIZED"


def test_global_concurrency_and_deadline_fail_closed() -> None:
    auth = make_auth()
    store = BlockingStore()
    service = ExperimentTrackingService(
        policy=load_experiment_policy(),
        authorizer=TenantExperimentAuthorizer(),
        store=store,
    )
    outcomes: list[ExperimentRun] = []

    worker = Thread(
        target=lambda: outcomes.append(
            service.record(make_envelope(auth=auth), make_input(), auth, now=NOW)
        )
    )
    worker.start()
    assert store.entered.wait(timeout=5)
    try:
        with pytest.raises(ExperimentAdmissionError, match="global"):
            service.record(
                make_envelope(auth=auth, run_number=2),
                make_input(model_revision="model-v2"),
                auth,
                now=NOW,
            )
    finally:
        store.release.set()
        worker.join(timeout=5)
    assert not worker.is_alive()
    assert len(outcomes) == 1

    expired = make_envelope(auth=auth, run_number=3).model_copy(
        update={"deadline_at": NOW + timedelta(seconds=1)}
    )
    with pytest.raises(ExperimentAdmissionError, match="deadline"):
        service.record(
            expired,
            make_input(model_revision="model-v3"),
            auth,
            now=NOW + timedelta(seconds=1),
        )
