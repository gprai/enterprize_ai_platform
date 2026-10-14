"""Rollback contracts for disabling and preserving W9-002 redacted lineage."""

import pytest
from tests.fakes.w9_002_experiment_tracking import NOW, make_auth, make_envelope, make_input

from enterprise_ai_platform.experiment_tracking import (
    ExperimentStateError,
    ExperimentTrackingService,
    InMemoryMlflowStore,
    RunStatus,
    TenantExperimentAuthorizer,
    fingerprint,
    load_experiment_policy,
)


def test_disable_preserves_redacted_lineage_and_blocks_new_runs() -> None:
    auth = make_auth()
    store = InMemoryMlflowStore()
    service = ExperimentTrackingService(
        policy=load_experiment_policy(),
        authorizer=TenantExperimentAuthorizer(),
        store=store,
    )
    existing = service.record(make_envelope(auth=auth), make_input(), auth, now=NOW)

    service.disable()
    exported = service.export(now=NOW)

    assert exported.records == (existing,)
    assert fingerprint(exported)
    with pytest.raises(ExperimentStateError, match="disabled"):
        service.record(
            make_envelope(auth=auth, run_number=2),
            make_input(model_revision="model-v2"),
            auth,
            now=NOW,
        )


def test_cleanup_plan_is_exact_owner_controlled_and_retains_export() -> None:
    auth = make_auth()
    service = ExperimentTrackingService(
        policy=load_experiment_policy(),
        authorizer=TenantExperimentAuthorizer(),
        store=InMemoryMlflowStore(),
    )
    result = service.record(make_envelope(auth=auth), make_input(), auth, now=NOW)

    cleanup = service.cleanup_plan()

    assert cleanup.exact_run_ids == (result.envelope.run_id,)
    assert cleanup.retain_redacted_export is True
    assert cleanup.retention_days == 180
    assert cleanup.delete_shared_resources is False
    assert cleanup.owner_approval_required is True
    assert cleanup.status == "NOT_RUN"


def test_cancel_is_terminal_and_cannot_be_replaced_by_completion() -> None:
    auth = make_auth()
    store = InMemoryMlflowStore()
    service = ExperimentTrackingService(
        policy=load_experiment_policy(),
        authorizer=TenantExperimentAuthorizer(),
        store=store,
    )
    envelope = make_envelope(auth=auth)
    store.create(envelope, make_input())

    cancelled = service.cancel(envelope.run_id, now=NOW)

    assert cancelled.status is RunStatus.CANCELLED
    with pytest.raises(ExperimentStateError, match="immutable"):
        store.terminate(envelope.run_id, RunStatus.COMPLETED, completed_at=NOW)
