"""Zero-residue and exact-purge assertions for the source-only W9-002 contract."""

from pathlib import Path

import pytest

from enterprise_ai_platform.experiment_tracking import (
    ExperimentStateError,
    ExperimentTrackingService,
    InMemoryMlflowStore,
    TenantExperimentAuthorizer,
    fingerprint,
    load_experiment_policy,
)
from tests.fakes.w9_002_experiment_tracking import NOW, make_auth, make_envelope, make_input

ROOT = Path(__file__).resolve().parents[2]


def test_source_only_contract_contains_no_runtime_or_evidence_residue() -> None:
    for relative in (
        "reports/W9/W9-002",
        "evidence/W9/W9-002",
        ".pytest_cache",
        "mlruns",
        "configs/experiments/w9-002-runtime.json",
    ):
        assert not (ROOT / relative).exists()


def test_purge_requires_disablement_and_exact_verified_export_identity() -> None:
    auth = make_auth()
    store = InMemoryMlflowStore()
    service = ExperimentTrackingService(
        policy=load_experiment_policy(),
        authorizer=TenantExperimentAuthorizer(),
        store=store,
    )
    result = service.record(make_envelope(auth=auth), make_input(), auth, now=NOW)
    run_ids = (result.envelope.run_id,)

    with pytest.raises(ExperimentStateError, match="disabled"):
        store.purge(run_ids, export_identity_sha256="0" * 64)

    service.disable()
    exported = service.export(now=NOW)
    with pytest.raises(ExperimentStateError, match="latest"):
        store.purge(run_ids, export_identity_sha256="0" * 64)

    store.purge(run_ids, export_identity_sha256=fingerprint(exported))
    assert store.list() == ()


def test_no_task_specific_cache_or_backend_material_exists_in_repository() -> None:
    for relative in (
        ".cache/w9-002",
        "artifacts/w9-002",
        "mlruns",
        "mlflow.db",
    ):
        assert not (ROOT / relative).exists()
