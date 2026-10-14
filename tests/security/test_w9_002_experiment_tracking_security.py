"""Security and privacy checks for W9-002 experiment lineage."""

from copy import deepcopy
from pathlib import Path

import pytest

from enterprise_ai_platform.experiment_tracking import (
    ExperimentAuthorizationError,
    ExperimentTrackingService,
    ExperimentValidationError,
    InMemoryMlflowStore,
    TenantExperimentAuthorizer,
    load_experiment_policy,
)
from tests.fakes.w9_002_experiment_tracking import (
    NOW,
    make_auth,
    make_envelope,
    make_input,
)


class CountingStore(InMemoryMlflowStore):
    def __init__(self) -> None:
        super().__init__()
        self.create_calls = 0

    def create(self, envelope: object, experiment_input: object) -> object:
        self.create_calls += 1
        return super().create(envelope, experiment_input)  # type: ignore[arg-type,return-value]


def test_cross_tenant_request_fails_before_store_access() -> None:
    owner = make_auth()
    other = make_auth(tenant_id="tenant-b")
    store = CountingStore()
    service = ExperimentTrackingService(
        policy=load_experiment_policy(),
        authorizer=TenantExperimentAuthorizer(),
        store=store,
    )

    with pytest.raises(ExperimentAuthorizationError, match="tenant"):
        service.record(make_envelope(auth=owner), make_input(), other, now=NOW)
    assert store.create_calls == 0


def test_policy_substitution_fails_before_store_access() -> None:
    auth = make_auth()
    payload = deepcopy(make_envelope(auth=auth).model_dump(mode="python"))
    payload["policy_sha256"] = "0" * 64
    substituted = type(make_envelope()).model_validate(payload, strict=True)
    store = CountingStore()
    service = ExperimentTrackingService(
        policy=load_experiment_policy(),
        authorizer=TenantExperimentAuthorizer(),
        store=store,
    )

    with pytest.raises(ExperimentValidationError, match="policy"):
        service.record(substituted, make_input(), auth, now=NOW)
    assert store.create_calls == 0


def test_duplicate_policy_keys_and_yaml_aliases_are_rejected(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.yaml"
    duplicate.write_text(
        "schema_version: w9-002.experiment-policy.v1\nschema_version: duplicate\n",
        encoding="utf-8",
    )
    alias = tmp_path / "alias.yaml"
    alias.write_text("value: &shared one\ncopy: *shared\n", encoding="utf-8")

    with pytest.raises(ExperimentValidationError, match="duplicate YAML key"):
        load_experiment_policy(duplicate)
    with pytest.raises(ExperimentValidationError, match="aliases"):
        load_experiment_policy(alias)


def test_package_has_no_vendor_network_process_or_environment_client() -> None:
    root = Path(__file__).resolve().parents[2]
    package = root / "src/enterprise_ai_platform/experiment_tracking"
    rendered = "\n".join(path.read_text(encoding="utf-8") for path in package.glob("*.py"))

    for forbidden in (
        "import mlflow",
        "boto3",
        "requests.",
        "httpx",
        "subprocess",
        "import socket",
        "MLFLOW_TRACKING_URI",
        "os.environ",
    ):
        assert forbidden not in rendered
