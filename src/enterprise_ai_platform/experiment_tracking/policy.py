"""Strict duplicate-safe W9-002 experiment-lineage policy loader."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal, cast

import yaml  # type: ignore[import-untyped]
from pydantic import ValidationError

from .errors import ExperimentValidationError
from .models import LineageModel
from .serialization import fingerprint

DEFAULT_POLICY_PATH = Path("configs/experiments/governed-mlflow-experiment-lineage.yaml")


class ExperimentLimits(LineageModel):
    global_active_runs: Literal[1] = 1
    per_tenant_active_runs: Literal[1] = 1
    maximum_retained_runs: Literal[100] = 100
    maximum_parameters: Literal[128] = 128
    maximum_metrics: Literal[32] = 32
    maximum_artifacts: Literal[16] = 16
    maximum_comparison_runs: Literal[16] = 16
    maximum_run_seconds: Literal[900] = 900
    automatic_retry_attempts: Literal[0] = 0


class ExperimentSecurity(LineageModel):
    allowed_classifications: tuple[Literal["PUBLIC", "INTERNAL"], ...]
    production_data_allowed: Literal[False] = False
    raw_content_allowed: Literal[False] = False
    hashed_principal_references_only: Literal[True] = True


class ExperimentRetention(LineageModel):
    redacted_export_days: Literal[180] = 180
    export_before_purge: Literal[True] = True
    delete_shared_resources: Literal[False] = False


class ExperimentApprovals(LineageModel):
    deployment_approval: Literal["NOT_AUTHORIZED"] = "NOT_AUTHORIZED"
    promotion_approval: Literal["NOT_AUTHORIZED"] = "NOT_AUTHORIZED"


class ExperimentBackend(LineageModel):
    tracking_uri_binding: Literal["OWNER_BINDING_REQUIRED"] = "OWNER_BINDING_REQUIRED"
    network_access: Literal[False] = False
    managed_backend: Literal["NOT_AUTHORIZED"] = "NOT_AUTHORIZED"


class ExperimentPolicy(LineageModel):
    schema_version: Literal["w9-002.experiment-policy.v1"]
    feature_ids: tuple[Literal["MLFLOW-001", "RET-003"], ...]
    region: Literal["ap-southeast-1"]
    operating_mode: Literal["process_local_memory"]
    limits: ExperimentLimits
    security: ExperimentSecurity
    retention: ExperimentRetention
    approvals: ExperimentApprovals
    backend: ExperimentBackend

    @property
    def identity_sha256(self) -> str:
        return fingerprint(self)


class _UniqueKeyLoader(yaml.SafeLoader):  # type: ignore[misc]
    pass


def _construct_unique_mapping(
    loader: _UniqueKeyLoader, node: Any, deep: bool = False
) -> dict[object, object]:
    result: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise ExperimentValidationError(f"duplicate YAML key: {key!r}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)


def load_experiment_policy(path: Path = DEFAULT_POLICY_PATH) -> ExperimentPolicy:
    try:
        payload = path.read_bytes()
        if not payload or len(payload) > 65_536 or payload.startswith((b"\xff\xfe", b"\xfe\xff")):
            raise ExperimentValidationError("experiment policy encoding or size is invalid")
        text = payload.decode("utf-8", errors="strict")
        if "&" in text or "*" in text:
            raise ExperimentValidationError("YAML aliases are not permitted")
        loader = _UniqueKeyLoader(text)
        try:
            raw = loader.get_single_data()
        finally:
            loader.dispose()
        if not isinstance(raw, dict):
            raise ExperimentValidationError("experiment policy must be a mapping")
        policy = ExperimentPolicy.model_validate(cast(dict[str, object], raw), strict=False)
        if policy.feature_ids != ("MLFLOW-001", "RET-003"):
            raise ExperimentValidationError("feature ownership must be MLFLOW-001 then RET-003")
        if policy.security.allowed_classifications != ("PUBLIC", "INTERNAL"):
            raise ExperimentValidationError("classification allowlist order differs")
        return policy
    except ExperimentValidationError:
        raise
    except (OSError, UnicodeError, yaml.YAMLError, ValidationError, ValueError) as error:
        raise ExperimentValidationError("invalid experiment policy") from error
