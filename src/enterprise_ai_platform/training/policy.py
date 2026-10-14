"""Strict duplicate-safe W9-001 training-policy loader."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal, cast

import yaml  # type: ignore[import-untyped]
from pydantic import ValidationError

from .errors import TrainingValidationError
from .models import TrainingModel
from .serialization import fingerprint

DEFAULT_POLICY_PATH = Path("configs/training/governed-sagemaker-training.yaml")


class TrainingLimits(TrainingModel):
    global_active_training_jobs: Literal[1] = 1
    per_tenant_active_training_jobs: Literal[1] = 1
    maximum_instance_count: Literal[1] = 1
    maximum_runtime_seconds: Literal[21600] = 21600
    maximum_volume_gib: Literal[100] = 100
    maximum_lora_rank: Literal[64] = 64
    automatic_retry_attempts: Literal[0] = 0


class TrainingSecurity(TrainingModel):
    network_isolation_required: Literal[True] = True
    inter_container_encryption_required: Literal[True] = True
    plaintext_secrets_forbidden: Literal[True] = True
    trust_remote_code: Literal[False] = False
    local_files_only: Literal[True] = True
    safetensors_required: Literal[True] = True


class OwnerBindings(TrainingModel):
    aws_account: Literal["OWNER_BINDING_REQUIRED"] = "OWNER_BINDING_REQUIRED"
    training_role: Literal["OWNER_BINDING_REQUIRED"] = "OWNER_BINDING_REQUIRED"
    input_bucket: Literal["OWNER_BINDING_REQUIRED"] = "OWNER_BINDING_REQUIRED"
    output_bucket: Literal["OWNER_BINDING_REQUIRED"] = "OWNER_BINDING_REQUIRED"
    kms_key: Literal["OWNER_BINDING_REQUIRED"] = "OWNER_BINDING_REQUIRED"
    private_network: Literal["OWNER_BINDING_REQUIRED"] = "OWNER_BINDING_REQUIRED"
    instance_type: Literal["OWNER_BINDING_REQUIRED"] = "OWNER_BINDING_REQUIRED"
    runtime_seconds: Literal["OWNER_BINDING_REQUIRED"] = "OWNER_BINDING_REQUIRED"
    training_budget_usd: Literal["OWNER_BINDING_REQUIRED"] = "OWNER_BINDING_REQUIRED"


class PeftPolicy(TrainingModel):
    enabled_by_default: Literal[False] = False
    owner_approval_required: Literal[True] = True


class TrainingPolicy(TrainingModel):
    schema_version: Literal["w9-001.governed-training-policy.v1"]
    feature_ids: tuple[Literal["TRAIN-001", "COST-006"], ...]
    region: Literal["ap-southeast-1"]
    execution_scope: Literal["offline_contract_only"]
    limits: TrainingLimits
    security: TrainingSecurity
    bindings: OwnerBindings
    peft: PeftPolicy
    live_execution: Literal["NOT_AUTHORIZED"]
    provisioning: Literal["NOT_RUN"]

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
            raise TrainingValidationError(f"duplicate YAML key: {key!r}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)


def load_training_policy(path: Path = DEFAULT_POLICY_PATH) -> TrainingPolicy:
    try:
        payload = path.read_bytes()
        if not payload or len(payload) > 65_536 or payload.startswith((b"\xff\xfe", b"\xfe\xff")):
            raise TrainingValidationError("training policy encoding or size is invalid")
        text = payload.decode("utf-8", errors="strict")
        if "&" in text or "*" in text:
            raise TrainingValidationError("YAML aliases are not permitted")
        loader = _UniqueKeyLoader(text)
        try:
            raw = loader.get_single_data()
        finally:
            loader.dispose()
        if not isinstance(raw, dict):
            raise TrainingValidationError("training policy must be a mapping")
        policy = TrainingPolicy.model_validate(cast(dict[str, object], raw), strict=False)
        if policy.feature_ids != ("TRAIN-001", "COST-006"):
            raise TrainingValidationError("feature ownership must be TRAIN-001 then COST-006")
        return policy
    except TrainingValidationError:
        raise
    except (OSError, UnicodeError, yaml.YAMLError, ValidationError, ValueError) as error:
        raise TrainingValidationError("invalid training policy") from error
