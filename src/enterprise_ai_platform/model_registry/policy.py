"""Strict duplicate-safe W9-003 model-registry policy loader."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal, cast

import yaml  # type: ignore[import-untyped]
from pydantic import ValidationError

from .errors import RegistryValidationError
from .models import RegistryModel
from .serialization import fingerprint

DEFAULT_POLICY_PATH = Path("configs/model-registry/governed-sagemaker-model-promotion.yaml")


class RegistryLimits(RegistryModel):
    global_active_mutations: Literal[1] = 1
    per_tenant_active_mutations: Literal[1] = 1
    maximum_retained_packages: Literal[100] = 100
    maximum_audit_events: Literal[1000] = 1000
    maximum_request_seconds: Literal[900] = 900
    automatic_retry_attempts: Literal[0] = 0


class RegistrySecurity(RegistryModel):
    allowed_classifications: tuple[Literal["PUBLIC", "INTERNAL"], ...]
    hashed_principal_references_only: Literal[True] = True
    raw_content_allowed: Literal[False] = False
    mutable_model_tags_allowed: Literal[False] = False


class RegistryApprovals(RegistryModel):
    separation_of_duties_required: Literal[True] = True
    deployment_approval: Literal["NOT_AUTHORIZED"] = "NOT_AUTHORIZED"
    live_registry_mutation: Literal["NOT_AUTHORIZED"] = "NOT_AUTHORIZED"


class RegistryPromotion(RegistryModel):
    stages: tuple[Literal["CANDIDATE", "STAGING", "PRODUCTION"], ...]
    direct_candidate_to_production: Literal[False] = False
    exact_reviewed_package_required: Literal[True] = True
    known_good_rollback_required: Literal[True] = True


class RegistryRetention(RegistryModel):
    audit_export_days: Literal[180] = 180
    export_before_deletion: Literal[True] = True
    preserve_failed_candidates: Literal[True] = True
    delete_shared_resources: Literal[False] = False


class RegistryBindings(RegistryModel):
    model_package_group_name: Literal["OWNER_BINDING_REQUIRED"] = "OWNER_BINDING_REQUIRED"


class RegistryPolicy(RegistryModel):
    schema_version: Literal["w9-003.model-registry-policy.v1"]
    feature_ids: tuple[Literal["REGISTRY-001"], ...]
    region: Literal["ap-southeast-1"]
    operating_mode: Literal["process_local_memory"]
    limits: RegistryLimits
    security: RegistrySecurity
    approvals: RegistryApprovals
    promotion: RegistryPromotion
    retention: RegistryRetention
    bindings: RegistryBindings
    network_access: Literal[False] = False

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
            raise RegistryValidationError(f"duplicate YAML key: {key!r}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def load_registry_policy(path: Path = DEFAULT_POLICY_PATH) -> RegistryPolicy:
    try:
        payload = path.read_bytes()
        if not payload or len(payload) > 65_536 or payload.startswith((b"\xff\xfe", b"\xfe\xff")):
            raise RegistryValidationError("registry policy encoding or size is invalid")
        text = payload.decode("utf-8", errors="strict")
        if "&" in text or "*" in text:
            raise RegistryValidationError("YAML aliases are not permitted")
        loader = _UniqueKeyLoader(text)
        try:
            raw = loader.get_single_data()
        finally:
            loader.dispose()
        if not isinstance(raw, dict):
            raise RegistryValidationError("registry policy must be a mapping")
        policy = RegistryPolicy.model_validate(cast(dict[str, object], raw), strict=False)
        if policy.feature_ids != ("REGISTRY-001",):
            raise RegistryValidationError("feature ownership must be REGISTRY-001")
        if policy.security.allowed_classifications != ("PUBLIC", "INTERNAL"):
            raise RegistryValidationError("classification allowlist order differs")
        if policy.promotion.stages != ("CANDIDATE", "STAGING", "PRODUCTION"):
            raise RegistryValidationError("promotion stage order differs")
        return policy
    except RegistryValidationError:
        raise
    except (OSError, UnicodeError, yaml.YAMLError, ValidationError, ValueError) as error:
        raise RegistryValidationError("invalid registry policy") from error
