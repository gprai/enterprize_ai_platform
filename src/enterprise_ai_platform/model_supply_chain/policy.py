"""Strict loading for the owner-approved W9-004 policy."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, model_validator

from .errors import SupplyChainValidationError
from .serialization import fingerprint

DEFAULT_POLICY_PATH = Path("configs/ci/w9-004.json")


class PolicyModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class Limits(PolicyModel):
    maximum_artifact_bytes: Literal[10_737_418_240]
    maximum_archive_entries: Literal[10_000]
    maximum_report_bytes: Literal[52_428_800]
    maximum_run_evidence_bytes: Literal[104_857_600]
    workflow_timeout_minutes: Literal[60]
    oidc_session_seconds: Literal[900]
    evidence_freshness_hours: Literal[24]
    automatic_retry_attempts: Literal[0]
    concurrent_candidates: Literal[1]


class Security(PolicyModel):
    allowed_classifications: tuple[Literal["PUBLIC", "INTERNAL"], ...]
    hosted_runner_raw_artifact_classifications: tuple[Literal["PUBLIC"], ...]
    allowed_licenses: tuple[Literal["Apache-2.0"], ...]
    allowed_weight_extensions: tuple[Literal[".safetensors"], ...]
    denied_extensions: tuple[str, ...]
    critical_findings_allowed: Literal[0]
    high_findings_require_owner_treatment: Literal[True]
    scanner_disagreement: Literal["BLOCK"]
    static_cloud_credentials_allowed: Literal[False]


class Github(PolicyModel):
    repository: Literal["gprai/enterprize_ai_platform"]
    ref: Literal["refs/heads/main"]
    environment: Literal["sandbox"]
    event: Literal["workflow_dispatch"]
    role_variable: Literal["W9_004_READ_ROLE_ARN"]
    oidc_audience: Literal["sts.amazonaws.com"]
    required_reviewers: Literal[True]
    cancel_in_progress: Literal[False]


class ToolVersions(PolicyModel):
    python: Literal["3.13.15"]
    trivy: Literal["0.74.0"]
    grype: Literal["0.118.0"]
    syft: Literal["1.51.1"]
    cosign: Literal["3.1.2"]
    opa: Literal["1.20.0"]
    checkov: Literal["3.3.16"]
    actionlint: Literal["1.7.12"]


class Retention(PolicyModel):
    transient_github_artifact_days: Literal[7]
    canonical_evidence_days: Literal[180]
    preserve_failed_candidates: Literal[True]
    delete_shared_resources: Literal[False]


class Bindings(PolicyModel):
    manifest_bucket: Literal["OWNER_BINDING_REQUIRED"]
    read_role_arn: Literal["OWNER_BINDING_REQUIRED"]
    signer_issuer: Literal["OWNER_BINDING_REQUIRED"]
    signer_subject: Literal["OWNER_BINDING_REQUIRED"]


class SupplyChainPolicy(PolicyModel):
    schema_version: Literal["w9-004.policy.v1"]
    feature_ids: tuple[Literal["SUPPLY-002", "GHA-002"], ...]
    region: Literal["ap-southeast-1"]
    operating_mode: Literal["source_and_manual_workflow"]
    limits: Limits
    security: Security
    github: Github
    tools: ToolVersions
    retention: Retention
    bindings: Bindings
    network_access: Literal["OWNER_APPROVED_WORKFLOW_ONLY"]
    deployment_approval: Literal["NOT_AUTHORIZED"]

    @model_validator(mode="after")
    def require_exact_ordering(self) -> SupplyChainPolicy:
        if self.feature_ids != ("SUPPLY-002", "GHA-002"):
            raise ValueError("feature IDs must use the approved order")
        if self.security.allowed_classifications != ("PUBLIC", "INTERNAL"):
            raise ValueError("classification order differs")
        if self.security.denied_extensions != tuple(sorted(set(self.security.denied_extensions))):
            raise ValueError("denied extensions must be sorted and unique")
        return self

    @property
    def identity_sha256(self) -> str:
        return fingerprint(self)


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise SupplyChainValidationError(f"duplicate policy key: {key}")
        result[key] = value
    return result


def _freeze_json_arrays(value: object) -> object:
    if isinstance(value, list):
        return tuple(_freeze_json_arrays(item) for item in value)
    if isinstance(value, dict):
        return {key: _freeze_json_arrays(item) for key, item in value.items()}
    return value


def load_supply_chain_policy(path: Path = DEFAULT_POLICY_PATH) -> SupplyChainPolicy:
    try:
        payload = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_pairs
        )
        return SupplyChainPolicy.model_validate(_freeze_json_arrays(payload), strict=True)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise SupplyChainValidationError(f"invalid W9-004 policy: {error}") from None
