"""Strict loader and fixed bounds for the W8-003 workflow policy."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml  # type: ignore[import-untyped]
from pydantic import model_validator

from enterprise_ai_platform.retrieval.models import Classification

from .errors import OrchestrationValidationError
from .models import OrchestrationModel, RetryPolicy, WorkflowKind, WorkflowTimeout
from .serialization import fingerprint

DEFAULT_POLICY_PATH = Path("configs/orchestration/async-workflow-policy.yaml")


class OrchestrationLimits(OrchestrationModel):
    maximum_event_bytes: Literal[65_536] = 65_536
    maximum_state_bytes: Literal[65_536] = 65_536
    maximum_transitions: Literal[32] = 32
    maximum_fanout: Literal[8] = 8
    maximum_active_global: Literal[4] = 4
    maximum_active_per_tenant: Literal[2] = 2
    maximum_pending_per_tenant: Literal[8] = 8


class WorkflowTimeouts(OrchestrationModel):
    asynchronous_inference: WorkflowTimeout
    long_running_ingestion: WorkflowTimeout
    model_training: WorkflowTimeout

    def for_kind(self, kind: WorkflowKind) -> WorkflowTimeout:
        return {
            WorkflowKind.ASYNCHRONOUS_INFERENCE: self.asynchronous_inference,
            WorkflowKind.LONG_RUNNING_INGESTION: self.long_running_ingestion,
            WorkflowKind.MODEL_TRAINING: self.model_training,
        }[kind]


class ApprovalPolicy(OrchestrationModel):
    ttl_seconds: Literal[600] = 600
    sensitive_classifications: tuple[Literal["CONFIDENTIAL"], Literal["RESTRICTED"]] = (
        "CONFIDENTIAL",
        "RESTRICTED",
    )
    always_required_workflows: tuple[Literal["model_training"]] = ("model_training",)
    high_cost_requires_approval: Literal[True] = True


class RetentionPolicy(OrchestrationModel):
    state_and_audit_days: Literal[30] = 30
    dead_letter_days: Literal[7] = 7


class ProviderCircuitPolicy(OrchestrationModel):
    owner: Literal["w8-002-serving"] = "w8-002-serving"
    failure_threshold: Literal[5] = 5
    open_seconds: Literal[30] = 30
    half_open_probes: Literal[1] = 1


class OrchestrationPolicy(OrchestrationModel):
    schema_version: Literal["w8-003.orchestration-policy.v1"]
    feature_ids: tuple[Literal["ORCH-001"], Literal["COST-004"]]
    region: Literal["ap-southeast-1"]
    execution_mode: Literal["offline_contract_only"]
    eventbridge: Literal["compatible_contract_only"]
    step_functions: Literal["compatible_contract_only"]
    limits: OrchestrationLimits
    retry: RetryPolicy
    timeouts: WorkflowTimeouts
    approval: ApprovalPolicy
    retention: RetentionPolicy
    provider_circuit: ProviderCircuitPolicy
    live_cost_ceiling: Literal["OWNER_BINDING_REQUIRED"]
    live_execution: Literal["NOT_AUTHORIZED"]
    provisioning: Literal["NOT_RUN"]

    @model_validator(mode="after")
    def require_exact_contract(self) -> OrchestrationPolicy:
        if self.feature_ids != ("ORCH-001", "COST-004"):
            raise ValueError("feature IDs must remain ordered")
        expected = {
            WorkflowKind.ASYNCHRONOUS_INFERENCE: (120, 300),
            WorkflowKind.LONG_RUNNING_INGESTION: (120, 900),
            WorkflowKind.MODEL_TRAINING: (60, 21_600),
        }
        for kind, values in expected.items():
            timeout = self.timeouts.for_kind(kind)
            if (timeout.task_seconds, timeout.workflow_seconds) != values:
                raise ValueError("workflow timeout differs from the approved boundary")
        if tuple(self.approval.sensitive_classifications) != (
            Classification.CONFIDENTIAL.value,
            Classification.RESTRICTED.value,
        ):
            raise ValueError("sensitive classifications differ from the approved boundary")
        return self

    @property
    def identity_sha256(self) -> str:
        return fingerprint(self)


class _UniqueKeyLoader(yaml.SafeLoader):  # type: ignore[misc]
    pass


def _construct_unique_mapping(loader: Any, node: Any, deep: bool = False) -> dict[object, object]:
    result: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise yaml.constructor.ConstructorError(
                "mapping", node.start_mark, "duplicate key", key_node.start_mark
            )
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def load_workflow_policy(path: Path = DEFAULT_POLICY_PATH) -> OrchestrationPolicy:
    """Load one bounded UTF-8 YAML policy while rejecting aliases and duplicates."""

    try:
        raw = path.read_bytes()
        if not raw or len(raw) > 65_536 or raw.startswith((b"\xff\xfe", b"\xfe\xff")):
            raise OrchestrationValidationError
        text = raw.decode("utf-8", errors="strict")
        if "&" in text or "*" in text:
            raise OrchestrationValidationError
        loader = _UniqueKeyLoader(text)
        try:
            value = loader.get_single_data()
        finally:
            loader.dispose()
        return OrchestrationPolicy.model_validate(value, strict=False)
    except OrchestrationValidationError:
        raise
    except Exception:
        raise OrchestrationValidationError from None
