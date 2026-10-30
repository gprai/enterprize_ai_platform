"""W11-002 bounded, in-process dependency-chaos contract; never executes AWS FIS."""

from __future__ import annotations

import hashlib
import json
import time
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any, Final, Literal, Protocol

import yaml  # type: ignore[import-untyped]
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)
from yaml.tokens import AliasToken, AnchorToken  # type: ignore[import-untyped]

from enterprise_ai_platform.telemetry.ai_reliability import (
    AIReliabilityPolicy,
    BurnRateEvidence,
    CollectionStatus,
    DecisionStatus,
    SLIEvidence,
    ThresholdDirection,
    evaluate_burn_rate,
    evaluate_sli,
    load_ai_reliability_policy,
)

CHAOS_SCHEMA_VERSION: Final = "w11-002.controlled-dependency-chaos.v1"
DEFAULT_CHAOS_POLICY_PATH: Final = Path("configs/chaos/controlled-dependency-chaos.yaml")
MAXIMUM_POLICY_BYTES: Final = 131_072
SOURCE_PATHS: Final = {
    "fis_plan_sha256": Path("configs/chaos/fis-plan.yaml"),
    "slo_policy_sha256": Path("configs/observability/slo.yaml"),
    "fis_template_sha256": Path("infra/modules/observability/main.tf"),
    "fis_iam_sha256": Path("infra/bootstrap/modules/platform-iam/main.tf"),
}
STOP_CONDITIONS: Final = (
    "missing_or_stale_telemetry",
    "unsafe_state",
    "target_or_scenario_limit_exceeded",
    "local_deadline_exceeded",
    "cancellation_requested",
    "recovery_or_residue_unverified",
)
SCENARIO_CONTRACT: Final = (
    ("eks_pod_loss", "eks", "pod_loss", "availability", "EnterpriseAIAvailabilityFastBurnW11"),
    (
        "eks_node_loss",
        "eks",
        "node_loss_simulated",
        "availability",
        "EnterpriseAIAvailabilityFastBurnW11",
    ),
    (
        "bedrock_timeout",
        "bedrock",
        "timeout",
        "model_dependency_availability",
        "EnterpriseAIModelDependencyUnavailable",
    ),
    (
        "bedrock_throttle",
        "bedrock",
        "throttle",
        "model_dependency_availability",
        "EnterpriseAIModelDependencyUnavailable",
    ),
    (
        "opensearch_unavailable",
        "opensearch",
        "unavailable",
        "retrieval_dependency_availability",
        "EnterpriseAIRetrievalDependencyUnavailable",
    ),
    (
        "opensearch_stale",
        "opensearch",
        "stale_response",
        "retrieval_dependency_availability",
        "EnterpriseAIRetrievalDependencyUnavailable",
    ),
    (
        "s3_unavailable",
        "s3",
        "unavailable",
        "ingestion_freshness_hours",
        "EnterpriseAISLIBreach",
    ),
    (
        "s3_partial",
        "s3",
        "partial_failure",
        "ingestion_freshness_hours",
        "EnterpriseAISLIBreach",
    ),
    (
        "inference_timeout",
        "inference",
        "timeout",
        "model_dependency_availability",
        "EnterpriseAIModelDependencyUnavailable",
    ),
    (
        "inference_partial",
        "inference",
        "partial_failure",
        "model_dependency_availability",
        "EnterpriseAIModelDependencyUnavailable",
    ),
    (
        "network_timeout",
        "network",
        "timeout",
        "availability",
        "EnterpriseAIAvailabilityFastBurnW11",
    ),
    (
        "telemetry_loss",
        "telemetry",
        "exporter_loss",
        "availability",
        "EnterpriseAISLIEvidenceIndeterminate",
    ),
    (
        "unsafe_state",
        "safety",
        "unsafe_state",
        "safety_violation_rate",
        "EnterpriseAISafetyViolation",
    ),
)


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, validate_default=True)


class SourceIdentities(_StrictModel):
    fis_plan_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    slo_policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    fis_template_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    fis_iam_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("*", mode="before")
    @classmethod
    def normalize_grouped_sha256(cls, value: object) -> object:
        if isinstance(value, str) and len(value) == 71:
            groups = value.split("-")
            if len(groups) == 8 and all(
                len(group) == 8 and all(character in "0123456789abcdef" for character in group)
                for group in groups
            ):
                return "".join(groups)
        return value


class BlastRadius(_StrictModel):
    maximum_scenarios: Literal[1]
    maximum_targets: Literal[1]
    maximum_duration_seconds: Literal[300]
    local_deadline_seconds: Literal[30]
    retry_count: Literal[0]


class ScenarioContract(_StrictModel):
    id: str
    domain: str
    fault: str
    sli_id: str
    expected_alert: str


class ChaosPolicy(_StrictModel):
    schema_version: Literal["w11-002.controlled-dependency-chaos.v1"]
    prompt_id: Literal["W11-002"]
    feature_ids: tuple[str, ...]
    classification: Literal["source-contract-not-live-evidence"]
    environment: Literal["sandbox"]
    region: Literal["ap-southeast-1"]
    execution_mode: Literal["synthetic-in-process-only"]
    live_execution_status: Literal["NOT RUN"]
    source_identities: SourceIdentities
    blast_radius: BlastRadius
    stop_conditions: tuple[str, ...]
    scenarios: tuple[ScenarioContract, ...]

    @model_validator(mode="after")
    def require_exact_inventory(self) -> ChaosPolicy:
        if self.feature_ids != ("FIS-002", "RES-002"):
            raise ValueError("chaos feature ownership differs")
        if self.stop_conditions != STOP_CONDITIONS:
            raise ValueError("chaos stop conditions differ")
        actual = tuple(
            (item.id, item.domain, item.fault, item.sli_id, item.expected_alert)
            for item in self.scenarios
        )
        if actual != SCENARIO_CONTRACT:
            raise ValueError("chaos scenario inventory or order differs")
        return self


class LocalObservation(_StrictModel):
    telemetry_available: bool
    unsafe_state: bool
    synthetic_alert_observed: bool
    sample_count: int = Field(ge=0)
    observed_value: Decimal | None = Field(default=None, ge=0)
    observed_at: datetime

    @model_validator(mode="after")
    def require_utc_and_finite_value(self) -> LocalObservation:
        if self.observed_at.tzinfo is None or self.observed_at.utcoffset() != timedelta(0):
            raise ValueError("observation time must be UTC")
        if self.observed_value is not None and not self.observed_value.is_finite():
            raise ValueError("observation value must be finite")
        return self


class ExerciseResult(_StrictModel):
    schema_version: Literal["w11-002.controlled-dependency-chaos.v1"] = CHAOS_SCHEMA_VERSION
    scenario_id: str
    policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    local_control_status: DecisionStatus
    sli_status: DecisionStatus
    burn_status: DecisionStatus
    synthetic_alert_status: DecisionStatus
    recovery_status: DecisionStatus
    residue_status: DecisionStatus
    live_status: Literal["NOT RUN"] = "NOT RUN"
    stop_reason: str
    error_budget_remaining_ratio: Decimal | None = Field(default=None, ge=0, le=1)
    injected_count: int = Field(ge=0, le=1)
    restored_count: int = Field(ge=0, le=1)


class FaultPort(Protocol):
    injected_count: int
    restored_count: int

    def inject(self, scenario_id: str) -> None: ...

    def restore(self) -> None: ...

    def is_clean(self) -> bool: ...


class ObservationPort(Protocol):
    def sample(self, phase: Literal["before", "after"]) -> LocalObservation: ...


class ClockPort(Protocol):
    def now_utc(self) -> datetime: ...

    def monotonic(self) -> float: ...

    def cancelled(self) -> bool: ...


class SystemClock:
    """Local clock; there is no background task or process signal handler."""

    def now_utc(self) -> datetime:
        return datetime.now(UTC)

    def monotonic(self) -> float:
        return time.monotonic()

    def cancelled(self) -> bool:
        return False


class InMemoryFaultTarget:
    """The sole CLI fault target; it has no network, Kubernetes or AWS client."""

    def __init__(self) -> None:
        self.injected_count = 0
        self.restored_count = 0
        self._active = False

    def inject(self, scenario_id: str) -> None:
        if (
            self._active
            or self.injected_count
            or not any(item[0] == scenario_id for item in SCENARIO_CONTRACT)
        ):
            raise ValueError("synthetic fault target is not available")
        self._active = True
        self.injected_count = 1

    def restore(self) -> None:
        if self._active and self.restored_count == 0:
            self._active = False
            self.restored_count = 1

    def is_clean(self) -> bool:
        return not self._active


class InMemoryObserver:
    def __init__(self, before: LocalObservation, after: LocalObservation) -> None:
        self.before = before
        self.after = after

    def sample(self, phase: Literal["before", "after"]) -> LocalObservation:
        return self.before if phase == "before" else self.after


class _UniqueKeyLoader(yaml.SafeLoader):  # type: ignore[misc]
    pass


def _construct_unique_mapping(
    loader: _UniqueKeyLoader, node: Any, deep: bool = False
) -> dict[object, object]:
    result: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise ValueError("duplicate YAML key")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)


def _read_yaml(path: Path) -> object:
    payload = path.read_bytes()
    if not payload or len(payload) > MAXIMUM_POLICY_BYTES:
        raise ValueError("YAML input is empty or oversized")
    if payload.startswith((b"\xff\xfe", b"\xfe\xff")):
        raise ValueError("YAML input must be UTF-8")
    text = payload.decode("utf-8", errors="strict")
    if any(isinstance(token, (AliasToken, AnchorToken)) for token in yaml.scan(text)):
        raise ValueError("YAML aliases are forbidden")
    loader = _UniqueKeyLoader(text)
    try:
        return loader.get_single_data()
    finally:
        loader.dispose()


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def policy_sha256(policy: ChaosPolicy) -> str:
    canonical = json.dumps(policy.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _current_count(value: int) -> int:
    """Read a mutable adapter count without retaining prior control-flow narrowing."""

    return value


def load_chaos_policy(path: Path, *, repository_root: Path) -> ChaosPolicy:
    """Validate one exact local policy, its upstream bytes and alert inventory."""

    root = repository_root.resolve()
    if path.resolve() != (root / DEFAULT_CHAOS_POLICY_PATH).resolve():
        raise ValueError("chaos policy path differs from the authoritative path")
    try:
        raw = _read_yaml(path)
        policy = ChaosPolicy.model_validate(raw, strict=False)
        identities = policy.source_identities.model_dump()
        for field, relative in SOURCE_PATHS.items():
            if _file_sha256(root / relative) != identities[field]:
                raise ValueError("upstream source identity differs")
        fis = _read_yaml(root / SOURCE_PATHS["fis_plan_sha256"])
        if not isinstance(fis, dict) or (
            fis.get("classification") != "plan-only-not-authorized-for-execution"
            or fis.get("action")
            != {"id": "aws:eks:pod-delete", "maximum_targets": 1, "duration_seconds": 300}
            or fis.get("local_rehearsals", {}).get("execution") != "fake-provider-only"
            or fis.get("live_scenarios", {}).get("execution") != "unauthorized"
        ):
            raise ValueError("upstream FIS boundary differs")
        reliability = load_ai_reliability_policy(root / SOURCE_PATHS["slo_policy_sha256"])
        known_slis = {item.sli_id for item in reliability.slis}
        if any(item.sli_id not in known_slis for item in policy.scenarios):
            raise ValueError("chaos SLI binding differs")
        alerts = _read_yaml(root / "observability/alerts.yml")
        if not isinstance(alerts, dict):
            raise ValueError("alert inventory is invalid")
        names = {
            rule["alert"]
            for group in alerts.get("groups", [])
            for rule in group.get("rules", [])
            if isinstance(rule, dict) and isinstance(rule.get("alert"), str)
        }
        if any(item.expected_alert not in names for item in policy.scenarios):
            raise ValueError("expected alert is absent")
        return policy
    except (OSError, UnicodeError, yaml.YAMLError, ValidationError, TypeError) as error:
        raise ValueError("invalid bounded chaos policy") from error


def _observation_is_unsafe(
    observation: LocalObservation, clock: ClockPort, deadline_seconds: int
) -> str | None:
    if not observation.telemetry_available:
        return "missing_telemetry"
    age = clock.now_utc() - observation.observed_at
    if age < timedelta(0) or age > timedelta(seconds=deadline_seconds):
        return "stale_telemetry"
    if observation.unsafe_state:
        return "unsafe_state"
    return None


def synthetic_observer(
    policy: ChaosPolicy, scenario_id: str, *, observed_at: datetime
) -> InMemoryObserver:
    """Build content-free observations; these are not provider or alert-delivery evidence."""

    scenario = next((item for item in policy.scenarios if item.id == scenario_id), None)
    if scenario is None:
        raise ValueError("unknown chaos scenario")
    reliability = load_ai_reliability_policy(
        Path(__file__).resolve().parents[2] / SOURCE_PATHS["slo_policy_sha256"]
    )
    contract = next(item for item in reliability.slis if item.sli_id == scenario.sli_id)
    measured = (
        max(Decimal(0), contract.threshold - Decimal("0.5"))
        if contract.direction is ThresholdDirection.MINIMUM
        else contract.threshold + Decimal(1)
    )
    before = LocalObservation(
        telemetry_available=True,
        unsafe_state=False,
        synthetic_alert_observed=False,
        sample_count=contract.minimum_samples,
        observed_value=contract.threshold,
        observed_at=observed_at,
    )
    after = LocalObservation(
        telemetry_available=scenario_id != "telemetry_loss",
        unsafe_state=scenario_id == "unsafe_state",
        synthetic_alert_observed=scenario_id != "telemetry_loss",
        sample_count=contract.minimum_samples,
        observed_value=measured,
        observed_at=observed_at,
    )
    return InMemoryObserver(before, after)


def run_local_rehearsal(
    policy: ChaosPolicy,
    scenario_id: str,
    *,
    fault: FaultPort,
    observer: ObservationPort,
    clock: ClockPort,
) -> ExerciseResult:
    """Exercise one fake; stop and restore even when observation fails."""

    scenario = next((item for item in policy.scenarios if item.id == scenario_id), None)
    if scenario is None or not fault.is_clean() or fault.injected_count or fault.restored_count:
        raise ValueError("scenario or local target is not eligible")
    digest = policy_sha256(policy)
    started = clock.monotonic()
    reason = "not_started"
    sli_status = DecisionStatus.NOT_RUN
    burn_status = DecisionStatus.NOT_RUN
    alert_status = DecisionStatus.NOT_RUN
    budget: Decimal | None = None
    detected = False
    recovery_status = DecisionStatus.NOT_RUN
    try:
        before = observer.sample("before")
        reason = (
            _observation_is_unsafe(before, clock, policy.blast_radius.local_deadline_seconds) or ""
        )
        if reason or clock.cancelled():
            reason = reason or "cancellation_requested"
            detected = True
            sli_status = DecisionStatus.INDETERMINATE
        else:
            fault.inject(scenario_id)
            after = observer.sample("after")
            reason = (
                _observation_is_unsafe(after, clock, policy.blast_radius.local_deadline_seconds)
                or ""
            )
            if clock.cancelled():
                reason = "cancellation_requested"
            if clock.monotonic() - started > policy.blast_radius.local_deadline_seconds:
                reason = "local_deadline_exceeded"
            if reason:
                detected = True
                sli_status = (
                    DecisionStatus.FAIL
                    if reason == "unsafe_state"
                    else DecisionStatus.INDETERMINATE
                )
            else:
                reliability: AIReliabilityPolicy = load_ai_reliability_policy(
                    Path(__file__).resolve().parents[2] / SOURCE_PATHS["slo_policy_sha256"]
                )
                contract = next(item for item in reliability.slis if item.sli_id == scenario.sli_id)
                evidence = SLIEvidence(
                    sli_id=scenario.sli_id,
                    collection_status=CollectionStatus.MEASURED,
                    sample_count=after.sample_count,
                    observed_value=after.observed_value,
                    observed_at=after.observed_at,
                    source_identity_sha256=policy.source_identities.slo_policy_sha256,
                )
                evaluation = evaluate_sli(contract, evidence)
                sli_status = evaluation.status
                budget = evaluation.error_budget_remaining_ratio
                alert_status = (
                    DecisionStatus.PASS if after.synthetic_alert_observed else DecisionStatus.FAIL
                )
                if scenario.sli_id == "availability":
                    burn_status = evaluate_burn_rate(
                        reliability,
                        BurnRateEvidence(
                            tier="fast",
                            collection_status=CollectionStatus.MEASURED,
                            short_window_burn_factor=Decimal("14.4"),
                            long_window_burn_factor=Decimal("14.4"),
                            short_window_events=20,
                            observed_at=after.observed_at,
                        ),
                    ).status
                detected = sli_status is DecisionStatus.FAIL and alert_status is DecisionStatus.PASS
                reason = "expected_fault_observed" if detected else "fault_detection_unverified"
    except Exception:
        reason = "local_observation_or_fault_failed"
        sli_status = DecisionStatus.INDETERMINATE
    finally:
        if _current_count(fault.injected_count) or not fault.is_clean():
            try:
                fault.restore()
            except Exception:
                recovery_status = DecisionStatus.FAIL
            else:
                recovery_status = (
                    DecisionStatus.PASS
                    if _current_count(fault.restored_count) == 1 and fault.is_clean()
                    else DecisionStatus.FAIL
                )
    residue_status = DecisionStatus.PASS if fault.is_clean() else DecisionStatus.FAIL
    local_status = (
        DecisionStatus.PASS
        if detected
        and _current_count(fault.injected_count) == 1
        and residue_status is DecisionStatus.PASS
        and recovery_status is DecisionStatus.PASS
        else DecisionStatus.FAIL
    )
    return ExerciseResult(
        scenario_id=scenario_id,
        policy_sha256=digest,
        local_control_status=local_status,
        sli_status=sli_status,
        burn_status=burn_status,
        synthetic_alert_status=alert_status,
        recovery_status=recovery_status,
        residue_status=residue_status,
        stop_reason=reason,
        error_budget_remaining_ratio=budget,
        injected_count=fault.injected_count,
        restored_count=fault.restored_count,
    )
