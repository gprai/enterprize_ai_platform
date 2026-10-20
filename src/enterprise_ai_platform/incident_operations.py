"""Provider-neutral W11-004 incident and game-day evidence contracts."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Final, Literal, Protocol, Self, cast

import yaml  # type: ignore[import-untyped]
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator
from yaml.tokens import AliasToken, AnchorToken  # type: ignore[import-untyped]

POLICY_SCHEMA_VERSION: Final = "w11-004.incident-operations.v1"
EVIDENCE_SCHEMA_VERSION: Final = "w11-004.game-day-evidence.v1"
DEFAULT_INCIDENT_POLICY_PATH: Final = Path("configs/incidents/incident-operations.yaml")
MAXIMUM_POLICY_BYTES: Final = 512 * 1024
SHA256 = re.compile(r"^[0-9a-f]{64}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
REDACTION_PATTERNS: Final = (
    re.compile(r"(?i)(authorization\s*[:=]\s*)([^\s,;]+)"),
    re.compile(r"(?i)((?:api[_-]?key|token|password|secret)\s*[:=]\s*)([^\s,;]+)"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
)


class IncidentContractError(ValueError):
    """Raised when incident policy or evidence cannot be trusted."""


class IncidentStatus(StrEnum):
    PASS = "PASS"  # noqa: S105 - evidence status, never a credential.
    FAIL = "FAIL"
    INDETERMINATE = "INDETERMINATE"
    NOT_RUN = "NOT RUN"


class CommandClassification(StrEnum):
    SUCCEEDED = "SUCCEEDED"
    EXPECTED_ABSENT = "EXPECTED_ABSENT"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"
    CANCELLED = "CANCELLED"
    INDETERMINATE = "INDETERMINATE"


class ScenarioId(StrEnum):
    CAPACITY = "CAPACITY"
    SATURATION = "SATURATION"
    DEPENDENCY_FAILURE = "DEPENDENCY_FAILURE"


class RunnerProfileId(StrEnum):
    WINDOWS_POWERSHELL_5_1 = "windows-powershell-5.1"
    POWERSHELL_7 = "powershell-7"


class RunbookStage(StrEnum):
    DECLARE = "DECLARE"
    DIAGNOSE = "DIAGNOSE"
    CONTAIN = "CONTAIN"
    REMEDIATE = "REMEDIATE"
    ROLLBACK = "ROLLBACK"
    RECOVERY = "RECOVERY"
    NATIVE_VERIFY = "NATIVE_VERIFY"
    CLEANUP = "CLEANUP"
    REVIEW = "REVIEW"


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        validate_default=True,
    )


def _safe_identifier(value: str, field_name: str) -> str:
    if SAFE_IDENTIFIER.fullmatch(value) is None:
        raise ValueError(f"{field_name} is not a safe stable identifier")
    return value


def _utc(value: datetime, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return value.astimezone(UTC)


class SourceBinding(_StrictModel):
    path: str
    sha256: str

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        path = Path(value)
        if path.is_absolute() or ".." in path.parts or "\\" in value:
            raise ValueError("source binding must be a portable repository-relative path")
        return value

    @field_validator("sha256")
    @classmethod
    def validate_sha256(cls, value: str) -> str:
        if SHA256.fullmatch(value) is None:
            raise ValueError("source binding requires lowercase SHA-256")
        return value


class RunnerProfile(_StrictModel):
    profile_id: RunnerProfileId
    wrapper_path: str
    minimum_major_version: int = Field(ge=5)
    maximum_major_version: int | None = Field(default=None, ge=5)

    @model_validator(mode="after")
    def validate_profile(self) -> Self:
        wrapper = Path(self.wrapper_path)
        if wrapper.is_absolute() or ".." in wrapper.parts or wrapper.suffix.casefold() != ".ps1":
            raise ValueError("runner wrapper must be a repository-relative .ps1 path")
        expected = {
            RunnerProfileId.WINDOWS_POWERSHELL_5_1: (5, 5),
            RunnerProfileId.POWERSHELL_7: (7, None),
        }[self.profile_id]
        if (self.minimum_major_version, self.maximum_major_version) != expected:
            raise ValueError("runner version bounds differ from the approved profile")
        return self


class RolePolicy(_StrictModel):
    role_id: str
    responsibilities: tuple[str, ...]

    @model_validator(mode="after")
    def validate_role(self) -> Self:
        _safe_identifier(self.role_id, "role_id")
        if not self.responsibilities or any(not item.strip() for item in self.responsibilities):
            raise ValueError("role responsibilities must be complete")
        return self


class SeverityPolicy(_StrictModel):
    severity_id: Literal["SEV1", "SEV2", "SEV3"]
    acknowledgement_seconds: int = Field(gt=0)
    escalation_seconds: int = Field(gt=0)
    business_impact: str

    @model_validator(mode="after")
    def validate_severity(self) -> Self:
        if (
            self.escalation_seconds < self.acknowledgement_seconds
            or not self.business_impact.strip()
        ):
            raise ValueError("severity timing or impact is invalid")
        return self


class CommunicationPolicy(_StrictModel):
    allowed_channels: tuple[str, ...]
    minimum_update_seconds: int = Field(gt=0)
    personal_destinations_prohibited: Literal[True]


class EscalationPolicy(_StrictModel):
    ordered_role_ids: tuple[str, ...]
    missing_acknowledgement_blocks_progress: Literal[True]


class CommandPolicy(_StrictModel):
    command_id: str
    argv: tuple[str, ...]
    timeout_seconds: int = Field(gt=0)
    read_only: bool
    expected_absence: bool
    native_verification_required: bool

    @model_validator(mode="after")
    def validate_command(self) -> Self:
        _safe_identifier(self.command_id, "command_id")
        if not self.argv or any(not item or "\x00" in item for item in self.argv):
            raise ValueError("command argv must be a non-empty exact array")
        if self.expected_absence and not self.native_verification_required:
            raise ValueError("expected absence requires native verification")
        return self


class RunbookStep(_StrictModel):
    stage: RunbookStage
    owner_role_id: str
    requires_owner_approval: bool


class RunbookPolicy(_StrictModel):
    version: Literal["incident-runbook-v1"]
    identity_material: str
    last_validated_identity: str
    stages: tuple[RunbookStep, ...]

    @model_validator(mode="after")
    def validate_runbook(self) -> Self:
        if (
            DIGEST.fullmatch(self.last_validated_identity) is None
            or self.last_validated_identity != f"sha256:{sha256_text(self.identity_material)}"
        ):
            raise ValueError("runbook identity must be an immutable digest")
        if tuple(item.stage for item in self.stages) != tuple(RunbookStage):
            raise ValueError("runbook stages must be complete and ordered")
        return self


class ScenarioPolicy(_StrictModel):
    scenario_id: ScenarioId
    injected_condition: str
    command_ids: tuple[str, ...]
    required_terminal_action: Literal[RunbookStage.ROLLBACK, RunbookStage.RECOVERY]

    @model_validator(mode="after")
    def validate_scenario(self) -> Self:
        if not self.injected_condition.strip() or not self.command_ids:
            raise ValueError("scenario condition and commands are required")
        if len(self.command_ids) != len(set(self.command_ids)):
            raise ValueError("scenario commands must be unique")
        return self


class ExecutionBounds(_StrictModel):
    maximum_mutation_concurrency: Literal[1]
    mutation_retries: Literal[0]
    read_probe_retries: int = Field(ge=0, le=2)
    command_deadline_seconds: int = Field(gt=0, le=300)
    scenario_deadline_seconds: int = Field(gt=0, le=900)
    progress_interval_seconds: int = Field(gt=0, le=30)
    maximum_output_bytes: Literal[8388608]


class EvidencePolicy(_StrictModel):
    schema_version: Literal["w11-004.game-day-evidence.v1"]
    scope: Literal["LOCAL_FAKE"]
    retention_days: int = Field(gt=0, le=365)
    redact_output: Literal[True]
    preserve_failed_evidence: Literal[True]
    canonical_json: Literal[True]


class CleanupPolicy(_StrictModel):
    retain_evidence: Literal[True]
    require_native_absence: Literal[True]
    require_zero_unexpected_residue: Literal[True]


class CorrectiveActionPolicy(_StrictModel):
    require_owner: Literal[True]
    require_due_date: Literal[True]
    block_pass_when_incomplete: Literal[True]


class IncidentPolicy(_StrictModel):
    schema_version: Literal["w11-004.incident-operations.v1"]
    feature_ids: tuple[str, ...]
    tracker_status: Literal["Blocked"]
    environment: Literal["sandbox"]
    classification: Literal["source-contract-not-live-evidence"]
    tenant_boundary: Literal["NO_TENANT_DATA_LOCAL_FAKE"]
    privacy_boundary: Literal["NO_USER_CONTENT"]
    residency_boundary: Literal["LOCAL_EXTERNAL_EVIDENCE_ROOT"]
    runner_version: Literal["incident-command-runner-v1"]
    runner_profiles: tuple[RunnerProfile, ...]
    roles: tuple[RolePolicy, ...]
    severity_levels: tuple[SeverityPolicy, ...]
    communications: CommunicationPolicy
    escalation: EscalationPolicy
    commands: tuple[CommandPolicy, ...]
    runbook: RunbookPolicy
    scenarios: tuple[ScenarioPolicy, ...]
    execution_bounds: ExecutionBounds
    evidence_policy: EvidencePolicy
    cleanup_policy: CleanupPolicy
    corrective_action_policy: CorrectiveActionPolicy
    source_bindings: tuple[SourceBinding, ...]

    @model_validator(mode="after")
    def validate_contract(self) -> Self:
        if self.feature_ids != ("INC-001", "RUNNER-001"):
            raise ValueError("feature IDs differ from W11-004")
        if tuple(item.profile_id for item in self.runner_profiles) != tuple(RunnerProfileId):
            raise ValueError("runner profiles must be complete and ordered")
        expected_roles = (
            "incident_commander",
            "operations_lead",
            "developer_lead",
            "security_privacy_lead",
            "communications_lead",
            "evidence_custodian",
            "business_owner",
        )
        if tuple(item.role_id for item in self.roles) != expected_roles:
            raise ValueError("incident roles must be complete and ordered")
        role_ids = set(expected_roles)
        if set(self.escalation.ordered_role_ids) - role_ids:
            raise ValueError("escalation references an unknown role")
        if tuple(item.severity_id for item in self.severity_levels) != ("SEV1", "SEV2", "SEV3"):
            raise ValueError("severity levels must be complete and ordered")
        command_ids = tuple(item.command_id for item in self.commands)
        if len(command_ids) != len(set(command_ids)):
            raise ValueError("command IDs must be unique")
        if tuple(item.scenario_id for item in self.scenarios) != tuple(ScenarioId):
            raise ValueError("game-day scenarios must be complete and ordered")
        for scenario in self.scenarios:
            if not set(scenario.command_ids).issubset(command_ids):
                raise ValueError("scenario references an unknown command")
        source_paths = tuple(item.path for item in self.source_bindings)
        if len(source_paths) != len(set(source_paths)):
            raise ValueError("source bindings must be unique")
        return self


class NativeVerification(_StrictModel):
    verifier: str
    expected_identity: str
    observed_identity: str | None
    identity_match: bool
    integrity_ok: bool
    health_ok: bool
    expected_absence: bool
    native_absent: bool
    residue_count: int = Field(ge=0)
    details: str

    @model_validator(mode="after")
    def validate_native_evidence(self) -> Self:
        if SHA256.fullmatch(self.expected_identity) is None or (
            self.observed_identity is not None and SHA256.fullmatch(self.observed_identity) is None
        ):
            raise ValueError("native identities must be lowercase SHA-256")
        if self.identity_match and self.observed_identity != self.expected_identity:
            raise ValueError("native identity match differs from observed evidence")
        return self


class PowerShellNativeRequest(_StrictModel):
    observed_identity: str
    identity_match: bool
    integrity_ok: bool
    health_ok: bool
    native_absent: bool
    residue_count: int = Field(ge=0)

    @field_validator("observed_identity")
    @classmethod
    def validate_observed_identity(cls, value: str) -> str:
        if SHA256.fullmatch(value) is None:
            raise ValueError("observed identity must be lowercase SHA-256")
        return value


class PowerShellRequest(_StrictModel):
    schema_version: Literal["w11-004.powershell-request.v1"]
    command: tuple[str, ...]
    working_directory: str
    timeout_seconds: int = Field(gt=0, le=300)
    progress_interval_seconds: int = Field(gt=0, le=30)
    maximum_output_bytes: int = Field(gt=0, le=8388608)
    expected_absence: bool
    expected_identity: str
    native_verification: PowerShellNativeRequest

    @model_validator(mode="after")
    def validate_request(self) -> Self:
        if not self.command or any(not item or "\x00" in item for item in self.command):
            raise ValueError("PowerShell request command must be an exact non-empty array")
        if (
            not Path(self.command[0]).is_absolute()
            or not Path(self.working_directory).is_absolute()
        ):
            raise ValueError("PowerShell executable and working directory must be absolute")
        if SHA256.fullmatch(self.expected_identity) is None:
            raise ValueError("expected identity must be lowercase SHA-256")
        if self.native_verification.identity_match != (
            self.native_verification.observed_identity == self.expected_identity
        ):
            raise ValueError("native identity-match evidence differs")
        return self


class CommandEvidence(_StrictModel):
    command_id: str
    argv: tuple[str, ...]
    argv_sha256: str
    runner_profile: RunnerProfileId
    executable_identity: str
    executable_sha256: str
    tool_version: str
    started_at: datetime
    completed_at: datetime
    duration_seconds: float = Field(ge=0)
    stdout: str
    stdout_sha256: str
    stderr: str
    stderr_sha256: str
    exit_code: int
    classification: CommandClassification
    progress: tuple[str, ...]
    deadline_seconds: int = Field(gt=0)
    timed_out: bool
    cancelled: bool
    native_verification: NativeVerification

    @model_validator(mode="after")
    def validate_evidence(self) -> Self:
        started = _utc(self.started_at, "started_at")
        completed = _utc(self.completed_at, "completed_at")
        if completed < started:
            raise ValueError("command completion precedes start")
        if not self.argv or canonical_sha256(list(self.argv)) != self.argv_sha256:
            raise ValueError("command argv identity differs")
        if SHA256.fullmatch(self.executable_sha256) is None:
            raise ValueError("executable SHA-256 is invalid")
        if (
            sha256_text(self.stdout) != self.stdout_sha256
            or sha256_text(self.stderr) != self.stderr_sha256
        ):
            raise ValueError("captured output identity differs")
        if self.classification is CommandClassification.SUCCEEDED and self.exit_code != 0:
            raise ValueError("non-zero command cannot be successful")
        if self.classification is CommandClassification.SUCCEEDED and (
            self.timed_out or self.cancelled
        ):
            raise ValueError("timed out or cancelled command cannot be successful")
        if self.classification is CommandClassification.EXPECTED_ABSENT and (
            self.exit_code == 0
            or not self.native_verification.expected_absence
            or not self.native_verification.native_absent
            or not self.native_verification.identity_match
            or self.native_verification.residue_count != 0
        ):
            raise ValueError("expected absence lacks exact native evidence")
        if self.classification is CommandClassification.TIMED_OUT and not self.timed_out:
            raise ValueError("timeout classification requires timeout evidence")
        if self.classification is CommandClassification.CANCELLED and not self.cancelled:
            raise ValueError("cancel classification requires cancellation evidence")
        if len(self.stdout.encode("utf-8")) + len(self.stderr.encode("utf-8")) > 8388608:
            raise ValueError("captured output exceeds the approved bound")
        if redact_output(self.stdout) != self.stdout or redact_output(self.stderr) != self.stderr:
            raise ValueError("captured output contains an unredacted value")
        return self


class CorrectiveAction(_StrictModel):
    action_id: str
    description: str
    owner_role_id: str
    due_at: datetime
    status: Literal["OPEN", "CLOSED"]

    @model_validator(mode="after")
    def validate_action(self) -> Self:
        _safe_identifier(self.action_id, "action_id")
        _safe_identifier(self.owner_role_id, "owner_role_id")
        _utc(self.due_at, "due_at")
        if not self.description.strip():
            raise ValueError("corrective action description is required")
        return self


class GameDayEvidence(_StrictModel):
    schema_version: Literal["w11-004.game-day-evidence.v1"] = EVIDENCE_SCHEMA_VERSION
    scope: Literal["LOCAL_FAKE"] = "LOCAL_FAKE"
    environment: Literal["sandbox"]
    classification: Literal["source-contract-not-live-evidence"]
    tenant_boundary: Literal["NO_TENANT_DATA_LOCAL_FAKE"]
    privacy_boundary: Literal["NO_USER_CONTENT"]
    residency_boundary: Literal["LOCAL_EXTERNAL_EVIDENCE_ROOT"]
    run_id: str
    scenario_id: ScenarioId
    severity_id: Literal["SEV1", "SEV2", "SEV3"]
    runner_profile: RunnerProfileId
    runner_execution: Literal["SIMULATED_PROFILE_SELECTION"]
    policy_sha256: str
    source_identities: tuple[SourceBinding, ...]
    recovered_identities: tuple[SourceBinding, ...]
    approval_references: tuple[str, ...]
    started_at: datetime
    completed_at: datetime
    command_evidence: tuple[CommandEvidence, ...]
    runbook_version: str
    runbook_identity: str
    terminal_action: Literal[RunbookStage.ROLLBACK, RunbookStage.RECOVERY]
    target_rto_seconds: int = Field(gt=0)
    achieved_rto_seconds: float = Field(ge=0)
    target_rpo_seconds: int = Field(gt=0)
    achieved_rpo_seconds: float = Field(ge=0)
    integrity_ok: bool
    health_ok: bool
    cleanup_complete: bool
    unexpected_residue: tuple[str, ...]
    failed_steps: tuple[str, ...]
    skipped_steps: tuple[str, ...]
    residual_risk: tuple[str, ...]
    review_completed: bool
    review_summary: str
    corrective_actions: tuple[CorrectiveAction, ...]
    evidence_retained: bool
    status: IncidentStatus

    @model_validator(mode="after")
    def validate_game_day(self) -> Self:
        _safe_identifier(self.run_id, "run_id")
        started = _utc(self.started_at, "started_at")
        completed = _utc(self.completed_at, "completed_at")
        if completed < started or SHA256.fullmatch(self.policy_sha256) is None:
            raise ValueError("game-day time or policy identity is invalid")
        if (
            not self.approval_references
            or not self.command_evidence
            or not self.review_summary.strip()
        ):
            raise ValueError("approval and command evidence are required")
        for reference in self.approval_references:
            _safe_identifier(reference, "approval_reference")
        if DIGEST.fullmatch(self.runbook_identity) is None:
            raise ValueError("game-day runbook identity is invalid")
        source_paths = tuple(item.path for item in self.source_identities)
        recovered_paths = tuple(item.path for item in self.recovered_identities)
        if (
            not source_paths
            or len(source_paths) != len(set(source_paths))
            or set(source_paths) != set(recovered_paths)
        ):
            raise ValueError("source and recovered identity scopes differ")
        computed = evaluate_game_day_status(self)
        if self.status is not computed:
            raise ValueError(f"game-day status must be {computed.value}")
        return self


class ClockPort(Protocol):
    def now(self) -> datetime: ...


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)


class _UniqueKeyLoader(yaml.SafeLoader):  # type: ignore[misc]
    pass


def _construct_unique_mapping(
    loader: _UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[object, object]:
    result: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise IncidentContractError(f"duplicate YAML key: {key}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)


def _read_yaml(path: Path) -> object:
    raw = path.read_bytes()
    if len(raw) > MAXIMUM_POLICY_BYTES or raw.startswith(b"\xef\xbb\xbf"):
        raise IncidentContractError("incident policy is oversized or contains a BOM")
    text = raw.decode("utf-8", errors="strict")
    if any(isinstance(token, (AliasToken, AnchorToken)) for token in yaml.scan(text)):
        raise IncidentContractError("YAML aliases and anchors are prohibited")
    return yaml.load(text, Loader=_UniqueKeyLoader)  # noqa: S506 - restricted SafeLoader subclass.


def canonical_json_bytes(value: BaseModel | object) -> bytes:
    serializable: object
    if isinstance(value, BaseModel):
        serializable = value.model_dump(mode="json")
    else:
        serializable = value
    return (
        json.dumps(serializable, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
    ).encode("utf-8")


def canonical_sha256(value: BaseModel | object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def redact_output(value: str) -> str:
    redacted = value
    for pattern in REDACTION_PATTERNS:
        if pattern.groups >= 2:
            redacted = pattern.sub(r"\1[REDACTED]", redacted)
        else:
            redacted = pattern.sub("[REDACTED]", redacted)
    return redacted


def load_incident_policy(path: Path, *, repository_root: Path) -> IncidentPolicy:
    root = repository_root.resolve(strict=True)
    resolved = path.resolve(strict=True)
    if not resolved.is_relative_to(root):
        raise IncidentContractError("incident policy must be inside the repository")
    try:
        policy = IncidentPolicy.model_validate(_read_yaml(resolved), strict=False)
        for binding in policy.source_bindings:
            source = (root / binding.path).resolve(strict=True)
            if not source.is_relative_to(root) or file_sha256(source) != binding.sha256:
                raise IncidentContractError(f"source binding differs: {binding.path}")
        return policy
    except (OSError, UnicodeError, yaml.YAMLError, ValidationError, TypeError) as error:
        raise IncidentContractError("incident policy validation failed") from error


def classify_command(
    *,
    exit_code: int,
    stderr: str,
    timed_out: bool,
    cancelled: bool,
    expected_absence: bool,
    expected_identity: str,
    native_verification: NativeVerification,
) -> CommandClassification:
    if timed_out:
        return CommandClassification.TIMED_OUT
    if cancelled:
        return CommandClassification.CANCELLED
    if exit_code == 0:
        if (
            expected_absence
            or not native_verification.identity_match
            or not native_verification.integrity_ok
            or not native_verification.health_ok
            or native_verification.residue_count != 0
        ):
            return CommandClassification.FAILED
        return CommandClassification.SUCCEEDED
    normalized = stderr.casefold().replace(" ", "")
    if (
        expected_absence
        and "notfound" in normalized
        and native_verification.expected_absence
        and native_verification.native_absent
        and native_verification.identity_match
        and native_verification.integrity_ok
        and native_verification.health_ok
        and native_verification.expected_identity == expected_identity
        and native_verification.residue_count == 0
    ):
        return CommandClassification.EXPECTED_ABSENT
    return CommandClassification.FAILED


def evaluate_game_day_status(value: GameDayEvidence) -> IncidentStatus:
    if not value.evidence_retained:
        return IncidentStatus.INDETERMINATE
    classifications = tuple(item.classification for item in value.command_evidence)
    if any(
        item
        in {
            CommandClassification.TIMED_OUT,
            CommandClassification.CANCELLED,
            CommandClassification.INDETERMINATE,
        }
        for item in classifications
    ):
        return IncidentStatus.INDETERMINATE
    if (
        any(item is CommandClassification.FAILED for item in classifications)
        or any(
            not item.native_verification.identity_match
            or not item.native_verification.integrity_ok
            or not item.native_verification.health_ok
            or item.native_verification.residue_count != 0
            for item in value.command_evidence
        )
        or value.failed_steps
        or value.skipped_steps
        or not value.integrity_ok
        or not value.health_ok
        or not value.cleanup_complete
        or value.unexpected_residue
        or value.achieved_rto_seconds > value.target_rto_seconds
        or value.achieved_rpo_seconds > value.target_rpo_seconds
        or not value.review_completed
        or any(action.status != "CLOSED" for action in value.corrective_actions)
    ):
        return IncidentStatus.FAIL
    return IncidentStatus.PASS


def command_evidence(
    command: CommandPolicy,
    *,
    runner_profile: RunnerProfileId,
    source_identity: str,
    started_at: datetime,
    completed_at: datetime,
    exit_code: int = 0,
    stderr: str = "",
    timed_out: bool = False,
    cancelled: bool = False,
) -> CommandEvidence:
    safe_stdout = redact_output(f"offline verification completed for {command.command_id}")
    safe_stderr = redact_output(stderr)
    verification = NativeVerification(
        verifier="offline-native-api-v1",
        expected_identity=source_identity,
        observed_identity=source_identity,
        identity_match=True,
        integrity_ok=True,
        health_ok=True,
        expected_absence=command.expected_absence,
        native_absent=command.expected_absence,
        residue_count=0,
        details="deterministic local fake; no provider or network call",
    )
    classification = classify_command(
        exit_code=exit_code,
        stderr=safe_stderr,
        timed_out=timed_out,
        cancelled=cancelled,
        expected_absence=command.expected_absence,
        expected_identity=source_identity,
        native_verification=verification,
    )
    return CommandEvidence(
        command_id=command.command_id,
        argv=command.argv,
        argv_sha256=canonical_sha256(list(command.argv)),
        runner_profile=runner_profile,
        executable_identity="offline-injected-port",
        executable_sha256=source_identity,
        tool_version="w11-004.offline-injected.v1",
        started_at=started_at,
        completed_at=completed_at,
        duration_seconds=max(0.0, (completed_at - started_at).total_seconds()),
        stdout=safe_stdout,
        stdout_sha256=sha256_text(safe_stdout),
        stderr=safe_stderr,
        stderr_sha256=sha256_text(safe_stderr),
        exit_code=exit_code,
        classification=classification,
        progress=("started deadline_seconds=300", "native verification complete"),
        deadline_seconds=command.timeout_seconds,
        timed_out=timed_out,
        cancelled=cancelled,
        native_verification=verification,
    )


def build_offline_game_day_evidence(
    policy: IncidentPolicy,
    *,
    scenario_id: ScenarioId,
    runner_profile: RunnerProfileId,
    run_id: str,
    approval_reference: str,
    clock: ClockPort | None = None,
) -> GameDayEvidence:
    selected_clock = clock or SystemClock()
    started = selected_clock.now()
    scenario = next(item for item in policy.scenarios if item.scenario_id is scenario_id)
    command_lookup = {item.command_id: item for item in policy.commands}
    source_identity = canonical_sha256(
        [item.model_dump(mode="json") for item in policy.source_bindings]
    )
    commands = tuple(
        command_evidence(
            command_lookup[command_id],
            runner_profile=runner_profile,
            source_identity=source_identity,
            started_at=started,
            completed_at=selected_clock.now(),
        )
        for command_id in scenario.command_ids
    )
    completed = selected_clock.now()
    recovered = tuple(
        SourceBinding(path=item.path, sha256=item.sha256) for item in policy.source_bindings
    )
    evidence_values: dict[str, object] = {
        "environment": policy.environment,
        "classification": policy.classification,
        "tenant_boundary": policy.tenant_boundary,
        "privacy_boundary": policy.privacy_boundary,
        "residency_boundary": policy.residency_boundary,
        "run_id": run_id,
        "scenario_id": scenario_id,
        "severity_id": "SEV2",
        "runner_profile": runner_profile,
        "runner_execution": "SIMULATED_PROFILE_SELECTION",
        "policy_sha256": canonical_sha256(policy),
        "source_identities": policy.source_bindings,
        "recovered_identities": recovered,
        "approval_references": (approval_reference,),
        "started_at": started,
        "completed_at": completed,
        "command_evidence": commands,
        "runbook_version": policy.runbook.version,
        "runbook_identity": policy.runbook.last_validated_identity,
        "terminal_action": scenario.required_terminal_action,
        "target_rto_seconds": 28800,
        "achieved_rto_seconds": max(0.0, (completed - started).total_seconds()),
        "target_rpo_seconds": 86400,
        "achieved_rpo_seconds": 0.0,
        "integrity_ok": True,
        "health_ok": True,
        "cleanup_complete": True,
        "unexpected_residue": (),
        "failed_steps": (),
        "skipped_steps": (),
        "residual_risk": ("local fake does not establish live or production readiness",),
        "review_completed": True,
        "review_summary": "local fake completed; no unresolved corrective action was identified",
        "corrective_actions": (),
        "evidence_retained": True,
        "status": IncidentStatus.PASS,
    }
    return GameDayEvidence.model_validate(evidence_values)


def parse_scenario(value: str) -> ScenarioId:
    try:
        return ScenarioId(value)
    except ValueError as error:
        raise IncidentContractError(f"unknown scenario: {value}") from error


def parse_runner_profile(value: str) -> RunnerProfileId:
    try:
        return RunnerProfileId(value)
    except ValueError as error:
        raise IncidentContractError(f"unknown runner profile: {value}") from error


def evidence_from_json(raw: bytes) -> GameDayEvidence:
    try:
        value = cast(
            Mapping[str, object],
            json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_json_keys),
        )
        return GameDayEvidence.model_validate(value, strict=False)
    except (UnicodeError, json.JSONDecodeError, ValidationError, TypeError) as error:
        raise IncidentContractError("game-day evidence validation failed") from error


def _reject_duplicate_json_keys(pairs: Sequence[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise IncidentContractError(f"duplicate JSON key: {key}")
        result[key] = value
    return result
