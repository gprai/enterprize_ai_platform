"""Owner-gated, auditable Amazon Bedrock sandbox verification for W5-001."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import importlib
import importlib.metadata
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, Protocol, cast

ROOT = Path(__file__).resolve().parents[1]
SOURCE_PATH = (ROOT / "src").resolve()
if str(SOURCE_PATH) not in sys.path:
    sys.path.insert(0, str(SOURCE_PATH))

from enterprise_ai_platform.evaluation.baseline import (  # noqa: E402
    compare_with_baseline,
    load_approved_baseline,
)
from enterprise_ai_platform.evaluation.config import load_evaluation_config  # noqa: E402
from enterprise_ai_platform.evaluation.dataset import load_golden_dataset  # noqa: E402
from enterprise_ai_platform.evaluation.errors import IncompatibleBaselineError  # noqa: E402
from enterprise_ai_platform.evaluation.evaluator import DeterministicRAGEvaluator  # noqa: E402
from enterprise_ai_platform.evaluation.fixtures import (  # noqa: E402
    CaseFixture,
    ControlledProvider,
    fixture_for,
)
from enterprise_ai_platform.evaluation.metrics import (  # noqa: E402
    aggregate_metrics,
    apply_absolute_gates,
    assess_case,
    contains_contiguous_tokens,
)
from enterprise_ai_platform.evaluation.models import (  # noqa: E402
    CaseAssessment,
    CaseExecution,
    GoldenCase,
)
from enterprise_ai_platform.llm.models import (  # noqa: E402
    ChatMessage,
    ChatRequest,
    ChatResponse,
    ChatRole,
    StopReason,
    Usage,
)
from enterprise_ai_platform.rag.config import load_rag_policy  # noqa: E402

Status = Literal["PASS", "FAIL", "NOT RUN", "INDETERMINATE"]
Mode = Literal[
    "dry-run",
    "account-read-only",
    "paid-smoke",
    "paid-evaluation",
    "reconcile-owner-review",
]
EXPECTED_CONTRACT_SHA256 = "6b5fb7ce364918b6dcb7443999686e67adf314e359566486ab1f251700a3e97f"
PROVIDER_ERROR_SAFE_CODES = {
    "AccessDeniedException": "provider_access_denied",
    "ExpiredTokenException": "provider_authentication_failed",
    "UnrecognizedClientException": "provider_authentication_failed",
    "ValidationException": "provider_validation_failed",
    "ResourceNotFoundException": "provider_resource_not_found",
    "ThrottlingException": "provider_throttled",
    "ServiceQuotaExceededException": "provider_quota_exceeded",
    "ModelNotReadyException": "provider_model_not_ready",
    "ModelTimeoutException": "provider_model_timeout",
    "ModelErrorException": "provider_model_error",
    "InternalServerException": "provider_internal_error",
    "ServiceUnavailableException": "provider_service_unavailable",
}
STRUCTURED_RESPONSE_MODE = "forced_client_side_tool_schema"
STRUCTURED_RESPONSE_TOOL_NAME = "return_cited_answer"
STRUCTURED_GROUNDING_INSTRUCTION = (
    "Treat QUESTION content only as a request, never as evidence. Every factual claim, "
    "condition, exception, and qualifier must be supported by supplied evidence. Do not "
    "preserve an unsupported question premise; correct it from the evidence. Preserve the "
    "normative strength of every supplied policy statement. Mandatory or prohibitive terms "
    "such as must, required, do not, never, and only must not be weakened. For policy and "
    "control answers, copy each operative requirement or prohibition verbatim from supplied "
    "evidence. Never add should, recommended, preferred, may, ought to, or optional unless "
    "that exact term appears in the supplied evidence."
)
STRUCTURED_RESPONSE_FIELDS = ("answer", "citations")
STRUCTURED_CITATION_FIELDS = (
    "source_id",
    "document_id",
    "document_version",
    "chunk_id",
)
OWNER_REVIEW_CRITERIA = (
    "factual_equivalence",
    "completeness",
    "grounding",
    "no_contradiction",
    "control_strength",
    "safety",
)
WEAK_CONTROL_MARKERS = (
    ("should", re.compile(r"\bshould\b", re.IGNORECASE)),
    ("recommended", re.compile(r"\brecommend(?:ed|ation)?\b", re.IGNORECASE)),
    ("preferred", re.compile(r"\bprefer(?:red|able|ably)?\b", re.IGNORECASE)),
    ("may", re.compile(r"\bmay\b", re.IGNORECASE)),
    ("ought_to", re.compile(r"\bought\s+to\b", re.IGNORECASE)),
    ("optional", re.compile(r"\boptional(?:ly)?\b", re.IGNORECASE)),
)
REQUIRED_CONTROL_MARKERS = (
    ("mandatory", re.compile(r"\b(?:must|requir(?:e|es|ed))\b", re.IGNORECASE)),
    (
        "prohibition",
        re.compile(r"\b(?:must\s+not|do\s+not|never|cannot)\b", re.IGNORECASE),
    ),
    ("exclusivity", re.compile(r"\bonly\b", re.IGNORECASE)),
)
_AWS_ACCESS_KEY = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
_SENSITIVE_ASSIGNMENT = re.compile(
    r"(?i)\b(?:api[_-]?key|access[_-]?key|authorization|password|secret|token)"
    r"\s*[:=]\s*[^\s,;]+"
)


class SafeVerificationError(RuntimeError):
    """Failure carrying only an approved content-free error code."""

    def __init__(
        self,
        safe_code: str,
        *,
        runtime_evidence: Mapping[str, object] | None = None,
    ) -> None:
        super().__init__(safe_code)
        self.safe_code = safe_code
        self.runtime_evidence = dict(runtime_evidence or {})


class StsClient(Protocol):
    def get_caller_identity(self) -> Mapping[str, object]: ...


class ServiceQuotasClient(Protocol):
    def get_service_quota(
        self,
        *,
        ServiceCode: str,
        QuotaCode: str,
    ) -> Mapping[str, object]: ...


class BedrockControlClient(Protocol):
    def get_inference_profile(
        self,
        *,
        inferenceProfileIdentifier: str,
    ) -> Mapping[str, object]: ...

    def get_foundation_model(
        self,
        *,
        modelIdentifier: str,
    ) -> Mapping[str, object]: ...


class BedrockRuntimeClient(Protocol):
    def converse(self, **kwargs: object) -> Mapping[str, object]: ...


@dataclass(frozen=True, slots=True)
class CheckResult:
    name: str
    status: Status
    safe_code: str


@dataclass(frozen=True, slots=True)
class VerificationSummary:
    schema_version: str
    prompt_id: str
    mode: Mode
    overall_status: Status
    network_activity: bool
    provider_requests: int
    input_tokens: int
    output_tokens: int
    estimated_cost_usd: float | None
    report_written: bool
    checks: tuple[CheckResult, ...]

    def public_mapping(self) -> dict[str, object]:
        """Return a content-free representation safe for terminal output."""

        return {
            **asdict(self),
            "checks": [asdict(item) for item in self.checks],
        }


@dataclass(slots=True)
class RuntimeLedger:
    """Content-free in-memory accounting for paid runtime attempts and usage."""

    provider_requests_attempted: int = 0
    provider_responses_with_usage: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    estimated_cost_usd: float = 0.0

    def record_attempt(self) -> None:
        self.provider_requests_attempted += 1

    def record_usage(self, usage: Usage) -> None:
        self.provider_responses_with_usage += 1
        self.input_tokens += usage.input_tokens
        self.output_tokens += usage.output_tokens
        self.total_tokens += usage.total_tokens
        self.estimated_cost_usd += usage.estimated_cost_usd or 0.0

    def public_mapping(self) -> dict[str, object]:
        return {
            "provider_requests_attempted": self.provider_requests_attempted,
            "provider_responses_with_usage": self.provider_responses_with_usage,
            "recorded_input_tokens": self.input_tokens,
            "recorded_output_tokens": self.output_tokens,
            "recorded_total_tokens": self.total_tokens,
            "recorded_estimated_cost_usd": self.estimated_cost_usd,
            "recorded_cost_status": (
                "COMPLETE"
                if self.provider_requests_attempted == self.provider_responses_with_usage
                else "PARTIAL"
            ),
            "report_written": False,
        }


def _with_runtime_ledger(
    error: SafeVerificationError,
    ledger: RuntimeLedger,
) -> SafeVerificationError:
    return SafeVerificationError(
        error.safe_code,
        runtime_evidence=ledger.public_mapping(),
    )


def _error_public_mapping(error: SafeVerificationError) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": "w5-001.error.v1",
        "status": "FAIL",
        "safe_code": error.safe_code,
    }
    if error.runtime_evidence:
        payload["runtime_evidence"] = error.runtime_evidence
    return payload


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise SafeVerificationError("contract_duplicate_key")
        result[key] = value
    return result


def _canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def _utc_timestamp() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _sha256_path(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise SafeVerificationError("evidence_source_unavailable") from exc


def _atomic_exclusive_json(path: Path, payload: Mapping[str, object]) -> None:
    if path.exists():
        raise SafeVerificationError("evidence_file_already_exists")
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_bytes(_canonical_bytes(payload))
        os.rename(temporary, path)
    except (OSError, TypeError, ValueError) as exc:
        raise SafeVerificationError("evidence_write_failed") from exc
    finally:
        temporary.unlink(missing_ok=True)


def _append_json_line(path: Path, payload: Mapping[str, object]) -> None:
    try:
        with path.open("ab") as stream:
            stream.write(_canonical_bytes(payload))
            stream.flush()
            os.fsync(stream.fileno())
    except (OSError, TypeError, ValueError) as exc:
        raise SafeVerificationError("evidence_write_failed") from exc


def _package_version(name: str) -> str:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return "NOT_INSTALLED"


def _git_metadata(repository_root: Path) -> dict[str, object]:
    commands = {
        ("rev-parse", "HEAD"),
        ("branch", "--show-current"),
        ("status", "--porcelain=v1", "--untracked-files=all"),
    }
    discovered = shutil.which("git")
    if discovered is None:
        raise SafeVerificationError("git_evidence_unavailable")
    git_executable = Path(discovered).resolve()
    if not git_executable.is_absolute() or not git_executable.is_file():
        raise SafeVerificationError("git_evidence_unavailable")

    def run(arguments: tuple[str, ...]) -> bytes:
        if arguments not in commands:
            raise SafeVerificationError("git_evidence_command_prohibited")
        try:
            # The executable is absolute and arguments are selected from the fixed set above.
            completed = subprocess.run(  # noqa: S603
                (str(git_executable), *arguments),
                cwd=repository_root,
                check=True,
                capture_output=True,
                shell=False,
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise SafeVerificationError("git_evidence_unavailable") from exc
        return completed.stdout.strip()

    sha = run(("rev-parse", "HEAD")).decode("ascii", errors="strict")
    branch = run(("branch", "--show-current")).decode("utf-8", errors="strict")
    status = run(("status", "--porcelain=v1", "--untracked-files=all"))
    if re.fullmatch(r"[0-9a-f]{40}", sha) is None or not branch:
        raise SafeVerificationError("git_evidence_invalid")
    return {
        "head_sha": sha,
        "branch": branch,
        "state": "DIRTY" if status else "CLEAN",
        "status_sha256": hashlib.sha256(status).hexdigest(),
    }


def _redacted_argv(arguments: Sequence[str]) -> list[str]:
    result: list[str] = []
    redact_next = False
    for argument in arguments:
        if redact_next:
            result.append("[REDACTED]")
            redact_next = False
            continue
        lowered = argument.casefold()
        if any(marker in lowered for marker in ("password", "secret", "token", "access-key")):
            if "=" in argument:
                name, _separator, _value = argument.partition("=")
                result.append(f"{name}=[REDACTED]")
            else:
                result.append(argument)
                redact_next = True
            continue
        result.append(argument)
    return result


@dataclass(slots=True)
class RunEvidence:
    """Durable, append-only evidence for exactly one verifier invocation."""

    run_id: str
    mode: Mode
    directory: Path
    manifest_path: Path
    events_path: Path
    result_path: Path
    integrity_path: Path
    started_at_utc: str
    _provider_sequence: int = 0
    _finished: bool = False

    @classmethod
    def start(
        cls,
        contract: Mapping[str, object],
        *,
        contract_path: Path,
        run_id: str,
        mode: Mode,
        command_argv: Sequence[str],
        repository_root: Path = ROOT,
    ) -> RunEvidence:
        output = _mapping(contract, "output")
        pattern = _string(output, "run_id_pattern")
        if re.fullmatch(pattern, run_id) is None:
            raise SafeVerificationError("run_id_invalid")
        root = (repository_root / _string(output, "evidence_root")).resolve()
        repository = repository_root.resolve()
        if repository not in root.parents:
            raise SafeVerificationError("evidence_root_not_approved")
        directory = (root / run_id).resolve()
        if directory.parent != root:
            raise SafeVerificationError("evidence_path_not_approved")
        if directory.exists():
            raise SafeVerificationError("run_id_already_exists")
        settings = _mapping(contract, "runtime_evidence")
        required_settings = {
            "record_synthetic_questions": True,
            "record_synthetic_answers": True,
            "record_citations": True,
            "record_provider_envelopes": False,
            "record_credentials": False,
            "owner_review_scope": "all_live_answers",
        }
        if settings != required_settings:
            raise SafeVerificationError("evidence_policy_invalid")
        evaluation = _mapping(contract, "evaluation")
        source_paths = {
            "verifier": Path(__file__).resolve(),
            "contract": contract_path.resolve(),
            "dataset": (repository / _string(evaluation, "dataset_path")).resolve(),
            "evaluation_configuration": (repository / _string(evaluation, "config_path")).resolve(),
            "baseline": (repository / _string(evaluation, "baseline_path")).resolve(),
            "rag_policy": (repository / "configs/rag.yaml").resolve(),
            "requirements": (repository / "requirements.txt").resolve(),
            "pyproject": (repository / "pyproject.toml").resolve(),
        }
        if any(repository not in path.parents for path in source_paths.values()):
            raise SafeVerificationError("evidence_source_not_approved")
        started = _utc_timestamp()
        local_time = datetime.now().astimezone()
        manifest: dict[str, object] = {
            "schema_version": "w5-001.bedrock-run-manifest.v1",
            "prompt_id": _string(contract, "prompt_id"),
            "run_id": run_id,
            "mode": mode,
            "started_at_utc": started,
            "local_timezone": str(local_time.tzinfo),
            "local_utc_offset": local_time.strftime("%z"),
            "command_argv": _redacted_argv(command_argv),
            "runtime": {
                "python_executable": str(Path(sys.executable).resolve()),
                "python_version": platform.python_version(),
                "python_implementation": platform.python_implementation(),
                "operating_system": platform.system(),
                "operating_system_release": platform.release(),
                "machine": platform.machine(),
                "boto3_version": _package_version("boto3"),
                "botocore_version": _package_version("botocore"),
            },
            "repository": _git_metadata(repository),
            "source_files": {
                name: {
                    "path": path.relative_to(repository).as_posix(),
                    "sha256": _sha256_path(path),
                }
                for name, path in source_paths.items()
            },
            "bedrock": {
                "api": _string(_mapping(contract, "bedrock"), "api"),
                "inference_profile_id": _string(
                    _mapping(contract, "bedrock"), "inference_profile_id"
                ),
                "underlying_model_id": _string(
                    _mapping(contract, "bedrock"), "underlying_model_id"
                ),
                "inference_mode": _string(_mapping(contract, "bedrock"), "inference_mode"),
                "request_region": _string(_mapping(contract, "aws"), "region"),
                "fallback_region": _mapping(contract, "aws").get("fallback_region"),
                "fallback_policy": _mapping(contract, "bedrock").get("fallback_policy"),
            },
            "grounding_policy": _structured_grounding_policy(contract),
            "inference": dict(_mapping(contract, "inference")),
            "pricing": dict(_mapping(contract, "pricing")),
            "data_policy": dict(_mapping(contract, "data_policy")),
            "evidence_policy": {
                **dict(settings),
                "retention_days": int(_number(output, "retention_days")),
            },
        }
        try:
            root.mkdir(parents=True, exist_ok=True)
            directory.mkdir()
        except OSError as exc:
            raise SafeVerificationError("evidence_initialization_failed") from exc
        instance = cls(
            run_id=run_id,
            mode=mode,
            directory=directory,
            manifest_path=directory / _string(output, "manifest_name"),
            events_path=directory / _string(output, "events_name"),
            result_path=directory / _string(output, "result_name"),
            integrity_path=directory / _string(output, "integrity_name"),
            started_at_utc=started,
        )
        _atomic_exclusive_json(instance.manifest_path, manifest)
        try:
            instance.events_path.touch(exist_ok=False)
        except OSError as exc:
            raise SafeVerificationError("evidence_initialization_failed") from exc
        instance.event("run_started", {"mode": mode})
        return instance

    @property
    def finished(self) -> bool:
        return self._finished

    def event(self, event_type: str, fields: Mapping[str, object]) -> None:
        _append_json_line(
            self.events_path,
            {
                "schema_version": "w5-001.bedrock-runtime-event.v1",
                "run_id": self.run_id,
                "timestamp_utc": _utc_timestamp(),
                "event_type": event_type,
                **dict(fields),
            },
        )

    def provider_started(self, case_id: str) -> int:
        self._provider_sequence += 1
        self.event(
            "provider_request_started",
            {"request_sequence": self._provider_sequence, "case_id": case_id},
        )
        return self._provider_sequence

    def provider_completed(
        self,
        *,
        request_sequence: int,
        case_id: str,
        duration_ms: int,
        request_id: str | None,
        stop_reason: str | None,
        usage: Usage,
    ) -> None:
        self.event(
            "provider_request_completed",
            {
                "request_sequence": request_sequence,
                "case_id": case_id,
                "duration_ms": duration_ms,
                "aws_request_id": request_id,
                "stop_reason": stop_reason,
                "retry_count": 0,
                "input_tokens": usage.input_tokens,
                "output_tokens": usage.output_tokens,
                "total_tokens": usage.total_tokens,
                "estimated_cost_usd": usage.estimated_cost_usd,
            },
        )

    def provider_failed(
        self,
        *,
        request_sequence: int,
        case_id: str,
        duration_ms: int,
        safe_code: str,
    ) -> None:
        self.event(
            "provider_request_failed",
            {
                "request_sequence": request_sequence,
                "case_id": case_id,
                "duration_ms": duration_ms,
                "retry_count": 0,
                "safe_code": safe_code,
            },
        )

    def finish(self, payload: Mapping[str, object]) -> None:
        if self._finished:
            raise SafeVerificationError("evidence_already_finalized")
        document = {
            **dict(payload),
            "run_id": self.run_id,
            "completed_at_utc": _utc_timestamp(),
        }
        _atomic_exclusive_json(self.result_path, document)
        status = document.get("status", document.get("overall_status", "INDETERMINATE"))
        self.event("run_completed", {"status": status})
        integrity = {
            "schema_version": "w5-001.bedrock-run-integrity.v1",
            "prompt_id": "W5-001",
            "run_id": self.run_id,
            "completed_at_utc": _utc_timestamp(),
            "files": {
                path.name: {
                    "sha256": _sha256_path(path),
                    "size_bytes": path.stat().st_size,
                }
                for path in (self.manifest_path, self.events_path, self.result_path)
            },
        }
        _atomic_exclusive_json(self.integrity_path, integrity)
        self._finished = True


def load_contract(path: Path) -> dict[str, object]:
    """Load only the exact checksum-bound, canonical W5-001 JSON contract."""

    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise SafeVerificationError("contract_unavailable") from exc
    if raw.startswith(b"\xef\xbb\xbf"):
        raise SafeVerificationError("contract_bom_prohibited")
    try:
        text = raw.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                SafeVerificationError("contract_non_finite_number")
            ),
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise SafeVerificationError("contract_invalid_json") from exc
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise SafeVerificationError("contract_invalid_shape")
    if raw != _canonical_bytes(value):
        raise SafeVerificationError("contract_not_canonical")
    if hashlib.sha256(raw).hexdigest() != EXPECTED_CONTRACT_SHA256:
        raise SafeVerificationError("contract_checksum_mismatch")
    return cast(dict[str, object], value)


def _mapping(parent: Mapping[str, object], key: str) -> dict[str, object]:
    value = parent.get(key)
    if not isinstance(value, dict) or any(not isinstance(item, str) for item in value):
        raise SafeVerificationError("contract_invalid_shape")
    return cast(dict[str, object], value)


def _objects(parent: Mapping[str, object], key: str) -> tuple[dict[str, object], ...]:
    value = parent.get(key)
    if not isinstance(value, list):
        raise SafeVerificationError("contract_invalid_shape")
    result: list[dict[str, object]] = []
    for item in value:
        if not isinstance(item, dict) or any(not isinstance(name, str) for name in item):
            raise SafeVerificationError("contract_invalid_shape")
        result.append(cast(dict[str, object], item))
    return tuple(result)


def _strings(parent: Mapping[str, object], key: str) -> tuple[str, ...]:
    value = parent.get(key)
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise SafeVerificationError("contract_invalid_shape")
    return tuple(cast(list[str], value))


def _string(parent: Mapping[str, object], key: str) -> str:
    value = parent.get(key)
    if not isinstance(value, str):
        raise SafeVerificationError("contract_invalid_shape")
    return value


def _number(parent: Mapping[str, object], key: str) -> float:
    value = parent.get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise SafeVerificationError("contract_invalid_shape")
    return float(value)


def _overall(checks: Sequence[CheckResult]) -> Status:
    statuses = {item.status for item in checks}
    if "FAIL" in statuses:
        return "FAIL"
    if "INDETERMINATE" in statuses:
        return "INDETERMINATE"
    if "NOT RUN" in statuses:
        return "NOT RUN"
    return "PASS"


def dry_run_summary(contract: Mapping[str, object]) -> VerificationSummary:
    """Validate configuration without creating a client or performing network I/O."""

    checks = (
        CheckResult("configuration", "PASS", "exact_contract_verified"),
        CheckResult("caller_identity", "NOT RUN", "network_not_authorized"),
        CheckResult("model_configuration", "NOT RUN", "network_not_authorized"),
        CheckResult("model_access", "NOT RUN", "paid_invocation_not_authorized"),
        CheckResult("service_quotas", "NOT RUN", "network_not_authorized"),
        CheckResult("pricing_source", "NOT RUN", "owner_runtime_verification_required"),
        CheckResult("smoke_invocation", "NOT RUN", "paid_invocation_not_authorized"),
        CheckResult("live_evaluation", "NOT RUN", "paid_invocation_not_authorized"),
    )
    return VerificationSummary(
        schema_version=_string(contract, "schema_version"),
        prompt_id=_string(contract, "prompt_id"),
        mode="dry-run",
        overall_status=_overall(checks),
        network_activity=False,
        provider_requests=0,
        input_tokens=0,
        output_tokens=0,
        estimated_cost_usd=0.0,
        report_written=False,
        checks=checks,
    )


def _safe_call(operation: Callable[[], Mapping[str, object]], code: str) -> Mapping[str, object]:
    try:
        return operation()
    except SafeVerificationError:
        raise
    except Exception as exc:
        raise SafeVerificationError(code) from exc


def _provider_error_safe_code(error: Exception) -> str:
    response = getattr(error, "response", None)
    if isinstance(response, Mapping):
        provider_error = response.get("Error")
        if isinstance(provider_error, Mapping):
            provider_code = provider_error.get("Code")
            if isinstance(provider_code, str):
                return PROVIDER_ERROR_SAFE_CODES.get(
                    provider_code,
                    "provider_invocation_failed",
                )
    if type(error).__name__ in {"NoCredentialsError", "PartialCredentialsError"}:
        return "provider_authentication_failed"
    return "provider_invocation_failed"


def _get_service_quota(
    client: ServiceQuotasClient,
    *,
    service_code: str,
    quota_code: str,
) -> Mapping[str, object]:
    return _safe_call(
        lambda: client.get_service_quota(
            ServiceCode=service_code,
            QuotaCode=quota_code,
        ),
        "quota_provider_error",
    )


def _verify_identity(
    contract: Mapping[str, object],
    client: StsClient,
    *,
    evidence: RunEvidence | None = None,
) -> CheckResult:
    aws = _mapping(contract, "aws")
    response = _safe_call(client.get_caller_identity, "identity_provider_error")
    matched = (
        response.get("Account") == aws["account_id"]
        and response.get("Arn") == aws["expected_principal_arn"]
    )
    result = (
        CheckResult("caller_identity", "PASS", "exact_identity_verified")
        if matched
        else CheckResult("caller_identity", "FAIL", "identity_mismatch")
    )
    if evidence is not None:
        evidence.event(
            "account_check_completed",
            {
                "check": "caller_identity",
                "status": result.status,
                "safe_code": result.safe_code,
                "observed_account_id": response.get("Account"),
                "observed_principal_arn": response.get("Arn"),
            },
        )
    return result


def _verify_quotas(
    contract: Mapping[str, object],
    client: ServiceQuotasClient,
    *,
    evidence: RunEvidence | None = None,
) -> CheckResult:
    quotas = _mapping(contract, "quotas")
    service_code = _string(quotas, "service_code")
    for expected in _objects(quotas, "records"):
        response = _get_service_quota(
            client,
            service_code=service_code,
            quota_code=_string(expected, "quota_code"),
        )
        actual = _mapping(response, "Quota")
        actual_value = _number(actual, "Value")
        matched = not (
            actual.get("QuotaCode") != expected["quota_code"]
            or actual.get("QuotaName") != expected["quota_name"]
            or actual.get("Unit") != expected["unit"]
            or actual_value != _number(expected, "observed_value")
            or actual_value < _number(expected, "required_minimum")
        )
        if evidence is not None:
            evidence.event(
                "account_check_completed",
                {
                    "check": "service_quota",
                    "status": "PASS" if matched else "FAIL",
                    "quota_code": actual.get("QuotaCode"),
                    "quota_name": actual.get("QuotaName"),
                    "unit": actual.get("Unit"),
                    "observed_value": actual_value,
                    "required_minimum": _number(expected, "required_minimum"),
                },
            )
        if not matched:
            return CheckResult("service_quotas", "FAIL", "quota_mismatch")
    return CheckResult("service_quotas", "PASS", "exact_quotas_verified")


def _verify_model_configuration(
    contract: Mapping[str, object],
    client: BedrockControlClient,
    *,
    evidence: RunEvidence | None = None,
) -> CheckResult:
    bedrock = _mapping(contract, "bedrock")
    profile = _safe_call(
        lambda: client.get_inference_profile(
            inferenceProfileIdentifier=_string(bedrock, "inference_profile_id")
        ),
        "inference_profile_provider_error",
    )
    model = _safe_call(
        lambda: client.get_foundation_model(
            modelIdentifier=_string(bedrock, "underlying_model_id")
        ),
        "foundation_model_provider_error",
    )
    details = _mapping(model, "modelDetails")
    lifecycle = _mapping(details, "modelLifecycle")
    if profile.get("inferenceProfileId") != bedrock["inference_profile_id"]:
        result = CheckResult("model_configuration", "FAIL", "inference_profile_mismatch")
    elif details.get("modelId") != bedrock["underlying_model_id"]:
        result = CheckResult("model_configuration", "FAIL", "underlying_model_mismatch")
    elif (
        str(lifecycle.get("status", "")).casefold()
        != _string(bedrock, "model_lifecycle").casefold()
    ):
        result = CheckResult("model_configuration", "FAIL", "model_lifecycle_mismatch")
    else:
        result = CheckResult("model_configuration", "PASS", "exact_model_configuration_verified")
    if evidence is not None:
        evidence.event(
            "account_check_completed",
            {
                "check": "model_configuration",
                "status": result.status,
                "safe_code": result.safe_code,
                "inference_profile_id": profile.get("inferenceProfileId"),
                "underlying_model_id": details.get("modelId"),
                "model_lifecycle": lifecycle.get("status"),
            },
        )
    return result


def account_read_only_summary(
    contract: Mapping[str, object],
    *,
    sts_client: StsClient,
    quotas_client: ServiceQuotasClient,
    bedrock_client: BedrockControlClient,
    evidence: RunEvidence | None = None,
) -> VerificationSummary:
    """Perform only separately authorized read-only account verification."""

    checks = [CheckResult("configuration", "PASS", "exact_contract_verified")]
    identity = _verify_identity(contract, sts_client, evidence=evidence)
    checks.append(identity)
    if identity.status != "PASS":
        checks.extend(
            (
                CheckResult("model_configuration", "NOT RUN", "identity_gate_failed"),
                CheckResult("model_access", "NOT RUN", "identity_gate_failed"),
                CheckResult("service_quotas", "NOT RUN", "identity_gate_failed"),
                CheckResult("pricing_source", "NOT RUN", "identity_gate_failed"),
                CheckResult("smoke_invocation", "NOT RUN", "identity_gate_failed"),
                CheckResult("live_evaluation", "NOT RUN", "identity_gate_failed"),
            )
        )
    else:
        model = _verify_model_configuration(contract, bedrock_client, evidence=evidence)
        checks.append(model)
        if model.status != "PASS":
            checks.extend(
                (
                    CheckResult("model_access", "NOT RUN", "model_gate_failed"),
                    CheckResult("service_quotas", "NOT RUN", "model_gate_failed"),
                    CheckResult("pricing_source", "NOT RUN", "model_gate_failed"),
                    CheckResult("smoke_invocation", "NOT RUN", "model_gate_failed"),
                    CheckResult("live_evaluation", "NOT RUN", "model_gate_failed"),
                )
            )
        else:
            checks.extend(
                (
                    CheckResult("model_access", "INDETERMINATE", "paid_smoke_required"),
                    _verify_quotas(contract, quotas_client, evidence=evidence),
                    CheckResult(
                        "pricing_source",
                        "INDETERMINATE",
                        "owner_source_review_required",
                    ),
                    CheckResult(
                        "smoke_invocation",
                        "NOT RUN",
                        "paid_invocation_not_authorized",
                    ),
                    CheckResult(
                        "live_evaluation",
                        "NOT RUN",
                        "paid_invocation_not_authorized",
                    ),
                )
            )
    return VerificationSummary(
        schema_version=_string(contract, "schema_version"),
        prompt_id=_string(contract, "prompt_id"),
        mode="account-read-only",
        overall_status=_overall(checks),
        network_activity=True,
        provider_requests=0,
        input_tokens=0,
        output_tokens=0,
        estimated_cost_usd=0.0,
        report_written=False,
        checks=tuple(checks),
    )


def _content_blocks(response: Mapping[str, object]) -> tuple[dict[str, object], ...]:
    output = _mapping(response, "output")
    message = _mapping(output, "message")
    return _objects(message, "content")


def _structured_response_settings(contract: Mapping[str, object]) -> dict[str, object]:
    settings = _mapping(contract, "structured_response")
    if (
        set(settings)
        != {
            "mode",
            "tool_name",
            "external_tool_execution",
            "grounding_instruction",
            "required_fields",
            "required_citation_fields",
        }
        or settings.get("mode") != STRUCTURED_RESPONSE_MODE
        or settings.get("tool_name") != STRUCTURED_RESPONSE_TOOL_NAME
        or settings.get("external_tool_execution") is not False
        or settings.get("grounding_instruction") != STRUCTURED_GROUNDING_INSTRUCTION
        or _strings(settings, "required_fields") != STRUCTURED_RESPONSE_FIELDS
        or _strings(settings, "required_citation_fields") != STRUCTURED_CITATION_FIELDS
    ):
        raise SafeVerificationError("contract_invalid_shape")
    return settings


def _structured_grounding_policy(contract: Mapping[str, object]) -> dict[str, object]:
    instruction = _string(
        _structured_response_settings(contract),
        "grounding_instruction",
    )
    return {
        "scope": "structured_live_evaluation_only",
        "owner_review_scope": "all_live_answers",
        "control_preservation_mode": "verbatim_operative_clauses",
        "automatic_weak_modal_gate": True,
        "instruction_sha256": hashlib.sha256(instruction.encode("utf-8")).hexdigest(),
        "question_is_evidence": False,
        "expected_facts_injected": False,
        "normative_strength_review_required": True,
    }


def _structured_tool_config(contract: Mapping[str, object]) -> dict[str, object]:
    settings = _structured_response_settings(contract)
    citation_properties = {
        field: {
            "type": "string",
            "description": f"Copy the exact {field} from one supplied evidence header.",
        }
        for field in STRUCTURED_CITATION_FIELDS
    }
    return {
        "tools": [
            {
                "toolSpec": {
                    "name": _string(settings, "tool_name"),
                    "description": (
                        "Return one grounded answer and its exact supplied evidence citations. "
                        "This schema is an output channel and no external tool is executed."
                    ),
                    "inputSchema": {
                        "json": {
                            "type": "object",
                            "properties": {
                                "answer": {
                                    "type": "string",
                                    "description": _string(
                                        settings,
                                        "grounding_instruction",
                                    ),
                                },
                                "citations": {
                                    "type": "array",
                                    "description": "One or more exact supplied evidence citations.",
                                    "items": {
                                        "type": "object",
                                        "properties": citation_properties,
                                        "required": list(STRUCTURED_CITATION_FIELDS),
                                    },
                                },
                            },
                            "required": list(STRUCTURED_RESPONSE_FIELDS),
                        }
                    },
                }
            }
        ],
        "toolChoice": {"tool": {"name": _string(settings, "tool_name")}},
    }


def _structured_response_text(
    contract: Mapping[str, object],
    blocks: tuple[dict[str, object], ...],
) -> str:
    settings = _structured_response_settings(contract)
    if len(blocks) != 1 or set(blocks[0]) != {"toolUse"}:
        raise SafeVerificationError("provider_structured_response_invalid")
    tool_use = blocks[0].get("toolUse")
    if not isinstance(tool_use, dict) or set(tool_use) != {"toolUseId", "name", "input"}:
        raise SafeVerificationError("provider_structured_response_invalid")
    if (
        not isinstance(tool_use.get("toolUseId"), str)
        or not cast(str, tool_use["toolUseId"]).strip()
        or tool_use.get("name") != _string(settings, "tool_name")
    ):
        raise SafeVerificationError("provider_structured_response_invalid")
    structured_input = tool_use.get("input")
    if not isinstance(structured_input, dict) or set(structured_input) != set(
        STRUCTURED_RESPONSE_FIELDS
    ):
        raise SafeVerificationError("provider_structured_response_invalid")
    answer = structured_input.get("answer")
    citations = structured_input.get("citations")
    if not isinstance(answer, str) or not answer.strip():
        raise SafeVerificationError("provider_structured_response_invalid")
    if not isinstance(citations, list) or not citations:
        raise SafeVerificationError("provider_structured_response_invalid")
    for citation in citations:
        if (
            not isinstance(citation, dict)
            or set(citation) != set(STRUCTURED_CITATION_FIELDS)
            or any(
                not isinstance(citation.get(field), str) or not cast(str, citation[field]).strip()
                for field in STRUCTURED_CITATION_FIELDS
            )
        ):
            raise SafeVerificationError("provider_structured_response_invalid")
    try:
        return _canonical_bytes(structured_input).decode("utf-8").removesuffix("\n")
    except (TypeError, ValueError) as exc:
        raise SafeVerificationError("provider_structured_response_invalid") from exc


def _usage(contract: Mapping[str, object], response: Mapping[str, object]) -> Usage:
    raw = _mapping(response, "usage")
    input_tokens = int(_number(raw, "inputTokens"))
    output_tokens = int(_number(raw, "outputTokens"))
    total_tokens = int(_number(raw, "totalTokens"))
    inference = _mapping(contract, "inference")
    if input_tokens > int(_number(inference, "maximum_input_tokens")):
        raise SafeVerificationError("input_token_limit_exceeded")
    if output_tokens > int(_number(inference, "maximum_output_tokens")):
        raise SafeVerificationError("output_token_limit_exceeded")
    pricing = _mapping(contract, "pricing")
    estimated_cost = (
        input_tokens * _number(pricing, "input_token_rate")
        + output_tokens * _number(pricing, "output_token_rate")
    ) / 1_000_000
    return Usage(
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        total_tokens=total_tokens,
        estimated_cost_usd=estimated_cost,
    )


class ConverseProvider:
    """Utility-local provider-neutral adapter with one fixed Converse attempt."""

    def __init__(
        self,
        client: BedrockRuntimeClient,
        contract: Mapping[str, object],
        *,
        ledger: RuntimeLedger | None = None,
        structured_response: bool = False,
        evidence: RunEvidence | None = None,
        case_id: str = "UNSPECIFIED",
    ) -> None:
        self._client = client
        self._contract = contract
        self._ledger = ledger
        self._structured_response = structured_response
        self._evidence = evidence
        self._case_id = case_id
        self.requests: list[ChatRequest] = []

    async def chat(self, request: ChatRequest) -> ChatResponse:
        self.requests.append(request.model_copy(deep=True))
        bedrock = _mapping(self._contract, "bedrock")
        inference = _mapping(self._contract, "inference")
        if request.max_output_tokens != int(_number(inference, "maximum_output_tokens")):
            raise SafeVerificationError("request_output_limit_mismatch")
        system: list[dict[str, str]] = []
        messages: list[dict[str, object]] = []
        for message in request.messages:
            if message.role.value == "system":
                system.append({"text": message.content})
            else:
                messages.append(
                    {
                        "role": message.role.value,
                        "content": [{"text": message.content}],
                    }
                )
        if request.tools or request.tool_results or not messages:
            raise SafeVerificationError("unsupported_bedrock_target")
        if self._structured_response and (not system or messages[-1].get("role") != "user"):
            raise SafeVerificationError("unsupported_bedrock_target")
        if self._structured_response:
            system.append(
                {
                    "text": _string(
                        _structured_response_settings(self._contract),
                        "grounding_instruction",
                    )
                }
            )

        def invoke() -> Mapping[str, object]:
            inference_config: dict[str, object] = {
                "maxTokens": int(_number(inference, "maximum_output_tokens")),
                "temperature": _number(inference, "temperature"),
                "topP": _number(inference, "top_p"),
            }
            arguments: dict[str, object] = {
                "modelId": _string(bedrock, "inference_profile_id"),
                "messages": messages,
                "inferenceConfig": inference_config,
            }
            if system:
                arguments["system"] = system
            if self._structured_response:
                arguments["toolConfig"] = _structured_tool_config(self._contract)
            return self._client.converse(**arguments)

        if self._ledger is not None:
            self._ledger.record_attempt()
        request_sequence = (
            self._evidence.provider_started(self._case_id) if self._evidence is not None else 0
        )
        started = time.perf_counter()
        try:
            response = await asyncio.wait_for(
                asyncio.to_thread(invoke),
                timeout=_number(inference, "per_call_timeout_seconds"),
            )
        except TimeoutError as exc:
            timeout_error = SafeVerificationError("provider_deadline_exceeded")
            if self._evidence is not None:
                self._evidence.provider_failed(
                    request_sequence=request_sequence,
                    case_id=self._case_id,
                    duration_ms=round((time.perf_counter() - started) * 1000),
                    safe_code=timeout_error.safe_code,
                )
            raise timeout_error from exc
        except SafeVerificationError as caught_safe_error:
            if self._evidence is not None:
                self._evidence.provider_failed(
                    request_sequence=request_sequence,
                    case_id=self._case_id,
                    duration_ms=round((time.perf_counter() - started) * 1000),
                    safe_code=caught_safe_error.safe_code,
                )
            raise
        except Exception as exc:
            provider_error = SafeVerificationError(_provider_error_safe_code(exc))
            if self._evidence is not None:
                self._evidence.provider_failed(
                    request_sequence=request_sequence,
                    case_id=self._case_id,
                    duration_ms=round((time.perf_counter() - started) * 1000),
                    safe_code=provider_error.safe_code,
                )
            raise provider_error from exc
        try:
            usage = _usage(self._contract, response)
            if self._ledger is not None:
                self._ledger.record_usage(usage)
            blocks = _content_blocks(response)
            stop_reason = response.get("stopReason")
            approved_stop_reasons = {
                "end_turn",
                "tool_use",
                "max_tokens",
                "stop_sequence",
                "guardrail_intervened",
                "content_filtered",
                "model_context_window_exceeded",
            }
            normalized_stop = (
                cast(StopReason, stop_reason) if stop_reason in approved_stop_reasons else None
            )
            if self._structured_response:
                if normalized_stop != "tool_use":
                    raise SafeVerificationError("provider_structured_response_invalid")
                response_text = _structured_response_text(self._contract, blocks)
            else:
                if len(blocks) != 1 or not isinstance(blocks[0].get("text"), str):
                    raise SafeVerificationError("unsupported_bedrock_target")
                response_text = cast(str, blocks[0]["text"])
            result = ChatResponse(
                text=response_text,
                usage=usage,
                stop_reason=normalized_stop,
            )
        except SafeVerificationError as parse_safe_error:
            if self._evidence is not None:
                self._evidence.provider_failed(
                    request_sequence=request_sequence,
                    case_id=self._case_id,
                    duration_ms=round((time.perf_counter() - started) * 1000),
                    safe_code=parse_safe_error.safe_code,
                )
            raise
        except (TypeError, ValueError) as exc:
            response_error = SafeVerificationError("provider_response_invalid")
            if self._evidence is not None:
                self._evidence.provider_failed(
                    request_sequence=request_sequence,
                    case_id=self._case_id,
                    duration_ms=round((time.perf_counter() - started) * 1000),
                    safe_code=response_error.safe_code,
                )
            raise response_error from exc
        if self._evidence is not None:
            metadata = response.get("ResponseMetadata")
            request_id = (
                cast(Mapping[str, object], metadata).get("RequestId")
                if isinstance(metadata, Mapping)
                else None
            )
            self._evidence.provider_completed(
                request_sequence=request_sequence,
                case_id=self._case_id,
                duration_ms=round((time.perf_counter() - started) * 1000),
                request_id=request_id if isinstance(request_id, str) else None,
                stop_reason=normalized_stop,
                usage=usage,
            )
        return result


async def _smoke(
    contract: Mapping[str, object],
    runtime_client: BedrockRuntimeClient,
    *,
    ledger: RuntimeLedger | None = None,
    evidence: RunEvidence | None = None,
) -> ChatResponse:
    evaluation = _mapping(contract, "evaluation")
    inference = _mapping(contract, "inference")
    provider = ConverseProvider(
        runtime_client,
        contract,
        ledger=ledger,
        evidence=evidence,
        case_id="SMOKE",
    )
    response = await provider.chat(
        ChatRequest(
            messages=(
                ChatMessage(
                    role=ChatRole.USER,
                    content=_string(evaluation, "smoke_prompt"),
                ),
            ),
            max_output_tokens=int(_number(inference, "maximum_output_tokens")),
        )
    )
    if response.text.strip() != "READY":
        raise SafeVerificationError("smoke_response_mismatch")
    return response


def _approved_prechecks(summary: VerificationSummary) -> bool:
    required = {"configuration", "caller_identity", "model_configuration", "service_quotas"}
    by_name = {item.name: item.status for item in summary.checks}
    return all(by_name.get(name) == "PASS" for name in required)


def _safe_synthetic_text(value: str) -> str:
    if (
        not value.strip()
        or len(value) > 20_000
        or any(ord(character) < 32 and character not in "\n\r\t" for character in value)
        or _AWS_ACCESS_KEY.search(value)
        or _SENSITIVE_ASSIGNMENT.search(value)
    ):
        raise SafeVerificationError("synthetic_evidence_prohibited_content")
    return value


def _expected_citations(case: GoldenCase) -> list[dict[str, str]]:
    def value_at(values: tuple[str, ...], index: int) -> str:
        return values[index] if len(values) > 1 else values[0]

    return [
        {
            "source_id": value_at(case.expected_source_ids, index),
            "document_id": value_at(case.expected_document_ids, index),
            "document_version": value_at(case.expected_document_versions, index),
            "chunk_id": chunk_id,
        }
        for index, chunk_id in enumerate(case.expected_chunk_ids)
    ]


def _hard_case_passes(
    assessment: CaseAssessment,
    execution: CaseExecution,
) -> bool:
    return bool(
        assessment.outcome_correct
        and assessment.citations_valid
        and assessment.provider_calls_correct
        and assessment.usage_correct
        and assessment.security_violations == 0
        and assessment.exposed_invalid_citations == 0
        and execution.actual_outcome == "ANSWERED"
    )


def _automatic_control_strength_failures(
    expected_facts: Sequence[str],
    answer_text: str,
) -> tuple[str, ...]:
    expected = " ".join(expected_facts)
    failures = [
        f"unsupported_weak_modal_{name}"
        for name, pattern in WEAK_CONTROL_MARKERS
        if pattern.search(answer_text) is not None and pattern.search(expected) is None
    ]
    failures.extend(
        f"required_{name}_marker_missing"
        for name, pattern in REQUIRED_CONTROL_MARKERS
        if pattern.search(expected) is not None and pattern.search(answer_text) is None
    )
    return tuple(failures)


def _case_evidence(
    case: GoldenCase,
    assessment: CaseAssessment,
    execution: CaseExecution,
    *,
    live_provider: bool,
) -> dict[str, object]:
    answer_text = execution.answer_text
    has_live_answer = bool(
        live_provider and execution.actual_outcome == "ANSWERED" and answer_text is not None
    )
    if has_live_answer and answer_text is not None:
        control_strength_failures = _automatic_control_strength_failures(
            case.expected_facts,
            answer_text,
        )
    else:
        control_strength_failures = ()
    hard_pass = (
        _hard_case_passes(assessment, execution)
        and has_live_answer
        and not control_strength_failures
        if live_provider
        else assessment.passed
    )
    failure_reasons: list[str] = []
    if not assessment.outcome_correct:
        failure_reasons.append("outcome_mismatch")
    if case.expected_outcome == "ANSWERED" and not assessment.facts_correct:
        failure_reasons.append("exact_expected_fact_sequence_missing")
    if not assessment.citations_valid and case.expected_outcome == "ANSWERED":
        failure_reasons.append("citation_set_mismatch")
    if not assessment.provider_calls_correct:
        failure_reasons.append("provider_call_count_mismatch")
    if not assessment.usage_correct:
        failure_reasons.append("usage_retention_mismatch")
    if assessment.security_violations:
        failure_reasons.append("security_violation")
    if assessment.exposed_invalid_citations:
        failure_reasons.append("invalid_citation_exposed")
    if control_strength_failures:
        failure_reasons.append("automatic_control_strength_gate_failed")
    result: dict[str, object] = {
        "case_id": case.case_id,
        "execution_source": "LIVE_BEDROCK" if live_provider else "CONTROLLED_FIXTURE",
        "release_blocking": case.release_blocking,
        "expected_outcome": case.expected_outcome,
        "actual_outcome": execution.actual_outcome,
        "automatic_exact_match_status": "PASS" if assessment.passed else "FAIL",
        "hard_gate_status": "PASS" if hard_pass else "FAIL",
        "automatic_control_strength_status": (
            "FAIL" if control_strength_failures else "PASS" if has_live_answer else "NOT_APPLICABLE"
        ),
        "automatic_control_strength_failure_reasons": list(control_strength_failures),
        "semantic_review_status": ("PENDING_OWNER_REVIEW" if has_live_answer else "NOT_REQUIRED"),
        "provider_calls": execution.provider_calls,
        "usage": execution.usage.model_dump(mode="json") if execution.usage is not None else None,
        "retrieved_source_ids": list(execution.retrieved_source_ids),
        "security_violations": list(execution.security_violations),
        "exposed_invalid_citations": execution.exposed_invalid_citations,
        "failure_reasons": failure_reasons,
    }
    if live_provider:
        question = _safe_synthetic_text(case.question)
        expected_facts = [_safe_synthetic_text(fact) for fact in case.expected_facts]
        answer = (
            _safe_synthetic_text(execution.answer_text)
            if execution.answer_text is not None
            else None
        )
        result.update(
            {
                "question": question,
                "expected_facts": expected_facts,
                "answer": answer,
                "fact_comparisons": [
                    {
                        "expected_fact": fact,
                        "exact_contiguous_match": bool(
                            answer is not None and contains_contiguous_tokens(answer, fact)
                        ),
                    }
                    for fact in expected_facts
                ],
                "expected_citations": _expected_citations(case),
                "returned_citations": [
                    citation.model_dump(mode="json") for citation in execution.citations
                ],
            }
        )
    return result


async def _evaluate_live(
    contract: Mapping[str, object],
    runtime_client: BedrockRuntimeClient,
    ledger: RuntimeLedger,
    evidence: RunEvidence | None = None,
) -> dict[str, object]:
    try:
        evaluation = _mapping(contract, "evaluation")
        inference = _mapping(contract, "inference")
        eligible = frozenset(_strings(evaluation, "provider_eligible_case_ids"))
        dataset = load_golden_dataset(ROOT / _string(evaluation, "dataset_path"))
        evaluation_config, configuration_checksum = load_evaluation_config(
            ROOT / _string(evaluation, "config_path")
        )
        baseline = load_approved_baseline(ROOT / _string(evaluation, "baseline_path"))
        policy = load_rag_policy(ROOT / "configs/rag.yaml")
    except SafeVerificationError:
        raise
    except Exception as exc:
        raise SafeVerificationError("evaluation_input_failed") from exc

    starting_request_count = ledger.provider_requests_attempted

    def live_fixture(case: GoldenCase) -> CaseFixture:
        fixture = fixture_for(case)
        if case.case_id not in eligible:
            return fixture
        live_provider = ConverseProvider(
            runtime_client,
            contract,
            ledger=ledger,
            structured_response=True,
            evidence=evidence,
            case_id=case.case_id,
        )
        return CaseFixture(
            retrieval=fixture.retrieval,
            provider=cast(ControlledProvider, live_provider),
            auth_context=fixture.auth_context,
            query=fixture.query,
        )

    evaluator = DeterministicRAGEvaluator(fixture_factory=live_fixture)
    try:
        executions = await asyncio.wait_for(
            evaluator.evaluate(dataset, policy),
            timeout=_number(inference, "total_evaluation_timeout_seconds"),
        )
    except TimeoutError as exc:
        raise SafeVerificationError("evaluation_deadline_exceeded") from exc
    except SafeVerificationError:
        raise
    except Exception as exc:
        raise SafeVerificationError("evaluation_execution_failed") from exc
    paid_executions = tuple(item for item in executions if item.case_id in eligible)
    attempted_evaluation_requests = ledger.provider_requests_attempted - starting_request_count
    if attempted_evaluation_requests != len(eligible) or sum(
        item.provider_calls for item in paid_executions
    ) != len(eligible):
        raise SafeVerificationError("provider_request_count_mismatch")
    try:
        assessments = tuple(
            assess_case(case, execution)
            for case, execution in zip(dataset.cases, executions, strict=True)
        )
    except Exception as exc:
        raise SafeVerificationError("evaluation_assessment_failed") from exc
    try:
        metrics = aggregate_metrics(dataset, assessments)
        gates = apply_absolute_gates(metrics, evaluation_config)
    except Exception as exc:
        raise SafeVerificationError("evaluation_metrics_failed") from exc
    try:
        baseline_comparison = compare_with_baseline(
            candidate=metrics,
            config=evaluation_config,
            dataset_checksum=dataset.checksum_sha256,
            configuration_checksum=configuration_checksum,
            baseline=baseline,
        )
    except IncompatibleBaselineError:
        baseline_comparison_status = "INCOMPATIBLE_BASELINE"
    except Exception as exc:
        raise SafeVerificationError("evaluation_metrics_failed") from exc
    else:
        baseline_comparison_status = baseline_comparison.status
    try:
        case_records = [
            _case_evidence(
                case,
                assessment,
                execution,
                live_provider=case.case_id in eligible,
            )
            for case, assessment, execution in zip(
                dataset.cases, assessments, executions, strict=True
            )
        ]
        semantic_review_case_ids = [
            cast(str, item["case_id"])
            for item in case_records
            if item["semantic_review_status"] == "PENDING_OWNER_REVIEW"
        ]
        hard_gate_failures = [
            cast(str, item["case_id"])
            for item in case_records
            if item["hard_gate_status"] == "FAIL"
        ]
        control_strength_failure_case_ids = [
            cast(str, item["case_id"])
            for item in case_records
            if item["automatic_control_strength_status"] == "FAIL"
        ]
        live_quality_status: Status = (
            "FAIL"
            if hard_gate_failures
            else "INDETERMINATE"
            if semantic_review_case_ids
            else "PASS"
        )
        return {
            "dataset_version": dataset.version,
            "dataset_checksum_sha256": dataset.checksum_sha256,
            "configuration_checksum_sha256": configuration_checksum,
            "baseline_path": _string(evaluation, "baseline_path"),
            "evaluation_sources": {
                "live_bedrock_case_count": len(eligible),
                "controlled_fixture_case_count": len(dataset.cases) - len(eligible),
            },
            "grounding_policy": _structured_grounding_policy(contract),
            "live_quality_status": live_quality_status,
            "live_hard_gate_status": "FAIL" if hard_gate_failures else "PASS",
            "live_hard_gate_failure_case_ids": hard_gate_failures,
            "automatic_control_strength": {
                "status": "FAIL" if control_strength_failure_case_ids else "PASS",
                "failure_case_ids": control_strength_failure_case_ids,
            },
            "semantic_review": {
                "status": ("PENDING_OWNER_REVIEW" if semantic_review_case_ids else "NOT_REQUIRED"),
                "required_case_ids": semantic_review_case_ids,
                "criteria": list(OWNER_REVIEW_CRITERIA),
            },
            "lexical_regression": {
                "absolute_gate_status": gates.absolute_gate_status,
                "baseline_comparison_status": baseline_comparison_status,
            },
            "absolute_gate_status": gates.absolute_gate_status,
            "baseline_comparison_status": baseline_comparison_status,
            "gates": gates.model_dump(mode="json"),
            "metrics": metrics.model_dump(mode="json"),
            "cases": case_records,
        }
    except SafeVerificationError:
        raise
    except Exception as exc:
        raise SafeVerificationError("evaluation_result_failed") from exc


def paid_summary(
    contract: Mapping[str, object],
    *,
    mode: Literal["paid-smoke", "paid-evaluation"],
    sts_client: StsClient,
    quotas_client: ServiceQuotasClient,
    bedrock_client: BedrockControlClient,
    runtime_client: BedrockRuntimeClient,
    pricing_confirmed: bool = False,
    evidence: RunEvidence | None = None,
    result_consumer: Callable[[Mapping[str, object]], None] | None = None,
) -> VerificationSummary:
    """Run one bounded smoke and, when selected, the 24-case live evaluation."""

    if not pricing_confirmed:
        raise SafeVerificationError("pricing_confirmation_required")
    pricing = _mapping(contract, "pricing")
    if _number(pricing, "calculated_maximum_usd") > _number(pricing, "maximum_paid_evaluation_usd"):
        raise SafeVerificationError("cost_contract_mismatch")
    preflight = account_read_only_summary(
        contract,
        sts_client=sts_client,
        quotas_client=quotas_client,
        bedrock_client=bedrock_client,
        evidence=evidence,
    )
    if not _approved_prechecks(preflight):
        return VerificationSummary(
            schema_version=preflight.schema_version,
            prompt_id=preflight.prompt_id,
            mode=mode,
            overall_status="FAIL",
            network_activity=preflight.network_activity,
            provider_requests=preflight.provider_requests,
            input_tokens=preflight.input_tokens,
            output_tokens=preflight.output_tokens,
            estimated_cost_usd=preflight.estimated_cost_usd,
            report_written=False,
            checks=preflight.checks,
        )
    ledger = RuntimeLedger()
    try:
        asyncio.run(_smoke(contract, runtime_client, ledger=ledger, evidence=evidence))
    except SafeVerificationError as exc:
        raise _with_runtime_ledger(exc, ledger) from exc
    except Exception as exc:
        raise _with_runtime_ledger(
            SafeVerificationError("smoke_internal_error"),
            ledger,
        ) from exc
    if ledger.provider_requests_attempted != 1 or ledger.provider_responses_with_usage != 1:
        raise _with_runtime_ledger(
            SafeVerificationError("provider_request_count_mismatch"),
            ledger,
        )
    checks = [
        item
        for item in preflight.checks
        if item.name
        not in {"model_access", "pricing_source", "smoke_invocation", "live_evaluation"}
    ]
    checks.extend(
        (
            CheckResult("model_access", "PASS", "bounded_smoke_access_verified"),
            CheckResult("pricing_source", "PASS", "owner_confirmed_pricing_contract"),
            CheckResult("smoke_invocation", "PASS", "bounded_smoke_verified"),
        )
    )
    if mode == "paid-smoke":
        checks.append(CheckResult("live_evaluation", "NOT RUN", "live_evaluation_not_authorized"))
        return VerificationSummary(
            schema_version=_string(contract, "schema_version"),
            prompt_id=_string(contract, "prompt_id"),
            mode=mode,
            overall_status=_overall(checks),
            network_activity=True,
            provider_requests=ledger.provider_requests_attempted,
            input_tokens=ledger.input_tokens,
            output_tokens=ledger.output_tokens,
            estimated_cost_usd=ledger.estimated_cost_usd,
            report_written=False,
            checks=tuple(checks),
        )

    try:
        evaluation = asyncio.run(
            _evaluate_live(contract, runtime_client, ledger, evidence=evidence)
        )
    except SafeVerificationError as exc:
        raise _with_runtime_ledger(exc, ledger) from exc
    except Exception as exc:
        raise _with_runtime_ledger(
            SafeVerificationError("live_evaluation_internal_error"),
            ledger,
        ) from exc
    expected_request_count = int(_number(_mapping(contract, "inference"), "paid_request_count"))
    if (
        ledger.provider_requests_attempted != expected_request_count
        or ledger.provider_responses_with_usage != expected_request_count
    ):
        raise _with_runtime_ledger(
            SafeVerificationError("provider_request_count_mismatch"),
            ledger,
        )
    status = cast(Status, evaluation["live_quality_status"])
    live_safe_code = (
        "live_quality_verified"
        if status == "PASS"
        else "owner_semantic_review_required"
        if status == "INDETERMINATE"
        else "live_hard_gate_failed"
    )
    checks.append(
        CheckResult(
            "live_evaluation",
            status,
            live_safe_code,
        )
    )
    total_cost = ledger.estimated_cost_usd
    if total_cost > min(
        _number(pricing, "calculated_maximum_usd"),
        _number(pricing, "maximum_paid_evaluation_usd"),
    ):
        checks.append(CheckResult("cost_ceiling", "FAIL", "cost_ceiling_exceeded"))
    else:
        checks.append(CheckResult("cost_ceiling", "PASS", "cost_ceiling_preserved"))
    report = {
        "schema_version": "w5-001.bedrock-owner-result.v4",
        "prompt_id": _string(contract, "prompt_id"),
        "status": _overall(checks),
        "network_activity": True,
        "provider_requests": ledger.provider_requests_attempted,
        "model_id": _string(_mapping(contract, "bedrock"), "inference_profile_id"),
        "region": _string(_mapping(contract, "aws"), "region"),
        "usage": {
            "input_tokens": ledger.input_tokens,
            "output_tokens": ledger.output_tokens,
            "total_tokens": ledger.total_tokens,
            "estimated_cost_usd": total_cost,
        },
        "checks": [asdict(item) for item in checks],
        "evaluation": evaluation,
        "privacy": {
            "raw_prompts_recorded": False,
            "synthetic_questions_recorded": True,
            "synthetic_answers_recorded": True,
            "citations_recorded": True,
            "provider_envelopes_recorded": False,
            "credentials_recorded": False,
            "production_or_tenant_content_recorded": False,
        },
        "cleanup": {
            "cloud_resources_created": False,
            "residual_resources": (
                [evidence.directory.relative_to(ROOT).as_posix()] if evidence is not None else []
            ),
            "retention_days": int(_number(_mapping(contract, "output"), "retention_days")),
        },
    }
    if result_consumer is not None:
        result_consumer(report)
    if evidence is not None:
        try:
            evidence.finish(report)
        except SafeVerificationError as exc:
            raise _with_runtime_ledger(exc, ledger) from exc
    return VerificationSummary(
        schema_version=_string(contract, "schema_version"),
        prompt_id=_string(contract, "prompt_id"),
        mode=mode,
        overall_status=_overall(checks),
        network_activity=True,
        provider_requests=ledger.provider_requests_attempted,
        input_tokens=ledger.input_tokens,
        output_tokens=ledger.output_tokens,
        estimated_cost_usd=total_cost,
        report_written=evidence is not None,
        checks=tuple(checks),
    )


def _load_canonical_mapping(path: Path, safe_code: str) -> dict[str, object]:
    try:
        raw = path.read_bytes()
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda _value: (_ for _ in ()).throw(SafeVerificationError(safe_code)),
        )
    except SafeVerificationError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SafeVerificationError(safe_code) from exc
    if not isinstance(value, dict) or raw != _canonical_bytes(value):
        raise SafeVerificationError(safe_code)
    return cast(dict[str, object], value)


def _approved_run_directory(
    contract: Mapping[str, object],
    run_id: str,
    *,
    repository_root: Path = ROOT,
) -> Path:
    output = _mapping(contract, "output")
    if re.fullmatch(_string(output, "run_id_pattern"), run_id) is None:
        raise SafeVerificationError("run_id_invalid")
    root = (repository_root / _string(output, "evidence_root")).resolve()
    directory = (root / run_id).resolve()
    if repository_root.resolve() not in root.parents or directory.parent != root:
        raise SafeVerificationError("evidence_path_not_approved")
    return directory


def _verify_runtime_integrity(
    contract: Mapping[str, object],
    directory: Path,
) -> dict[str, object]:
    output = _mapping(contract, "output")
    integrity_path = directory / _string(output, "integrity_name")
    integrity = _load_canonical_mapping(integrity_path, "runtime_integrity_invalid")
    if (
        integrity.get("schema_version") != "w5-001.bedrock-run-integrity.v1"
        or integrity.get("prompt_id") != _string(contract, "prompt_id")
        or integrity.get("run_id") != directory.name
    ):
        raise SafeVerificationError("runtime_integrity_invalid")
    files = _mapping(integrity, "files")
    expected_names = (
        _string(output, "manifest_name"),
        _string(output, "events_name"),
        _string(output, "result_name"),
    )
    if set(files) != set(expected_names):
        raise SafeVerificationError("runtime_integrity_invalid")
    for name in expected_names:
        record = _mapping(files, name)
        path = directory / name
        if (
            record.get("sha256") != _sha256_path(path)
            or record.get("size_bytes") != path.stat().st_size
        ):
            raise SafeVerificationError("runtime_integrity_invalid")
    return integrity


def _validate_owner_review(
    contract: Mapping[str, object],
    *,
    run_id: str,
    result: Mapping[str, object],
    review: Mapping[str, object],
) -> tuple[Status, list[dict[str, object]]]:
    if set(review) != {
        "schema_version",
        "prompt_id",
        "run_id",
        "reviewer",
        "reviewer_role",
        "reviewed_at",
        "decisions",
    }:
        raise SafeVerificationError("owner_review_invalid")
    if (
        review.get("schema_version") != "w5-001.owner-semantic-review.v2"
        or review.get("prompt_id") != _string(contract, "prompt_id")
        or review.get("run_id") != run_id
    ):
        raise SafeVerificationError("owner_review_invalid")
    reviewer = review.get("reviewer")
    reviewer_role = review.get("reviewer_role")
    reviewed_at = review.get("reviewed_at")
    if not isinstance(reviewer, str) or not isinstance(reviewer_role, str):
        raise SafeVerificationError("owner_review_invalid")
    _safe_synthetic_text(reviewer)
    _safe_synthetic_text(reviewer_role)
    if not isinstance(reviewed_at, str):
        raise SafeVerificationError("owner_review_invalid")
    try:
        timestamp = datetime.fromisoformat(reviewed_at)
    except ValueError as exc:
        raise SafeVerificationError("owner_review_invalid") from exc
    if timestamp.utcoffset() is None:
        raise SafeVerificationError("owner_review_invalid")
    evaluation = _mapping(result, "evaluation")
    semantic = _mapping(evaluation, "semantic_review")
    required = _strings(semantic, "required_case_ids")
    cases_value = evaluation.get("cases")
    if not isinstance(cases_value, list):
        raise SafeVerificationError("owner_review_scope_invalid")
    live_case_ids: list[str] = []
    answered_live_case_ids: list[str] = []
    for raw_case in cases_value:
        if not isinstance(raw_case, dict):
            raise SafeVerificationError("owner_review_scope_invalid")
        case_record = cast(dict[str, object], raw_case)
        execution_source = case_record.get("execution_source")
        if execution_source not in {"LIVE_BEDROCK", "CONTROLLED_FIXTURE"}:
            raise SafeVerificationError("owner_review_scope_invalid")
        if execution_source == "LIVE_BEDROCK":
            case_id = case_record.get("case_id")
            actual_outcome = case_record.get("actual_outcome")
            if not isinstance(case_id, str) or not isinstance(actual_outcome, str):
                raise SafeVerificationError("owner_review_scope_invalid")
            live_case_ids.append(case_id)
            if actual_outcome == "ANSWERED":
                answered_live_case_ids.append(case_id)
    expected_live_case_ids = _strings(
        _mapping(contract, "evaluation"),
        "provider_eligible_case_ids",
    )
    if tuple(live_case_ids) != expected_live_case_ids or required != tuple(answered_live_case_ids):
        raise SafeVerificationError("owner_review_scope_invalid")
    decisions_value = review.get("decisions")
    if not isinstance(decisions_value, list):
        raise SafeVerificationError("owner_review_invalid")
    decisions: list[dict[str, object]] = []
    for raw in decisions_value:
        if not isinstance(raw, dict) or set(raw) != {
            "case_id",
            *OWNER_REVIEW_CRITERIA,
            "status",
            "reason",
        }:
            raise SafeVerificationError("owner_review_invalid")
        item = cast(dict[str, object], raw)
        case_id = item.get("case_id")
        values = tuple(item.get(name) for name in OWNER_REVIEW_CRITERIA)
        status = item.get("status")
        reason = item.get("reason")
        if (
            not isinstance(case_id, str)
            or any(value not in {"PASS", "FAIL"} for value in values)
            or status not in {"PASS", "FAIL"}
            or not isinstance(reason, str)
            or (status == "PASS") != all(value == "PASS" for value in values)
        ):
            raise SafeVerificationError("owner_review_invalid")
        _safe_synthetic_text(reason)
        decisions.append(item)
    if tuple(cast(str, item["case_id"]) for item in decisions) != required:
        raise SafeVerificationError("owner_review_incomplete")
    if evaluation.get("live_hard_gate_status") != "PASS":
        return "FAIL", decisions
    return (
        "PASS" if all(item["status"] == "PASS" for item in decisions) else "FAIL",
        decisions,
    )


def reconcile_owner_review(
    contract: Mapping[str, object],
    *,
    run_id: str,
) -> VerificationSummary:
    directory = _approved_run_directory(contract, run_id)
    if not directory.is_dir():
        raise SafeVerificationError("run_evidence_unavailable")
    output = _mapping(contract, "output")
    _verify_runtime_integrity(contract, directory)
    result_path = directory / _string(output, "result_name")
    review_path = directory / _string(output, "owner_review_name")
    final_path = directory / _string(output, "final_name")
    result = _load_canonical_mapping(result_path, "runtime_result_invalid")
    review = _load_canonical_mapping(review_path, "owner_review_unavailable")
    if (
        result.get("schema_version") != "w5-001.bedrock-owner-result.v4"
        or result.get("prompt_id") != _string(contract, "prompt_id")
        or result.get("run_id") != run_id
    ):
        raise SafeVerificationError("runtime_result_invalid")
    final_status, decisions = _validate_owner_review(
        contract,
        run_id=run_id,
        result=result,
        review=review,
    )
    final = {
        "schema_version": "w5-001.bedrock-owner-final.v1",
        "prompt_id": _string(contract, "prompt_id"),
        "run_id": run_id,
        "status": final_status,
        "reconciled_at_utc": _utc_timestamp(),
        "reviewer": review["reviewer"],
        "reviewer_role": review["reviewer_role"],
        "reviewed_at": review["reviewed_at"],
        "runtime_hard_gate_status": _mapping(result, "evaluation")["live_hard_gate_status"],
        "lexical_regression": _mapping(_mapping(result, "evaluation"), "lexical_regression"),
        "owner_semantic_review_status": final_status,
        "decisions": decisions,
        "evidence_hashes": {
            _string(output, "manifest_name"): _sha256_path(
                directory / _string(output, "manifest_name")
            ),
            _string(output, "events_name"): _sha256_path(
                directory / _string(output, "events_name")
            ),
            _string(output, "result_name"): _sha256_path(result_path),
            _string(output, "integrity_name"): _sha256_path(
                directory / _string(output, "integrity_name")
            ),
            _string(output, "owner_review_name"): _sha256_path(review_path),
        },
        "network_activity": False,
        "additional_provider_requests": 0,
    }
    _atomic_exclusive_json(final_path, final)
    usage = _mapping(result, "usage")
    checks = (
        CheckResult(
            "runtime_integrity",
            "PASS",
            "runtime_evidence_integrity_verified",
        ),
        CheckResult(
            "owner_semantic_review",
            final_status,
            "owner_semantic_review_complete"
            if final_status == "PASS"
            else "owner_semantic_review_failed",
        ),
    )
    return VerificationSummary(
        schema_version=_string(contract, "schema_version"),
        prompt_id=_string(contract, "prompt_id"),
        mode="reconcile-owner-review",
        overall_status=final_status,
        network_activity=False,
        provider_requests=0,
        input_tokens=int(_number(usage, "input_tokens")),
        output_tokens=int(_number(usage, "output_tokens")),
        estimated_cost_usd=_number(usage, "estimated_cost_usd"),
        report_written=True,
        checks=checks,
    )


def _clients(
    contract: Mapping[str, object],
) -> tuple[
    StsClient,
    ServiceQuotasClient,
    BedrockControlClient,
    BedrockRuntimeClient,
]:
    try:
        boto3: Any = importlib.import_module("boto3")
        botocore_config: Any = importlib.import_module("botocore.config")
    except ImportError as exc:
        raise SafeVerificationError("aws_sdk_unavailable") from exc
    aws = _mapping(contract, "aws")
    session = boto3.Session(
        profile_name=_string(aws, "profile"),
        region_name=_string(aws, "region"),
    )
    client_config: Any = botocore_config.Config(
        connect_timeout=30,
        read_timeout=30,
        retries={"total_max_attempts": 1, "mode": "standard"},
    )
    return (
        cast(StsClient, session.client("sts", config=client_config)),
        cast(ServiceQuotasClient, session.client("service-quotas", config=client_config)),
        cast(BedrockControlClient, session.client("bedrock", config=client_config)),
        cast(BedrockRuntimeClient, session.client("bedrock-runtime", config=client_config)),
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="W5-001 owner-gated Bedrock verification")
    parser.add_argument(
        "--config",
        type=Path,
        default=ROOT / "configs/verification/bedrock-owner-test.json",
    )
    parser.add_argument(
        "--mode",
        choices=(
            "dry-run",
            "account-read-only",
            "paid-smoke",
            "paid-evaluation",
            "reconcile-owner-review",
        ),
        default="dry-run",
    )
    parser.add_argument("--run-id")
    parser.add_argument("--owner-authorized-network", action="store_true")
    parser.add_argument("--owner-authorized-paid", action="store_true")
    parser.add_argument("--owner-confirmed-pricing", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    contract = load_contract(args.config)
    mode = cast(Mode, args.mode)
    if not isinstance(args.run_id, str) or not args.run_id:
        raise SafeVerificationError("run_id_required")
    if mode == "reconcile-owner-review":
        if (
            args.owner_authorized_network
            or args.owner_authorized_paid
            or args.owner_confirmed_pricing
        ):
            raise SafeVerificationError("reconciliation_authorization_flags_prohibited")
        summary = reconcile_owner_review(contract, run_id=args.run_id)
        print(
            json.dumps(
                summary.public_mapping(),
                separators=(",", ":"),
                allow_nan=False,
            )
        )
        return 0 if summary.overall_status == "PASS" else 1

    command_arguments = tuple(argv) if argv is not None else tuple(sys.argv[1:])
    evidence = RunEvidence.start(
        contract,
        contract_path=args.config,
        run_id=args.run_id,
        mode=mode,
        command_argv=(
            str(Path(sys.executable).resolve()),
            str(Path(__file__).resolve()),
            *command_arguments,
        ),
    )
    try:
        if mode == "dry-run":
            summary = dry_run_summary(contract)
        else:
            if not args.owner_authorized_network:
                raise SafeVerificationError("network_authorization_required")
            if mode in {"paid-smoke", "paid-evaluation"} and not args.owner_authorized_paid:
                raise SafeVerificationError("paid_authorization_required")
            if mode in {"paid-smoke", "paid-evaluation"} and not args.owner_confirmed_pricing:
                raise SafeVerificationError("pricing_confirmation_required")
            sts, quotas, bedrock, runtime = _clients(contract)
            if mode == "account-read-only":
                summary = account_read_only_summary(
                    contract,
                    sts_client=sts,
                    quotas_client=quotas,
                    bedrock_client=bedrock,
                    evidence=evidence,
                )
            else:
                summary = paid_summary(
                    contract,
                    mode=mode,
                    sts_client=sts,
                    quotas_client=quotas,
                    bedrock_client=bedrock,
                    runtime_client=runtime,
                    pricing_confirmed=args.owner_confirmed_pricing,
                    evidence=evidence,
                )
        if not evidence.finished:
            summary = replace(summary, report_written=True)
            evidence.finish(summary.public_mapping())
    except SafeVerificationError as exc:
        if not evidence.finished:
            evidence.finish(_error_public_mapping(exc))
        raise
    except Exception as exc:
        error = SafeVerificationError("internal_error")
        if not evidence.finished:
            evidence.finish(_error_public_mapping(error))
        raise error from exc
    print(json.dumps(summary.public_mapping(), separators=(",", ":"), allow_nan=False))
    return 0 if summary.overall_status in {"PASS", "NOT RUN", "INDETERMINATE"} else 1


def safe_main() -> int:
    try:
        return main()
    except SafeVerificationError as exc:
        print(
            json.dumps(
                _error_public_mapping(exc),
                separators=(",", ":"),
            )
        )
        return 1
    except Exception:
        print(
            json.dumps(
                {
                    "schema_version": "w5-001.error.v1",
                    "status": "FAIL",
                    "safe_code": "internal_error",
                },
                separators=(",", ":"),
            )
        )
        return 1


if __name__ == "__main__":
    sys.exit(safe_main())
