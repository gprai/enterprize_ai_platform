"""W6-004 Kubernetes deployment, rollback and teardown evidence contracts."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum

DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
NAMESPACE = "enterprise-ai-sandbox"
STAGES = ("server_dry_run", "deploy", "live_verify", "rollback", "teardown")


class KubernetesLifecycleError(ValueError):
    """Raised when Kubernetes lifecycle evidence fails closed."""


def validate_kubernetes_evidence(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise KubernetesLifecycleError("Kubernetes evidence must be an object")
    expected = {
        "schema_version",
        "stage",
        "namespace",
        "cluster_arn",
        "application_digest",
        "collector_digest",
        "manifest_sha256",
        "observed",
        "status",
    }
    if set(value) != expected or value.get("schema_version") != "w6-004.kubernetes-evidence.v1":
        raise KubernetesLifecycleError("Kubernetes evidence fields or schema differ")
    if value.get("stage") not in STAGES or value.get("namespace") != NAMESPACE:
        raise KubernetesLifecycleError("Kubernetes stage or namespace differs")
    for field in ("application_digest", "collector_digest"):
        field_value = value.get(field)
        if not isinstance(field_value, str) or DIGEST.fullmatch(field_value) is None:
            raise KubernetesLifecycleError(f"{field} must be an immutable digest")
    manifest = value.get("manifest_sha256")
    if not isinstance(manifest, str) or SHA256.fullmatch(manifest) is None:
        raise KubernetesLifecycleError("manifest_sha256 must be lowercase SHA-256")
    observed = value.get("observed")
    if not isinstance(observed, Sequence) or isinstance(observed, str) or not observed:
        raise KubernetesLifecycleError("observed checks must be a non-empty list")
    if value.get("status") not in {"PASS", "FAIL", "INDETERMINATE"}:
        raise KubernetesLifecycleError("status differs")
    return value


class TeardownPhase(StrEnum):
    DATA_PLANE_DELETE = "DATA_PLANE_DELETE"
    DATA_PLANE_ABSENCE = "DATA_PLANE_ABSENCE"
    TEMPORARY_TRUST_RESTORED = "TEMPORARY_TRUST_RESTORED"
    WORKLOAD_DELETE = "WORKLOAD_DELETE"
    WORKLOAD_ABSENCE = "WORKLOAD_ABSENCE"
    NAMESPACE_DELETE = "NAMESPACE_DELETE"
    NATIVE_ABSENCE = "NATIVE_ABSENCE"


TEARDOWN_ORDER = tuple(TeardownPhase)


@dataclass(frozen=True)
class PodObservation:
    name: str
    uid: str
    ready: bool
    deleting: bool
    digest: str


@dataclass(frozen=True)
class TeardownObservation:
    phase: TeardownPhase
    expected_mutations: int
    acknowledged_mutations: int
    native_absent: bool
    trust_restored: bool
    progress_sequence: int
    maximum_wait_seconds: int
    targets_existed: bool = False


@dataclass(frozen=True)
class PatchIdentity:
    path: str
    sha256: str
    utf8_bom: bool
    targets: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class RejoinObservation:
    interrupted_uid: str
    replacement_uid: str
    elapsed_seconds: int
    maximum_seconds: int
    rejoined: bool


def validate_rejoin(value: RejoinObservation) -> RejoinObservation:
    if (
        not value.interrupted_uid
        or not value.replacement_uid
        or value.interrupted_uid == value.replacement_uid
        or value.elapsed_seconds < 0
        or value.maximum_seconds <= 0
        or value.elapsed_seconds > value.maximum_seconds
        or not value.rejoined
    ):
        raise KubernetesLifecycleError("bounded rejoin was not established")
    return value


def validate_patch_identity(value: PatchIdentity) -> PatchIdentity:
    """Bind a BOM-free patch to exact Kubernetes names and UIDs."""
    if not value.path or SHA256.fullmatch(value.sha256) is None or value.utf8_bom:
        raise KubernetesLifecycleError("patch identity must be BOM-free UTF-8 with SHA-256")
    if not value.targets or len(value.targets) != len(set(value.targets)):
        raise KubernetesLifecycleError("patch targets must contain unique exact names and UIDs")
    if any(not name or not uid for name, uid in value.targets):
        raise KubernetesLifecycleError("patch target identity is incomplete")
    return value


def validate_replica_progress(
    observations: Sequence[int], *, target_replicas: int, maximum_observed_replicas: int
) -> tuple[int, ...]:
    """Keep progress samples separate from the independently captured maximum."""
    values = tuple(observations)
    if (
        not values
        or target_replicas < 0
        or any(value < 0 for value in values)
        or maximum_observed_replicas != max(values)
        or values[-1] != target_replicas
    ):
        raise KubernetesLifecycleError("replica progress or maximum observation differs")
    return values


def validate_delete_arguments(arguments: Sequence[str]) -> tuple[str, ...]:
    """Reject unsupported client-side preconditions and ambiguous delete targets."""
    values = tuple(arguments)
    if (
        len(values) < 3
        or values[0] != "delete"
        or any(value.startswith("--precondition") for value in values)
        or any(not value or "\x00" in value for value in values)
    ):
        raise KubernetesLifecycleError("Kubernetes delete arguments are not approved")
    return values


def classify_pods(
    observations: Sequence[PodObservation], *, expected_digest: str
) -> tuple[tuple[PodObservation, ...], tuple[PodObservation, ...]]:
    if DIGEST.fullmatch(expected_digest) is None:
        raise KubernetesLifecycleError("expected image digest is invalid")
    identities = {(item.name, item.uid) for item in observations}
    if len(identities) != len(observations) or any(
        not item.name or not item.uid for item in observations
    ):
        raise KubernetesLifecycleError("pod identity is missing or duplicated")
    active = tuple(item for item in observations if not item.deleting)
    terminating = tuple(item for item in observations if item.deleting)
    if any(item.digest != expected_digest for item in active):
        raise KubernetesLifecycleError("active pod image identity differs")
    return active, terminating


def validate_teardown_observations(
    observations: Sequence[TeardownObservation],
) -> tuple[TeardownObservation, ...]:
    if not observations or tuple(item.phase for item in observations) != TEARDOWN_ORDER:
        raise KubernetesLifecycleError("teardown phases are incomplete or out of order")
    previous = 0
    for item in observations:
        if item.progress_sequence <= previous or item.maximum_wait_seconds <= 0:
            raise KubernetesLifecycleError("teardown progress or deadline is invalid")
        previous = item.progress_sequence
        if item.expected_mutations < 0 or item.acknowledged_mutations < 0:
            raise KubernetesLifecycleError("teardown mutation count is invalid")
        if item.targets_existed and item.expected_mutations == 0:
            raise KubernetesLifecycleError("existing targets require a nonzero expected mutation")
        if item.expected_mutations and item.acknowledged_mutations != item.expected_mutations:
            raise KubernetesLifecycleError("positive deletion acknowledgement is incomplete")
        if item.phase is TeardownPhase.TEMPORARY_TRUST_RESTORED and not item.trust_restored:
            raise KubernetesLifecycleError("temporary trust was not restored")
        if (
            item.phase in {TeardownPhase.DATA_PLANE_ABSENCE, TeardownPhase.NATIVE_ABSENCE}
            and not item.native_absent
        ):
            raise KubernetesLifecycleError("native absence is not established")
    return tuple(observations)


def classify_not_found(*, exit_code: int, stderr: str, expected_absence: bool) -> str:
    """Separate an expected exact NotFound from transport or command failure."""
    if exit_code == 0:
        return "PRESENT"
    normalized = stderr.casefold()
    if expected_absence and "notfound" in normalized.replace(" ", ""):
        return "ABSENT"
    raise KubernetesLifecycleError("Kubernetes command failed without expected absence")
