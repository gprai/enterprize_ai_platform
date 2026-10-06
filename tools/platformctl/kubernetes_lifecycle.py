"""W6-004 Kubernetes deployment, rollback and teardown evidence contracts."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence

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
