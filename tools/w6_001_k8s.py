"""Offline, fail-closed W6-001 Kubernetes template and release binding controls."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlsplit

import yaml  # type: ignore[import-untyped]

from tools.platformctl.contracts import ContractError
from tools.platformctl.lifecycle_io import reserve_operation_directory, verify_private_directory

APP_SENTINEL = "enterprise-ai.invalid/w6-001:OWNER_BINDING_REQUIRED"
COLLECTOR_SENTINEL = "enterprise-ai.invalid/w6-004-otel:OWNER_BINDING_REQUIRED"
OPENSEARCH_SENTINEL = "https://OWNER_BINDING_REQUIRED"
BEDROCK_SENTINEL = "OWNER_BINDING_REQUIRED"
SENTINEL = APP_SENTINEL
NAMESPACE = "enterprise-ai-sandbox"
SERVICE_ACCOUNT = "enterprise-ai-runtime"
INGESTION_SERVICE_ACCOUNT = "enterprise-ai-ingestion"
FIS_SERVICE_ACCOUNT = "fis-experiment"
FIS_ROLE = "fis-pod-delete"
APP_NAME = "enterprise-ai-api"
REPOSITORY_NAME = "enterprise-ai/sandbox/api"
COLLECTOR_REPOSITORY_NAME = REPOSITORY_NAME
TEMPLATE_STATUS = "SOURCE TEMPLATE VALID — NOT DEPLOYABLE"
RELEASE_STATUS = "IMMUTABLE RELEASE PACKAGE VALID — NOT DEPLOYED"
TEMPLATE_FILES = (
    "kustomization.yaml",
    "namespace.yaml",
    "serviceaccount.yaml",
    "configmap.yaml",
    "otel-collector-configmap.yaml",
    "deployment.yaml",
    "service.yaml",
    "networkpolicy.yaml",
    "hpa.yaml",
    "pdb.yaml",
)
EXPECTED_OBJECTS = {
    ("v1", "Namespace", NAMESPACE),
    ("apps/v1", "Deployment", APP_NAME),
    ("v1", "Service", APP_NAME),
    ("v1", "ServiceAccount", SERVICE_ACCOUNT),
    ("v1", "ServiceAccount", INGESTION_SERVICE_ACCOUNT),
    ("v1", "ServiceAccount", FIS_SERVICE_ACCOUNT),
    ("rbac.authorization.k8s.io/v1", "Role", FIS_ROLE),
    ("rbac.authorization.k8s.io/v1", "RoleBinding", FIS_ROLE),
    ("v1", "ConfigMap", "enterprise-ai-runtime"),
    ("v1", "ConfigMap", "enterprise-ai-otel-collector"),
    ("networking.k8s.io/v1", "NetworkPolicy", "enterprise-ai-default-deny"),
    ("networking.k8s.io/v1", "NetworkPolicy", "enterprise-ai-dns-egress"),
    ("networking.k8s.io/v1", "NetworkPolicy", "enterprise-ai-api-ingress"),
    ("networking.k8s.io/v1", "NetworkPolicy", "enterprise-ai-private-aws-egress"),
    ("networking.k8s.io/v1", "NetworkPolicy", "enterprise-ai-pod-identity-egress"),
    ("autoscaling/v2", "HorizontalPodAutoscaler", APP_NAME),
    ("policy/v1", "PodDisruptionBudget", APP_NAME),
}
RELEASE_KEYS = {
    "schema_version",
    "ecr_repository_uri",
    "digest",
    "aws_account_id",
    "aws_region",
    "source_identity",
    "oci_identity",
    "trivy",
    "grype",
    "spdx_sbom_sha256",
    "cyclonedx_sbom_sha256",
    "provenance",
    "image_composition_identity",
    "w6_01_operation_identity",
    "owner_approval_identity",
    "expires_at",
    "allowed_output_root",
    "output_root",
    "collector",
    "runtime",
}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
ECR_RE = re.compile(
    r"^(?P<account>[0-9]{12})\.dkr\.ecr\.(?P<region>[a-z0-9-]+)\.amazonaws\.com/"
    r"(?P<repository>[a-z0-9]+(?:[._/-][a-z0-9]+)*)$"
)


class W6001Error(ValueError):
    """Raised when a W6-001 source or release contract fails closed."""


class UniqueSafeLoader(yaml.SafeLoader):  # type: ignore[misc]
    """Safe YAML loader that rejects duplicate mapping keys."""


def _construct_mapping(loader: UniqueSafeLoader, node: yaml.Node, deep: bool = False) -> Any:
    mapping: dict[object, object] = {}
    for key_node, value_node in cast(yaml.MappingNode, node).value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise W6001Error(f"duplicate YAML key: {key!r}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


UniqueSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping,
)


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical_json(value: object) -> bytes:
    serialized = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return f"{serialized}\n".encode()


def _strict_json(path: Path) -> dict[str, object]:
    def reject_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise W6001Error(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_pairs)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise W6001Error("release binding input must be strict UTF-8 JSON") from exc
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise W6001Error("release binding input must be an object")
    return cast(dict[str, object], value)


def load_documents(path: Path) -> list[dict[str, object]]:
    try:
        values = list(yaml.load_all(path.read_text(encoding="utf-8"), Loader=UniqueSafeLoader))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise W6001Error(f"invalid YAML: {path}") from exc
    documents: list[dict[str, object]] = []
    for value in values:
        if value is None:
            continue
        if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
            raise W6001Error(f"every YAML document must be an object: {path}")
        documents.append(cast(dict[str, object], value))
    return documents


def load_template(template_root: Path) -> tuple[list[dict[str, object]], dict[str, bytes]]:
    if template_root.resolve() != template_root.resolve(strict=False):
        raise W6001Error("template root is invalid")
    payloads: dict[str, bytes] = {}
    documents: list[dict[str, object]] = []
    for name in TEMPLATE_FILES:
        path = template_root / name
        try:
            payloads[name] = path.read_bytes()
        except OSError as exc:
            raise W6001Error(f"missing template file: {name}") from exc
        if name != "kustomization.yaml":
            documents.extend(load_documents(path))
    return documents, payloads


def template_identity(payloads: dict[str, bytes]) -> str:
    digest = hashlib.sha256()
    for name in sorted(payloads):
        digest.update(name.encode())
        digest.update(b"\0")
        digest.update(payloads[name])
        digest.update(b"\0")
    return digest.hexdigest()


def _mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise W6001Error(f"{label} must be an object")
    return cast(dict[str, object], value)


def _list(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        raise W6001Error(f"{label} must be a list")
    return value


def _metadata(document: dict[str, object]) -> dict[str, object]:
    return _mapping(document.get("metadata"), "metadata")


def _objects_by_kind(documents: Iterable[dict[str, object]]) -> dict[str, list[dict[str, object]]]:
    result: dict[str, list[dict[str, object]]] = {}
    identities: set[tuple[str, str, str]] = set()
    for document in documents:
        api_version = document.get("apiVersion")
        kind = document.get("kind")
        metadata = _metadata(document)
        name = metadata.get("name")
        namespace = metadata.get("namespace")
        if not all(isinstance(value, str) and value for value in (api_version, kind, name)):
            raise W6001Error("every object requires apiVersion, kind, and metadata.name")
        if kind == "Namespace" and namespace is not None:
            raise W6001Error("Namespace object must not declare metadata.namespace")
        if kind != "Namespace" and namespace != NAMESPACE:
            raise W6001Error(f"every object must use namespace {NAMESPACE}")
        identity = cast(tuple[str, str, str], (api_version, kind, name))
        if identity in identities:
            raise W6001Error(f"duplicate object identity: {identity}")
        identities.add(identity)
        if identity not in EXPECTED_OBJECTS:
            raise W6001Error(f"unexpected Kubernetes object: {identity}")
        result.setdefault(cast(str, kind), []).append(document)
    if identities != EXPECTED_OBJECTS:
        missing = sorted(EXPECTED_OBJECTS - identities)
        raise W6001Error(f"Kubernetes object inventory mismatch; missing={missing}")
    return result


def _validate_deployment(deployment: dict[str, object], *, template_mode: bool) -> tuple[str, str]:
    metadata = _metadata(deployment)
    labels = _mapping(metadata.get("labels"), "Deployment metadata.labels")
    expected_artifact = "w6-001-source-template" if template_mode else "w6-001-release-package"
    expected_deployable = "false" if template_mode else "true"
    if labels.get("enterprise-ai.vayunetrix.com/artifact-type") != expected_artifact:
        raise W6001Error("artifact type does not match validation mode")
    if labels.get("enterprise-ai.vayunetrix.com/deployable") != expected_deployable:
        raise W6001Error("deployable label does not match validation mode")
    spec = _mapping(deployment.get("spec"), "Deployment spec")
    if spec.get("replicas") != 2 or spec.get("revisionHistoryLimit") != 3:
        raise W6001Error("Deployment replica or revision bounds differ")
    if spec.get("progressDeadlineSeconds") != 300:
        raise W6001Error("Deployment progress deadline differs")
    strategy = _mapping(spec.get("strategy"), "Deployment strategy")
    rolling = _mapping(strategy.get("rollingUpdate"), "rollingUpdate")
    if strategy.get("type") != "RollingUpdate" or rolling != {"maxSurge": 1, "maxUnavailable": 0}:
        raise W6001Error("rolling update contract differs")
    selector = _mapping(_mapping(spec.get("selector"), "selector").get("matchLabels"), "selector")
    pod = _mapping(spec.get("template"), "pod template")
    pod_metadata = _metadata(pod)
    pod_labels = _mapping(pod_metadata.get("labels"), "pod labels")
    if selector != {"app.kubernetes.io/name": APP_NAME} or any(
        pod_labels.get(key) != value for key, value in selector.items()
    ):
        raise W6001Error("Deployment selector and pod labels differ")
    pod_spec = _mapping(pod.get("spec"), "pod spec")
    if pod_spec.get("serviceAccountName") != SERVICE_ACCOUNT:
        raise W6001Error("approved service account is required")
    if pod_spec.get("automountServiceAccountToken") is not False:
        raise W6001Error("service-account token automount must be disabled")
    if pod_spec.get("terminationGracePeriodSeconds") != 30:
        raise W6001Error("termination grace period differs")
    if any(key in pod_spec for key in ("hostNetwork", "hostPID", "hostIPC")):
        raise W6001Error("host namespaces are prohibited")
    security = _mapping(pod_spec.get("securityContext"), "pod securityContext")
    if security != {
        "runAsNonRoot": True,
        "runAsUser": 65532,
        "runAsGroup": 65532,
        "fsGroup": 65532,
        "fsGroupChangePolicy": "OnRootMismatch",
        "seccompProfile": {"type": "RuntimeDefault"},
    }:
        raise W6001Error("pod security context differs")
    containers = _list(pod_spec.get("containers"), "containers")
    if len(containers) != 2 or "initContainers" in pod_spec:
        raise W6001Error("exactly the api and telemetry sidecar containers are permitted")
    container = _mapping(containers[0], "container")
    if container.get("name") != "api" or not isinstance(container.get("image"), str):
        raise W6001Error("approved api container and image are required")
    image = cast(str, container["image"])
    if container.get("imagePullPolicy") != "Always":
        raise W6001Error("container imagePullPolicy must be Always")
    if template_mode and image != APP_SENTINEL:
        raise W6001Error("template mode requires the exact reserved sentinel")
    if not template_mode and (image == APP_SENTINEL or not ECR_RE.match(image.split("@", 1)[0])):
        raise W6001Error("release mode requires an immutable ECR image")
    if not template_mode:
        parts = image.split("@", 1)
        if len(parts) != 2 or not DIGEST_RE.fullmatch(parts[1]):
            raise W6001Error("release image must use an exact lowercase digest")
    container_security = _mapping(container.get("securityContext"), "container securityContext")
    capabilities = _mapping(container_security.get("capabilities"), "capabilities")
    if container_security.get("allowPrivilegeEscalation") is not False:
        raise W6001Error("privilege escalation must be disabled")
    if container_security.get("readOnlyRootFilesystem") is not True:
        raise W6001Error("root filesystem must be read-only")
    if capabilities != {"drop": ["ALL"]} or container_security.get("privileged") is True:
        raise W6001Error("all capabilities must be dropped and privileged mode prohibited")
    if container.get("envFrom") != [{"configMapRef": {"name": "enterprise-ai-runtime"}}]:
        raise W6001Error("runtime configuration source differs")
    if container.get("env") != [
        {
            "name": "ENTERPRISE_AI_SANDBOX_AUTH_SIGNING_KEY_FILE",
            "value": "/var/run/secrets/enterprise-ai/sandbox-auth-signing-key",
        }
    ]:
        raise W6001Error("sandbox auth secret must use the approved mounted file")
    standard_library_http_client = "urllib" + ".request"
    expected_drain_command = [
        "/venv/bin/python",
        "-B",
        "-c",
        (
            f"import {standard_library_http_client}; "
            f"request={standard_library_http_client}.Request("
            "'http://127.0.0.1:8000/_internal/drain',method='POST'); "
            f"{standard_library_http_client}.urlopen(request,timeout=23).read()"
        ),
    ]
    lifecycle = _mapping(container.get("lifecycle"), "api lifecycle")
    pre_stop = _mapping(lifecycle.get("preStop"), "api lifecycle preStop")
    drain_exec = _mapping(pre_stop.get("exec"), "api lifecycle preStop exec")
    if drain_exec.get("command") != expected_drain_command:
        raise W6001Error("api drain hook differs")
    if container.get("volumeMounts") != [
        {"name": "tmp", "mountPath": "/tmp"},  # noqa: S108 - fixed container mount
        {
            "name": "sandbox-auth-signing-key",
            "mountPath": "/var/run/secrets/enterprise-ai",
            "readOnly": True,
        },
    ]:
        raise W6001Error("api volume mounts differ")
    resources = _mapping(container.get("resources"), "resources")
    if resources != {
        "requests": {"cpu": "500m", "memory": "1Gi", "ephemeral-storage": "256Mi"},
        "limits": {"cpu": "1000m", "memory": "2Gi", "ephemeral-storage": "1Gi"},
    }:
        raise W6001Error("resource contract differs")
    expected_probes = {
        "startupProbe": "/health",
        "livenessProbe": "/health/live",
        "readinessProbe": "/health/ready",
    }
    for key, path in expected_probes.items():
        probe = _mapping(container.get(key), key)
        http_get = _mapping(probe.get("httpGet"), f"{key}.httpGet")
        if http_get != {"path": path, "port": "http"}:
            raise W6001Error(f"{key} path or port differs")
        if not all(
            isinstance(probe.get(field), int) and cast(int, probe[field]) > 0
            for field in ("periodSeconds", "timeoutSeconds", "failureThreshold")
        ):
            raise W6001Error(f"{key} timing must be bounded")
    collector = _mapping(containers[1], "collector container")
    collector_image = collector.get("image")
    if collector.get("name") != "otel-collector" or not isinstance(collector_image, str):
        raise W6001Error("approved telemetry sidecar and image are required")
    if collector.get("imagePullPolicy") != "Always":
        raise W6001Error("collector imagePullPolicy must be Always")
    if template_mode and collector_image != COLLECTOR_SENTINEL:
        raise W6001Error("template mode requires the exact collector sentinel")
    if not template_mode:
        collector_parts = collector_image.split("@", 1)
        collector_match = (
            ECR_RE.fullmatch(collector_parts[0]) if len(collector_parts) == 2 else None
        )
        if (
            collector_match is None
            or collector_match.group("repository") != COLLECTOR_REPOSITORY_NAME
            or not DIGEST_RE.fullmatch(collector_parts[1])
        ):
            raise W6001Error("release mode requires the approved immutable private collector image")
    collector_security = _mapping(collector.get("securityContext"), "collector securityContext")
    if collector_security != {
        "allowPrivilegeEscalation": False,
        "readOnlyRootFilesystem": True,
        "capabilities": {"drop": ["ALL"]},
    }:
        raise W6001Error("collector security context differs")
    volumes = _list(pod_spec.get("volumes"), "volumes")
    if volumes != [
        {"name": "tmp", "emptyDir": {"sizeLimit": "256Mi"}},
        {"name": "otel-config", "configMap": {"name": "enterprise-ai-otel-collector"}},
        {"name": "otel-tmp", "emptyDir": {"sizeLimit": "64Mi"}},
        {
            "name": "sandbox-auth-signing-key",
            "secret": {
                "secretName": "enterprise-ai-runtime-secrets",  # pragma: allowlist secret
                "defaultMode": 288,
                "items": [
                    {
                        "key": "sandbox-auth-signing-key",
                        "path": "sandbox-auth-signing-key",
                    }
                ],
            },
        },
    ]:
        raise W6001Error("bounded workload volumes differ")
    return image, collector_image


def _validate_service(service: dict[str, object]) -> None:
    spec = _mapping(service.get("spec"), "Service spec")
    if spec.get("type") != "ClusterIP":
        raise W6001Error("Service must be ClusterIP")
    if spec.get("selector") != {"app.kubernetes.io/name": APP_NAME}:
        raise W6001Error("Service selector differs")
    expected_ports = [{"name": "http", "protocol": "TCP", "port": 8000, "targetPort": "http"}]
    if spec.get("ports") != expected_ports:
        raise W6001Error("Service port contract differs")


def _validate_scaling(hpa: dict[str, object], pdb: dict[str, object]) -> None:
    hpa_spec = _mapping(hpa.get("spec"), "HPA spec")
    if hpa_spec.get("minReplicas") != 2 or hpa_spec.get("maxReplicas") != 4:
        raise W6001Error("HPA bounds differ")
    expected_target = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "name": APP_NAME,
    }
    if hpa_spec.get("scaleTargetRef") != expected_target:
        raise W6001Error("HPA target differs")
    metrics = _list(hpa_spec.get("metrics"), "HPA metrics")
    expected_metrics = [
        {
            "type": "Resource",
            "resource": {
                "name": "cpu",
                "target": {"type": "Utilization", "averageUtilization": 70},
            },
        },
        {
            "type": "Resource",
            "resource": {
                "name": "memory",
                "target": {"type": "Utilization", "averageUtilization": 75},
            },
        },
    ]
    if metrics != expected_metrics:
        raise W6001Error("HPA metric contract differs")
    expected_behavior = {
        "scaleUp": {
            "stabilizationWindowSeconds": 0,
            "selectPolicy": "Max",
            "policies": [
                {"type": "Pods", "value": 1, "periodSeconds": 60},
                {"type": "Percent", "value": 100, "periodSeconds": 60},
            ],
        },
        "scaleDown": {
            "stabilizationWindowSeconds": 300,
            "selectPolicy": "Min",
            "policies": [{"type": "Pods", "value": 1, "periodSeconds": 60}],
        },
    }
    if hpa_spec.get("behavior") != expected_behavior:
        raise W6001Error("HPA behavior contract differs")
    pdb_spec = _mapping(pdb.get("spec"), "PDB spec")
    expected_pdb = {
        "maxUnavailable": 1,
        "selector": {"matchLabels": {"app.kubernetes.io/name": APP_NAME}},
    }
    if pdb_spec != expected_pdb:
        raise W6001Error("PDB contract differs or is incompatible")


def _validate_network(policies: list[dict[str, object]]) -> None:
    by_name = {cast(str, _metadata(policy)["name"]): policy for policy in policies}
    deny = _mapping(by_name["enterprise-ai-default-deny"].get("spec"), "default deny")
    if deny != {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]}:
        raise W6001Error("default-deny policy differs")
    dns = _mapping(by_name["enterprise-ai-dns-egress"].get("spec"), "DNS policy")
    if dns.get("policyTypes") != ["Egress"] or "ingress" in dns:
        raise W6001Error("DNS policy may provide egress only")
    rendered = json.dumps(dns, sort_keys=True)
    for forbidden in ("0.0.0.0/0", "::/0", "ipBlock"):
        if forbidden in rendered:
            raise W6001Error("unrestricted egress is prohibited")
    if rendered.count('"port": 53') != 2 or "kube-dns" not in rendered:
        raise W6001Error("DNS egress must be bounded to verified DNS pods")
    private_egress = _mapping(
        by_name["enterprise-ai-private-aws-egress"].get("spec"),
        "private AWS egress policy",
    )
    private_rendered = json.dumps(private_egress, sort_keys=True)
    if "10.60.0.0/16" not in private_rendered or private_rendered.count('"port": 443') != 1:
        raise W6001Error("AWS egress must be bounded to the sandbox VPC over TLS")
    pod_identity = _mapping(
        by_name["enterprise-ai-pod-identity-egress"].get("spec"),
        "Pod Identity egress policy",
    )
    expected_pod_identity = {
        "podSelector": {"matchLabels": {"app.kubernetes.io/name": APP_NAME}},
        "policyTypes": ["Egress"],
        "egress": [
            {
                "to": [{"ipBlock": {"cidr": "169.254.170.23/32"}}],
                "ports": [{"protocol": "TCP", "port": 80}],
            }
        ],
    }
    if pod_identity != expected_pod_identity:
        raise W6001Error("Pod Identity egress must be bounded to the credential endpoint")
    ingress = _mapping(by_name["enterprise-ai-api-ingress"].get("spec"), "API ingress")
    ingress_rendered = json.dumps(ingress, sort_keys=True)
    if NAMESPACE not in ingress_rendered or ingress_rendered.count('"port": 8000') != 1:
        raise W6001Error("API ingress must be namespace-local on port 8000")


def _validate_namespace(namespace: dict[str, object]) -> None:
    metadata = _metadata(namespace)
    if metadata != {
        "name": NAMESPACE,
        "labels": {
            "kubernetes.io/metadata.name": NAMESPACE,
            "pod-security.kubernetes.io/enforce": "restricted",
            "pod-security.kubernetes.io/audit": "restricted",
            "pod-security.kubernetes.io/warn": "restricted",
        },
    }:
        raise W6001Error("Namespace identity or restricted pod-security labels differ")


def validate_documents(
    documents: list[dict[str, object]], *, template_mode: bool
) -> tuple[str, str]:
    objects = _objects_by_kind(documents)
    _validate_namespace(objects["Namespace"][0])
    image = _validate_deployment(objects["Deployment"][0], template_mode=template_mode)
    _validate_service(objects["Service"][0])
    _validate_scaling(objects["HorizontalPodAutoscaler"][0], objects["PodDisruptionBudget"][0])
    _validate_network(objects["NetworkPolicy"])
    service_accounts = {
        _mapping(item.get("metadata"), "ServiceAccount metadata").get("name"): item
        for item in objects["ServiceAccount"]
    }
    if set(service_accounts) != {SERVICE_ACCOUNT, INGESTION_SERVICE_ACCOUNT, FIS_SERVICE_ACCOUNT}:
        raise W6001Error("runtime, ingestion, and FIS ServiceAccounts are required")
    if any(
        service_accounts[name].get("automountServiceAccountToken") is not False
        for name in (SERVICE_ACCOUNT, INGESTION_SERVICE_ACCOUNT)
    ):
        raise W6001Error("ServiceAccount token automount must be disabled")
    if service_accounts[FIS_SERVICE_ACCOUNT].get("automountServiceAccountToken") is not True:
        raise W6001Error("FIS ServiceAccount token automount must be enabled")
    fis_role = objects["Role"]
    fis_binding = objects["RoleBinding"]
    if len(fis_role) != 1 or len(fis_binding) != 1:
        raise W6001Error("exactly one FIS Role and RoleBinding are required")
    role_rules = _list(fis_role[0].get("rules"), "FIS Role rules")
    if role_rules != [
        {
            "apiGroups": [""],
            "resources": ["configmaps"],
            "verbs": ["get", "create", "patch", "delete"],
        },
        {
            "apiGroups": [""],
            "resources": ["pods"],
            "verbs": ["create", "list", "get", "delete", "deletecollection"],
        },
        {
            "apiGroups": [""],
            "resources": ["pods/ephemeralcontainers"],
            "verbs": ["update"],
        },
        {
            "apiGroups": [""],
            "resources": ["pods/exec"],
            "verbs": ["create"],
        },
        {
            "apiGroups": ["apps"],
            "resources": ["deployments"],
            "verbs": ["get"],
        },
    ]:
        raise W6001Error("FIS Role permissions differ")
    binding = fis_binding[0]
    if binding.get("roleRef") != {
        "apiGroup": "rbac.authorization.k8s.io",
        "kind": "Role",
        "name": FIS_ROLE,
    }:
        raise W6001Error("FIS RoleBinding roleRef differs")
    if binding.get("subjects") != [
        {"kind": "ServiceAccount", "name": FIS_SERVICE_ACCOUNT, "namespace": NAMESPACE},
        {"apiGroup": "rbac.authorization.k8s.io", "kind": "User", "name": FIS_SERVICE_ACCOUNT},
    ]:
        raise W6001Error("FIS RoleBinding subjects differ")
    configs = [_mapping(item.get("data"), "ConfigMap data") for item in objects["ConfigMap"]]
    config = {key: value for item in configs for key, value in item.items()}
    sensitive = re.compile(r"(?i)(secret|password|token|credential|private.?key|access.?key)")
    if any(sensitive.search(key) or sensitive.search(str(value)) for key, value in config.items()):
        raise W6001Error("ConfigMap contains credential-like content")
    opensearch_endpoint = config.get("ENTERPRISE_AI_OPENSEARCH_URL")
    bedrock_profile = config.get("ENTERPRISE_AI_LLM_MODEL_ID")
    if template_mode:
        if opensearch_endpoint != OPENSEARCH_SENTINEL or bedrock_profile != BEDROCK_SENTINEL:
            raise W6001Error("source template requires exact runtime sentinels")
    else:
        if not isinstance(opensearch_endpoint, str) or not isinstance(bedrock_profile, str):
            raise W6001Error("release runtime bindings are missing")
        parsed_endpoint = urlsplit(opensearch_endpoint)
        if (
            parsed_endpoint.scheme != "https"
            or parsed_endpoint.hostname is None
            or not parsed_endpoint.hostname.endswith(".ap-southeast-1.es.amazonaws.com")
            or parsed_endpoint.path not in {"", "/"}
            or bedrock_profile == BEDROCK_SENTINEL
            or not bedrock_profile.strip()
        ):
            raise W6001Error("release runtime bindings are malformed")
    serialized = json.dumps(documents, sort_keys=True)
    if template_mode:
        if serialized.count(APP_SENTINEL) != 1 or serialized.count(COLLECTOR_SENTINEL) != 1:
            raise W6001Error("source template must contain both exact image sentinels once")
    elif APP_SENTINEL in serialized or COLLECTOR_SENTINEL in serialized:
        raise W6001Error("release package must not contain source sentinels")
    elif "OWNER_BINDING_REQUIRED" in serialized:
        raise W6001Error("release package retains an owner-binding sentinel")
    return image


def validate_template(template_root: Path) -> str:
    documents, _ = load_template(template_root)
    validate_documents(documents, template_mode=True)
    return TEMPLATE_STATUS


def _sha_field(value: object, label: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise W6001Error(f"{label} must be 64 lowercase hexadecimal characters")
    return value


def _identity(value: object, label: str, digest: str) -> dict[str, object]:
    identity = _mapping(value, label)
    if set(identity) != {"image_digest", "sha256"}:
        raise W6001Error(f"{label} fields differ")
    if identity.get("image_digest") != digest:
        raise W6001Error(f"{label} image identity mismatch")
    _sha_field(identity.get("sha256"), f"{label}.sha256")
    return identity


def validate_release_binding(
    binding: dict[str, object],
    *,
    source_template_sha256: str,
    now: datetime | None = None,
) -> tuple[str, str]:
    if set(binding) != RELEASE_KEYS:
        raise W6001Error("release binding fields must exactly match the v2 schema")
    if binding.get("schema_version") != "w6-004.release-binding.v2":
        raise W6001Error("release binding schema version differs")
    repository = binding.get("ecr_repository_uri")
    digest = binding.get("digest")
    account = binding.get("aws_account_id")
    region = binding.get("aws_region")
    if not isinstance(repository, str) or not isinstance(digest, str):
        raise W6001Error("repository URI and digest are required")
    match = ECR_RE.fullmatch(repository)
    if match is None or match.group("repository") != REPOSITORY_NAME:
        raise W6001Error("ECR repository must be the approved repository")
    if match.group("account") != account or match.group("region") != region:
        raise W6001Error("ECR account or Region mismatch")
    if not DIGEST_RE.fullmatch(digest) or digest == "sha256:" + "0" * 64:
        raise W6001Error("digest must be exact lowercase sha256")
    source = _mapping(binding.get("source_identity"), "source_identity")
    if set(source) != {"template_sha256", "source_commit"}:
        raise W6001Error("source_identity fields differ")
    if source.get("template_sha256") != source_template_sha256:
        raise W6001Error("changed source-template identity")
    source_commit = source.get("source_commit")
    if not isinstance(source_commit, str) or not re.fullmatch(r"[0-9a-f]{40}", source_commit):
        raise W6001Error("source_identity.source_commit must be a lowercase Git commit")
    _identity(binding.get("oci_identity"), "oci_identity", digest)
    for scanner in ("trivy", "grype"):
        record = _mapping(binding.get(scanner), scanner)
        if set(record) != {"image_digest", "report_sha256", "result"}:
            raise W6001Error(f"{scanner} fields differ")
        if record.get("image_digest") != digest or record.get("result") != "PASS":
            raise W6001Error(f"{scanner} result or image identity mismatch")
        _sha_field(record.get("report_sha256"), f"{scanner}.report_sha256")
    _sha_field(binding.get("spdx_sbom_sha256"), "spdx_sbom_sha256")
    _sha_field(binding.get("cyclonedx_sbom_sha256"), "cyclonedx_sbom_sha256")
    _identity(binding.get("provenance"), "provenance", digest)
    _identity(binding.get("image_composition_identity"), "image_composition_identity", digest)
    for field in ("w6_01_operation_identity", "owner_approval_identity"):
        value = binding.get(field)
        if not isinstance(value, str) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._:-]{7,127}", value
        ):
            raise W6001Error(f"{field} is missing or malformed")
    expiry = binding.get("expires_at")
    if not isinstance(expiry, str):
        raise W6001Error("expires_at is required")
    try:
        parsed_expiry = datetime.fromisoformat(expiry.replace("Z", "+00:00"))
    except ValueError as exc:
        raise W6001Error("expires_at must be ISO-8601") from exc
    if parsed_expiry.tzinfo is None or parsed_expiry <= (now or datetime.now(UTC)):
        raise W6001Error("owner approval is expired")
    for field in ("allowed_output_root", "output_root"):
        value = binding.get(field)
        if not isinstance(value, str) or not Path(value).is_absolute():
            raise W6001Error(f"{field} must be an absolute external path")
    allowed_output_root = Path(cast(str, binding["allowed_output_root"])).resolve(strict=False)
    output_root = Path(cast(str, binding["output_root"])).resolve(strict=False)
    operation_identity = cast(str, binding["w6_01_operation_identity"])
    if output_root.parent != allowed_output_root or output_root.name != operation_identity:
        raise W6001Error("output_root must be the single-use W6-01 operation directory")
    collector = _mapping(binding.get("collector"), "collector")
    collector_keys = {
        "ecr_repository_uri",
        "digest",
        "oci_identity",
        "trivy",
        "grype",
        "spdx_sbom_sha256",
        "cyclonedx_sbom_sha256",
        "provenance",
        "image_composition_identity",
    }
    if set(collector) != collector_keys:
        raise W6001Error("collector fields differ")
    collector_repository = collector.get("ecr_repository_uri")
    collector_digest = collector.get("digest")
    if not isinstance(collector_repository, str) or not isinstance(collector_digest, str):
        raise W6001Error("collector repository URI and digest are required")
    collector_match = ECR_RE.fullmatch(collector_repository)
    if (
        collector_match is None
        or collector_match.group("repository") != COLLECTOR_REPOSITORY_NAME
        or collector_match.group("account") != account
        or collector_match.group("region") != region
    ):
        raise W6001Error("collector private ECR authority differs")
    if not DIGEST_RE.fullmatch(collector_digest) or collector_digest == "sha256:" + "0" * 64:
        raise W6001Error("collector digest must be exact lowercase sha256")
    _identity(collector.get("oci_identity"), "collector.oci_identity", collector_digest)
    for scanner in ("trivy", "grype"):
        record = _mapping(collector.get(scanner), f"collector.{scanner}")
        if set(record) != {"image_digest", "report_sha256", "result"}:
            raise W6001Error(f"collector.{scanner} fields differ")
        if record.get("image_digest") != collector_digest or record.get("result") != "PASS":
            raise W6001Error(f"collector.{scanner} result or image identity mismatch")
        _sha_field(record.get("report_sha256"), f"collector.{scanner}.report_sha256")
    for field in ("spdx_sbom_sha256", "cyclonedx_sbom_sha256"):
        _sha_field(collector.get(field), f"collector.{field}")
    _identity(collector.get("provenance"), "collector.provenance", collector_digest)
    _identity(
        collector.get("image_composition_identity"),
        "collector.image_composition_identity",
        collector_digest,
    )
    runtime = _mapping(binding.get("runtime"), "runtime")
    if set(runtime) != {
        "opensearch_endpoint",
        "bedrock_model_id",
        "bedrock_inference_profile",
        "embedding_snapshot_sha256",
    }:
        raise W6001Error("runtime fields differ")
    endpoint = runtime.get("opensearch_endpoint")
    model_id = runtime.get("bedrock_model_id")
    inference_profile = runtime.get("bedrock_inference_profile")
    if not all(
        isinstance(item, str) and item.strip() for item in (endpoint, model_id, inference_profile)
    ):
        raise W6001Error("runtime endpoint and Bedrock identities are required")
    parsed_endpoint = urlsplit(cast(str, endpoint))
    if (
        parsed_endpoint.scheme != "https"
        or parsed_endpoint.hostname is None
        or not parsed_endpoint.hostname.endswith(".ap-southeast-1.es.amazonaws.com")
        or parsed_endpoint.path not in {"", "/"}
        or BEDROCK_SENTINEL in {model_id, inference_profile}
    ):
        raise W6001Error("runtime endpoint or Bedrock identity differs")
    _sha_field(runtime.get("embedding_snapshot_sha256"), "runtime.embedding_snapshot_sha256")
    return f"{repository}@{digest}", f"{collector_repository}@{collector_digest}"


def build_release_files(
    payloads: dict[str, bytes],
    binding: dict[str, object],
    images: tuple[str, str],
    *,
    binding_input_sha256: str | None = None,
) -> dict[str, bytes]:
    runtime = _mapping(binding.get("runtime"), "runtime")
    files, rendered_documents = _substitute_release_templates(
        payloads,
        images,
        cast(str, runtime["opensearch_endpoint"]),
        cast(str, runtime["bedrock_inference_profile"]),
    )
    rendered_documents.sort(
        key=lambda item: (
            str(item.get("apiVersion")),
            str(item.get("kind")),
            str(_metadata(item).get("name")),
        )
    )
    files["rendered.json"] = _canonical_json(rendered_documents)
    files["release-binding.json"] = _canonical_json(binding)
    hashes = {name: _sha256(payload) for name, payload in sorted(files.items())}
    files["release-hashes.json"] = _canonical_json(
        {
            "schema_version": "w6-004.release-hashes.v2",
            "binding_input_sha256": binding_input_sha256 or _sha256(_canonical_json(binding)),
            "source_template_files": {
                name: _sha256(payload) for name, payload in sorted(payloads.items())
            },
            "output_files": hashes,
        }
    )
    return files


def _substitute_release_templates(
    payloads: dict[str, bytes],
    images: tuple[str, str],
    opensearch_endpoint: str,
    bedrock_profile: str,
) -> tuple[dict[str, bytes], list[dict[str, object]]]:
    """One fixed substitution implementation shared by the two explicit contracts."""
    files: dict[str, bytes] = {}
    rendered_documents: list[dict[str, object]] = []
    app_occurrences = 0
    collector_occurrences = 0
    app_image, collector_image = images
    for name, payload in payloads.items():
        app_occurrences += payload.count(APP_SENTINEL.encode())
        collector_occurrences += payload.count(COLLECTOR_SENTINEL.encode())
        replaced = payload.replace(APP_SENTINEL.encode(), app_image.encode())
        replaced = replaced.replace(COLLECTOR_SENTINEL.encode(), collector_image.encode())
        if name == "configmap.yaml":
            replaced = replaced.replace(OPENSEARCH_SENTINEL.encode(), opensearch_endpoint.encode())
            replaced = replaced.replace(
                b"ENTERPRISE_AI_LLM_MODEL_ID: OWNER_BINDING_REQUIRED",
                f"ENTERPRISE_AI_LLM_MODEL_ID: {bedrock_profile}".encode(),
            )
        if name == "deployment.yaml":
            replaced = replaced.replace(b"w6-001-source-template", b"w6-001-release-package")
            replaced = replaced.replace(b'deployable: "false"', b'deployable: "true"')
            replaced = replaced.replace(
                b"  annotations:\n"
                b"    checkov.io/skip1: CKV_K8S_43=Both images are non-deployable source "
                b"sentinels; release validation requires immutable digests.\n",
                b"",
            )
        files[name] = replaced
        if name != "kustomization.yaml":
            parsed = list(yaml.load_all(replaced.decode("utf-8"), Loader=UniqueSafeLoader))
            rendered_documents.extend(
                cast(dict[str, object], item) for item in parsed if item is not None
            )
    if app_occurrences != 1 or collector_occurrences != 1:
        raise W6001Error("release binding must replace both reserved sentinels exactly once")
    return files, rendered_documents


@dataclass(frozen=True, slots=True)
class W12RenderBindings:
    application_image: str
    otel_collector_image: str
    opensearch_https_endpoint: str
    bedrock_inference_profile_arn: str
    release_record_sha256: str
    render_inputs_sha256: str
    w6_release_hashes_sha256: str


class _W12NoAliasDumper(yaml.SafeDumper):  # type: ignore[misc]
    def ignore_aliases(self, data: object) -> bool:
        return True


def _w12_annotate(document: dict[str, object], digests: dict[str, str]) -> None:
    if document.get("kind") == "List":
        for item in _list(document.get("items"), "List items"):
            _w12_annotate(_mapping(item, "List object"), digests)
        return
    metadata = _metadata(document)
    annotations = metadata.setdefault("annotations", {})
    if not isinstance(annotations, dict):
        raise W6001Error("W12 annotation metadata is malformed")
    for name, value in digests.items():
        if name in annotations and annotations[name] != value:
            raise W6001Error("W12 provenance annotation conflicts")
        annotations[name] = value
    spec = document.get("spec")
    if isinstance(spec, dict) and isinstance(spec.get("template"), dict):
        template = cast(dict[str, object], spec["template"])
        pod_metadata = template.setdefault("metadata", {})
        if not isinstance(pod_metadata, dict):
            raise W6001Error("W12 pod-template metadata is malformed")
        pod_annotations = pod_metadata.setdefault("annotations", {})
        if not isinstance(pod_annotations, dict):
            raise W6001Error("W12 pod-template annotations are malformed")
        for name, value in digests.items():
            if name in pod_annotations and pod_annotations[name] != value:
                raise W6001Error("W12 pod-template provenance annotation conflicts")
            pod_annotations[name] = value


def render_w12_release(*, source_root: Path, bindings: W12RenderBindings) -> dict[str, bytes]:
    """Pure W12 rendering path; W6 v2 binding and output contracts stay separate."""
    if not isinstance(bindings, W12RenderBindings):
        raise W6001Error("W12 render bindings are required")
    image_re = re.compile(
        r"[a-z0-9][a-z0-9.-]*(?::[0-9]{1,5})?/[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}\Z"
    )
    for image in (bindings.application_image, bindings.otel_collector_image):
        if (
            not isinstance(image, str)
            or not image_re.fullmatch(image)
            or any(c.isspace() for c in image)
        ):
            raise W6001Error("W12 immutable image binding is invalid")
    endpoint = bindings.opensearch_https_endpoint
    if not isinstance(endpoint, str):
        raise W6001Error("W12 OpenSearch HTTPS origin is invalid")
    parsed = urlsplit(endpoint)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.hostname != parsed.hostname.lower()
        or parsed.username
        or parsed.password
        or parsed.netloc != parsed.hostname
        or parsed.path
        or parsed.query
        or parsed.fragment
        or endpoint != f"https://{parsed.hostname}"
    ):
        raise W6001Error("W12 OpenSearch HTTPS origin is invalid")
    profile = bindings.bedrock_inference_profile_arn
    if not isinstance(profile, str) or not re.fullmatch(
        r"arn:(?:aws|aws-us-gov|aws-cn):bedrock:[a-z0-9-]+:(?:[0-9]{12})?:inference-profile/[A-Za-z0-9._-]+",
        profile,
    ):
        raise W6001Error("W12 Bedrock inference profile is invalid")
    for value in (
        bindings.release_record_sha256,
        bindings.render_inputs_sha256,
        bindings.w6_release_hashes_sha256,
    ):
        if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
            raise W6001Error("W12 provenance digest is invalid")
    if not source_root.is_dir() or source_root.is_symlink():
        raise W6001Error("W12 source root is invalid")
    for name in TEMPLATE_FILES:
        path = source_root / name
        if (
            path.is_symlink()
            or not path.is_file()
            or path.resolve().parent != source_root.resolve()
        ):
            raise W6001Error("W12 source template path is unsafe")
    source_documents, payloads = load_template(source_root)
    validate_documents(source_documents, template_mode=True)
    files, _ = _substitute_release_templates(
        payloads,
        (bindings.application_image, bindings.otel_collector_image),
        endpoint,
        profile,
    )
    annotations = {
        "enterprise.ai/release-record-sha256": bindings.release_record_sha256,
        "enterprise.ai/render-inputs-sha256": bindings.render_inputs_sha256,
        "enterprise.ai/w6-release-hashes-sha256": bindings.w6_release_hashes_sha256,
    }
    rendered: dict[str, bytes] = {}
    for name in sorted(files):
        if name == "kustomization.yaml":
            continue
        try:
            documents = list(yaml.load_all(files[name].decode("utf-8"), Loader=UniqueSafeLoader))
        except (UnicodeDecodeError, yaml.YAMLError, TypeError) as exc:
            raise W6001Error("W12 Kubernetes object is malformed") from exc
        if not documents or any(not isinstance(item, dict) for item in documents):
            raise W6001Error("W12 Kubernetes object is malformed")
        for document in documents:
            _w12_annotate(cast(dict[str, object], document), annotations)
        text = yaml.dump_all(
            documents, Dumper=_W12NoAliasDumper, sort_keys=True, allow_unicode=True
        )
        output = text.replace("\r\n", "\n").rstrip("\n") + "\n"
        if (
            "OWNER_BINDING_REQUIRED" in output
            or APP_SENTINEL in output
            or COLLECTOR_SENTINEL in output
            or re.search(r"\$\{[^}]+\}|\{\{[^}]+\}\}|__[A-Z0-9_]+__", output)
        ):
            raise W6001Error("W12 unresolved source placeholder")
        rendered[name] = output.encode("utf-8")
    if not rendered or len({name.casefold() for name in rendered}) != len(rendered):
        raise W6001Error("W12 rendered output set is invalid")
    return rendered


def bind_release(template_root: Path, binding_path: Path, repository_root: Path) -> Path:
    documents, payloads = load_template(template_root)
    validate_documents(documents, template_mode=True)
    binding = _strict_json(binding_path)
    images = validate_release_binding(binding, source_template_sha256=template_identity(payloads))
    output_root = Path(cast(str, binding["output_root"]))
    allowed_root = Path(cast(str, binding["allowed_output_root"]))
    repository = repository_root.resolve(strict=False)
    resolved_binding = binding_path.resolve(strict=True)
    if resolved_binding.parent != allowed_root.resolve(strict=False):
        raise W6001Error("binding input must be a direct child of the approved external root")
    if resolved_binding == repository or repository in resolved_binding.parents:
        raise W6001Error("binding input must be outside the Git working tree")
    release_files = build_release_files(
        payloads,
        binding,
        images,
        binding_input_sha256=_sha256(binding_path.read_bytes()),
    )
    reserve_operation_directory(output_root, allowed_root, repository_root)
    try:
        for name, payload in sorted(release_files.items()):
            target = output_root / name
            with target.open("xb") as stream:
                stream.write(payload)
        validate_release(
            output_root,
            template_root=template_root,
            binding_path=output_root / "release-binding.json",
        )
    except Exception:
        # Fail closed without adopting, repairing, or deleting the reserved operation directory.
        raise
    return output_root


def validate_release(
    release_root: Path,
    *,
    template_root: Path,
    binding_path: Path | None = None,
) -> str:
    verify_private_directory(release_root)
    documents, payloads = load_template(release_root)
    images = validate_documents(documents, template_mode=False)
    binding = _strict_json(binding_path or release_root / "release-binding.json")
    source_identity = _mapping(binding.get("source_identity"), "source_identity")
    source_hash = source_identity.get("template_sha256")
    if not isinstance(source_hash, str):
        raise W6001Error("source template identity is missing")
    _, source_payloads = load_template(template_root)
    if template_identity(source_payloads) != source_hash:
        raise W6001Error("changed source-template identity")
    expected_images = validate_release_binding(binding, source_template_sha256=source_hash)
    if images != expected_images:
        raise W6001Error("release images do not match binding")
    runtime = _mapping(binding.get("runtime"), "runtime")
    config_document = next(
        item
        for item in documents
        if item.get("kind") == "ConfigMap"
        and _metadata(item).get("name") == "enterprise-ai-runtime"
    )
    config_data = _mapping(config_document.get("data"), "runtime ConfigMap data")
    if config_data.get("ENTERPRISE_AI_OPENSEARCH_URL") != runtime.get(
        "opensearch_endpoint"
    ) or config_data.get("ENTERPRISE_AI_LLM_MODEL_ID") != runtime.get("bedrock_inference_profile"):
        raise W6001Error("release runtime bindings do not match the binding contract")
    hashes_path = release_root / "release-hashes.json"
    hashes = _strict_json(hashes_path)
    if set(hashes) != {
        "schema_version",
        "binding_input_sha256",
        "source_template_files",
        "output_files",
    }:
        raise W6001Error("release hash fields differ")
    if hashes.get("schema_version") != "w6-004.release-hashes.v2":
        raise W6001Error("release hash schema differs")
    recorded = _mapping(hashes.get("output_files"), "release hashes")
    expected_names = set(TEMPLATE_FILES) | {"rendered.json", "release-binding.json"}
    if set(recorded) != expected_names:
        raise W6001Error("release hash inventory differs")
    source_hashes = _mapping(hashes.get("source_template_files"), "source template hashes")
    if source_hashes != {
        name: _sha256(payload) for name, payload in sorted(source_payloads.items())
    }:
        raise W6001Error("source template file identity differs")
    _sha_field(hashes.get("binding_input_sha256"), "binding_input_sha256")
    for name in expected_names:
        if recorded.get(name) != _sha256((release_root / name).read_bytes()):
            raise W6001Error(f"release file hash mismatch: {name}")
    canonical_documents = sorted(
        documents,
        key=lambda item: (
            str(item.get("apiVersion")),
            str(item.get("kind")),
            str(_metadata(item).get("name")),
        ),
    )
    if (release_root / "rendered.json").read_bytes() != _canonical_json(canonical_documents):
        raise W6001Error("canonical render differs from the release manifests")
    joined = b"".join(payloads.values())
    if APP_SENTINEL.encode() in joined or COLLECTOR_SENTINEL.encode() in joined:
        raise W6001Error("release package retains a sentinel")
    return RELEASE_STATUS


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    template = subparsers.add_parser("validate-template")
    template.add_argument("--template-root", type=Path, required=True)
    bind = subparsers.add_parser("bind-release")
    bind.add_argument("--template-root", type=Path, required=True)
    bind.add_argument("--binding", type=Path, required=True)
    bind.add_argument("--repository-root", type=Path, required=True)
    release = subparsers.add_parser("validate-release")
    release.add_argument("--release-root", type=Path, required=True)
    release.add_argument("--template-root", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "validate-template":
            print(validate_template(arguments.template_root))
        elif arguments.command == "bind-release":
            output = bind_release(
                arguments.template_root,
                arguments.binding,
                arguments.repository_root,
            )
            print(f"RELEASE PACKAGE CREATED: {output}")
        else:
            print(validate_release(arguments.release_root, template_root=arguments.template_root))
    except (W6001Error, ContractError, OSError) as exc:
        print(f"W6-001 VALIDATION FAILED: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
