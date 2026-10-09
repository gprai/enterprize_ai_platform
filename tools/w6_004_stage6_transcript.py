"""Render and execute a synthetic-only W6-004 Stage 6 transcript Job."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import sys
import time
import uuid
from pathlib import Path
from typing import Any

import httpx

SCHEMA_VERSION = "w6-004.stage6-transcript.v1"
BASE_URL = "http://enterprise-ai-api.enterprise-ai-sandbox.svc.cluster.local:8000"
KEY_PATH = "/var/run/secrets/enterprise-ai/sandbox-auth-signing-key"
IMAGE_PATTERN = re.compile(
    r"^[0-9]{12}\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com/.+@sha256:[0-9a-f]{64}$"
)
OPERATION_PATTERN = re.compile(r"^stage6-transcript-[0-9]{3}$")
DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
MAX_TRANSCRIPT_BYTES = 131_072


class TranscriptError(RuntimeError):
    """Raised when transcript creation or validation fails closed."""


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _encode(value: dict[str, object]) -> str:
    raw = canonical_json(value).encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _token(*, tenant: str, signing_key: bytes) -> str:
    now = int(time.time())
    header = _encode({"alg": "HS256", "typ": "JWT"})
    claims = _encode(
        {
            "iss": os.environ["ENTERPRISE_AI_SANDBOX_AUTH_ISSUER"],
            "aud": os.environ["ENTERPRISE_AI_SANDBOX_AUTH_AUDIENCE"],
            "sub": "stage6-transcript-validator",
            "tenant_id": tenant,
            "roles": ["reader"],
            "clearance": "INTERNAL",
            "iat": now,
            "nbf": now,
            "exp": now + 600,
            "jti": str(uuid.uuid4()),
            "data_classification": "INTERNAL",
        }
    )
    signing_input = f"{header}.{claims}".encode("ascii")
    signature = (
        base64.urlsafe_b64encode(hmac.new(signing_key, signing_input, hashlib.sha256).digest())
        .rstrip(b"=")
        .decode("ascii")
    )
    return f"{header}.{claims}.{signature}"


def synthetic_questions(operation_identity: str) -> dict[str, str]:
    if not OPERATION_PATTERN.fullmatch(operation_identity):
        raise TranscriptError("operation identity is not approved")
    return {
        "grounded": (
            f"Synthetic evidence operation {operation_identity}: "
            "what is the exact W6-004 Stage 6 accessible synthetic marker?"
        ),
        "abstention": (
            f"Synthetic evidence operation {operation_identity}: return the synthetic fact "
            "STAGE6-FACT-THAT-DOES-NOT-EXIST-4f2d9a."
        ),
    }


def validate_transcript(value: object, *, operation_identity: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise TranscriptError("transcript must be an object")
    required = {
        "schema_version",
        "operation_identity",
        "model_id",
        "application_image",
        "started_at",
        "completed_at",
        "tests",
    }
    if set(value) != required:
        raise TranscriptError("transcript fields differ")
    if value["schema_version"] != SCHEMA_VERSION:
        raise TranscriptError("transcript schema differs")
    if value["operation_identity"] != operation_identity:
        raise TranscriptError("transcript operation differs")
    if value["model_id"] != "global.amazon.nova-2-lite-v1:0":
        raise TranscriptError("transcript model differs")
    image = value["application_image"]
    if not isinstance(image, str) or not IMAGE_PATTERN.fullmatch(image):
        raise TranscriptError("application image is not immutable")
    tests = value["tests"]
    if not isinstance(tests, list) or len(tests) != 2:
        raise TranscriptError("transcript must contain two tests")
    expected_questions = synthetic_questions(operation_identity)
    expected = (("grounded", "answered"), ("abstention", "abstained"))
    for item, (test_id, outcome) in zip(tests, expected, strict=True):
        if not isinstance(item, dict):
            raise TranscriptError("test record must be an object")
        if item.get("test_id") != test_id:
            raise TranscriptError("test order or identity differs")
        if item.get("question") != expected_questions[test_id]:
            raise TranscriptError("test question differs")
        response = item.get("response")
        if not isinstance(response, dict) or response.get("outcome") != outcome:
            raise TranscriptError("test response differs")
        if not isinstance(response.get("request_id"), str):
            raise TranscriptError("application request ID is absent")
        if test_id == "grounded":
            if not isinstance(response.get("answer"), str) or not response["answer"].strip():
                raise TranscriptError("grounded answer is absent")
            citations = response.get("citations")
            if not isinstance(citations, list) or not citations:
                raise TranscriptError("grounded citations are absent")
            usage = response.get("usage")
            if not isinstance(usage, dict) or not isinstance(usage.get("total_tokens"), int):
                raise TranscriptError("grounded token usage is absent")
        elif not isinstance(response.get("reason"), str):
            raise TranscriptError("abstention reason is absent")
    serialized = canonical_json(value)
    if len(serialized.encode("utf-8")) > MAX_TRANSCRIPT_BYTES:
        raise TranscriptError("transcript exceeds the bounded size")
    forbidden = ("authorization", "bearer ", "sandbox-auth-signing-key", "access_key")
    lowered = serialized.casefold()
    if any(token in lowered for token in forbidden):
        raise TranscriptError("transcript contains protected material")
    return value


def execute() -> int:
    operation_identity = os.environ["STAGE6_OPERATION_IDENTITY"]
    questions = synthetic_questions(operation_identity)
    signing_key = Path(KEY_PATH).read_bytes().strip()
    if len(signing_key) < 32:
        raise TranscriptError("signing key is invalid")
    tenant = os.environ["ENTERPRISE_AI_SANDBOX_AUTH_TENANT_ID"]
    headers = {
        "Authorization": f"Bearer {_token(tenant=tenant, signing_key=signing_key)}",
        "Content-Type": "application/json",
    }
    started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    records: list[dict[str, object]] = []
    with httpx.Client(timeout=120.0) as client:
        for test_id in ("grounded", "abstention"):
            response = client.post(
                f"{BASE_URL}/v1/query",
                headers=headers,
                json={"query": questions[test_id]},
            )
            if response.status_code != 200:
                raise TranscriptError(f"{test_id} request returned HTTP {response.status_code}")
            body = response.json()
            if not isinstance(body, dict):
                raise TranscriptError(f"{test_id} response is not an object")
            records.append(
                {
                    "test_id": test_id,
                    "question": questions[test_id],
                    "response": body,
                }
            )
    transcript: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "operation_identity": operation_identity,
        "model_id": os.environ["ENTERPRISE_AI_LLM_MODEL_ID"],
        "application_image": os.environ["STAGE6_APPLICATION_IMAGE"],
        "started_at": started_at,
        "completed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "tests": records,
    }
    validate_transcript(transcript, operation_identity=operation_identity)
    serialized = canonical_json(transcript)
    encoded = base64.b64encode(serialized.encode("utf-8")).decode("ascii")
    print(f"STAGE6_TRANSCRIPT_BASE64={encoded}", flush=True)
    print(f"STAGE6_TRANSCRIPT_SHA256={sha256_text(serialized)}", flush=True)
    print("STAGE6_SYNTHETIC_TRANSCRIPT_RESULT=PASS", flush=True)
    return 0


def build_package(
    *,
    operation_identity: str,
    application_image: str,
    mutation_deadline: str,
    service_cluster_ip: str,
) -> dict[str, object]:
    synthetic_questions(operation_identity)
    if not IMAGE_PATTERN.fullmatch(application_image):
        raise TranscriptError("application image is not immutable")
    source = Path(__file__).read_text(encoding="utf-8")
    name = f"enterprise-ai-{operation_identity}"
    common_metadata: dict[str, Any] = {
        "name": name,
        "namespace": "enterprise-ai-sandbox",
        "labels": {
            "app.kubernetes.io/name": "enterprise-ai-stage6-transcript",
            "app.kubernetes.io/part-of": "enterprise-ai-platform",
            "enterprise-ai-platform/operation": operation_identity,
        },
        "annotations": {
            "enterprise-ai-platform/application-digest": application_image.rsplit("@", 1)[1],
            "enterprise-ai-platform/mutation-deadline": mutation_deadline,
        },
    }
    pod_labels = dict(common_metadata["labels"])
    return {
        "apiVersion": "v1",
        "kind": "List",
        "items": [
            {
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": common_metadata,
                "immutable": True,
                "data": {"w6_004_stage6_transcript.py": source},
            },
            {
                "apiVersion": "networking.k8s.io/v1",
                "kind": "NetworkPolicy",
                "metadata": common_metadata,
                "spec": {
                    "podSelector": {"matchLabels": pod_labels},
                    "policyTypes": ["Egress"],
                    "egress": [
                        {
                            "to": [
                                {
                                    "namespaceSelector": {
                                        "matchLabels": {
                                            "kubernetes.io/metadata.name": "kube-system"
                                        }
                                    },
                                    "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}},
                                }
                            ],
                            "ports": [
                                {"port": 53, "protocol": "UDP"},
                                {"port": 53, "protocol": "TCP"},
                            ],
                        },
                        {
                            "to": [{"ipBlock": {"cidr": f"{service_cluster_ip}/32"}}],
                            "ports": [{"port": 8000, "protocol": "TCP"}],
                        },
                    ],
                },
            },
            {
                "apiVersion": "batch/v1",
                "kind": "Job",
                "metadata": common_metadata,
                "spec": {
                    "backoffLimit": 0,
                    "activeDeadlineSeconds": 600,
                    "ttlSecondsAfterFinished": 3600,
                    "template": {
                        "metadata": {"labels": pod_labels},
                        "spec": {
                            "serviceAccountName": "enterprise-ai-runtime",
                            "restartPolicy": "Never",
                            "automountServiceAccountToken": False,
                            "securityContext": {
                                "runAsNonRoot": True,
                                "runAsUser": 65532,
                                "runAsGroup": 65532,
                                "fsGroup": 65532,
                                "seccompProfile": {"type": "RuntimeDefault"},
                            },
                            "containers": [
                                {
                                    "name": "validation",
                                    "image": application_image,
                                    "imagePullPolicy": "Always",
                                    "workingDir": "/app",
                                    "command": [
                                        "python",
                                        "-B",
                                        "/stage6/w6_004_stage6_transcript.py",
                                        "run",
                                    ],
                                    "envFrom": [
                                        {"configMapRef": {"name": "enterprise-ai-runtime"}}
                                    ],
                                    "env": [
                                        {
                                            "name": "STAGE6_OPERATION_IDENTITY",
                                            "value": operation_identity,
                                        },
                                        {
                                            "name": "STAGE6_APPLICATION_IMAGE",
                                            "value": application_image,
                                        },
                                    ],
                                    "resources": {
                                        "requests": {"cpu": "250m", "memory": "512Mi"},
                                        "limits": {"cpu": "1000m", "memory": "2Gi"},
                                    },
                                    "securityContext": {
                                        "allowPrivilegeEscalation": False,
                                        "readOnlyRootFilesystem": True,
                                        "capabilities": {"drop": ["ALL"]},
                                    },
                                    "volumeMounts": [
                                        {
                                            "name": "script",
                                            "mountPath": "/stage6",
                                            "readOnly": True,
                                        },
                                        {
                                            "name": "tmp",
                                            "mountPath": "/tmp",  # noqa: S108 -- pod-local EmptyDir
                                        },
                                        {
                                            "name": "sandbox-auth-signing-key",
                                            "mountPath": "/var/run/secrets/enterprise-ai",
                                            "readOnly": True,
                                        },
                                    ],
                                }
                            ],
                            "volumes": [
                                {"name": "script", "configMap": {"name": name}},
                                {"name": "tmp", "emptyDir": {"sizeLimit": "256Mi"}},
                                {
                                    "name": "sandbox-auth-signing-key",
                                    "secret": {
                                        "secretName": "enterprise-ai-runtime-secrets",
                                        "defaultMode": 288,
                                        "items": [
                                            {
                                                "key": "sandbox-auth-signing-key",
                                                "path": "sandbox-auth-signing-key",
                                            }
                                        ],
                                    },
                                },
                            ],
                        },
                    },
                },
            },
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="mode", required=True)
    subparsers.add_parser("run")
    render = subparsers.add_parser("render")
    render.add_argument("--operation-identity", required=True)
    render.add_argument("--application-image", required=True)
    render.add_argument("--mutation-deadline", required=True)
    render.add_argument("--service-cluster-ip", required=True)
    render.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.mode == "run":
        return execute()
    package = build_package(
        operation_identity=args.operation_identity,
        application_image=args.application_image,
        mutation_deadline=args.mutation_deadline,
        service_cluster_ip=args.service_cluster_ip,
    )
    if args.output.exists():
        raise TranscriptError("transcript package destination already exists")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    rendered = canonical_json(package)
    args.output.write_text(rendered, encoding="utf-8")
    print(f"STAGE6_TRANSCRIPT_PACKAGE={args.output}")
    print(f"STAGE6_TRANSCRIPT_PACKAGE_SHA256={sha256_text(rendered)}")
    print("KUBERNETES_MUTATION=NOT_RUN")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, TranscriptError, httpx.HTTPError) as error:
        print(f"STAGE6_TRANSCRIPT_ERROR={error}", file=sys.stderr)
        raise SystemExit(1) from None
