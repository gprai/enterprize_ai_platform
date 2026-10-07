"""Unit coverage for the offline W6-001 source-template and release binder."""

from __future__ import annotations

import copy
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml
from tools import w6_001_k8s

ROOT = Path(__file__).resolve().parents[2]
TEMPLATE_ROOT = ROOT / "deploy/k8s"
DIGEST = "sha256:" + "a" * 64
COLLECTOR_DIGEST = "sha256:" + "d" * 64
SHA = "b" * 64


def valid_binding(output_root: Path, allowed_root: Path) -> dict[str, object]:
    _, payloads = w6_001_k8s.load_template(TEMPLATE_ROOT)
    return {
        "schema_version": "w6-004.release-binding.v2",
        "ecr_repository_uri": (
            "526338061652.dkr.ecr.ap-southeast-1.amazonaws.com/enterprise-ai/sandbox/api"
        ),
        "digest": DIGEST,
        "aws_account_id": "526338061652",
        "aws_region": "ap-southeast-1",
        "source_identity": {
            "template_sha256": w6_001_k8s.template_identity(payloads),
            "source_commit": "c" * 40,
        },
        "oci_identity": {"image_digest": DIGEST, "sha256": SHA},
        "trivy": {"image_digest": DIGEST, "report_sha256": SHA, "result": "PASS"},
        "grype": {"image_digest": DIGEST, "report_sha256": SHA, "result": "PASS"},
        "spdx_sbom_sha256": SHA,
        "cyclonedx_sbom_sha256": SHA,
        "provenance": {"image_digest": DIGEST, "sha256": SHA},
        "image_composition_identity": {"image_digest": DIGEST, "sha256": SHA},
        "w6_01_operation_identity": output_root.name,
        "owner_approval_identity": "owner-approval-0001",
        "expires_at": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
        "allowed_output_root": str(allowed_root.resolve()),
        "output_root": str(output_root.resolve()),
        "collector": {
            "ecr_repository_uri": (
                "526338061652.dkr.ecr.ap-southeast-1.amazonaws.com/enterprise-ai/sandbox/api"
            ),
            "digest": COLLECTOR_DIGEST,
            "oci_identity": {"image_digest": COLLECTOR_DIGEST, "sha256": SHA},
            "trivy": {
                "image_digest": COLLECTOR_DIGEST,
                "report_sha256": SHA,
                "result": "PASS",
            },
            "grype": {
                "image_digest": COLLECTOR_DIGEST,
                "report_sha256": SHA,
                "result": "PASS",
            },
            "spdx_sbom_sha256": SHA,
            "cyclonedx_sbom_sha256": SHA,
            "provenance": {"image_digest": COLLECTOR_DIGEST, "sha256": SHA},
            "image_composition_identity": {
                "image_digest": COLLECTOR_DIGEST,
                "sha256": SHA,
            },
        },
        "runtime": {
            "opensearch_endpoint": (
                "https://search-enterprise-ai-sandbox.example.ap-southeast-1.es.amazonaws.com"
            ),
            "bedrock_model_id": "global.amazon.nova-2-lite-v1:0",
            "bedrock_inference_profile": "global.amazon.nova-2-lite-v1:0",
            "embedding_snapshot_sha256": SHA,
        },
    }


def template_documents() -> list[dict[str, object]]:
    documents, _ = w6_001_k8s.load_template(TEMPLATE_ROOT)
    return documents


def deployment(documents: list[dict[str, object]]) -> dict[str, object]:
    return next(document for document in documents if document["kind"] == "Deployment")


def test_exact_sentinel_is_accepted_only_in_template_mode() -> None:
    assert w6_001_k8s.validate_template(TEMPLATE_ROOT) == w6_001_k8s.TEMPLATE_STATUS
    documents = copy.deepcopy(template_documents())
    labels = deployment(documents)["metadata"]["labels"]  # type: ignore[index]
    labels["enterprise-ai.vayunetrix.com/artifact-type"] = "w6-001-release-package"
    labels["enterprise-ai.vayunetrix.com/deployable"] = "true"
    with pytest.raises(w6_001_k8s.W6001Error, match="release mode"):
        w6_001_k8s.validate_documents(documents, template_mode=False)


@pytest.mark.parametrize(
    "image",
    [
        "enterprise-ai.invalid/w6-001:owner_binding_required",
        " enterprise-ai.invalid/w6-001:OWNER_BINDING_REQUIRED",
        "enterprise-ai.invalid/w6-001:OWNER_BINDING_REQUIRED ",
        "repository:latest",
        "repository:TODO",
        "sha256:" + "0" * 64,
        "${W6_IMAGE}",
    ],
)
def test_every_other_unresolved_image_is_rejected(image: str) -> None:
    documents = copy.deepcopy(template_documents())
    deployment(documents)["spec"]["template"]["spec"]["containers"][0]["image"] = image  # type: ignore[index]
    with pytest.raises(w6_001_k8s.W6001Error, match="exact reserved sentinel"):
        w6_001_k8s.validate_documents(documents, template_mode=True)


def test_third_container_and_multiple_sentinels_are_rejected() -> None:
    documents = copy.deepcopy(template_documents())
    containers = deployment(documents)["spec"]["template"]["spec"]["containers"]  # type: ignore[index]
    containers.append(copy.deepcopy(containers[0]))
    with pytest.raises(w6_001_k8s.W6001Error, match="exactly the api and telemetry"):
        w6_001_k8s.validate_documents(documents, template_mode=True)


def test_duplicate_yaml_key_and_unsafe_tag_are_rejected(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.yaml"
    duplicate.write_text("apiVersion: v1\nkind: ConfigMap\nkind: Secret\n", encoding="utf-8")
    with pytest.raises(w6_001_k8s.W6001Error, match="duplicate YAML key"):
        w6_001_k8s.load_documents(duplicate)
    unsafe = tmp_path / "unsafe.yaml"
    unsafe.write_text(
        "value: !!python/object/apply:os.system ['echo forbidden']\n",
        encoding="utf-8",
    )
    with pytest.raises(w6_001_k8s.W6001Error, match="invalid YAML"):
        w6_001_k8s.load_documents(unsafe)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("digest", "sha256:" + "A" * 64, "lowercase"),
        ("digest", "sha256:" + "a" * 63, "lowercase"),
        ("digest", "sha256:" + "a" * 65, "lowercase"),
        ("digest", "sha256:" + "0" * 64, "lowercase"),
        ("aws_account_id", "000000000000", "account or Region"),
        ("aws_region", "us-east-1", "account or Region"),
        (
            "ecr_repository_uri",
            "526338061652.dkr.ecr.ap-southeast-1.amazonaws.com/wrong",
            "approved repository",
        ),
    ],
)
def test_binding_rejects_wrong_image_authority(
    tmp_path: Path, field: str, value: str, message: str
) -> None:
    binding = valid_binding(tmp_path / "operation", tmp_path)
    binding[field] = value
    with pytest.raises(w6_001_k8s.W6001Error, match=message):
        w6_001_k8s.validate_release_binding(
            binding,
            source_template_sha256=binding["source_identity"]["template_sha256"],  # type: ignore[index]
        )


@pytest.mark.parametrize(
    "field",
    ["oci_identity", "trivy", "grype", "provenance", "image_composition_identity"],
)
def test_binding_rejects_every_image_identity_mismatch(tmp_path: Path, field: str) -> None:
    binding = valid_binding(tmp_path / "operation", tmp_path)
    binding[field]["image_digest"] = "sha256:" + "c" * 64  # type: ignore[index]
    with pytest.raises(w6_001_k8s.W6001Error, match="mismatch"):
        w6_001_k8s.validate_release_binding(
            binding,
            source_template_sha256=binding["source_identity"]["template_sha256"],  # type: ignore[index]
        )


@pytest.mark.parametrize(
    "repository",
    [
        "public.ecr.aws/aws-observability/aws-otel-collector",
        "public.ecr.aws/aws-observability/wrong",
        "docker.io/aws-observability/aws-otel-collector",
        "526338061652.dkr.ecr.ap-southeast-1.amazonaws.com/enterprise-ai/sandbox/otel-collector",
        "111122223333.dkr.ecr.ap-southeast-1.amazonaws.com/enterprise-ai/sandbox/api",
        "526338061652.dkr.ecr.us-east-1.amazonaws.com/enterprise-ai/sandbox/api",
    ],
)
def test_binding_rejects_unapproved_collector_repository(tmp_path: Path, repository: str) -> None:
    binding = valid_binding(tmp_path / "operation", tmp_path)
    binding["collector"]["ecr_repository_uri"] = repository  # type: ignore[index]
    with pytest.raises(w6_001_k8s.W6001Error, match="private ECR authority"):
        w6_001_k8s.validate_release_binding(
            binding,
            source_template_sha256=binding["source_identity"]["template_sha256"],  # type: ignore[index]
        )


@pytest.mark.parametrize("digest", ["latest", "sha256:" + "0" * 64, "sha256:" + "d" * 63])
def test_binding_rejects_mutable_or_invalid_collector_identity(tmp_path: Path, digest: str) -> None:
    binding = valid_binding(tmp_path / "operation", tmp_path)
    binding["collector"]["digest"] = digest  # type: ignore[index]
    with pytest.raises(w6_001_k8s.W6001Error, match="collector digest"):
        w6_001_k8s.validate_release_binding(
            binding,
            source_template_sha256=binding["source_identity"]["template_sha256"],  # type: ignore[index]
        )


@pytest.mark.parametrize(
    "field", ["oci_identity", "trivy", "grype", "provenance", "image_composition_identity"]
)
def test_binding_rejects_collector_evidence_identity_mismatch(tmp_path: Path, field: str) -> None:
    binding = valid_binding(tmp_path / "operation", tmp_path)
    binding["collector"][field]["image_digest"] = "sha256:" + "e" * 64  # type: ignore[index]
    with pytest.raises(w6_001_k8s.W6001Error, match="mismatch"):
        w6_001_k8s.validate_release_binding(
            binding,
            source_template_sha256=binding["source_identity"]["template_sha256"],  # type: ignore[index]
        )


@pytest.mark.parametrize("field", ["spdx_sbom_sha256", "cyclonedx_sbom_sha256"])
def test_binding_rejects_sbom_mismatch_shape(tmp_path: Path, field: str) -> None:
    binding = valid_binding(tmp_path / "operation", tmp_path)
    binding[field] = "bad"
    with pytest.raises(w6_001_k8s.W6001Error, match=field):
        w6_001_k8s.validate_release_binding(
            binding,
            source_template_sha256=binding["source_identity"]["template_sha256"],  # type: ignore[index]
        )


def test_binding_rejects_missing_operation_expiry_and_unknown_field(tmp_path: Path) -> None:
    binding = valid_binding(tmp_path / "operation", tmp_path)
    del binding["w6_01_operation_identity"]
    with pytest.raises(w6_001_k8s.W6001Error, match="exactly match"):
        w6_001_k8s.validate_release_binding(binding, source_template_sha256=SHA)
    binding = valid_binding(tmp_path / "operation", tmp_path)
    binding["expires_at"] = "2000-01-01T00:00:00+00:00"
    with pytest.raises(w6_001_k8s.W6001Error, match="expired"):
        w6_001_k8s.validate_release_binding(
            binding,
            source_template_sha256=binding["source_identity"]["template_sha256"],  # type: ignore[index]
        )


def test_canonical_binding_is_deterministic_and_does_not_mutate_template(tmp_path: Path) -> None:
    documents, payloads = w6_001_k8s.load_template(TEMPLATE_ROOT)
    before = dict(payloads)
    binding = valid_binding(tmp_path / "operation", tmp_path)
    images = w6_001_k8s.validate_release_binding(
        binding, source_template_sha256=w6_001_k8s.template_identity(payloads)
    )
    first = w6_001_k8s.build_release_files(payloads, binding, images)
    second = w6_001_k8s.build_release_files(payloads, binding, images)
    assert first == second
    assert payloads == before
    assert json.loads(first["release-binding.json"]) == binding
    assert isinstance(json.loads(first["rendered.json"]), list)
    assert w6_001_k8s.SENTINEL not in first["deployment.yaml"].decode()
    assert w6_001_k8s.COLLECTOR_SENTINEL not in first["deployment.yaml"].decode()
    assert w6_001_k8s.validate_documents(documents, template_mode=True) == (
        w6_001_k8s.APP_SENTINEL,
        w6_001_k8s.COLLECTOR_SENTINEL,
    )


def test_manifest_security_scaling_and_probe_contracts_fail_closed() -> None:
    mutations = (
        ("securityContext", {"runAsNonRoot": False}),
        ("resources", {"requests": {"cpu": "2"}, "limits": {"cpu": "1"}}),
        ("readinessProbe", {"httpGet": {"path": "/health", "port": "http"}}),
        ("imagePullPolicy", "IfNotPresent"),
    )
    for key, value in mutations:
        documents = copy.deepcopy(template_documents())
        container = deployment(documents)["spec"]["template"]["spec"]["containers"][0]  # type: ignore[index]
        container[key] = value
        with pytest.raises(w6_001_k8s.W6001Error):
            w6_001_k8s.validate_documents(documents, template_mode=True)


def test_source_template_pass_wording_cannot_be_mistaken_for_release_or_deployment() -> None:
    assert w6_001_k8s.TEMPLATE_STATUS == "SOURCE TEMPLATE VALID — NOT DEPLOYABLE"
    assert w6_001_k8s.RELEASE_STATUS == "IMMUTABLE RELEASE PACKAGE VALID — NOT DEPLOYED"
    assert "DEPLOYED" not in w6_001_k8s.TEMPLATE_STATUS
    assert w6_001_k8s.RELEASE_STATUS.endswith("NOT DEPLOYED")


def test_strict_binding_json_rejects_duplicate_fields(tmp_path: Path) -> None:
    path = tmp_path / "binding.json"
    path.write_text('{"schema_version":"one","schema_version":"two"}', encoding="utf-8")
    with pytest.raises(w6_001_k8s.W6001Error, match="duplicate JSON key"):
        w6_001_k8s._strict_json(path)


def test_yaml_documents_are_canonical_json_serializable() -> None:
    serialized = json.dumps(template_documents(), sort_keys=True, separators=(",", ":"))
    assert yaml.safe_load(json.dumps(json.loads(serialized))) is not None
