"""Machine-readable W6-001 source and release contract tests."""

from __future__ import annotations

import json
from pathlib import Path

from tools import w6_001_k8s

ROOT = Path(__file__).resolve().parents[2]


def test_exact_source_inventory_and_object_inventory() -> None:
    root = ROOT / "deploy/k8s"
    assert tuple(path.name for path in sorted(root.iterdir())) == tuple(
        sorted(w6_001_k8s.TEMPLATE_FILES)
    )
    documents, _ = w6_001_k8s.load_template(root)
    observed = {
        (document["apiVersion"], document["kind"], document["metadata"]["name"])
        for document in documents
    }
    assert observed == w6_001_k8s.EXPECTED_OBJECTS


def test_kustomization_is_bounded_and_contains_no_apply_interface() -> None:
    text = (ROOT / "deploy/k8s/kustomization.yaml").read_text(encoding="utf-8")
    assert "namespace: enterprise-ai-sandbox" in text
    assert text.count("  - ") == 9
    assert "kubectl" not in text
    assert "helm" not in text.casefold()


def test_release_binding_schema_is_closed() -> None:
    assert w6_001_k8s.RELEASE_KEYS == {
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


def test_collector_authority_is_the_existing_private_repository() -> None:
    assert w6_001_k8s.COLLECTOR_REPOSITORY_NAME == "enterprise-ai/sandbox/api"
    assert w6_001_k8s.COLLECTOR_REPOSITORY_NAME == w6_001_k8s.REPOSITORY_NAME


def test_tool_has_no_cluster_registry_or_aws_client() -> None:
    source = (ROOT / "tools/w6_001_k8s.py").read_text(encoding="utf-8")
    prohibited = (
        "boto3",
        "kubernetes.client",
        "docker.from_env",
        "urllib.request",
        "requests.",
        "kubectl apply",
    )
    assert not any(token in source for token in prohibited)
    assert "reserve_operation_directory" in source
    assert "SOURCE TEMPLATE VALID — NOT DEPLOYABLE" in source
    assert "IMMUTABLE RELEASE PACKAGE VALID — NOT DEPLOYED" in source


def test_feature_contract_is_json_compatible() -> None:
    matrix = json.loads((ROOT / "feature-matrix.yaml").read_text(encoding="utf-8"))
    feature = next(item for item in matrix["features"] if item["id"] == "EKS-001")
    assert feature["linked_tracker_steps"] == [
        "W6-02",
        "W6-03",
        "W6-04",
        "W6-05",
        "W6-004",
    ]
