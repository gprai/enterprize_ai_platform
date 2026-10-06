"""Feature-level W6-001 EKS workload contract tests."""

from pathlib import Path

from tools import w6_001_k8s

ROOT = Path(__file__).resolve().parents[2]


def test_eks_001_source_template_is_valid_but_not_deployable() -> None:
    result = w6_001_k8s.validate_template(ROOT / "deploy/k8s")
    assert result == "SOURCE TEMPLATE VALID — NOT DEPLOYABLE"


def test_eks_001_uses_approved_namespace_identity_service_and_port() -> None:
    documents, _ = w6_001_k8s.load_template(ROOT / "deploy/k8s")
    assert {item["metadata"]["namespace"] for item in documents if item["kind"] != "Namespace"} == {
        "enterprise-ai-sandbox"
    }
    assert (
        next(item for item in documents if item["kind"] == "Namespace")["metadata"]["name"]
        == "enterprise-ai-sandbox"
    )
    service = next(item for item in documents if item["kind"] == "Service")
    deployment = next(item for item in documents if item["kind"] == "Deployment")
    assert service["spec"]["type"] == "ClusterIP"
    assert service["spec"]["ports"][0]["port"] == 8000
    assert deployment["spec"]["template"]["spec"]["serviceAccountName"] == "enterprise-ai-runtime"


def test_eks_001_has_no_public_or_stateful_resource() -> None:
    documents, _ = w6_001_k8s.load_template(ROOT / "deploy/k8s")
    forbidden = {
        "Ingress",
        "Gateway",
        "Secret",
        "PersistentVolume",
        "PersistentVolumeClaim",
        "StatefulSet",
    }
    assert forbidden.isdisjoint({item["kind"] for item in documents})
