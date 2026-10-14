"""Offline composition checks for W6-001 Kubernetes consumers."""

from pathlib import Path

from tools import w6_001_k8s

ROOT = Path(__file__).resolve().parents[2]


def test_manifest_consumers_share_exact_identity() -> None:
    documents, _ = w6_001_k8s.load_template(ROOT / "deploy/k8s")
    deployment = next(item for item in documents if item["kind"] == "Deployment")
    service = next(item for item in documents if item["kind"] == "Service")
    hpa = next(item for item in documents if item["kind"] == "HorizontalPodAutoscaler")
    pdb = next(item for item in documents if item["kind"] == "PodDisruptionBudget")
    label = {"app.kubernetes.io/name": "enterprise-ai-api"}
    assert deployment["spec"]["selector"]["matchLabels"] == label
    assert service["spec"]["selector"] == label
    assert hpa["spec"]["scaleTargetRef"]["name"] == deployment["metadata"]["name"]
    assert pdb["spec"]["selector"]["matchLabels"] == label
    assert hpa["spec"]["metrics"] == [
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
    assert hpa["spec"]["behavior"]["scaleDown"]["stabilizationWindowSeconds"] == 300
    assert pdb["spec"]["maxUnavailable"] == 1
    assert "minAvailable" not in pdb["spec"]


def test_make_ci_checkov_and_opa_have_offline_w6_consumers() -> None:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    checkov = (ROOT / ".checkov.yml").read_text(encoding="utf-8")
    for target in (
        "w6-001-template-validate",
        "w6-001-policy",
        "w6-001-release-bind",
        "w6-001-release-validate",
    ):
        assert f"{target}:" in makefile
    assert "validate-template" in workflow
    assert "framework:" in checkov and "kubernetes" in checkov
    assert "kubectl" not in "\n".join(
        line
        for line in makefile.splitlines()
        if line.startswith("w6-001-") or line.startswith("\t")
    )


def test_template_contains_exactly_two_non_deployable_image_sentinels() -> None:
    combined = b"".join(
        (ROOT / "deploy/k8s" / name).read_bytes() for name in w6_001_k8s.TEMPLATE_FILES
    )
    assert combined.count(w6_001_k8s.SENTINEL.encode()) == 1
    assert combined.count(w6_001_k8s.COLLECTOR_SENTINEL.encode()) == 1
    assert b"w6-001-source-template" in combined
    assert b'deployable: "false"' in combined
