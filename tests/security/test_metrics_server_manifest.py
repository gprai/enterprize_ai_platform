from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "deploy/addons/metrics-server.yaml"
EXPECTED_DIGEST = "sha256:25d291fde59974547bac6f07fa9d6cf6f5bedd1f19d60c893311c5e741e0a42f"


def _documents() -> list[dict[str, object]]:
    return [item for item in yaml.safe_load_all(MANIFEST.read_text(encoding="utf-8")) if item]


def test_metrics_server_uses_exact_private_digest_and_safe_kubelet_transport() -> None:
    deployment = next(item for item in _documents() if item["kind"] == "Deployment")
    container = deployment["spec"]["template"]["spec"]["containers"][0]  # type: ignore[index]
    image = container["image"]
    assert image == (
        "526338061652.dkr.ecr.ap-southeast-1.amazonaws.com/"
        f"enterprise-ai/sandbox/api@{EXPECTED_DIGEST}"
    )
    assert "--kubelet-insecure-tls" not in container["args"]
    assert "--kubelet-preferred-address-types=InternalIP,Hostname" in container["args"]
    assert container["securityContext"] == {
        "allowPrivilegeEscalation": False,
        "readOnlyRootFilesystem": True,
        "capabilities": {"drop": ["ALL"]},
    }


def test_metrics_server_rbac_has_no_wildcards() -> None:
    for document in _documents():
        for rule in document.get("rules", []):
            assert "*" not in rule.get("apiGroups", [])
            assert "*" not in rule.get("resources", [])
            assert "*" not in rule.get("verbs", [])
