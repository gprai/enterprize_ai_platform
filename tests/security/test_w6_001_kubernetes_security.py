"""Security tests for the W6-001 source template and release boundary."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from tools import w6_001_k8s

ROOT = Path(__file__).resolve().parents[2]


def _documents() -> list[dict[str, object]]:
    return w6_001_k8s.load_template(ROOT / "deploy/k8s")[0]


def _deployment(documents: list[dict[str, object]]) -> dict[str, object]:
    return next(item for item in documents if item["kind"] == "Deployment")


@pytest.mark.parametrize("field", ["hostNetwork", "hostPID", "hostIPC"])
def test_host_namespaces_are_rejected(field: str) -> None:
    documents = copy.deepcopy(_documents())
    _deployment(documents)["spec"]["template"]["spec"][field] = True  # type: ignore[index]
    with pytest.raises(w6_001_k8s.W6001Error, match="host namespaces"):
        w6_001_k8s.validate_documents(documents, template_mode=True)


def test_host_path_and_unbounded_network_are_rejected() -> None:
    documents = copy.deepcopy(_documents())
    pod_spec = _deployment(documents)["spec"]["template"]["spec"]  # type: ignore[index]
    pod_spec["volumes"] = [{"name": "bad", "hostPath": {"path": "/"}}]
    with pytest.raises(w6_001_k8s.W6001Error):
        w6_001_k8s.validate_documents(documents, template_mode=True)
    documents = copy.deepcopy(_documents())
    policy = next(
        item for item in documents if item["metadata"]["name"] == "enterprise-ai-dns-egress"
    )
    policy["spec"]["egress"][0]["to"] = [{"ipBlock": {"cidr": "0.0.0.0/0"}}]  # type: ignore[index]
    with pytest.raises(w6_001_k8s.W6001Error, match="unrestricted"):
        w6_001_k8s.validate_documents(documents, template_mode=True)


def test_plaintext_secret_and_credential_environment_name_are_rejected() -> None:
    documents = copy.deepcopy(_documents())
    config = next(item for item in documents if item["kind"] == "ConfigMap")
    config["data"]["AWS_ACCESS_KEY_ID"] = "fixture-only"  # type: ignore[index]
    with pytest.raises(w6_001_k8s.W6001Error):
        w6_001_k8s.validate_documents(documents, template_mode=True)


def test_source_and_policy_contain_no_complete_secret_fixture() -> None:
    paths = (
        ROOT / "tools/w6_001_k8s.py",
        ROOT / "policies/opa/kubernetes.rego",
        ROOT / "policies/opa/kubernetes_test.rego",
    )
    combined = "\n".join(path.read_text(encoding="utf-8") for path in paths)
    assert "AKIA" not in combined
    assert "0.0.0.0/0:443" not in combined
    assert "http.send" not in combined
    assert json.dumps(_documents())


def test_only_the_digest_check_has_a_source_template_skip() -> None:
    deployment = (ROOT / "deploy/k8s/deployment.yaml").read_text(encoding="utf-8")

    assert deployment.count("checkov.io/skip") == 1
    assert "CKV_K8S_43" in deployment
    assert "non-deployable source sentinels" in deployment
