"""Kubernetes workload authentication and TLS resource contracts."""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_probe_uses_projected_service_account_identity() -> None:
    probe = _read("deploy/codebuild/capstone-probe.yaml")
    auth = _read("src/enterprise_ai_platform/api/workload_auth.py")
    assert "serviceAccountToken:" in probe
    assert "enterprise-ai-capstone-probe" in probe
    assert "enterprise-ai-capstone-probe" in auth
    assert "tokenreviews" in auth
    assert "SandboxTokenAuthenticator" not in auth


def test_application_service_is_tls_only_with_reviewed_trust() -> None:
    overlay = _read("deploy/capstone/api-overlay.yaml")
    pki = _read("deploy/capstone/pki.yaml")
    trust = _read("deploy/capstone/trust-bundle.yaml")
    deploy = _read("tools/capstone_deploy.py")
    deployment, service = list(yaml.safe_load_all(overlay))
    api = deployment["spec"]["template"]["spec"]["containers"][0]
    assert api["ports"] == [{"name": "https", "containerPort": 8000, "protocol": "TCP"}]
    assert api["args"][api["args"].index("--port") + 1] == "8000"
    assert "--ssl-certfile" in api["args"]
    assert "--ssl-keyfile" in api["args"]
    assert service["spec"]["ports"] == [
        {"name": "https", "protocol": "TCP", "port": 443, "targetPort": "https"}
    ]
    assert "cert-manager.io/v1" in pki
    assert "trust.cert-manager.io/v1alpha1" in trust
    assert "CERT_NONE" not in deploy
    assert "verify=False" not in deploy
    assert "http://enterprise-ai-api" not in deploy


def test_regular_deploy_rbac_has_no_secret_read() -> None:
    rbac = _read("deploy/capstone/tokenreview-rbac.yaml")
    assert "tokenreviews" in rbac
    assert "secrets" not in rbac.lower()


def test_pki_charts_and_images_are_immutably_pinned() -> None:
    cert_manager = _read("deploy/capstone/cert-manager-values.yaml")
    trust_manager = _read("deploy/capstone/trust-manager-values.yaml")

    assert "cert-manager:v1.21.3" in cert_manager
    assert "trust-manager:v0.26.0" in trust_manager
    digest_pattern = r"^\s+digest: sha256:[0-9a-f]{64}$"
    assert len(re.findall(digest_pattern, cert_manager, re.MULTILINE)) == 4
    assert len(re.findall(digest_pattern, trust_manager, re.MULTILINE)) == 2
    assert "trust-pkg-debian-trixie" in trust_manager

    lock = json.loads(_read("deploy/capstone/pki-supply-chain-lock.json"))
    assert lock["schema_version"] == "w12-pki-supply-chain.v1"
    assert lock["metrics_server"].endswith(
        "@sha256:d9862115e7c7881280d3d75ca26bda8ffc0fc213315979575bf23ce9826205c0"
    )
    assert len(lock["cert_manager"]["images"]) == 4
    assert len(lock["trust_manager"]["images"]) == 2


def test_owner_local_pki_bootstrap_contract_contains_no_private_material() -> None:
    contract = json.loads(_read("deploy/capstone/pki-bootstrap-contract.json"))
    serialized = json.dumps(contract, sort_keys=True)

    assert contract["schema_version"] == "w12-pki-bootstrap.v1"
    assert contract["root_ca"]["algorithm"] == "ECDSA_P256"
    assert contract["root_ca"]["validity_hours"] == 8760
    assert contract["kubernetes"]["ca_resource_name"] == "enterprise-ai-capstone-root"
    assert contract["kubernetes"]["public_config_map_name"] == (
        "enterprise-ai-capstone-public-root"
    )
    assert "-----BEGIN" not in serialized
