"""Kubernetes workload authentication and TLS resource contracts."""

from __future__ import annotations

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
