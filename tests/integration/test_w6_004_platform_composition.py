from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


def test_terraform_kubernetes_and_observability_are_composed() -> None:
    terraform = (ROOT / "infra/environments/sandbox/main.tf").read_text(encoding="utf-8")
    assert 'module "eks"' in terraform
    assert 'module "observability"' in terraform
    assert 'resource "terraform_data" "w6_004_runtime_gate"' in terraform
    deployment = yaml.safe_load((ROOT / "deploy/k8s/deployment.yaml").read_text(encoding="utf-8"))
    assert [item["name"] for item in deployment["spec"]["template"]["spec"]["containers"]] == [
        "api",
        "otel-collector",
    ]
    api = deployment["spec"]["template"]["spec"]["containers"][0]
    assert api["env"] == [
        {
            "name": "ENTERPRISE_AI_SANDBOX_AUTH_SIGNING_KEY_FILE",
            "value": "/var/run/secrets/enterprise-ai/sandbox-auth-signing-key",
        }
    ]
    assert api["volumeMounts"][-1] == {
        "name": "sandbox-auth-signing-key",
        "mountPath": "/var/run/secrets/enterprise-ai",
        "readOnly": True,
    }
    assert deployment["spec"]["template"]["spec"]["volumes"][-1] == {
        "name": "sandbox-auth-signing-key",
        "secret": {
            "secretName": "enterprise-ai-runtime-secrets",  # pragma: allowlist secret
            "defaultMode": 0o440,
            "items": [
                {
                    "key": "sandbox-auth-signing-key",
                    "path": "sandbox-auth-signing-key",
                }
            ],
        },
    }
    service_accounts = [
        item
        for item in yaml.safe_load_all(
            (ROOT / "deploy/k8s/serviceaccount.yaml").read_text(encoding="utf-8")
        )
        if item["kind"] == "ServiceAccount"
    ]
    assert [item["metadata"]["name"] for item in service_accounts] == [
        "enterprise-ai-runtime",
        "enterprise-ai-ingestion",
        "fis-experiment",
    ]


def test_aws_composition_is_pod_identity_sigv4_and_has_no_fake_fallback() -> None:
    source = (ROOT / "src/enterprise_ai_platform/api/aws_composition.py").read_text(
        encoding="utf-8"
    )
    assert 'getattr(credentials, "method", None) != "container-role"' in source
    assert "AWSV4SignerAuth" in source
    assert "max_retries=0" in source
    assert "FakeLLMProvider" not in source
