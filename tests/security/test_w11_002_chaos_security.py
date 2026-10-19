"""Synthetic-only W11-002 trust, privacy and execution boundary tests."""

from pathlib import Path

from enterprise_ai_platform.chaos import DEFAULT_CHAOS_POLICY_PATH, load_chaos_policy

ROOT = Path(__file__).resolve().parents[2]


def test_chaos_source_has_no_cloud_network_or_subprocess_execution() -> None:
    source = (ROOT / "src/enterprise_ai_platform/chaos.py").read_text(encoding="utf-8")
    cli = (ROOT / "tools/chaosctl.py").read_text(encoding="utf-8")
    for forbidden in (
        "import boto3",
        "import kubernetes",
        "import socket",
        "import subprocess",
        "start_experiment",
        "start-experiment",
        "terraform apply",
        "terraform destroy",
    ):
        assert forbidden not in source
        assert forbidden not in cli


def test_only_synthetic_mode_and_no_sensitive_sli_labels() -> None:
    policy = load_chaos_policy(ROOT / DEFAULT_CHAOS_POLICY_PATH, repository_root=ROOT)
    assert policy.execution_mode == "synthetic-in-process-only"
    assert policy.environment == "sandbox"
    assert policy.live_execution_status == "NOT RUN"
    assert policy.blast_radius.maximum_targets == 1
    assert policy.blast_radius.retry_count == 0
    text = (ROOT / DEFAULT_CHAOS_POLICY_PATH).read_text(encoding="utf-8")
    for secret_field in ("api_key:", "password:", "tenant_id:", "prompt:", "response:"):
        assert secret_field not in text
