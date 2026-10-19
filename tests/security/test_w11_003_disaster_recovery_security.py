"""W11-003 trust, tenant, privacy and no-live-execution controls."""

from pathlib import Path

from enterprise_ai_platform.disaster_recovery import (
    DEFAULT_RECOVERY_POLICY_PATH,
    RecoveryStatus,
    load_recovery_policy,
    run_local_rehearsal,
)
from enterprise_ai_platform.retrieval.models import Role
from tests.fakes.w11_003_disaster_recovery import (
    FakeClock,
    RecordingTarget,
    RecordingVerifier,
    auth,
    plan,
)

ROOT = Path(__file__).resolve().parents[2]


def test_recovery_source_and_cli_have_no_live_execution_boundary() -> None:
    source = (ROOT / "src/enterprise_ai_platform/disaster_recovery.py").read_text(encoding="utf-8")
    cli = (ROOT / "tools/recoveryctl.py").read_text(encoding="utf-8")
    for forbidden in (
        "import boto3",
        "import botocore",
        "import socket",
        "import subprocess",
        "restore_snapshot",
        "terraform apply",
        "terraform destroy",
        "start_restore_job",
        "change_resource_record_sets",
    ):
        assert forbidden not in source
        assert forbidden not in cli


def test_authorization_failure_occurs_before_recovery_port() -> None:
    policy = load_recovery_policy(ROOT / DEFAULT_RECOVERY_POLICY_PATH, repository_root=ROOT)
    target = RecordingTarget()
    result = run_local_rehearsal(
        policy,
        plan(policy),
        auth_context=auth(role=Role.READER),
        target=target,
        verifier=RecordingVerifier(),
        clock=FakeClock(),
    )
    assert result.authorization_status is RecoveryStatus.FAIL
    assert target.execute_count == 0
    assert target.events == []


def test_policy_contains_no_credentials_tenant_payloads_or_dns_target() -> None:
    policy = load_recovery_policy(ROOT / DEFAULT_RECOVERY_POLICY_PATH, repository_root=ROOT)
    text = (ROOT / DEFAULT_RECOVERY_POLICY_PATH).read_text(encoding="utf-8")
    assert policy.secondary_account_id is None
    assert policy.secondary_region is None
    for forbidden in (
        "api_key:",
        "password:",
        "secret:",
        "access_key:",
        "tenant_id:",
        "prompt:",
        "response:",
        "dns_name:",
    ):
        assert forbidden not in text
