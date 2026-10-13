from __future__ import annotations

from pathlib import Path

from tests.fakes.w8_003_orchestration import make_policy

ROOT = Path(__file__).resolve().parents[2]


def test_source_only_contract_contains_no_cloud_or_runtime_artifacts() -> None:
    policy = make_policy()
    source = (ROOT / "src" / "enterprise_ai_platform" / "orchestration" / "engine.py").read_text(
        encoding="utf-8"
    )

    assert policy.execution_mode == "offline_contract_only"
    assert policy.eventbridge == "compatible_contract_only"
    assert policy.step_functions == "compatible_contract_only"
    assert policy.live_execution == "NOT_AUTHORIZED"
    assert policy.provisioning == "NOT_RUN"
    assert "boto3" not in source
    assert "subprocess" not in source
    assert "requests" not in source


def test_orchestration_package_does_not_create_local_state_paths() -> None:
    prohibited = (
        ROOT / "orchestration.db",
        ROOT / "reports" / "w8-003",
    )

    assert all(not path.exists() for path in prohibited)
