"""Cleanliness contract for source-only W7-003 controls."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_w7_003_source_has_no_live_sdk_or_repository_persistence() -> None:
    source = (ROOT / "src/enterprise_ai_platform/ingestion/privacy_lifecycle.py").read_text(
        encoding="utf-8"
    )
    assert "boto3" not in source
    assert "requests" not in source
    assert "subprocess" not in source
    assert ".write_text(" not in source
    assert ".write_bytes(" not in source


def test_config_keeps_cloud_and_destructive_retry_disabled() -> None:
    config = (ROOT / "configs/ingestion/privacy-retention-lifecycle.yaml").read_text(
        encoding="utf-8"
    )
    assert 'live_cloud_execution: "separate_owner_approval_required"' in config
    assert 'destructive_retry: "disabled"' in config
    assert 'shared_resource_deletion: "prohibited"' in config
