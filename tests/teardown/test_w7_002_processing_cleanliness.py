"""Cleanliness contract for source-only W7-002 processing."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_w7_002_source_declares_no_cloud_or_repository_persistence() -> None:
    source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted((ROOT / "src/enterprise_ai_platform/processing").glob("*.py"))
    )

    assert "boto3" not in source
    assert "requests" not in source
    assert "subprocess" not in source
    assert ".write_text(" not in source
    assert ".write_bytes(" not in source


def test_w7_002_config_keeps_external_runtime_capabilities_deferred() -> None:
    config = (ROOT / "configs/processing/w7-002.yaml").read_text(encoding="utf-8")

    assert 'quality_engine: "provider_neutral_compatible"' in config
    assert 'checkpoint_store: "protocol_in_memory_fake_only"' in config
    assert 'glue_spark: "compatible_interface_only"' in config
    assert 'network_access: "disabled"' in config
