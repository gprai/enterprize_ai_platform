"""Unit coverage for strict W7-001 configuration and canonical identities."""

from __future__ import annotations

from pathlib import Path

import pytest

from enterprise_ai_platform.ingestion.governance import (
    GovernanceContractError,
    canonical_json_bytes,
    canonical_sha256,
    load_data_foundation_config,
)

ROOT = Path(__file__).resolve().parents[2]


def test_approved_configuration_is_exact() -> None:
    config = load_data_foundation_config(ROOT / "configs/ingestion/governed-data-foundation.yaml")
    assert config.region == "ap-southeast-1"
    assert config.classifications == ("PUBLIC", "INTERNAL")
    assert {zone.value: item.retention_days for zone, item in config.zones.items()} == {
        "raw": 7,
        "quarantine": 7,
        "processed": 30,
        "evidence": 30,
    }
    assert config.synthetic_only is True


def test_canonical_json_is_order_independent_compact_and_newline_terminated() -> None:
    first = canonical_json_bytes({"b": 2, "a": {"z": 1}})
    second = canonical_json_bytes({"a": {"z": 1}, "b": 2})
    assert first == second == b'{"a":{"z":1},"b":2}\n'
    assert canonical_sha256({"b": 2, "a": 1}) == canonical_sha256({"a": 1, "b": 2})


def test_nonfinite_values_are_rejected() -> None:
    with pytest.raises(GovernanceContractError):
        canonical_json_bytes({"value": float("nan")})
