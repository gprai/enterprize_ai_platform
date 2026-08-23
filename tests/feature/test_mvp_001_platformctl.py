"""Feature mapping for the W1-004 control foundation."""

from __future__ import annotations

import json
from pathlib import Path

from tools.platformctl.cli import build_parser
from tools.platformctl.contracts import FIXED_TAG_VALUES

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def test_w1_004_maps_to_mvp_001_without_changing_the_matrix() -> None:
    matrix = json.loads(
        (REPOSITORY_ROOT / "feature-matrix.yaml").read_text(encoding="utf-8")
    )
    feature_ids = [feature["id"] for feature in matrix["features"]]
    assert feature_ids[0] == "MVP-001"
    assert feature_ids.count("MVP-001") == 1
    assert FIXED_TAG_VALUES["Feature"] == "MVP-001"
    assert "W1-MVP-001" not in set(feature_ids)


def test_mvp_control_surface_contains_all_lifecycle_commands() -> None:
    help_text = build_parser().format_help()
    for command in (
        "bootstrap",
        "plan",
        "deploy",
        "validate",
        "rollback",
        "destroy",
        "verify-clean",
    ):
        assert command in help_text
