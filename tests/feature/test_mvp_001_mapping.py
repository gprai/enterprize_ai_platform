"""Sample feature test mapped only to canonical feature ID MVP-001."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.fakes import FakeAnswerProvider

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
MATRIX_PATH = REPOSITORY_ROOT / "feature-matrix.yaml"
CANONICAL_FEATURE_ID = "MVP-001"
WEEKLY_REFERENCE_ID = "W1-MVP-001"


def read_matrix() -> dict[str, object]:
    return json.loads(MATRIX_PATH.read_text(encoding="utf-8"))


def test_sample_maps_to_canonical_feature_id(request: pytest.FixtureRequest) -> None:
    matrix = read_matrix()
    features = matrix["features"]
    matching = [feature for feature in features if feature["id"] == CANONICAL_FEATURE_ID]

    assert request.node.get_closest_marker("feature") is not None
    assert len(matching) == 1
    assert matching[0]["status"] in matrix["permitted_statuses"]
    assert WEEKLY_REFERENCE_ID != CANONICAL_FEATURE_ID


def test_sample_uses_deterministic_provider_only() -> None:
    provider = FakeAnswerProvider(answer_text="safe deterministic response")
    assert provider.answer("sample MVP-001 question") == "safe deterministic response"
