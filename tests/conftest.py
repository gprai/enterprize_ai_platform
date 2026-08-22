"""Shared W1-002 test values that never connect to external services."""

from __future__ import annotations

from pathlib import Path

import pytest

from enterprise_ai_platform.config import Settings

TESTS_ROOT = Path(__file__).resolve().parent
CATEGORY_MARKERS = frozenset(
    {
        "unit",
        "integration",
        "contract",
        "feature",
        "smoke",
        "security",
        "teardown",
    }
)


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Apply the approved category marker from each test's folder."""
    for item in items:
        try:
            relative_path = item.path.resolve().relative_to(TESTS_ROOT)
        except ValueError:
            continue
        if relative_path.parts and relative_path.parts[0] in CATEGORY_MARKERS:
            item.add_marker(relative_path.parts[0])


@pytest.fixture
def valid_settings_values() -> dict[str, object]:
    return {
        "aws_region": "ap-southeast-1",
        "embedding_model_id": "sentence-transformers/all-MiniLM-L6-v2",
        "qdrant_url": "http://127.0.0.1:6333",
        "opensearch_url": "https://opensearch.invalid",
        "qdrant_api_key": "",
    }


@pytest.fixture
def valid_settings(valid_settings_values: dict[str, object]) -> Settings:
    return Settings(_env_file=None, **valid_settings_values)
