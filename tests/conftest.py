"""Shared W1-002 test values that never connect to external services."""

from __future__ import annotations

import pytest

from enterprise_ai_platform.config import Settings


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
