"""Contract tests for the public W2-004 retrieval boundary."""

from __future__ import annotations

import inspect
from pathlib import Path
from typing import get_type_hints

from enterprise_ai_platform.retrieval import RetrievalService
from enterprise_ai_platform.retrieval.models import AuthContext, Query, RetrievedChunk

ROOT = Path(__file__).resolve().parents[2]


def test_retrieval_service_is_exported_with_provider_neutral_types() -> None:
    hints = get_type_hints(RetrievalService.retrieve)
    assert hints["query"] is Query
    assert hints["auth_context"] is AuthContext
    assert hints["return"] == tuple[RetrievedChunk, ...]


def test_retrieval_service_source_contains_no_vendor_or_mutation_boundary() -> None:
    source = inspect.getsource(RetrievalService)
    module = (
        ROOT / "src" / "enterprise_ai_platform" / "retrieval" / "service.py"
    ).read_text(encoding="utf-8")
    for forbidden in (
        "qdrant_client",
        "opensearchpy",
        "AsyncQdrantClient",
        "AsyncOpenSearch",
        "create_or_validate_collection(",
        "upsert_chunks(",
        "delete_by_document_id(",
        "delete_by_document_version(",
    ):
        assert forbidden not in source
        assert forbidden not in module
