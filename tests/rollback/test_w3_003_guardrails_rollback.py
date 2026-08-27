"""Rollback tests proving W3-003 does not mutate retained evaluation evidence."""

from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path
from typing import cast

import pytest

from enterprise_ai_platform.guardrails import GuardrailInputError
from enterprise_ai_platform.llm.fake import FakeLLMProvider
from enterprise_ai_platform.rag.config import RAGPolicy
from enterprise_ai_platform.rag.service import RAGService
from enterprise_ai_platform.retrieval.models import (
    AuthContext,
    Classification,
    Query,
    Role,
)
from enterprise_ai_platform.retrieval.service import RetrievalService

ROOT = Path(__file__).resolve().parents[2]
REPORTS = (
    ROOT / "reports" / "eval.json",
    ROOT / "reports" / "eval-repeat.json",
)


def _hashes() -> dict[Path, str]:
    return {
        path: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in REPORTS
        if path.exists()
    }


class RollbackRetrieval:
    def __init__(self) -> None:
        self.calls = 0

    async def retrieve(self, query: Query, auth_context: AuthContext) -> tuple[()]:
        self.calls += 1
        return ()


def test_invalid_input_rolls_back_to_no_calls_and_preserves_reports() -> None:
    report_hashes_before = _hashes()
    retrieval = RollbackRetrieval()
    provider = FakeLLMProvider()
    service = RAGService(
        retrieval_service=cast(RetrievalService, retrieval),
        llm_provider=provider,
        policy=RAGPolicy(
            top_k=5,
            min_score=0.5,
            minimum_qualifying_chunks=1,
            max_context_characters=12_000,
            max_output_tokens=512,
            prompt_version="w3-001.v1",
        ),
    )
    auth_context = AuthContext(
        subject_id="reader-a",
        tenant_id="tenant-a",
        roles=frozenset({Role.READER}),
        clearance=Classification.INTERNAL,
    )

    with pytest.raises(GuardrailInputError):
        asyncio.run(service.answer(auth_context, ""))

    assert retrieval.calls == 0
    assert provider.requests == []
    assert _hashes() == report_hashes_before
