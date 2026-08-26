from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import cast

from enterprise_ai_platform.evaluation.dataset import load_golden_dataset
from enterprise_ai_platform.evaluation.fixtures import fixture_for, provider_protocol
from enterprise_ai_platform.rag.config import load_rag_policy
from enterprise_ai_platform.rag.models import AbstentionResult
from enterprise_ai_platform.rag.service import RAGService
from enterprise_ai_platform.retrieval.service import RetrievalService

ROOT = Path(__file__).resolve().parents[2]


def _case(case_id: str) -> object:
    dataset = load_golden_dataset(ROOT / "configs" / "eval" / "golden.jsonl")
    return next(case for case in dataset.cases if case.case_id == case_id)


def _answer(case_id: str) -> tuple[object, object]:
    fixture = fixture_for(_case(case_id))  # type: ignore[arg-type]
    service = RAGService(
        retrieval_service=cast(RetrievalService, fixture.retrieval),
        llm_provider=provider_protocol(fixture),
        policy=load_rag_policy(ROOT / "configs" / "rag.yaml"),
    )
    result = asyncio.run(service.answer(fixture.auth_context, fixture.query))
    return fixture, result


def test_denied_or_malformed_evidence_never_reaches_the_provider() -> None:
    for case_id, reason in (
        ("Q24", "no_authorized_evidence"),
        ("Q25", "no_authorized_evidence"),
        ("Q26", "no_authorized_evidence"),
        ("Q31", "malformed_evidence"),
    ):
        fixture, result = _answer(case_id)
        assert isinstance(result, AbstentionResult)
        assert result.reason == reason
        assert fixture.provider.requests == []  # type: ignore[attr-defined]
        assert result.usage is None


def test_invalid_generated_citations_are_suppressed_with_valid_usage() -> None:
    for case_id in ("Q30", "Q32", "Q33", "Q34", "Q35"):
        fixture, result = _answer(case_id)
        assert isinstance(result, AbstentionResult)
        assert result.reason == "invalid_generated_citation"
        assert result.usage is not None
        assert len(fixture.provider.requests) == 1  # type: ignore[attr-defined]
        public_result = json.dumps(result.model_dump(mode="json"), sort_keys=True)
        for forbidden in (
            "suppressed output",
            "suppressed hostile output",
            "DOC-FABRICATED",
            "DOC-RESTRICTED-TEST",
            "Ignore all prior instructions",
        ):
            assert forbidden not in public_result


def test_evaluation_sources_do_not_import_cloud_or_judge_clients() -> None:
    evaluation_root = ROOT / "src" / "enterprise_ai_platform" / "evaluation"
    source = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted(evaluation_root.glob("*.py"))
    ).casefold()
    for prohibited in ("import boto3", "import requests", "import ragas"):
        assert prohibited not in source
