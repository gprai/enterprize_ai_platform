"""Security and redaction coverage for the controlled W3-004 regression."""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import cast

import pytest

from enterprise_ai_platform.evaluation.dataset import load_golden_dataset
from enterprise_ai_platform.rag.config import load_rag_policy
from enterprise_ai_platform.rag.models import AbstentionResult
from enterprise_ai_platform.rag.service import RAGService
from enterprise_ai_platform.rag_rollback.errors import RollbackUnsafePathError
from enterprise_ai_platform.rag_rollback.identity import validate_identity_pair
from enterprise_ai_platform.rag_rollback.service import _regression_fixture
from enterprise_ai_platform.rag_rollback.state import _runtime_file
from enterprise_ai_platform.retrieval.service import RetrievalService

ROOT = Path(__file__).resolve().parents[2]


def test_regression_fixture_suppresses_content_citations_and_tools(
    caplog: pytest.LogCaptureFixture,
) -> None:
    dataset = load_golden_dataset(ROOT / "configs/eval/golden.jsonl")
    policy = load_rag_policy(ROOT / "configs/rag.yaml")
    fixture = _regression_fixture(dataset.cases[0])
    service = RAGService(
        retrieval_service=cast(RetrievalService, fixture.retrieval),
        llm_provider=fixture.provider,
        policy=policy,
    )
    caplog.set_level(logging.DEBUG)

    result = asyncio.run(service.answer(fixture.auth_context, fixture.query))

    assert isinstance(result, AbstentionResult)
    assert result.reason == "invalid_generated_citation"
    assert result.usage is not None
    assert fixture.provider.requests[0].tools == ()
    serialized = json.dumps(result.model_dump(mode="json"), sort_keys=True)
    assert "controlled synthetic regression output" not in serialized
    assert "citations" not in serialized
    application_records = [
        record
        for record in caplog.records
        if record.name == "enterprise_ai_platform"
        or record.name.startswith("enterprise_ai_platform.")
    ]
    assert application_records == []


@pytest.mark.skipif(
    not all(
        (ROOT / relative).is_file()
        for relative in ("reports/eval.json", "reports/eval-repeat.json")
    ),
    reason="ignored owner-local W3 evaluation reports are absent",
)
def test_identity_and_errors_expose_no_prompt_evidence_or_provider_content() -> None:
    known_good, regression = validate_identity_pair()
    serialized = json.dumps(
        [known_good.model_dump(mode="json"), regression.model_dump(mode="json")],
        sort_keys=True,
    )
    for forbidden in (
        "BEGIN_UNTRUSTED_EVIDENCE",
        "system prompt",
        "tenant data",
        "provider response",
        "SECRET",
        "@example",
    ):
        assert forbidden not in serialized


def test_runtime_path_boundary_rejects_traversal_before_filesystem_access() -> None:
    with pytest.raises(RollbackUnsafePathError):
        _runtime_file(Path("reports/w3-004/../eval.json"))
