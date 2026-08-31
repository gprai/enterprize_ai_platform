"""Integration coverage for ordinary and injected deterministic evaluation."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from enterprise_ai_platform.evaluation.dataset import load_golden_dataset
from enterprise_ai_platform.evaluation.evaluator import DeterministicRAGEvaluator
from enterprise_ai_platform.evaluation.fixtures import (
    CaseFixture,
    ControlledProvider,
    fixture_for,
)
from enterprise_ai_platform.evaluation.models import GoldenCase
from enterprise_ai_platform.llm.models import ChatRequest, ChatResponse, Usage
from enterprise_ai_platform.rag.config import load_rag_policy

ROOT = Path(__file__).resolve().parents[2]


def test_default_fixture_factory_preserves_ordinary_w3_002_evaluation() -> None:
    dataset = load_golden_dataset(ROOT / "configs/eval/golden.jsonl")
    policy = load_rag_policy(ROOT / "configs/rag.yaml")

    default = asyncio.run(DeterministicRAGEvaluator().evaluate(dataset, policy))
    explicit = asyncio.run(
        DeterministicRAGEvaluator(fixture_factory=fixture_for).evaluate(
            dataset,
            policy,
        )
    )

    assert default == explicit
    assert len(default) == 39


def test_injected_factory_changes_only_controlled_q1_q2_provider_behavior() -> None:
    dataset = load_golden_dataset(ROOT / "configs/eval/golden.jsonl")
    policy = load_rag_policy(ROOT / "configs/rag.yaml")
    response = ChatResponse(
        text=json.dumps({"answer": "synthetic", "citations": []}),
        usage=Usage(
            input_tokens=10,
            output_tokens=5,
            total_tokens=15,
            estimated_cost_usd=0.0,
        ),
        stop_reason="end_turn",
    )

    def controlled_factory(case: GoldenCase) -> CaseFixture:
        ordinary = fixture_for(case)
        if case.case_id not in {"Q1", "Q2"}:
            return ordinary
        return CaseFixture(
            retrieval=ordinary.retrieval,
            provider=ControlledProvider(response),
            auth_context=ordinary.auth_context,
            query=ordinary.query,
        )

    executions = asyncio.run(
        DeterministicRAGEvaluator(
            fixture_factory=controlled_factory,
        ).evaluate(dataset, policy)
    )

    assert tuple(item.case_id for item in executions[:2]) == ("Q1", "Q2")
    assert all(item.actual_outcome == "ABSTAINED" for item in executions[:2])
    assert all(item.abstention_reason == "invalid_generated_citation" for item in executions[:2])
    assert all(item.provider_calls == 1 and item.usage is not None for item in executions[:2])
    assert executions[2:] == asyncio.run(DeterministicRAGEvaluator().evaluate(dataset, policy))[2:]


def test_injected_provider_cancellation_propagates_without_fallback() -> None:
    dataset = load_golden_dataset(ROOT / "configs/eval/golden.jsonl")
    policy = load_rag_policy(ROOT / "configs/rag.yaml")

    class CancellingProvider(ControlledProvider):
        async def chat(self, request: ChatRequest) -> ChatResponse:
            del request
            raise asyncio.CancelledError

    def cancelling_factory(case: GoldenCase) -> CaseFixture:
        ordinary = fixture_for(case)
        return CaseFixture(
            retrieval=ordinary.retrieval,
            provider=CancellingProvider(object()),
            auth_context=ordinary.auth_context,
            query=ordinary.query,
        )

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(
            DeterministicRAGEvaluator(
                fixture_factory=cancelling_factory,
            ).evaluate(dataset, policy)
        )
