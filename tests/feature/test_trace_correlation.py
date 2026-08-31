"""W4-08 proof: one local root trace per honest deterministic request scenario."""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Sequence
from uuid import uuid4

from fastapi.testclient import TestClient
from opentelemetry.sdk.trace import ReadableSpan

from enterprise_ai_platform.agent.controller import BoundedAgentController
from enterprise_ai_platform.agent.models import (
    AgentBudgets,
    AnswerReference,
    EvidenceGrade,
    EvidencePacket,
    MockSetServiceModeArguments,
    ToolKind,
    ToolProposal,
)
from enterprise_ai_platform.app import create_app
from enterprise_ai_platform.config import Settings
from enterprise_ai_platform.embeddings.fake import FakeEmbeddingProvider
from enterprise_ai_platform.json_contracts import strict_json_loads
from enterprise_ai_platform.llm.fake import FakeLLMProvider
from enterprise_ai_platform.llm.models import ChatResponse, Usage
from enterprise_ai_platform.rag.config import RAGPolicy
from enterprise_ai_platform.rag.service import RAGService
from enterprise_ai_platform.retrieval.models import (
    AuthContext,
    Classification,
    CollectionSpec,
    IngestionStatus,
    PiiStatus,
    Query,
    RetrievedChunk,
    Role,
    deterministic_chunk_id,
)
from enterprise_ai_platform.retrieval.service import RetrievalService
from enterprise_ai_platform.telemetry.models import SPAN_NAMES
from enterprise_ai_platform.telemetry.runtime import BoundedInMemorySpanExporter
from tests.fakes.agent import (
    FakeAgentGateway,
    FakeAgentPlanner,
    FakeLocalStatusProvider,
    InMemoryAgentStore,
)
from tests.fakes.api import FakeAuthenticator, FakeReadinessProbe
from tests.fakes.telemetry import SECURITY_SENTINELS
from tests.security.test_api_authorization import INJECTION, SECRET

_TRACE_OBSERVATION_FIELDS = frozenset(
    {
        "schema_version",
        "scope",
        "scenario_count",
        "total_trace_count",
        "scenarios",
        "redaction_verified",
    }
)
_TRACE_SCENARIO_FIELDS = frozenset(
    {
        "scenario",
        "trace_count",
        "span_count",
        "root_span_count",
        "root_span_names",
        "span_name_counts",
        "parent_child_edges",
        "maximum_depth",
        "all_parents_resolved",
        "all_spans_same_trace",
        "expected_span_names_present",
    }
)
_TRACE_EDGE_FIELDS = frozenset({"parent_span_name", "child_span_name", "count"})


def _auth(subject: str, *roles: Role) -> AuthContext:
    return AuthContext(
        subject_id=subject,
        tenant_id="tenant-a",
        roles=frozenset(roles),
        clearance=Classification.INTERNAL,
    )


def _chunk() -> RetrievedChunk:
    content_hash = "a" * 64
    chunk_id = deterministic_chunk_id(
        tenant_id="tenant-a",
        document_id="policy-001",
        document_version="v1",
        content_hash=content_hash,
        chunk_index=0,
    )
    return RetrievedChunk(
        tenant_id="tenant-a",
        source_id="source-001",
        media_type="text/plain",
        document_id="policy-001",
        document_version="v1",
        classification=Classification.INTERNAL,
        allowed_roles=frozenset({Role.READER}),
        data_owner="owner-a",
        content_hash=content_hash,
        pii_status=PiiStatus.CLEAR,
        ingestion_status=IngestionStatus.INDEXED,
        chunk_id=chunk_id,
        chunk_index=0,
        text="Approved synthetic evidence.",
        embedding=(1.0,) + (0.0,) * 383,
        score=0.95,
    )


class DeterministicVectorSearch:
    def __init__(self, result: RetrievedChunk) -> None:
        self.result = result
        self.search_calls = 0

    async def search(
        self,
        specification: CollectionSpec,
        query: Query,
        query_vector: Sequence[float],
        auth_context: AuthContext,
        *,
        timeout_seconds: float | None = None,
    ) -> tuple[RetrievedChunk, ...]:
        del specification, query, query_vector, auth_context, timeout_seconds
        self.search_calls += 1
        return (self.result.model_copy(deep=True),)


def _rag_service(
    runtime,  # type: ignore[no-untyped-def]
    chunk: RetrievedChunk,
) -> tuple[RAGService, DeterministicVectorSearch]:
    vector_search = DeterministicVectorSearch(chunk)
    retrieval = RetrievalService(
        embedder=FakeEmbeddingProvider(),
        vector_store=vector_search,  # type: ignore[arg-type]
        collection_spec=CollectionSpec(name="w4_003_trace"),
        telemetry=runtime,
    )
    response = ChatResponse(
        text=json.dumps(
            {
                "answer": "Governed answer.",
                "citations": [
                    {
                        "source_id": chunk.source_id,
                        "document_id": chunk.document_id,
                        "document_version": chunk.document_version,
                        "chunk_id": chunk.chunk_id,
                    }
                ],
            }
        ),
        usage=Usage(input_tokens=10, output_tokens=5, total_tokens=15),
        stop_reason="end_turn",
    )
    return (
        RAGService(
            retrieval_service=retrieval,
            llm_provider=FakeLLMProvider([response]),
            policy=RAGPolicy(
                top_k=5,
                min_score=0.5,
                minimum_qualifying_chunks=1,
                max_context_characters=12_000,
                max_output_tokens=512,
                prompt_version="w3-001.v1",
            ),
            telemetry=runtime,
        ),
        vector_search,
    )


def _enabled(settings: Settings) -> Settings:
    values = settings.model_dump(mode="python")
    values.update(
        api_routes_enabled=True,
        agent_enabled=True,
        telemetry_enabled=True,
    )
    return Settings(_env_file=None, **values)


def _span_depth(
    span_id: int,
    spans_by_id: dict[int, ReadableSpan],
    trace_id: int,
    ancestors: frozenset[int] = frozenset(),
) -> int:
    assert span_id not in ancestors
    span = spans_by_id[span_id]
    parent = span.parent
    if parent is None:
        return 0
    assert parent.trace_id == trace_id
    assert parent.span_id in spans_by_id
    return 1 + _span_depth(
        parent.span_id,
        spans_by_id,
        trace_id,
        ancestors | {span_id},
    )


def _build_trace_observation(
    spans: tuple[ReadableSpan, ...],
    scenario_specs: tuple[tuple[str, int, frozenset[str]], ...],
) -> dict[str, object]:
    approved_span_names = frozenset(SPAN_NAMES.values())
    spans_by_trace: dict[int, list[ReadableSpan]] = {}
    for span in spans:
        assert span.context is not None
        spans_by_trace.setdefault(span.context.trace_id, []).append(span)

    assert len(scenario_specs) == 3
    trace_ids = {trace_id for _, trace_id, _ in scenario_specs}
    assert len(trace_ids) == 3
    assert trace_ids == set(spans_by_trace)

    scenario_summaries: list[dict[str, object]] = []
    for scenario, trace_id, expected_names in scenario_specs:
        trace_spans = tuple(spans_by_trace[trace_id])
        assert trace_spans
        all_spans_same_trace = all(
            span.context is not None and span.context.trace_id == trace_id for span in trace_spans
        )
        assert all_spans_same_trace

        spans_by_id: dict[int, ReadableSpan] = {}
        for span in trace_spans:
            assert span.context is not None
            assert span.context.span_id not in spans_by_id
            spans_by_id[span.context.span_id] = span

        all_parents_resolved = all(
            span.parent is None
            or (span.parent.trace_id == trace_id and span.parent.span_id in spans_by_id)
            for span in trace_spans
        )
        assert all_parents_resolved

        root_spans = tuple(span for span in trace_spans if span.parent is None)
        assert len(root_spans) == 1
        name_counts = Counter(span.name for span in trace_spans)
        assert set(name_counts) <= approved_span_names
        expected_span_names_present = expected_names.issubset(name_counts)
        assert expected_span_names_present

        edge_counts: Counter[tuple[str, str]] = Counter()
        for span in trace_spans:
            if span.parent is None:
                continue
            parent_span = spans_by_id[span.parent.span_id]
            edge_counts[(parent_span.name, span.name)] += 1

        parent_child_edges = [
            {
                "parent_span_name": parent_name,
                "child_span_name": child_name,
                "count": edge_counts[(parent_name, child_name)],
            }
            for parent_name, child_name in sorted(edge_counts)
        ]
        span_name_counts = {name: name_counts[name] for name in sorted(name_counts)}
        maximum_depth = max(_span_depth(span_id, spans_by_id, trace_id) for span_id in spans_by_id)
        summary = {
            "scenario": scenario,
            "trace_count": 1,
            "span_count": len(trace_spans),
            "root_span_count": len(root_spans),
            "root_span_names": sorted(span.name for span in root_spans),
            "span_name_counts": span_name_counts,
            "parent_child_edges": parent_child_edges,
            "maximum_depth": maximum_depth,
            "all_parents_resolved": all_parents_resolved,
            "all_spans_same_trace": all_spans_same_trace,
            "expected_span_names_present": expected_span_names_present,
        }
        assert set(summary) == _TRACE_SCENARIO_FIELDS
        assert sum(span_name_counts.values()) == summary["span_count"]
        assert sum(edge["count"] for edge in parent_child_edges) == (
            summary["span_count"] - summary["root_span_count"]
        )
        assert all(set(edge) == _TRACE_EDGE_FIELDS for edge in parent_child_edges)
        scenario_summaries.append(summary)

    observation = {
        "schema_version": "w4-008.trace-observation.v1",
        "scope": "local_deterministic_in_process",
        "scenario_count": len(scenario_summaries),
        "total_trace_count": len(trace_ids),
        "scenarios": scenario_summaries,
        "redaction_verified": True,
    }
    assert set(observation) == _TRACE_OBSERVATION_FIELDS
    assert observation["scenario_count"] == 3
    assert observation["total_trace_count"] == 3
    return observation


def test_query_agent_start_and_agent_decision_form_three_correlated_traces(
    valid_settings: Settings,
    telemetry_factory,
) -> None:  # type: ignore[no-untyped-def]
    composition = telemetry_factory()
    runtime = composition.runtime
    chunk = _chunk()
    rag, vector_search = _rag_service(runtime, chunk)
    gateway = FakeAgentGateway(
        evidence=EvidencePacket(references=("b" * 64,)),
        grade=EvidenceGrade(authorized=True, sufficient=True),
        answer=AnswerReference(result_reference_sha256="c" * 64, total_tokens=12),
    )
    planner = FakeAgentPlanner(
        ToolProposal(
            name="mock_set_service_mode",
            kind=ToolKind.MOCK_WRITE,
            arguments=MockSetServiceModeArguments(mode="maintenance"),
        )
    )
    store = InMemoryAgentStore()
    controller = BoundedAgentController(
        gateway=gateway,
        planner=planner,
        status_provider=FakeLocalStatusProvider(),
        store=store,
        budgets=AgentBudgets(),
        mock_write_enabled=True,
        telemetry=runtime,
    )
    authenticator = FakeAuthenticator(_auth("reader-a", Role.READER))
    application = create_app(
        _enabled(valid_settings),
        authenticator=authenticator,
        rag_service=rag,
        readiness_probe=FakeReadinessProbe(),
        agent_controller=controller,
        telemetry_runtime=runtime,
    )
    client = TestClient(application)
    untrusted_headers = {
        "traceparent": "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01",
        "tracestate": "vendor=untrusted",
        "baggage": "tenant=untrusted",
        "X-Request-ID": "untrusted-request",
        "X-Correlation-ID": "untrusted-correlation",
        "X-Forwarded-For": "203.0.113.1",
    }

    query_response = client.post(
        "/v1/query",
        json={"query": "governed question"},
        headers=untrusted_headers,
    )
    authenticator.outcome = _auth("requester-a", Role.ADMIN)
    start_response = client.post(
        "/v1/agent",
        json={"action": "start", "query": "request controlled change"},
        headers=untrusted_headers,
    )
    approval_id = start_response.json()["approval_id"]
    authenticator.outcome = _auth("reviewer-a", Role.REVIEWER)
    decision_response = client.post(
        "/v1/agent",
        json={
            "action": "decide",
            "approval_id": approval_id,
            "idempotency_key": str(uuid4()),
            "decision": "approved",
            "tool_name": "mock_set_service_mode",
            "tool_version": "1.0",
            "arguments": {"mode": "maintenance"},
        },
        headers=untrusted_headers,
    )

    assert query_response.status_code == 200
    assert start_response.status_code == 202
    assert decision_response.status_code == 200
    assert vector_search.search_calls == 1
    assert gateway.calls == ["retrieve", "grade_evidence", "answer"]
    assert planner.calls == 1

    runtime.force_flush()
    assert isinstance(composition.span_exporter, BoundedInMemorySpanExporter)
    spans = composition.span_exporter.get_finished_spans()
    traces: dict[int, set[str]] = {}
    for span in spans:
        assert span.context is not None
        traces.setdefault(span.context.trace_id, set()).add(span.name)
    assert len(traces) == 3
    assert int("a" * 32, 16) not in traces

    query_trace_id, query_trace = next(
        (trace_id, names)
        for trace_id, names in traces.items()
        if "enterprise_ai.rag.answer" in names
    )
    start_trace_id, start_trace = next(
        (trace_id, names)
        for trace_id, names in traces.items()
        if "enterprise_ai.agent.await_human_approval" in names
        and "enterprise_ai.approval.evaluate" not in names
    )
    decision_trace_id, decision_trace = next(
        (trace_id, names)
        for trace_id, names in traces.items()
        if "enterprise_ai.approval.evaluate" in names
    )
    query_expected_names = frozenset(
        {
            "enterprise_ai.api.request",
            "enterprise_ai.auth.authenticate",
            "enterprise_ai.auth.authorize",
            "enterprise_ai.guardrail.validate",
            "enterprise_ai.rag.answer",
            "enterprise_ai.retrieval.retrieve",
            "enterprise_ai.embedding.query",
            "enterprise_ai.vector.search",
            "enterprise_ai.llm.chat",
        }
    )
    start_expected_names = frozenset(
        {
            "enterprise_ai.api.request",
            "enterprise_ai.agent.handle",
            "enterprise_ai.agent.validate_input",
            "enterprise_ai.agent.authorize",
            "enterprise_ai.agent.retrieve",
            "enterprise_ai.agent.grade_evidence",
            "enterprise_ai.agent.answer",
            "enterprise_ai.agent.propose_tool",
            "enterprise_ai.agent.await_human_approval",
            "enterprise_ai.agent.safe_terminal",
            "enterprise_ai.approval.persist",
        }
    )
    decision_expected_names = frozenset(
        {
            "enterprise_ai.api.request",
            "enterprise_ai.agent.handle",
            "enterprise_ai.approval.evaluate",
            "enterprise_ai.approval.persist",
            "enterprise_ai.tool.execute",
        }
    )
    assert query_expected_names.issubset(query_trace)
    assert start_expected_names.issubset(start_trace)
    assert decision_expected_names.issubset(decision_trace)

    request_ids = {
        str(record.request_id)
        for record in composition.log_sink.records()
        if record.request_id is not None
    }
    assert request_ids == {
        query_response.headers["X-Request-ID"],
        start_response.headers["X-Request-ID"],
        decision_response.headers["X-Request-ID"],
    }
    assert "untrusted-request" not in request_ids

    scenario_specs = (
        ("query", query_trace_id, query_expected_names),
        ("agent_start", start_trace_id, start_expected_names),
        ("agent_decision", decision_trace_id, decision_expected_names),
    )
    immutable_spans = tuple(spans)
    observation_one = _build_trace_observation(immutable_spans, scenario_specs)
    observation_two = _build_trace_observation(immutable_spans, scenario_specs)
    assert observation_one == observation_two
    canonical_one = json.dumps(
        observation_one,
        sort_keys=True,
        separators=(",", ":"),
    )
    canonical_two = json.dumps(
        observation_two,
        sort_keys=True,
        separators=(",", ":"),
    )
    assert canonical_one.encode("utf-8") == canonical_two.encode("utf-8")
    assert strict_json_loads(canonical_one) == observation_one

    raw_identifiers = {
        *(f"{trace_id:032x}" for trace_id in traces),
        *(f"{span.context.span_id:016x}" for span in immutable_spans if span.context is not None),
        *request_ids,
        "untrusted-request",
        "untrusted-correlation",
    }
    for forbidden in (
        INJECTION,
        SECRET,
        *SECURITY_SENTINELS,
        *raw_identifiers,
    ):
        assert forbidden not in canonical_one

    print(f"W4_08_TRACE_OBSERVATION={canonical_one}")
