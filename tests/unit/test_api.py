"""Unit coverage for the opt-in, bounded W4-001 FastAPI surface."""

from __future__ import annotations

import asyncio
from typing import cast
from uuid import UUID

import httpx
import pytest
from fastapi.testclient import TestClient

from enterprise_ai_platform.agent.models import (
    AgentOutcome,
    AgentResult,
    TerminalReason,
)
from enterprise_ai_platform.api.dependencies import RAGAnswerService
from enterprise_ai_platform.api.runtime import QueryCapacityLimiter
from enterprise_ai_platform.app import create_app
from enterprise_ai_platform.config import Settings
from enterprise_ai_platform.embeddings.errors import (
    EmbeddingExecutionError,
    EmbeddingInputTooLongError,
)
from enterprise_ai_platform.guardrails.errors import GuardrailInputError
from enterprise_ai_platform.llm.errors import (
    LLMAuthenticationError,
    LLMThrottlingError,
    LLMTimeoutError,
)
from enterprise_ai_platform.llm.models import Usage
from enterprise_ai_platform.rag.errors import (
    RAGConfigurationError,
    RAGOutputValidationError,
)
from enterprise_ai_platform.rag.models import AbstentionResult, CitedAnswerResult
from enterprise_ai_platform.retrieval.errors import (
    VectorStoreAuthorizationError,
    VectorStoreTimeoutError,
    VectorStoreUnavailableError,
    VectorStoreValidationError,
)
from enterprise_ai_platform.retrieval.models import (
    Answer,
    AuthContext,
    Citation,
    Classification,
    Role,
)
from tests.fakes.agent import FakeAgentController
from tests.fakes.api import FakeAuthenticator, FakeRAGService, FakeReadinessProbe


def _auth() -> AuthContext:
    return AuthContext(
        subject_id="reader-a",
        tenant_id="tenant-a",
        roles=frozenset({Role.READER}),
        clearance=Classification.INTERNAL,
    )


def _answered() -> CitedAnswerResult:
    return CitedAnswerResult(
        answer=Answer(
            text="Governed answer.",
            citations=(
                Citation(
                    source_id="source-001",
                    document_id="policy-001",
                    document_version="v1",
                    chunk_id="a" * 64,
                ),
            ),
        ),
        usage=Usage(input_tokens=10, output_tokens=5, total_tokens=15),
    )


def _abstained() -> AbstentionResult:
    return AbstentionResult(reason="insufficient_evidence", usage=None)


def _settings(settings: Settings, **updates: object) -> Settings:
    values = settings.model_dump(mode="python")
    values.update(updates)
    return Settings(_env_file=None, **values)


def _assert_request_id(value: str) -> None:
    parsed = UUID(value)
    assert parsed.version == 4
    assert str(parsed) == value


def _client(
    settings: Settings,
    rag: FakeRAGService,
    *,
    authenticator: FakeAuthenticator | None = None,
    readiness: FakeReadinessProbe | None = None,
    agent_controller: FakeAgentController | None = None,
    raise_server_exceptions: bool = True,
) -> TestClient:
    application = create_app(
        settings,
        authenticator=authenticator or FakeAuthenticator(_auth()),
        rag_service=rag,
        readiness_probe=readiness or FakeReadinessProbe(),
        agent_controller=agent_controller,
    )
    return TestClient(
        application,
        raise_server_exceptions=raise_server_exceptions,
    )


def test_default_off_preserves_exact_health_only_business_surface(
    valid_settings: Settings,
) -> None:
    application = create_app(valid_settings)
    paths = {route.path for route in application.routes}
    response = TestClient(application).get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "enterprise-ai-platform",
        "environment": "sandbox",
    }
    assert "X-Request-ID" not in response.headers
    assert not paths.intersection(
        {"/health/live", "/health/ready", "/v1/query", "/v1/agent"}
    )
    assert set(application.state._state) == {"settings"}


def test_enabled_health_live_ready_and_hidden_documentation_surface(
    api_settings: Settings,
) -> None:
    readiness = FakeReadinessProbe()
    application = create_app(
        api_settings,
        authenticator=FakeAuthenticator(_auth()),
        rag_service=FakeRAGService([_abstained()]),
        readiness_probe=readiness,
    )
    client = TestClient(application)

    health = client.get("/health")
    live = client.get(
        "/health/live",
        headers={"X-Request-ID": "client-controlled"},
    )
    ready = client.get("/health/ready")

    assert health.json() == {
        "status": "ok",
        "service": "enterprise-ai-platform",
        "environment": "sandbox",
    }
    _assert_request_id(health.headers["X-Request-ID"])
    assert live.status_code == 200
    assert live.json() == {
        "request_id": live.headers["X-Request-ID"],
        "status": "ok",
    }
    assert live.headers["X-Request-ID"] != "client-controlled"
    assert ready.status_code == 200
    assert ready.json()["status"] == "ready"
    assert ready.json()["request_id"] == ready.headers["X-Request-ID"]
    assert readiness.calls == 1
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404
    assert client.get("/redoc").status_code == 404
    assert client.get("/health/live/").status_code == 404


def test_readiness_degraded_failure_and_timeout_are_safe(
    api_settings: Settings,
) -> None:
    probes = (
        FakeReadinessProbe(False),
        FakeReadinessProbe(RuntimeError("private readiness failure")),
        FakeReadinessProbe(True, delay_seconds=0.02),
    )
    timeout_settings = _settings(
        api_settings,
        api_readiness_timeout_seconds=0.01,
    )

    for probe in probes:
        client = _client(
            timeout_settings,
            FakeRAGService([_abstained()]),
            readiness=probe,
        )
        response = client.get("/health/ready")

        assert response.status_code == 503
        assert response.json()["error"]["code"] == "service_not_ready"
        assert "private" not in response.text
        assert probe.calls == 1


def test_answered_and_abstained_queries_delegate_once_as_plain_text(
    api_settings: Settings,
) -> None:
    rag = FakeRAGService([_answered(), _abstained()])
    client = _client(api_settings, rag)

    answered = client.post("/v1/query", json={"query": "What is governed?"})
    abstained = client.post("/v1/query", json={"query": "Unknown fact"})

    assert answered.status_code == 200
    assert answered.json() == {
        "request_id": answered.headers["X-Request-ID"],
        "outcome": "answered",
        "answer": "Governed answer.",
        "citations": [
            {
                "source_id": "source-001",
                "document_id": "policy-001",
                "document_version": "v1",
                "chunk_id": "a" * 64,
                "label": None,
            }
        ],
        "prompt_version": "w3-001.v1",
        "usage": {
            "input_tokens": 10,
            "output_tokens": 5,
            "total_tokens": 15,
            "estimated_cost_usd": None,
        },
    }
    assert abstained.status_code == 200
    assert abstained.json() == {
        "request_id": abstained.headers["X-Request-ID"],
        "outcome": "abstained",
        "reason": "insufficient_evidence",
        "prompt_version": "w3-001.v1",
    }
    assert answered.headers["X-Request-ID"] != abstained.headers["X-Request-ID"]
    assert [call.query for call in rag.calls] == ["What is governed?", "Unknown fact"]
    assert all(call.content_type == "text/plain" for call in rag.calls)


@pytest.mark.parametrize(
    ("content", "headers", "expected_status", "expected_code"),
    [
        (b'{"query":"valid"}', {"Content-Type": "text/plain"}, 415, "api_unsupported_media_type"),
        (
            b'{"query":"valid"}',
            {"Content-Type": "application/json", "Content-Encoding": "gzip"},
            415,
            "api_unsupported_media_type",
        ),
        (b"not-json", {"Content-Type": "application/json"}, 400, "api_request_malformed"),
        (
            b'{"query":"first","query":"second"}',
            {"Content-Type": "application/json"},
            400,
            "api_request_malformed",
        ),
        (b'{"query":NaN}', {"Content-Type": "application/json"}, 400, "api_request_malformed"),
        (b"\xff", {"Content-Type": "application/json"}, 400, "api_request_malformed"),
        (b"{}", {"Content-Type": "application/json"}, 422, "api_request_invalid"),
        (
            b'{"query":1}',
            {"Content-Type": "application/json"},
            422,
            "api_request_invalid",
        ),
        (
            b'{"query":"valid","tenant_id":"tenant-a"}',
            {"Content-Type": "application/json"},
            422,
            "api_request_invalid",
        ),
    ],
)
def test_transport_rejection_occurs_before_authentication(
    api_settings: Settings,
    content: bytes,
    headers: dict[str, str],
    expected_status: int,
    expected_code: str,
) -> None:
    authenticator = FakeAuthenticator(_auth())
    client = _client(
        api_settings,
        FakeRAGService([_abstained()]),
        authenticator=authenticator,
    )

    response = client.post("/v1/query", content=content, headers=headers)

    assert response.status_code == expected_status
    assert response.json()["error"]["code"] == expected_code
    assert response.json()["request_id"] == response.headers["X-Request-ID"]
    assert authenticator.calls == 0


def test_raw_body_limit_is_enforced_before_json_validation(
    api_settings: Settings,
) -> None:
    bounded = _settings(api_settings, api_max_request_body_bytes=16)
    authenticator = FakeAuthenticator(_auth())
    client = _client(
        bounded,
        FakeRAGService([_abstained()]),
        authenticator=authenticator,
    )

    response = client.post("/v1/query", json={"query": "x" * 100})

    assert response.status_code == 413
    assert response.json()["error"]["code"] == "api_request_too_large"
    assert authenticator.calls == 0


@pytest.mark.parametrize(
    ("failure", "status", "code", "retryable"),
    [
        (GuardrailInputError(), 422, "guardrail_input_invalid", None),
        (VectorStoreAuthorizationError(), 403, "vector_store_authorization_denied", False),
        (VectorStoreTimeoutError(), 504, "vector_store_timeout", True),
        (VectorStoreUnavailableError(), 503, "vector_store_unavailable", True),
        (VectorStoreValidationError(), 503, "vector_store_validation", False),
        (EmbeddingInputTooLongError(), 422, "embedding_input_too_long", None),
        (EmbeddingExecutionError(), 503, "embedding_execution_failed", None),
        (RAGConfigurationError(), 503, "rag_configuration_invalid", None),
        (RAGOutputValidationError(), 502, "rag_output_invalid", None),
        (LLMAuthenticationError(), 503, "llm_authentication_failed", None),
        (LLMTimeoutError(), 504, "llm_timeout", None),
        (LLMThrottlingError(), 503, "llm_throttled", None),
    ],
)
def test_domain_errors_are_normalized_without_raw_content(
    api_settings: Settings,
    failure: Exception,
    status: int,
    code: str,
    retryable: bool | None,
) -> None:
    response = _client(api_settings, FakeRAGService([failure])).post(
        "/v1/query",
        json={"query": "safe query"},
    )

    assert response.status_code == status
    assert response.json()["error"]["code"] == code
    assert response.json()["error"].get("retryable") is retryable
    assert "safe query" not in response.text


def test_deadline_returns_safe_error_and_releases_capacity(
    api_settings: Settings,
) -> None:
    settings = _settings(api_settings, request_timeout_seconds=1)
    application = create_app(
        settings,
        authenticator=FakeAuthenticator(_auth()),
        rag_service=FakeRAGService([_abstained()], delay_seconds=1.1),
        readiness_probe=FakeReadinessProbe(),
    )

    response = TestClient(application).post(
        "/v1/query",
        json={"query": "bounded query"},
    )

    assert response.status_code == 504
    assert response.json()["error"]["code"] == "api_query_deadline_exceeded"
    limiter = cast(QueryCapacityLimiter, application.state.api_query_limiter)
    assert limiter.active == 0


def test_overload_rejects_without_rag_call_and_first_request_completes(
    api_settings: Settings,
) -> None:
    async def scenario() -> None:
        started = asyncio.Event()
        release = asyncio.Event()

        class BlockingRAG:
            def __init__(self) -> None:
                self.calls = 0

            async def answer(
                self,
                auth_context: AuthContext,
                query: str,
                *,
                content_type: str = "text/plain",
            ) -> AbstentionResult:
                del auth_context, query, content_type
                self.calls += 1
                started.set()
                await release.wait()
                return _abstained()

        rag = BlockingRAG()
        application = create_app(
            _settings(api_settings, api_max_inflight_queries=1),
            authenticator=FakeAuthenticator(_auth()),
            rag_service=cast(RAGAnswerService, rag),
            readiness_probe=FakeReadinessProbe(),
        )
        transport = httpx.ASGITransport(app=application)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://testserver",
        ) as client:
            first = asyncio.create_task(
                client.post("/v1/query", json={"query": "first"})
            )
            await started.wait()
            overloaded = await client.post("/v1/query", json={"query": "second"})
            release.set()
            completed = await first

        assert overloaded.status_code == 503
        assert overloaded.headers["Retry-After"] == "1"
        assert overloaded.json()["error"] == {
            "code": "api_overloaded",
            "message": "The query service is at capacity.",
            "retryable": True,
        }
        assert completed.status_code == 200
        assert rag.calls == 1

    asyncio.run(scenario())


def test_cancellation_propagates_and_capacity_is_released(
    api_settings: Settings,
) -> None:
    async def scenario() -> None:
        started = asyncio.Event()

        class CancellableRAG:
            async def answer(
                self,
                auth_context: AuthContext,
                query: str,
                *,
                content_type: str = "text/plain",
            ) -> AbstentionResult:
                del auth_context, query, content_type
                started.set()
                await asyncio.Event().wait()
                return _abstained()

        application = create_app(
            _settings(api_settings, api_max_inflight_queries=1),
            authenticator=FakeAuthenticator(_auth()),
            rag_service=cast(RAGAnswerService, CancellableRAG()),
            readiness_probe=FakeReadinessProbe(),
        )
        transport = httpx.ASGITransport(app=application)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://testserver",
        ) as client:
            request_task = asyncio.create_task(
                client.post("/v1/query", json={"query": "cancel me"})
            )
            await started.wait()
            request_task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await request_task

        limiter = cast(QueryCapacityLimiter, application.state.api_query_limiter)
        assert limiter.active == 0

    asyncio.run(scenario())


def test_disabled_agent_resolves_no_dependency_and_unknown_routes_are_safe(
    api_settings: Settings,
) -> None:
    authenticator = FakeAuthenticator(_auth())
    rag = FakeRAGService([_answered()])
    readiness = FakeReadinessProbe()
    controller = FakeAgentController(
        AgentResult(
            request_id=UUID("12345678-1234-4678-9234-567812345678"),
            run_id=UUID("22345678-1234-4678-9234-567812345678"),
            outcome=AgentOutcome.SAFE_TERMINAL,
            terminal_reason=TerminalReason.SAFE_FAILURE,
        )
    )
    client = _client(
        api_settings,
        rag,
        authenticator=authenticator,
        readiness=readiness,
        agent_controller=controller,
    )

    disabled = client.post("/v1/agent", json={"query": "ignored"})
    missing = client.get("/missing")
    wrong_method = client.get("/v1/query")

    assert disabled.status_code == 501
    assert disabled.json()["error"]["code"] == "agent_disabled"
    assert authenticator.calls == 0
    assert rag.calls == []
    assert readiness.calls == 0
    assert controller.calls == []
    assert missing.status_code == 404
    assert missing.json()["error"]["code"] == "api_not_found"
    assert wrong_method.status_code == 405
    assert wrong_method.json()["error"]["code"] == "api_method_not_allowed"


def test_unhandled_exception_is_content_free(
    api_settings: Settings,
) -> None:
    secret = "PROMPT_AND_EVIDENCE_MUST_NOT_ESCAPE"
    client = _client(
        api_settings,
        FakeRAGService([RuntimeError(secret)]),
        raise_server_exceptions=False,
    )

    response = client.post("/v1/query", json={"query": secret})

    assert response.status_code == 500
    assert response.json()["error"]["code"] == "internal_error"
    assert secret not in response.text
