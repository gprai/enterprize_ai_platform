"""In-process, provider-free probes for the approved W4-11 release profiles."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

import httpx
from fastapi import Request

from enterprise_ai_platform.agent.models import AgentCommand, AgentResult
from enterprise_ai_platform.app import create_app
from enterprise_ai_platform.config import Settings
from enterprise_ai_platform.json_contracts import strict_json_loads
from enterprise_ai_platform.rag.models import RAGResult
from enterprise_ai_platform.retrieval.models import AuthContext

from .errors import ReleaseProbeError
from .models import (
    CandidateProbeResult,
    ReleaseDescriptor,
    RestoredProbeResult,
)


class ReleaseProbe(Protocol):
    async def probe_candidate(
        self,
        descriptor: ReleaseDescriptor,
    ) -> CandidateProbeResult: ...

    async def probe_restored(
        self,
        descriptor: ReleaseDescriptor,
    ) -> RestoredProbeResult: ...


@dataclass(slots=True)
class _ProbeCounters:
    authentication: int = 0
    rag: int = 0
    retrieval: int = 0
    embedding: int = 0
    provider: int = 0
    graph: int = 0
    approval: int = 0
    tool: int = 0

    def require_zero_business_calls(self) -> None:
        if any(
            (
                self.authentication,
                self.rag,
                self.retrieval,
                self.embedding,
                self.provider,
                self.graph,
                self.approval,
                self.tool,
            )
        ):
            raise ReleaseProbeError


class _NeverAuthenticator:
    def __init__(self, counters: _ProbeCounters) -> None:
        self._counters = counters

    async def authenticate(self, request: Request) -> AuthContext:
        del request
        self._counters.authentication += 1
        raise ReleaseProbeError


class _NeverRAGService:
    def __init__(self, counters: _ProbeCounters) -> None:
        self._counters = counters

    async def answer(
        self,
        auth_context: AuthContext,
        query: str,
        *,
        content_type: str = "text/plain",
    ) -> RAGResult:
        del auth_context, query, content_type
        self._counters.rag += 1
        raise ReleaseProbeError


class _NeverReadinessProbe:
    async def check(self) -> bool:
        raise ReleaseProbeError


class _NeverAgentController:
    def __init__(self, counters: _ProbeCounters) -> None:
        self._counters = counters

    async def handle(
        self,
        transport: AgentCommand,
        auth_context: AuthContext,
        request_id: str,
    ) -> AgentResult:
        del transport, auth_context, request_id
        self._counters.graph += 1
        raise ReleaseProbeError


def _settings(*, agent_enabled: bool) -> Settings:
    return Settings.model_validate(
        {
            "app_name": "enterprise-ai-platform",
            "environment": "sandbox",
            "api_routes_enabled": True,
            "agent_enabled": agent_enabled,
            "embedding_model_id": "w4-011.local-fake",
            "qdrant_url": "http://127.0.0.1:6333",
            "opensearch_url": "https://opensearch.invalid",
        }
    )


def _safe_error_code(payload: str) -> str:
    try:
        parsed = strict_json_loads(payload)
    except (TypeError, ValueError):
        raise ReleaseProbeError from None
    if not isinstance(parsed, dict):
        raise ReleaseProbeError
    error = parsed.get("error")
    if not isinstance(error, dict):
        raise ReleaseProbeError
    code = error.get("code")
    if not isinstance(code, str):
        raise ReleaseProbeError
    return code


class LocalASGIReleaseProbe:
    """Probe FastAPI through ASGI transport without opening a socket."""

    async def probe_candidate(
        self,
        descriptor: ReleaseDescriptor,
    ) -> CandidateProbeResult:
        if descriptor.release_version != "w4-synthetic-regression-v1":
            raise ReleaseProbeError
        counters = _ProbeCounters()
        application = create_app(
            _settings(agent_enabled=descriptor.agent_enabled),
            authenticator=_NeverAuthenticator(counters),
            rag_service=_NeverRAGService(counters),
            readiness_probe=_NeverReadinessProbe(),
            agent_controller=_NeverAgentController(counters),
        )
        transport = httpx.ASGITransport(app=application)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://w4-release.invalid",
        ) as client:
            response = await client.post(
                "/v1/agent",
                json={"action": "start", "query": "synthetic release probe"},
            )
        counters.require_zero_business_calls()
        if response.status_code != 501 or _safe_error_code(response.text) != (
            descriptor.expected_safe_error_code
        ):
            raise ReleaseProbeError
        return CandidateProbeResult(
            status="EXPECTED_REGRESSION_DETECTED",
            http_status=501,
            safe_error_code="agent_disabled",
            rag_calls=0,
            retrieval_calls=0,
            embedding_calls=0,
            provider_calls=0,
            graph_calls=0,
            approval_calls=0,
            tool_calls=0,
            network_activity=False,
        )

    async def probe_restored(
        self,
        descriptor: ReleaseDescriptor,
    ) -> RestoredProbeResult:
        if descriptor.release_version != "w4-known-good-v1" or not descriptor.agent_enabled:
            raise ReleaseProbeError
        counters = _ProbeCounters()
        application = create_app(
            _settings(agent_enabled=descriptor.agent_enabled),
            authenticator=_NeverAuthenticator(counters),
            rag_service=_NeverRAGService(counters),
            readiness_probe=_NeverReadinessProbe(),
            agent_controller=_NeverAgentController(counters),
        )
        transport = httpx.ASGITransport(app=application)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://w4-release.invalid",
        ) as client:
            health = await client.get("/health")
            agent = await client.post("/v1/agent", json={})
        counters.require_zero_business_calls()
        try:
            health_payload = strict_json_loads(health.text)
        except (TypeError, ValueError):
            raise ReleaseProbeError from None
        expected_health = {
            "status": "ok",
            "service": "enterprise-ai-platform",
            "environment": "sandbox",
        }
        agent_code = _safe_error_code(agent.text)
        if (
            health.status_code != 200
            or health_payload != expected_health
            or agent.status_code != 422
            or agent_code != "api_request_invalid"
        ):
            raise ReleaseProbeError
        return RestoredProbeResult(
            status="RESTORED_RELEASE_VERIFIED",
            health_http_status=200,
            health_status="ok",
            service="enterprise-ai-platform",
            environment="sandbox",
            agent_route_http_status=422,
            agent_route_safe_error_code="api_request_invalid",
            agent_disabled_observed=False,
            network_activity=False,
        )
