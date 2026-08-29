"""Injected, provider-neutral dependencies for the W4-001 API boundary."""

from __future__ import annotations

from typing import Protocol, cast, runtime_checkable

from fastapi import Request

from enterprise_ai_platform.rag.errors import RAGConfigurationError
from enterprise_ai_platform.rag.models import RAGResult
from enterprise_ai_platform.retrieval.models import AuthContext

from .errors import AuthenticationNotConfiguredError


@runtime_checkable
class Authenticator(Protocol):
    """Construct trusted identity separately from untrusted request JSON."""

    async def authenticate(self, request: Request) -> AuthContext: ...


@runtime_checkable
class RAGAnswerService(Protocol):
    """The existing provider-neutral RAG operation consumed by the route."""

    async def answer(
        self,
        auth_context: AuthContext,
        query: str,
        *,
        content_type: str = "text/plain",
    ) -> RAGResult: ...


@runtime_checkable
class ReadinessProbe(Protocol):
    """One local, network-free check of the injected query wiring."""

    async def check(self) -> bool: ...


class UnconfiguredAuthenticator:
    """Fail closed until a trusted authenticator is explicitly injected."""

    async def authenticate(self, request: Request) -> AuthContext:
        del request
        raise AuthenticationNotConfiguredError


class UnconfiguredRAGService:
    """Prevent an enabled route from inventing default RAG wiring."""

    async def answer(
        self,
        auth_context: AuthContext,
        query: str,
        *,
        content_type: str = "text/plain",
    ) -> RAGResult:
        del auth_context, query, content_type
        raise RAGConfigurationError


class UnconfiguredReadinessProbe:
    """Report degraded local wiring without probing an external dependency."""

    async def check(self) -> bool:
        return False


def get_authenticator(request: Request) -> Authenticator:
    """Return the application-scoped authenticator without invoking it."""

    return cast(Authenticator, request.app.state.api_authenticator)


def get_rag_service(request: Request) -> RAGAnswerService:
    """Return the application-scoped RAG boundary."""

    return cast(RAGAnswerService, request.app.state.api_rag_service)


def get_readiness_probe(request: Request) -> ReadinessProbe:
    """Return the application-scoped local readiness probe."""

    return cast(ReadinessProbe, request.app.state.api_readiness_probe)
