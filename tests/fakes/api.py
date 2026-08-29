"""Deterministic in-memory dependencies for the W4-001 API tests."""

from __future__ import annotations

import asyncio
from collections.abc import Iterable
from dataclasses import dataclass

from fastapi import Request

from enterprise_ai_platform.rag.models import RAGResult
from enterprise_ai_platform.retrieval.models import AuthContext


class FakeAuthenticator:
    """Return one trusted context or one owner-selected safe failure."""

    def __init__(self, outcome: AuthContext | BaseException) -> None:
        self.outcome = outcome
        self.calls = 0
        self.paths: list[str] = []

    async def authenticate(self, request: Request) -> AuthContext:
        self.calls += 1
        self.paths.append(request.url.path)
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return self.outcome.model_copy(deep=True)


@dataclass(frozen=True, slots=True)
class RAGCall:
    auth_context: AuthContext
    query: str
    content_type: str


class FakeRAGService:
    """Return deterministic normalized results without retrieval or providers."""

    def __init__(
        self,
        outcomes: Iterable[RAGResult | BaseException],
        *,
        delay_seconds: float = 0.0,
    ) -> None:
        self._outcomes = tuple(outcomes)
        self._next = 0
        self._delay_seconds = delay_seconds
        self.calls: list[RAGCall] = []

    async def answer(
        self,
        auth_context: AuthContext,
        query: str,
        *,
        content_type: str = "text/plain",
    ) -> RAGResult:
        self.calls.append(
            RAGCall(
                auth_context=auth_context.model_copy(deep=True),
                query=query,
                content_type=content_type,
            )
        )
        if self._delay_seconds:
            await asyncio.sleep(self._delay_seconds)
        if self._next >= len(self._outcomes):
            raise AssertionError("fake RAG service has no remaining outcome")
        outcome = self._outcomes[self._next]
        self._next += 1
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome.model_copy(deep=True)


class FakeReadinessProbe:
    """Return one local readiness state with an optional bounded delay."""

    def __init__(
        self,
        outcome: bool | BaseException = True,
        *,
        delay_seconds: float = 0.0,
    ) -> None:
        self.outcome = outcome
        self.delay_seconds = delay_seconds
        self.calls = 0

    async def check(self) -> bool:
        self.calls += 1
        if self.delay_seconds:
            await asyncio.sleep(self.delay_seconds)
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return self.outcome
