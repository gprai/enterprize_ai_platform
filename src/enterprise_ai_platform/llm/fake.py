"""Deterministic in-memory provider for ordinary local and automated testing."""

from __future__ import annotations

from collections.abc import Iterable

from enterprise_ai_platform.llm.errors import LLMError
from enterprise_ai_platform.llm.models import ChatRequest, ChatResponse, Usage


class FakeLLMProvider:
    """Return owner-supplied outcomes without network, credentials, or SDK clients."""

    def __init__(self, outcomes: Iterable[ChatResponse | LLMError] | None = None) -> None:
        self._outcomes = tuple(outcomes or ())
        self._next_outcome = 0
        self.requests: list[ChatRequest] = []

    async def chat(self, request: ChatRequest) -> ChatResponse:
        self.requests.append(request.model_copy(deep=True))
        if self._next_outcome < len(self._outcomes):
            outcome = self._outcomes[self._next_outcome]
            self._next_outcome += 1
            if isinstance(outcome, LLMError):
                raise outcome
            return outcome.model_copy(deep=True)
        return ChatResponse(
            text='{"text":"Deterministic fake response.","citations":[]}',
            usage=Usage(input_tokens=0, output_tokens=0, total_tokens=0),
            stop_reason="end_turn",
        )
