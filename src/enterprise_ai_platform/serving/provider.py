"""Provider-neutral inference protocol with no provider discovery or fallback."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from enterprise_ai_platform.serving.models import ServingRequest, ServingResponse


@runtime_checkable
class InferenceProvider(Protocol):
    """The only operation exposed to serving orchestration code."""

    async def infer(self, request: ServingRequest) -> ServingResponse:
        """Return a normalized response or a normalized serving error."""

        ...
