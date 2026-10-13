"""Deterministic offline provider for contract and failure-boundary tests."""

from __future__ import annotations

from enterprise_ai_platform.serving.models import ServingProvider, ServingRequest, ServingResponse


class FakeInferenceProvider:
    def __init__(self, provider: ServingProvider) -> None:
        self.provider = provider

    async def infer(self, request: ServingRequest) -> ServingResponse:
        return ServingResponse(
            request_id=request.request_id,
            provider=self.provider,
            artifact_digest=request.artifact.artifact_digest,
            output={"status": "offline-fake"},
        )
