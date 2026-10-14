"""Provider-neutral dependency contracts for W9-001 training."""

from __future__ import annotations

from typing import Protocol

from enterprise_ai_platform.retrieval.models import AuthContext

from .models import CapabilityEvidence, TrainingRequest, TrainingResult


class TorchRuntime(Protocol):
    @property
    def version(self) -> str: ...

    def cuda_available(self) -> bool: ...

    def cuda_device_count(self) -> int: ...


class TrainingAuthorizer(Protocol):
    def authorize(self, request: TrainingRequest, auth_context: AuthContext) -> None: ...


class TrainingProvider(Protocol):
    def prepare(
        self, request: TrainingRequest, capability: CapabilityEvidence
    ) -> TrainingResult: ...
