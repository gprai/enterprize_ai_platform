"""Provider-neutral dependency contracts for W9-002 lineage tracking."""

from __future__ import annotations

from datetime import datetime
from typing import Protocol

from enterprise_ai_platform.retrieval.models import AuthContext

from .models import ExperimentInput, ExperimentRun, RedactedLineageExport, RunEnvelope, RunStatus


class ExperimentAuthorizer(Protocol):
    def authorize(self, envelope: RunEnvelope, auth_context: AuthContext, *, now: datetime) -> None:
        """Authorize one run before the store boundary."""


class ExperimentStore(Protocol):
    def create(self, envelope: RunEnvelope, experiment_input: ExperimentInput) -> ExperimentRun: ...

    def terminate(
        self,
        run_id: str,
        status: RunStatus,
        *,
        completed_at: datetime,
        safe_reason_code: str | None = None,
    ) -> ExperimentRun: ...

    def get(self, run_id: str) -> ExperimentRun: ...

    def list(self) -> tuple[ExperimentRun, ...]: ...

    def disable(self) -> None: ...

    def export(self, *, policy_sha256: str, exported_at: datetime) -> RedactedLineageExport: ...

    def purge(self, run_ids: tuple[str, ...], *, export_identity_sha256: str) -> None: ...
