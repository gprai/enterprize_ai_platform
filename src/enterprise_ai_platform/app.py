"""FastAPI application factory with an opt-in W4-001 service boundary."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Literal

from fastapi import FastAPI
from pydantic import BaseModel

from . import __version__
from .agent.contracts import AgentController
from .api.dependencies import Authenticator, RAGAnswerService, ReadinessProbe
from .api.routes import register_api_boundary
from .api.runtime import RequestIdMiddleware
from .config import Settings
from .telemetry.runtime import (
    TelemetryRuntime,
    telemetry_for_application,
)


class HealthResponse(BaseModel):
    """Non-sensitive liveness response."""

    status: Literal["ok"] = "ok"
    service: str
    environment: str


def create_app(
    settings: Settings | None = None,
    *,
    authenticator: Authenticator | None = None,
    rag_service: RAGAnswerService | None = None,
    readiness_probe: ReadinessProbe | None = None,
    agent_controller: AgentController | None = None,
    telemetry_runtime: TelemetryRuntime | None = None,
    telemetry_runtime_owned: bool = False,
) -> FastAPI:
    """Create the API after configuration validation, without external clients."""
    resolved_settings = settings if settings is not None else Settings()
    api_enabled = resolved_settings.api_routes_enabled
    resolved_telemetry = telemetry_for_application(
        enabled=resolved_settings.telemetry_enabled,
        injected=telemetry_runtime,
    )

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        del application
        try:
            yield
        finally:
            if telemetry_runtime_owned:
                resolved_telemetry.force_flush()
                resolved_telemetry.shutdown()

    application = FastAPI(
        title=resolved_settings.app_name,
        version=__version__,
        docs_url=None if api_enabled else "/docs",
        redoc_url=None if api_enabled else "/redoc",
        openapi_url=None if api_enabled else "/openapi.json",
        redirect_slashes=not api_enabled,
        lifespan=lifespan,
    )
    application.state.settings = resolved_settings

    @application.get("/health", response_model=HealthResponse, tags=["health"])
    def health() -> HealthResponse:
        return HealthResponse(
            service=resolved_settings.app_name,
            environment=resolved_settings.environment,
        )

    if api_enabled:
        application.state.telemetry_runtime = resolved_telemetry
        application.add_middleware(
            RequestIdMiddleware,
            telemetry=resolved_telemetry,
        )
        register_api_boundary(
            application,
            resolved_settings,
            authenticator=authenticator,
            rag_service=rag_service,
            readiness_probe=readiness_probe,
            agent_controller=agent_controller,
        )

    return application
