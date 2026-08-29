"""FastAPI application factory with an opt-in W4-001 service boundary."""

from __future__ import annotations

from typing import Literal

from fastapi import FastAPI
from pydantic import BaseModel

from . import __version__
from .api.dependencies import Authenticator, RAGAnswerService, ReadinessProbe
from .api.routes import register_api_boundary
from .api.runtime import RequestIdMiddleware
from .config import Settings


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
) -> FastAPI:
    """Create the API after configuration validation, without external clients."""
    resolved_settings = settings if settings is not None else Settings()
    api_enabled = resolved_settings.api_routes_enabled
    application = FastAPI(
        title=resolved_settings.app_name,
        version=__version__,
        docs_url=None if api_enabled else "/docs",
        redoc_url=None if api_enabled else "/redoc",
        openapi_url=None if api_enabled else "/openapi.json",
        redirect_slashes=not api_enabled,
    )
    application.state.settings = resolved_settings

    @application.get("/health", response_model=HealthResponse, tags=["health"])
    def health() -> HealthResponse:
        return HealthResponse(
            service=resolved_settings.app_name,
            environment=resolved_settings.environment,
        )

    if api_enabled:
        application.add_middleware(RequestIdMiddleware)
        register_api_boundary(
            application,
            resolved_settings,
            authenticator=authenticator,
            rag_service=rag_service,
            readiness_probe=readiness_probe,
        )

    return application
