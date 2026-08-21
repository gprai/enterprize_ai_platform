"""Minimal FastAPI application factory with no RAG runtime behavior."""

from __future__ import annotations

from typing import Literal

from fastapi import FastAPI
from pydantic import BaseModel

from . import __version__
from .config import Settings


class HealthResponse(BaseModel):
    """Non-sensitive liveness response."""

    status: Literal["ok"] = "ok"
    service: str
    environment: str


def create_app(settings: Settings | None = None) -> FastAPI:
    """Create the API after configuration validation, without external clients."""
    resolved_settings = settings if settings is not None else Settings()
    application = FastAPI(
        title=resolved_settings.app_name,
        version=__version__,
    )
    application.state.settings = resolved_settings

    @application.get("/health", response_model=HealthResponse, tags=["health"])
    def health() -> HealthResponse:
        return HealthResponse(
            service=resolved_settings.app_name,
            environment=resolved_settings.environment,
        )

    return application
