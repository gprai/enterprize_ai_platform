"""FastAPI application factory with explicit API and telemetry composition."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Literal

from fastapi import FastAPI
from pydantic import BaseModel

from . import __version__
from .agent.contracts import AgentController
from .api.aws_composition import AWSRuntimeComposition, compose_aws_runtime
from .api.dependencies import Authenticator, RAGAnswerService, ReadinessProbe
from .api.routes import register_api_boundary
from .api.runtime import ApplicationDrainController, RequestIdMiddleware
from .api.sandbox_auth import SandboxTokenAuthenticator
from .config import Settings
from .telemetry.export import ExportingTelemetryRuntime
from .telemetry.runtime import (
    OTLPTelemetryRuntime,
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
    """Create the API after configuration validation, without implicit clients."""
    resolved_settings = settings if settings is not None else Settings()
    aws_runtime: AWSRuntimeComposition | None = None
    if resolved_settings.aws_composition_enabled:
        if any(
            dependency is not None
            for dependency in (rag_service, readiness_probe, telemetry_runtime)
        ):
            raise ValueError("AWS composition cannot be mixed with injected provider wiring")
        aws_runtime = compose_aws_runtime(resolved_settings)
        rag_service = aws_runtime.rag_service
        readiness_probe = aws_runtime.readiness_probe
        telemetry_runtime = aws_runtime.telemetry
        telemetry_runtime_owned = True
    if authenticator is None and resolved_settings.sandbox_auth_enabled:
        signing_key = resolved_settings.sandbox_auth_signing_key
        issuer = resolved_settings.sandbox_auth_issuer
        audience = resolved_settings.sandbox_auth_audience
        tenant_id = resolved_settings.sandbox_auth_tenant_id
        if signing_key is None or issuer is None or audience is None or tenant_id is None:
            raise ValueError("enabled sandbox authentication configuration is incomplete")
        authenticator = SandboxTokenAuthenticator(
            signing_key=signing_key.get_secret_value(),
            issuer=issuer,
            audience=audience,
            tenant_id=tenant_id,
        )
    api_enabled = resolved_settings.api_routes_enabled
    resolved_telemetry = telemetry_for_application(
        enabled=resolved_settings.telemetry_enabled,
        injected=telemetry_runtime,
    )
    if resolved_settings.telemetry_exporter == "otlp_grpc" and not isinstance(
        resolved_telemetry,
        ExportingTelemetryRuntime | OTLPTelemetryRuntime,
    ):
        raise ValueError("otlp_grpc requires the bounded W6-002 export runtime")

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        try:
            if aws_runtime is not None:
                await aws_runtime.start()
                configuration_hashes = getattr(aws_runtime, "configuration_hashes", None)
                if configuration_hashes is not None:
                    resolved_telemetry.record_runtime_configuration(configuration_hashes)
            yield
        finally:
            drain_controller = getattr(application.state, "api_drain_controller", None)
            if isinstance(drain_controller, ApplicationDrainController):
                await drain_controller.drain(
                    completion_timeout_seconds=resolved_settings.api_drain_timeout_seconds,
                    cancellation_timeout_seconds=(
                        resolved_settings.api_cancellation_timeout_seconds
                    ),
                )
            if aws_runtime is not None:
                try:
                    async with asyncio.timeout(
                        resolved_settings.api_dependency_close_timeout_seconds
                    ):
                        await aws_runtime.close()
                except TimeoutError:
                    pass
            if telemetry_runtime_owned:
                try:
                    async with asyncio.timeout(
                        resolved_settings.api_dependency_close_timeout_seconds
                    ):
                        await asyncio.to_thread(resolved_telemetry.force_flush)
                        await asyncio.to_thread(resolved_telemetry.shutdown)
                except TimeoutError:
                    pass

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
