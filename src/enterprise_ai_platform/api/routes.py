"""Opt-in FastAPI routes that delegate through approved dependency contracts."""

from __future__ import annotations

import asyncio
from typing import Annotated, cast

from fastapi import APIRouter, Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError, ResponseValidationError
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.requests import ClientDisconnect
from starlette.responses import Response

from enterprise_ai_platform.agent.authorization import (
    require_decision_authorized,
    require_start_authorized,
)
from enterprise_ai_platform.agent.contracts import AgentController
from enterprise_ai_platform.agent.errors import AgentError
from enterprise_ai_platform.agent.models import (
    AgentOutcome,
    DecideAgentCommand,
    StartAgentCommand,
)
from enterprise_ai_platform.config import Settings
from enterprise_ai_platform.embeddings.errors import EmbeddingError
from enterprise_ai_platform.guardrails.errors import GuardrailInputError
from enterprise_ai_platform.llm.errors import LLMError
from enterprise_ai_platform.rag.errors import RAGError, RAGOutputValidationError
from enterprise_ai_platform.rag.models import AbstentionResult, CitedAnswerResult
from enterprise_ai_platform.retrieval.errors import VectorStoreError
from enterprise_ai_platform.retrieval.models import AuthContext, utc_now
from enterprise_ai_platform.telemetry.models import (
    SafeTelemetryAttributes,
    TelemetryEventName,
    TelemetryOperation,
    TelemetryOutcome,
    TelemetryStage,
)
from enterprise_ai_platform.telemetry.runtime import TelemetryRuntime

from .dependencies import (
    Authenticator,
    RAGAnswerService,
    ReadinessProbe,
    UnconfiguredAgentController,
    UnconfiguredAuthenticator,
    UnconfiguredRAGService,
    UnconfiguredReadinessProbe,
    get_agent_controller,
    get_authenticator,
    get_rag_service,
    get_readiness_probe,
)
from .errors import (
    APIError,
    AuthenticationInvalidError,
    api_error,
    normalize_agent_error,
    normalize_domain_error,
)
from .models import (
    AbstainedQueryResponse,
    AgentResponse,
    AnsweredQueryResponse,
    APIErrorDetail,
    APIErrorResponse,
    DecideAgentRequest,
    DrainResponse,
    LivenessResponse,
    QueryResponse,
    ReadinessResponse,
    StartAgentRequest,
)
from .runtime import (
    REQUEST_ID_HEADER,
    ApplicationDrainController,
    QueryCapacityLimiter,
    RAGCircuitBreaker,
    TenantRateLimiter,
    await_with_disconnect,
    overload_error,
    read_agent_request,
    read_query_request,
    request_id_for,
)

router = APIRouter()


def _telemetry_for(request: Request) -> TelemetryRuntime:
    return cast(TelemetryRuntime, request.app.state.telemetry_runtime)


def _error_response(request: Request, error: APIError) -> JSONResponse:
    payload = APIErrorResponse(
        request_id=request_id_for(request),
        error=APIErrorDetail(
            code=error.code,
            message=error.public_message,
            retryable=error.retryable,
        ),
    )
    headers = dict(error.headers)
    headers[REQUEST_ID_HEADER] = str(payload.request_id)
    return JSONResponse(
        status_code=error.status_code,
        content=payload.model_dump(mode="json", exclude_none=True),
        headers=headers,
    )


async def _api_error_handler(request: Request, error: Exception) -> Response:
    if not isinstance(error, APIError):
        return _error_response(request, api_error(500, "internal_error"))
    return _error_response(request, error)


async def _domain_error_handler(request: Request, error: Exception) -> Response:
    return _error_response(request, normalize_domain_error(error))


async def _agent_error_handler(request: Request, error: Exception) -> Response:
    if not isinstance(error, AgentError):
        return _error_response(request, api_error(500, "internal_error"))
    return _error_response(request, normalize_agent_error(error))


async def _request_validation_handler(request: Request, error: Exception) -> Response:
    del error
    return _error_response(request, api_error(422, "api_request_invalid"))


async def _http_error_handler(request: Request, error: Exception) -> Response:
    if not isinstance(error, StarletteHTTPException):
        return _error_response(request, api_error(500, "internal_error"))
    if error.status_code == 404:
        normalized = api_error(404, "api_not_found")
    elif error.status_code == 405:
        normalized = api_error(405, "api_method_not_allowed")
    else:
        normalized = api_error(500, "internal_error")
    return _error_response(request, normalized)


async def _internal_error_handler(request: Request, error: Exception) -> Response:
    if isinstance(error, ClientDisconnect):
        raise error
    return _error_response(request, api_error(500, "internal_error"))


def register_exception_handlers(application: FastAPI) -> None:
    """Normalize errors only on the explicitly enabled W4 surface."""

    application.add_exception_handler(APIError, _api_error_handler)
    application.add_exception_handler(AgentError, _agent_error_handler)
    for error_type in (
        GuardrailInputError,
        VectorStoreError,
        EmbeddingError,
        RAGError,
        LLMError,
    ):
        application.add_exception_handler(error_type, _domain_error_handler)
    application.add_exception_handler(
        RequestValidationError,
        _request_validation_handler,
    )
    application.add_exception_handler(
        ResponseValidationError,
        _internal_error_handler,
    )
    application.add_exception_handler(
        StarletteHTTPException,
        _http_error_handler,
    )
    application.add_exception_handler(Exception, _internal_error_handler)


async def _trusted_auth_context(
    request: Request,
    authenticator: Authenticator,
) -> AuthContext:
    telemetry = _telemetry_for(request)
    with telemetry.start_scope(
        TelemetryStage.AUTHENTICATION,
        TelemetryOperation.AUTHENTICATE,
    ) as telemetry_scope:
        try:
            raw_context: object = await authenticator.authenticate(request)
        except APIError as error:
            outcome = (
                TelemetryOutcome.DENIED
                if error.status_code in {401, 403}
                else TelemetryOutcome.ERROR
            )
            telemetry_scope.finish(outcome, safe_error_code=error.code)
            telemetry.emit_event(
                TelemetryEventName.SECURITY_DECISION,
                SafeTelemetryAttributes(
                    stage=TelemetryStage.AUTHENTICATION,
                    operation=TelemetryOperation.AUTHENTICATE,
                    outcome=outcome,
                    safe_error_code=error.code,
                ),
            )
            raise
        except asyncio.CancelledError:
            raise
        except Exception:
            telemetry_scope.finish(
                TelemetryOutcome.DENIED,
                safe_error_code="authentication_invalid",
            )
            raise AuthenticationInvalidError from None

        if not isinstance(raw_context, AuthContext):
            telemetry_scope.finish(
                TelemetryOutcome.DENIED,
                safe_error_code="authentication_invalid",
            )
            raise AuthenticationInvalidError
        try:
            trusted = AuthContext.model_validate(
                raw_context.model_dump(mode="python"),
                strict=True,
            )
        except ValidationError:
            telemetry_scope.finish(
                TelemetryOutcome.DENIED,
                safe_error_code="authentication_invalid",
            )
            raise AuthenticationInvalidError from None
        if not trusted.is_active(utc_now()):
            telemetry_scope.finish(
                TelemetryOutcome.DENIED,
                safe_error_code="authentication_invalid",
            )
            raise AuthenticationInvalidError
        telemetry_scope.finish(TelemetryOutcome.SUCCESS)
        telemetry.emit_event(
            TelemetryEventName.SECURITY_DECISION,
            SafeTelemetryAttributes(
                stage=TelemetryStage.AUTHENTICATION,
                operation=TelemetryOperation.AUTHENTICATE,
                outcome=TelemetryOutcome.SUCCESS,
            ),
        )
        return trusted


def _normalized_result(
    request: Request,
    result: object,
) -> QueryResponse:
    try:
        if isinstance(result, CitedAnswerResult):
            trusted = CitedAnswerResult.model_validate(
                result.model_dump(mode="python"),
                strict=True,
            )
            return AnsweredQueryResponse(
                request_id=request_id_for(request),
                answer=trusted.answer.text,
                citations=trusted.answer.citations,
                prompt_version=trusted.prompt_version,
                usage=trusted.usage,
            )
        if isinstance(result, AbstentionResult):
            trusted_abstention = AbstentionResult.model_validate(
                result.model_dump(mode="python"),
                strict=True,
            )
            return AbstainedQueryResponse(
                request_id=request_id_for(request),
                reason=trusted_abstention.reason,
                prompt_version=trusted_abstention.prompt_version,
            )
    except ValidationError:
        raise RAGOutputValidationError from None
    raise RAGOutputValidationError


@router.get("/health/live", response_model=LivenessResponse, tags=["health"])
async def live(request: Request) -> LivenessResponse:
    """Confirm only that this process can serve an event-loop request."""

    return LivenessResponse(request_id=request_id_for(request))


@router.get("/health/ready", response_model=ReadinessResponse, tags=["health"])
async def ready(
    request: Request,
    probe: Annotated[ReadinessProbe, Depends(get_readiness_probe)],
) -> ReadinessResponse:
    """Check one injected local wiring seam under a short deadline."""

    settings = cast(Settings, request.app.state.settings)
    drain = cast(ApplicationDrainController, request.app.state.api_drain_controller)
    if drain.is_draining:
        raise api_error(503, "service_not_ready")
    circuit = cast(RAGCircuitBreaker, request.app.state.api_rag_circuit_breaker)
    if circuit.state == "open":
        raise api_error(503, "service_not_ready")
    try:
        async with asyncio.timeout(settings.api_readiness_timeout_seconds):
            is_ready = await probe.check()
    except asyncio.CancelledError:
        raise
    except Exception:
        raise api_error(503, "service_not_ready") from None
    if is_ready is not True:
        raise api_error(503, "service_not_ready")
    return ReadinessResponse(request_id=request_id_for(request))


@router.post(
    "/v1/query",
    response_model=QueryResponse,
    tags=["query"],
)
async def query(
    request: Request,
    authenticator: Annotated[Authenticator, Depends(get_authenticator)],
    rag_service: Annotated[RAGAnswerService, Depends(get_rag_service)],
) -> QueryResponse:
    """Authenticate, admit, and delegate one strict text query to RAG."""

    settings = cast(Settings, request.app.state.settings)
    transport = await read_query_request(
        request,
        maximum_bytes=settings.api_max_request_body_bytes,
    )
    auth_context = await _trusted_auth_context(request, authenticator)
    rate_limiter = cast(TenantRateLimiter, request.app.state.api_tenant_rate_limiter)
    rate_allowed, retry_after = rate_limiter.try_consume(auth_context.tenant_id)
    if not rate_allowed:
        raise api_error(
            429,
            "api_rate_limited",
            retryable=True,
            headers={"Retry-After": str(retry_after)},
        )
    drain = cast(ApplicationDrainController, request.app.state.api_drain_controller)
    if not drain.try_register_current():
        raise api_error(503, "api_draining", retryable=True)
    limiter = cast(QueryCapacityLimiter, request.app.state.api_query_limiter)
    if not limiter.try_acquire():
        drain.unregister_current()
        raise overload_error()
    circuit = cast(RAGCircuitBreaker, request.app.state.api_rag_circuit_breaker)
    circuit_allowed, circuit_retry_after = circuit.try_acquire()
    if not circuit_allowed:
        limiter.release()
        drain.unregister_current()
        raise api_error(
            503,
            "rag_circuit_open",
            retryable=True,
            headers={"Retry-After": str(circuit_retry_after)},
        )
    try:
        try:
            result = await await_with_disconnect(
                request,
                rag_service.answer(
                    auth_context,
                    transport.query,
                    content_type="text/plain",
                ),
                timeout_seconds=float(settings.request_timeout_seconds),
                poll_seconds=settings.api_disconnect_poll_seconds,
            )
            normalized = _normalized_result(request, result)
        except ClientDisconnect:
            circuit.release_probe()
            raise
        except asyncio.CancelledError:
            circuit.release_probe()
            raise
        except TimeoutError:
            circuit.record_failure()
            raise api_error(504, "api_query_deadline_exceeded") from None
        except Exception:
            circuit.record_failure()
            raise
        circuit.record_success()
        return normalized
    finally:
        limiter.release()
        drain.unregister_current()


@router.post(
    "/_internal/drain",
    response_model=DrainResponse,
    include_in_schema=False,
)
async def drain(request: Request) -> DrainResponse:
    """Withdraw readiness and drain work only from the container loopback."""

    client = request.client
    if client is None or client.host not in {"127.0.0.1", "::1"}:
        raise api_error(403, "authorization_denied")
    settings = cast(Settings, request.app.state.settings)
    controller = cast(ApplicationDrainController, request.app.state.api_drain_controller)
    result = await controller.drain(
        completion_timeout_seconds=settings.api_drain_timeout_seconds,
        cancellation_timeout_seconds=settings.api_cancellation_timeout_seconds,
    )
    return DrainResponse(
        request_id=request_id_for(request),
        completed_requests=result.completed_requests,
        cancelled_requests=result.cancelled_requests,
    )


@router.post("/v1/agent", response_model=AgentResponse, tags=["agent"])
async def agent(request: Request, response: Response) -> Response | AgentResponse:
    """Preserve default-off behavior or invoke one authenticated controller."""

    settings = cast(Settings, request.app.state.settings)
    if not settings.agent_enabled:
        return _error_response(request, api_error(501, "agent_disabled"))
    transport = await read_agent_request(
        request,
        maximum_bytes=settings.api_max_request_body_bytes,
    )
    authenticator = get_authenticator(request)
    auth_context = await _trusted_auth_context(request, authenticator)
    rate_limiter = cast(TenantRateLimiter, request.app.state.api_tenant_rate_limiter)
    rate_allowed, retry_after = rate_limiter.try_consume(auth_context.tenant_id)
    if not rate_allowed:
        raise api_error(
            429,
            "api_rate_limited",
            retryable=True,
            headers={"Retry-After": str(retry_after)},
        )
    command: StartAgentCommand | DecideAgentCommand
    telemetry = _telemetry_for(request)
    with telemetry.start_scope(
        TelemetryStage.AUTHORIZATION,
        TelemetryOperation.AUTHORIZE,
    ) as authorization_scope:
        try:
            if isinstance(transport, StartAgentRequest):
                require_start_authorized(auth_context)
                command = StartAgentCommand(action="start", query=transport.query)
            elif isinstance(transport, DecideAgentRequest):
                require_decision_authorized(auth_context)
                command = DecideAgentCommand(
                    action="decide",
                    approval_id=transport.approval_id,
                    idempotency_key=transport.idempotency_key,
                    decision=transport.decision,
                    tool_name=transport.tool_name,
                    tool_version=transport.tool_version,
                    arguments=transport.arguments,
                )
            else:
                raise api_error(422, "api_request_invalid")
        except Exception:
            authorization_scope.finish(
                TelemetryOutcome.DENIED,
                terminal_reason="authorization_denied",
                safe_error_code="authorization_denied",
            )
            telemetry.emit_event(
                TelemetryEventName.SECURITY_DECISION,
                SafeTelemetryAttributes(
                    stage=TelemetryStage.AUTHORIZATION,
                    operation=TelemetryOperation.AUTHORIZE,
                    outcome=TelemetryOutcome.DENIED,
                    terminal_reason="authorization_denied",
                    safe_error_code="authorization_denied",
                ),
            )
            raise
        authorization_scope.finish(TelemetryOutcome.SUCCESS)
        telemetry.emit_event(
            TelemetryEventName.SECURITY_DECISION,
            SafeTelemetryAttributes(
                stage=TelemetryStage.AUTHORIZATION,
                operation=TelemetryOperation.AUTHORIZE,
                outcome=TelemetryOutcome.SUCCESS,
            ),
        )
    drain_controller = cast(
        ApplicationDrainController,
        request.app.state.api_drain_controller,
    )
    if not drain_controller.try_register_current():
        raise api_error(503, "api_draining", retryable=True)
    outer_limiter = cast(QueryCapacityLimiter, request.app.state.api_query_limiter)
    if not outer_limiter.try_acquire():
        drain_controller.unregister_current()
        raise api_error(
            503,
            "agent_overloaded",
            retryable=True,
            headers={"Retry-After": "1"},
        )
    try:
        controller = get_agent_controller(request)
        server_request_id = request_id_for(request)
        result = await controller.handle(
            command,
            auth_context,
            str(server_request_id),
        )
    finally:
        outer_limiter.release()
        drain_controller.unregister_current()
    if result.outcome is AgentOutcome.APPROVAL_REQUIRED:
        response.status_code = 202
    if result.request_id != server_request_id:
        raise api_error(500, "internal_error")
    return AgentResponse(
        request_id=server_request_id,
        run_id=result.run_id,
        outcome=result.outcome,
        terminal_reason=result.terminal_reason,
        approval_id=result.approval_id,
        result_reference_sha256=result.result_reference_sha256,
        safe_error_code=result.safe_error_code,
    )


def register_api_boundary(
    application: FastAPI,
    settings: Settings,
    *,
    authenticator: Authenticator | None = None,
    rag_service: RAGAnswerService | None = None,
    readiness_probe: ReadinessProbe | None = None,
    agent_controller: AgentController | None = None,
) -> None:
    """Attach application-scoped dependencies and the enabled route surface."""

    if settings.api_query_queue_capacity != 0:
        raise ValueError("W4-001 query queue capacity must remain zero")
    application.state.api_authenticator = (
        authenticator if authenticator is not None else UnconfiguredAuthenticator()
    )
    application.state.api_rag_service = (
        rag_service if rag_service is not None else UnconfiguredRAGService()
    )
    application.state.api_readiness_probe = (
        readiness_probe if readiness_probe is not None else UnconfiguredReadinessProbe()
    )
    if settings.agent_enabled:
        application.state.api_agent_controller = (
            agent_controller if agent_controller is not None else UnconfiguredAgentController()
        )
    application.state.api_query_limiter = QueryCapacityLimiter(settings.api_max_inflight_queries)
    application.state.api_tenant_rate_limiter = TenantRateLimiter(
        maximum_requests=settings.api_rate_limit_requests,
        window_seconds=settings.api_rate_limit_window_seconds,
        maximum_tenants=settings.api_rate_limit_maximum_tenants,
    )
    application.state.api_rag_circuit_breaker = RAGCircuitBreaker(
        failure_threshold=settings.api_circuit_breaker_failure_threshold,
        open_seconds=settings.api_circuit_breaker_open_seconds,
        half_open_probes=settings.api_circuit_breaker_half_open_probes,
    )
    application.state.api_drain_controller = ApplicationDrainController()
    register_exception_handlers(application)
    application.include_router(router)
