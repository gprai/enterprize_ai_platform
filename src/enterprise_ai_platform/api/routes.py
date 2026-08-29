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

from enterprise_ai_platform.config import Settings
from enterprise_ai_platform.embeddings.errors import EmbeddingError
from enterprise_ai_platform.guardrails.errors import GuardrailInputError
from enterprise_ai_platform.llm.errors import LLMError
from enterprise_ai_platform.rag.errors import RAGError, RAGOutputValidationError
from enterprise_ai_platform.rag.models import AbstentionResult, CitedAnswerResult
from enterprise_ai_platform.retrieval.errors import VectorStoreError
from enterprise_ai_platform.retrieval.models import AuthContext, utc_now

from .dependencies import (
    Authenticator,
    RAGAnswerService,
    ReadinessProbe,
    UnconfiguredAuthenticator,
    UnconfiguredRAGService,
    UnconfiguredReadinessProbe,
    get_authenticator,
    get_rag_service,
    get_readiness_probe,
)
from .errors import (
    APIError,
    AuthenticationInvalidError,
    api_error,
    normalize_domain_error,
)
from .models import (
    AbstainedQueryResponse,
    AnsweredQueryResponse,
    APIErrorDetail,
    APIErrorResponse,
    LivenessResponse,
    QueryResponse,
    ReadinessResponse,
)
from .runtime import (
    REQUEST_ID_HEADER,
    QueryCapacityLimiter,
    overload_error,
    read_query_request,
    request_id_for,
)

router = APIRouter()


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
    try:
        raw_context = await authenticator.authenticate(request)
    except APIError:
        raise
    except asyncio.CancelledError:
        raise
    except Exception:
        raise AuthenticationInvalidError from None

    if not isinstance(raw_context, AuthContext):
        raise AuthenticationInvalidError
    try:
        trusted = AuthContext.model_validate(
            raw_context.model_dump(mode="python"),
            strict=True,
        )
    except ValidationError:
        raise AuthenticationInvalidError from None
    if not trusted.is_active(utc_now()):
        raise AuthenticationInvalidError
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
    limiter = cast(QueryCapacityLimiter, request.app.state.api_query_limiter)
    if not limiter.try_acquire():
        raise overload_error()
    try:
        try:
            async with asyncio.timeout(float(settings.request_timeout_seconds)):
                result = await rag_service.answer(
                    auth_context,
                    transport.query,
                    content_type="text/plain",
                )
        except TimeoutError:
            raise api_error(504, "api_query_deadline_exceeded") from None
        return _normalized_result(request, result)
    finally:
        limiter.release()


@router.post("/v1/agent", tags=["agent"])
async def agent(request: Request) -> Response:
    """Return the stable disabled boundary without resolving dependencies."""

    return _error_response(request, api_error(501, "agent_disabled"))


def register_api_boundary(
    application: FastAPI,
    settings: Settings,
    *,
    authenticator: Authenticator | None = None,
    rag_service: RAGAnswerService | None = None,
    readiness_probe: ReadinessProbe | None = None,
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
        readiness_probe
        if readiness_probe is not None
        else UnconfiguredReadinessProbe()
    )
    application.state.api_query_limiter = QueryCapacityLimiter(
        settings.api_max_inflight_queries
    )
    register_exception_handlers(application)
    application.include_router(router)
