"""Request IDs, strict body parsing, and non-queuing query admission."""

from __future__ import annotations

import json
import threading
from typing import cast
from uuid import UUID, uuid4

from pydantic import ValidationError
from starlette.datastructures import MutableHeaders
from starlette.requests import Request
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from enterprise_ai_platform.json_contracts import DuplicateJSONKeyError, strict_json_loads

from .errors import APIError, api_error
from .models import QueryRequest

REQUEST_ID_HEADER = "X-Request-ID"


class RequestIdMiddleware:
    """Generate one untrusted-input-independent UUIDv4 for each HTTP request."""

    def __init__(self, app: ASGIApp) -> None:
        self._app = app

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        request_id = str(uuid4())
        state = scope.setdefault("state", {})
        state["request_id"] = request_id

        async def send_with_request_id(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers[REQUEST_ID_HEADER] = request_id
            await send(message)

        await self._app(scope, receive, send_with_request_id)


def request_id_for(request: Request) -> UUID:
    """Return only the UUID created by the server middleware."""

    return UUID(cast(str, request.state.request_id))


class QueryCapacityLimiter:
    """Thread-safe per-application admission with no query wait queue."""

    def __init__(self, maximum: int) -> None:
        if maximum < 1:
            raise ValueError("maximum must be positive")
        self._maximum = maximum
        self._active = 0
        self._lock = threading.Lock()

    @property
    def maximum(self) -> int:
        return self._maximum

    @property
    def active(self) -> int:
        with self._lock:
            return self._active

    def try_acquire(self) -> bool:
        """Acquire immediately or reject without creating a waiter."""

        with self._lock:
            if self._active >= self._maximum:
                return False
            self._active += 1
            return True

    def release(self) -> None:
        with self._lock:
            if self._active < 1:
                raise RuntimeError("capacity released without an admitted query")
            self._active -= 1


def _validate_media_type(request: Request) -> None:
    content_type = request.headers.get("content-type", "")
    media_type = content_type.partition(";")[0].strip().casefold()
    content_encoding = request.headers.get("content-encoding", "identity")
    if media_type != "application/json" or content_encoding.strip().casefold() not in {
        "",
        "identity",
    }:
        raise api_error(415, "api_unsupported_media_type")


async def read_query_request(request: Request, *, maximum_bytes: int) -> QueryRequest:
    """Count streaming bytes, then decode and strictly validate one query object."""

    _validate_media_type(request)
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > maximum_bytes:
            raise api_error(413, "api_request_too_large")
        body.extend(chunk)

    try:
        text = bytes(body).decode("utf-8")
        raw = strict_json_loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError, DuplicateJSONKeyError, ValueError, TypeError):
        raise api_error(400, "api_request_malformed") from None

    try:
        return QueryRequest.model_validate(raw, strict=True)
    except ValidationError:
        raise api_error(422, "api_request_invalid") from None


def overload_error() -> APIError:
    return api_error(
        503,
        "api_overloaded",
        retryable=True,
        headers={"Retry-After": "1"},
    )
