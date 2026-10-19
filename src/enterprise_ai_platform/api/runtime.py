"""Request IDs, strict body parsing, and non-queuing query admission."""

from __future__ import annotations

import asyncio
import hashlib
import json
import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Coroutine
from dataclasses import dataclass
from typing import Any, Literal, cast
from uuid import UUID, uuid4

from pydantic import TypeAdapter, ValidationError
from starlette.datastructures import MutableHeaders
from starlette.requests import ClientDisconnect, Request
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from enterprise_ai_platform.guardrails.errors import GuardrailInputError
from enterprise_ai_platform.json_contracts import (
    DuplicateJSONKeyError,
    strict_json_loads,
)
from enterprise_ai_platform.telemetry.models import (
    TelemetryOperation,
    TelemetryOutcome,
    TelemetryStage,
)
from enterprise_ai_platform.telemetry.runtime import (
    NullTelemetryRuntime,
    TelemetryRuntime,
)

from .errors import APIError, api_error
from .models import AgentRequest, QueryRequest

REQUEST_ID_HEADER = "X-Request-ID"


class RequestIdMiddleware:
    """Generate one untrusted-input-independent UUIDv4 for each HTTP request."""

    def __init__(
        self,
        app: ASGIApp,
        telemetry: TelemetryRuntime | None = None,
    ) -> None:
        self._app = app
        self._telemetry = telemetry or NullTelemetryRuntime()

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        request_uuid = uuid4()
        request_id = str(request_uuid)
        state = scope.setdefault("state", {})
        state["request_id"] = request_id
        response_status: int | None = None

        async def send_with_request_id(message: Message) -> None:
            nonlocal response_status
            if message["type"] == "http.response.start":
                response_status = int(message["status"])
                headers = MutableHeaders(scope=message)
                headers[REQUEST_ID_HEADER] = request_id
            await send(message)

        with self._telemetry.start_scope(
            TelemetryStage.API,
            TelemetryOperation.REQUEST,
            request_id=request_uuid,
            root=True,
        ) as telemetry_scope:
            await self._app(scope, receive, send_with_request_id)
            if response_status == 504:
                telemetry_scope.finish(TelemetryOutcome.TIMEOUT)
            elif response_status is None or response_status >= 500:
                telemetry_scope.finish(TelemetryOutcome.ERROR)
            elif response_status in {401, 403}:
                telemetry_scope.finish(TelemetryOutcome.DENIED)
            elif response_status >= 400:
                telemetry_scope.finish(TelemetryOutcome.REJECTED)
            else:
                telemetry_scope.finish(TelemetryOutcome.SUCCESS)


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

    @property
    def queue_depth(self) -> Literal[0]:
        """The approved API profile rejects overload and never queues requests."""

        return 0

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


class TenantRateLimiter:
    """Bounded, process-local fixed-window limits keyed by a tenant digest."""

    def __init__(
        self,
        *,
        maximum_requests: int,
        window_seconds: int,
        maximum_tenants: int,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if min(maximum_requests, window_seconds, maximum_tenants) < 1:
            raise ValueError("rate-limit values must be positive")
        self._maximum_requests = maximum_requests
        self._window_seconds = window_seconds
        self._maximum_tenants = maximum_tenants
        self._monotonic = monotonic
        self._windows: OrderedDict[bytes, tuple[float, int]] = OrderedDict()
        self._lock = threading.Lock()

    @property
    def tenant_count(self) -> int:
        with self._lock:
            return len(self._windows)

    def try_consume(self, tenant_id: str) -> tuple[bool, int]:
        """Consume one request or return a bounded Retry-After value."""

        tenant_key = hashlib.sha256(tenant_id.encode("utf-8")).digest()
        now = self._monotonic()
        with self._lock:
            expired = [
                key
                for key, (started, _count) in self._windows.items()
                if now - started >= self._window_seconds
            ]
            for key in expired:
                del self._windows[key]

            current = self._windows.get(tenant_key)
            if current is None:
                if len(self._windows) >= self._maximum_tenants:
                    return False, self._window_seconds
                self._windows[tenant_key] = (now, 1)
                return True, 0

            started, count = current
            if count >= self._maximum_requests:
                retry_after = max(1, int(self._window_seconds - (now - started) + 0.999))
                return False, retry_after
            self._windows[tenant_key] = (started, count + 1)
            self._windows.move_to_end(tenant_key)
            return True, 0


class RAGCircuitBreaker:
    """Aggregate process-local circuit with one bounded half-open probe."""

    def __init__(
        self,
        *,
        failure_threshold: int,
        open_seconds: int,
        half_open_probes: int,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if min(failure_threshold, open_seconds, half_open_probes) < 1:
            raise ValueError("circuit-breaker values must be positive")
        self._failure_threshold = failure_threshold
        self._open_seconds = open_seconds
        self._half_open_probes = half_open_probes
        self._monotonic = monotonic
        self._state = "closed"
        self._failures = 0
        self._open_until = 0.0
        self._active_probes = 0
        self._lock = threading.Lock()

    @property
    def state(self) -> str:
        with self._lock:
            if self._state == "open" and self._monotonic() >= self._open_until:
                self._state = "half_open"
                self._active_probes = 0
            return self._state

    def try_acquire(self) -> tuple[bool, int]:
        now = self._monotonic()
        with self._lock:
            if self._state == "open":
                if now < self._open_until:
                    return False, max(1, int(self._open_until - now + 0.999))
                self._state = "half_open"
                self._active_probes = 0
            if self._state == "half_open":
                if self._active_probes >= self._half_open_probes:
                    return False, 1
                self._active_probes += 1
            return True, 0

    def record_success(self) -> None:
        with self._lock:
            self._state = "closed"
            self._failures = 0
            self._open_until = 0.0
            self._active_probes = 0

    def record_failure(self) -> None:
        now = self._monotonic()
        with self._lock:
            self._active_probes = 0
            self._failures += 1
            if self._state == "half_open" or self._failures >= self._failure_threshold:
                self._state = "open"
                self._open_until = now + self._open_seconds

    def release_probe(self) -> None:
        with self._lock:
            if self._state == "half_open" and self._active_probes:
                self._active_probes -= 1


@dataclass(frozen=True, slots=True)
class DrainResult:
    completed_requests: int
    cancelled_requests: int


class ApplicationDrainController:
    """Withdraw readiness, reject new work, and bound in-flight cancellation."""

    def __init__(self) -> None:
        self._draining = False
        self._tasks: set[asyncio.Task[object]] = set()

    @property
    def is_draining(self) -> bool:
        return self._draining

    @property
    def active(self) -> int:
        return sum(not task.done() for task in self._tasks)

    def try_register_current(self) -> bool:
        if self._draining:
            return False
        task = asyncio.current_task()
        if task is None:
            raise RuntimeError("request execution requires an asyncio task")
        self._tasks.add(cast(asyncio.Task[object], task))
        return True

    def unregister_current(self) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._tasks.discard(cast(asyncio.Task[object], task))

    async def drain(
        self,
        *,
        completion_timeout_seconds: float,
        cancellation_timeout_seconds: float,
    ) -> DrainResult:
        self._draining = True
        current = asyncio.current_task()
        pending = {task for task in self._tasks if task is not current and not task.done()}
        initial = len(pending)
        if pending:
            _done, pending = await asyncio.wait(
                pending,
                timeout=completion_timeout_seconds,
            )
        cancelled = len(pending)
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.wait(pending, timeout=cancellation_timeout_seconds)
        self._tasks.difference_update(task for task in self._tasks if task.done())
        return DrainResult(
            completed_requests=initial - cancelled,
            cancelled_requests=cancelled,
        )


async def await_with_disconnect[ResultT](
    request: Request,
    operation: Coroutine[Any, Any, ResultT],
    *,
    timeout_seconds: float,
    poll_seconds: float,
) -> ResultT:
    """Cancel one scoped dependency call on deadline or client disconnect."""

    task = asyncio.create_task(operation)
    try:
        async with asyncio.timeout(timeout_seconds):
            while not task.done():
                done, _pending = await asyncio.wait({task}, timeout=poll_seconds)
                if done:
                    break
                if await request.is_disconnected():
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
                    raise ClientDisconnect
            return await task
    except BaseException:
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        raise


def _validate_media_type(request: Request) -> None:
    content_type = request.headers.get("content-type", "")
    media_type = content_type.partition(";")[0].strip().casefold()
    content_encoding = request.headers.get("content-encoding", "identity")
    if media_type != "application/json" or content_encoding.strip().casefold() not in {
        "",
        "identity",
    }:
        raise api_error(415, "api_unsupported_media_type")


async def _read_json_request[RequestT](
    request: Request,
    *,
    maximum_bytes: int,
    adapter: TypeAdapter[RequestT],
    bounded_text_field: str | None = None,
) -> RequestT:
    """Count raw bytes, reject unsafe JSON, then validate its JSON representation."""

    _validate_media_type(request)
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > maximum_bytes:
            raise api_error(413, "api_request_too_large")
        body.extend(chunk)

    try:
        text = bytes(body).decode("utf-8")
        strict_json_loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError, DuplicateJSONKeyError, ValueError, TypeError):
        raise api_error(400, "api_request_malformed") from None

    try:
        return adapter.validate_json(text, strict=True)
    except ValidationError as error:
        validation_errors = error.errors()
        if (
            bounded_text_field is not None
            and validation_errors
            and all(
                tuple(item.get("loc", ())) == (bounded_text_field,)
                and item.get("type") in {"string_too_short", "string_too_long"}
                for item in validation_errors
            )
        ):
            raise GuardrailInputError from None
        raise api_error(422, "api_request_invalid") from None


async def read_query_request(request: Request, *, maximum_bytes: int) -> QueryRequest:
    return await _read_json_request(
        request,
        maximum_bytes=maximum_bytes,
        adapter=TypeAdapter(QueryRequest),
        bounded_text_field="query",
    )


async def read_agent_request(request: Request, *, maximum_bytes: int) -> AgentRequest:
    return await _read_json_request(
        request,
        maximum_bytes=maximum_bytes,
        adapter=TypeAdapter(AgentRequest),
    )


def overload_error() -> APIError:
    return api_error(
        503,
        "api_overloaded",
        retryable=True,
        headers={"Retry-After": "1"},
    )
