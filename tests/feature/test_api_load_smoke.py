"""Deterministic, in-process W4-10 API load-smoke evidence producer."""

from __future__ import annotations

import asyncio
import json
import math
import multiprocessing
import os
import socket
import threading
from dataclasses import dataclass
from pathlib import Path
from time import perf_counter_ns
from typing import Never, cast
from uuid import UUID

import httpx
import pytest

from enterprise_ai_platform.api.runtime import QueryCapacityLimiter
from enterprise_ai_platform.app import create_app
from enterprise_ai_platform.config import Settings
from enterprise_ai_platform.rag.models import AbstentionResult
from enterprise_ai_platform.retrieval.models import (
    AuthContext,
    Classification,
    Role,
)
from tests.fakes.api import FakeAuthenticator, FakeReadinessProbe
from tests.fakes.telemetry import SECURITY_SENTINELS
from tests.security.test_api_authorization import INJECTION, SECRET

CONCURRENCY_LEVELS = (1, 4, 8)
WARMUP_REQUESTS_PER_LEVEL = 20
MEASURED_REQUESTS_PER_LEVEL = 200
PROFILE_MAXIMUM_SECONDS = 30
MAXIMUM_ADMITTED = 4

EXPECTED_COUNTS = {
    1: (200, 0, 1),
    4: (200, 0, 4),
    8: (100, 100, 4),
}


@dataclass(frozen=True, slots=True)
class PhaseResult:
    durations_ns: tuple[int, ...]
    successful_responses: int
    overload_responses: int
    request_ids: frozenset[str]


class CountingRAGService:
    """Test-local gate that measures only admitted public RAG calls."""

    def __init__(self) -> None:
        self.calls = 0
        self.active = 0
        self.maximum_active = 0
        self._expected_admitted = 0
        self._all_admitted = asyncio.Event()
        self._release = asyncio.Event()

    def prepare_wave(self, expected_admitted: int) -> None:
        assert self.active == 0
        assert 1 <= expected_admitted <= MAXIMUM_ADMITTED
        self._expected_admitted = expected_admitted
        self._all_admitted = asyncio.Event()
        self._release = asyncio.Event()

    @property
    def all_admitted(self) -> asyncio.Event:
        return self._all_admitted

    def release_wave(self) -> None:
        self._release.set()

    def reset_measurements(self) -> None:
        assert self.active == 0
        self.calls = 0
        self.maximum_active = 0

    async def answer(
        self,
        auth_context: AuthContext,
        query: str,
        *,
        content_type: str = "text/plain",
    ) -> AbstentionResult:
        del auth_context, query
        assert content_type == "text/plain"
        self.calls += 1
        self.active += 1
        self.maximum_active = max(self.maximum_active, self.active)
        if self.active == self._expected_admitted:
            self._all_admitted.set()
        try:
            await self._release.wait()
            return AbstentionResult(reason="insufficient_evidence", usage=None)
        finally:
            self.active -= 1


def _auth() -> AuthContext:
    return AuthContext(
        subject_id="load-reader",
        tenant_id="tenant-a",
        roles=frozenset({Role.READER}),
        clearance=Classification.INTERNAL,
    )


def _load_settings(settings: Settings) -> Settings:
    values = settings.model_dump(mode="python")
    values.update(
        api_routes_enabled=True,
        api_max_inflight_queries=MAXIMUM_ADMITTED,
        api_query_queue_capacity=0,
        telemetry_enabled=False,
    )
    return Settings(_env_file=None, **values)


async def _request(
    client: httpx.AsyncClient,
    query: str,
) -> tuple[int, httpx.Response]:
    started = perf_counter_ns()
    response = await client.post("/v1/query", json={"query": query})
    return perf_counter_ns() - started, response


async def _wait_for_completed(
    tasks: list[asyncio.Task[tuple[int, httpx.Response]]],
    expected: int,
) -> None:
    async with asyncio.timeout(1.0):
        while sum(task.done() for task in tasks) < expected:
            await asyncio.sleep(0)


async def _run_wave(
    *,
    client: httpx.AsyncClient,
    rag: CountingRAGService,
    query: str,
    size: int,
) -> list[tuple[int, httpx.Response]]:
    expected_admitted = min(size, MAXIMUM_ADMITTED)
    rag.prepare_wave(expected_admitted)
    tasks = [asyncio.create_task(_request(client, query)) for _ in range(size)]
    try:
        async with asyncio.timeout(1.0):
            await rag.all_admitted.wait()
        expected_overloads = size - expected_admitted
        if expected_overloads:
            await _wait_for_completed(tasks, expected_overloads)
        rag.release_wave()
        return list(await asyncio.gather(*tasks))
    finally:
        rag.release_wave()
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


def _classify_response(response: httpx.Response) -> tuple[str, str]:
    payload = response.json()
    request_id = payload["request_id"]
    assert request_id == response.headers["X-Request-ID"]
    parsed = UUID(request_id)
    assert parsed.version == 4
    assert str(parsed) == request_id
    if response.status_code == 200:
        assert payload["outcome"] == "abstained"
        assert payload["reason"] == "insufficient_evidence"
        return "success", request_id
    assert response.status_code == 503
    assert response.headers["Retry-After"] == "1"
    assert payload["error"]["code"] == "api_overloaded"
    assert payload["error"]["retryable"] is True
    return "overload", request_id


async def _run_phase(
    *,
    client: httpx.AsyncClient,
    rag: CountingRAGService,
    query: str,
    total_requests: int,
    concurrency: int,
) -> PhaseResult:
    durations: list[int] = []
    successful = 0
    overloaded = 0
    request_ids: list[str] = []
    for offset in range(0, total_requests, concurrency):
        size = min(concurrency, total_requests - offset)
        for duration_ns, response in await _run_wave(
            client=client,
            rag=rag,
            query=query,
            size=size,
        ):
            category, request_id = _classify_response(response)
            durations.append(duration_ns)
            request_ids.append(request_id)
            successful += category == "success"
            overloaded += category == "overload"
    assert len(durations) == total_requests
    assert len(set(request_ids)) == total_requests
    return PhaseResult(
        durations_ns=tuple(durations),
        successful_responses=successful,
        overload_responses=overloaded,
        request_ids=frozenset(request_ids),
    )


def _nearest_rank_milliseconds(values_ns: tuple[int, ...], percentile: float) -> float:
    ordered = sorted(values_ns)
    rank = max(1, math.ceil(percentile * len(ordered)))
    return round(ordered[rank - 1] / 1_000_000, 6)


async def _run_level(
    *,
    settings: Settings,
    concurrency: int,
    query: str,
) -> dict[str, int | float]:
    rag = CountingRAGService()
    authenticator = FakeAuthenticator(_auth())
    application = create_app(
        settings,
        authenticator=authenticator,
        rag_service=rag,
        readiness_probe=FakeReadinessProbe(),
    )
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://testserver",
    ) as client:
        warmup = await _run_phase(
            client=client,
            rag=rag,
            query=query,
            total_requests=WARMUP_REQUESTS_PER_LEVEL,
            concurrency=concurrency,
        )
        assert rag.calls == warmup.successful_responses
        assert rag.active == 0
        rag.reset_measurements()
        authentication_calls_before = authenticator.calls
        measured_started = perf_counter_ns()
        measured = await _run_phase(
            client=client,
            rag=rag,
            query=query,
            total_requests=MEASURED_REQUESTS_PER_LEVEL,
            concurrency=concurrency,
        )
        measured_duration_ns = perf_counter_ns() - measured_started

    expected_success, expected_overload, expected_maximum = EXPECTED_COUNTS[concurrency]
    assert measured.successful_responses == expected_success
    assert measured.overload_responses == expected_overload
    assert rag.calls == expected_success
    assert rag.maximum_active == expected_maximum
    assert rag.active == 0
    assert authenticator.calls - authentication_calls_before == (MEASURED_REQUESTS_PER_LEVEL)
    assert warmup.request_ids.isdisjoint(measured.request_ids)
    limiter = cast(QueryCapacityLimiter, application.state.api_query_limiter)
    assert limiter.active == 0

    return {
        "concurrency": concurrency,
        "total_requests": MEASURED_REQUESTS_PER_LEVEL,
        "successful_responses": measured.successful_responses,
        "safe_error_responses": measured.overload_responses,
        "overload_responses": measured.overload_responses,
        "downstream_calls": rag.calls,
        "maximum_inflight_downstream": rag.maximum_active,
        "duration_sample_count": len(measured.durations_ns),
        "measured_duration_milliseconds": round(measured_duration_ns / 1_000_000, 3),
        "p50_milliseconds": _nearest_rank_milliseconds(measured.durations_ns, 0.50),
        "p95_milliseconds": _nearest_rank_milliseconds(measured.durations_ns, 0.95),
        "p99_milliseconds": _nearest_rank_milliseconds(measured.durations_ns, 0.99),
    }


async def _run_profile(settings: Settings, query: str) -> dict[str, object]:
    profile_started = perf_counter_ns()
    levels: list[dict[str, int | float]] = []
    async with asyncio.timeout(PROFILE_MAXIMUM_SECONDS):
        for concurrency in CONCURRENCY_LEVELS:
            levels.append(
                await _run_level(
                    settings=settings,
                    concurrency=concurrency,
                    query=query,
                )
            )
    profile_duration_ns = perf_counter_ns() - profile_started
    assert profile_duration_ns < PROFILE_MAXIMUM_SECONDS * 1_000_000_000
    current = asyncio.current_task()
    assert {task for task in asyncio.all_tasks() if task is not current} == set()
    return {
        "schema_version": "w4-10.api-load-smoke.v1",
        "scope": "local_in_process_asgi_informational",
        "warmup_requests_per_level": WARMUP_REQUESTS_PER_LEVEL,
        "measured_requests_per_level": MEASURED_REQUESTS_PER_LEVEL,
        "profile_maximum_seconds": PROFILE_MAXIMUM_SECONDS,
        "total_measured_requests": (MEASURED_REQUESTS_PER_LEVEL * len(CONCURRENCY_LEVELS)),
        "profile_duration_milliseconds": round(profile_duration_ns / 1_000_000, 3),
        "levels": levels,
    }


def test_w4_10_profile_is_bounded_redacted_atomic_and_residue_free(
    api_settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    initial_threads = {thread.ident for thread in threading.enumerate()}
    initial_children = sorted(process.pid for process in multiprocessing.active_children())
    query = " ".join((INJECTION, SECRET, *SECURITY_SENTINELS))

    original_socket_type = socket.socket

    class _ForbiddenSocketMeta(type):
        def __instancecheck__(cls, instance: object) -> bool:
            del cls
            return isinstance(instance, original_socket_type)

        def __call__(cls, *args: object, **kwargs: object) -> Never:
            del cls, args, kwargs
            raise AssertionError("in-process ASGI load smoke must not create a socket")

    class _ForbiddenSocket(metaclass=_ForbiddenSocketMeta):
        """Reject construction while preserving socket instance checks."""

    async def scenario() -> dict[str, object]:
        with monkeypatch.context() as socket_guard:
            socket_guard.setattr(socket, "socket", _ForbiddenSocket)
            return await _run_profile(_load_settings(api_settings), query)

    profile = asyncio.run(scenario())
    serialized = json.dumps(profile, sort_keys=True, separators=(",", ":"))
    for forbidden in (
        INJECTION,
        SECRET,
        *SECURITY_SENTINELS,
        "request_id",
        "trace_id",
        "span_id",
        "tenant_id",
        "subject_id",
    ):
        assert forbidden not in serialized

    report = tmp_path / "W4-10-load.json"
    try:
        with report.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(serialized)
            stream.flush()
            os.fsync(stream.fileno())
        with pytest.raises(FileExistsError):
            report.open("x", encoding="utf-8")
        assert json.loads(report.read_text(encoding="utf-8")) == profile
        print(serialized)
    finally:
        report.unlink(missing_ok=True)

    assert not report.exists()
    assert list(tmp_path.iterdir()) == []
    assert {thread.ident for thread in threading.enumerate()} == initial_threads
    assert sorted(process.pid for process in multiprocessing.active_children()) == (
        initial_children
    )
