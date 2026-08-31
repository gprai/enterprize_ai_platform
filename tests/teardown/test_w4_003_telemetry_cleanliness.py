"""Clean shutdown and zero-residue tests for the local W4-003 runtime."""

from __future__ import annotations

import asyncio
import socket
import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from enterprise_ai_platform.app import create_app
from enterprise_ai_platform.config import Settings
from enterprise_ai_platform.telemetry.models import (
    TelemetryOperation,
    TelemetryStage,
)
from enterprise_ai_platform.telemetry.runtime import NullTelemetryRuntime


class CountingRuntime(NullTelemetryRuntime):
    def __init__(self) -> None:
        self.flush_calls = 0
        self.shutdown_calls = 0

    def force_flush(self) -> bool:
        self.flush_calls += 1
        return True

    def shutdown(self) -> bool:
        self.shutdown_calls += 1
        return True


def _enabled(settings: Settings) -> Settings:
    values = settings.model_dump(mode="python")
    values.update(api_routes_enabled=True, telemetry_enabled=True)
    return Settings(_env_file=None, **values)


def test_owned_runtime_flushes_and_shuts_down_exactly_once(
    valid_settings: Settings,
) -> None:
    runtime = CountingRuntime()
    application = create_app(
        _enabled(valid_settings),
        telemetry_runtime=runtime,
        telemetry_runtime_owned=True,
    )

    with TestClient(application) as client:
        assert client.get("/health").status_code == 200
        assert runtime.flush_calls == 0
        assert runtime.shutdown_calls == 0

    assert runtime.flush_calls == 1
    assert runtime.shutdown_calls == 1


def test_externally_owned_runtime_is_not_flushed_or_shut_down(
    valid_settings: Settings,
) -> None:
    runtime = CountingRuntime()
    application = create_app(
        _enabled(valid_settings),
        telemetry_runtime=runtime,
        telemetry_runtime_owned=False,
    )

    with TestClient(application) as client:
        assert client.get("/health/live").status_code == 200

    assert runtime.flush_calls == 0
    assert runtime.shutdown_calls == 0


def test_in_memory_runtime_creates_no_socket_file_thread_or_background_task(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    telemetry_factory,
) -> None:  # type: ignore[no-untyped-def]
    initial_threads = {thread.ident for thread in threading.enumerate()}

    def forbidden_socket(*args: object, **kwargs: object) -> socket.socket:
        del args, kwargs
        raise AssertionError("telemetry must not create a socket")

    with monkeypatch.context() as socket_guard:
        socket_guard.setattr(socket, "socket", forbidden_socket)
        composition = telemetry_factory()
        with composition.runtime.start_scope(
            TelemetryStage.API,
            TelemetryOperation.REQUEST,
        ):
            pass
        composition.runtime.force_flush()

    assert list(tmp_path.iterdir()) == []
    assert {thread.ident for thread in threading.enumerate()} == initial_threads

    async def no_background_tasks() -> None:
        current = asyncio.current_task()
        assert {task for task in asyncio.all_tasks() if task is not current} == set()

    asyncio.run(no_background_tasks())


def test_cancellation_propagates_without_replacement_work() -> None:
    started = asyncio.Event()
    replacement_calls = 0
    telemetry = NullTelemetryRuntime()

    async def scenario() -> None:
        async def business_work() -> None:
            nonlocal replacement_calls
            started.set()
            with telemetry.start_scope(
                TelemetryStage.RAG,
                TelemetryOperation.ANSWER,
            ):
                await asyncio.Event().wait()
                replacement_calls += 1

        task = asyncio.create_task(business_work())
        await started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await asyncio.sleep(0)
        assert task.cancelled()
        assert len(asyncio.all_tasks()) == 1

    asyncio.run(scenario())
    assert replacement_calls == 0
