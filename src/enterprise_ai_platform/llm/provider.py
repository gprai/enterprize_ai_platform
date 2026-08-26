"""Language-model protocol and process-wide blocking-call concurrency gate."""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Callable
from typing import Protocol, TypeVar, runtime_checkable

from enterprise_ai_platform.llm.models import ChatRequest, ChatResponse

T = TypeVar("T")


@runtime_checkable
class LLMProvider(Protocol):
    """The only provider operation exposed to application code."""

    async def chat(self, request: ChatRequest) -> ChatResponse:
        """Produce one normalized response without executing tools."""

        ...


class ProviderCallGate:
    """A thread-safe cap shared by every blocking provider call in a process."""

    def __init__(self, max_active_calls: int = 4) -> None:
        if max_active_calls < 1:
            raise ValueError("max_active_calls must be positive")
        self._max_active_calls = max_active_calls
        self._active_calls = 0
        self._waiting_calls = 0
        self._condition = threading.Condition()

    @property
    def max_active_calls(self) -> int:
        return self._max_active_calls

    @property
    def active_calls(self) -> int:
        with self._condition:
            return self._active_calls

    @property
    def waiting_calls(self) -> int:
        with self._condition:
            return self._waiting_calls

    def acquire(self, cancelled: threading.Event) -> bool:
        """Wait for a slot, returning false if cancellation wins the race."""

        with self._condition:
            while self._active_calls >= self._max_active_calls:
                if cancelled.is_set():
                    return False
                self._waiting_calls += 1
                try:
                    self._condition.wait()
                finally:
                    self._waiting_calls -= 1
            if cancelled.is_set():
                return False
            self._active_calls += 1
            return True

    def release(self) -> None:
        with self._condition:
            if self._active_calls < 1:
                raise RuntimeError("provider call gate released without an active call")
            self._active_calls -= 1
            self._condition.notify_all()

    def notify_cancelled(self) -> None:
        with self._condition:
            self._condition.notify_all()


PROCESS_WIDE_PROVIDER_CALL_GATE = ProviderCallGate(max_active_calls=4)


class ProviderWorkerTimeoutError(TimeoutError):
    """Internal signal that an outer provider attempt timed out."""


class ProviderWorkerCancelledError(Exception):
    """Internal signal that a queued worker was cancelled before execution."""


async def run_blocking_provider_call(
    operation: Callable[[], T],
    *,
    gate: ProviderCallGate,
    timeout_seconds: float,
) -> T:
    """Run one blocking attempt with cancellation-safe gate ownership."""

    cancelled = threading.Event()

    def gated_operation() -> T:
        if not gate.acquire(cancelled):
            raise ProviderWorkerCancelledError
        try:
            if cancelled.is_set():
                raise ProviderWorkerCancelledError
            return operation()
        finally:
            gate.release()

    worker = asyncio.create_task(asyncio.to_thread(gated_operation))

    def consume_late_task(completed: asyncio.Future[T]) -> None:
        """Retrieve a discarded result without logging or exposing its contents."""

        if not completed.cancelled():
            completed.exception()

    try:
        return await asyncio.wait_for(asyncio.shield(worker), timeout_seconds)
    except TimeoutError as exc:
        cancelled.set()
        gate.notify_cancelled()
        worker.add_done_callback(consume_late_task)
        raise ProviderWorkerTimeoutError from exc
    except asyncio.CancelledError:
        cancelled.set()
        gate.notify_cancelled()
        worker.add_done_callback(consume_late_task)
        raise
