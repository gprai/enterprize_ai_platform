"""Unit coverage for W8-002 bounded inference runtime controls."""

from __future__ import annotations

import asyncio

from enterprise_ai_platform.api.runtime import (
    ApplicationDrainController,
    RAGCircuitBreaker,
    TenantRateLimiter,
)


def test_tenant_rate_limit_is_bounded_and_uses_no_raw_tenant_key() -> None:
    now = [100.0]
    limiter = TenantRateLimiter(
        maximum_requests=2,
        window_seconds=60,
        maximum_tenants=2,
        monotonic=lambda: now[0],
    )

    assert limiter.try_consume("tenant-a") == (True, 0)
    assert limiter.try_consume("tenant-a") == (True, 0)
    assert limiter.try_consume("tenant-a") == (False, 60)
    assert limiter.try_consume("tenant-b") == (True, 0)
    assert limiter.try_consume("tenant-c") == (False, 60)
    assert "tenant-a" not in repr(limiter._windows)  # noqa: SLF001
    now[0] = 160.0
    assert limiter.try_consume("tenant-c") == (True, 0)
    assert limiter.tenant_count == 1


def test_circuit_opens_after_five_failures_and_allows_one_half_open_probe() -> None:
    now = [10.0]
    circuit = RAGCircuitBreaker(
        failure_threshold=5,
        open_seconds=30,
        half_open_probes=1,
        monotonic=lambda: now[0],
    )

    for _ in range(4):
        assert circuit.try_acquire() == (True, 0)
        circuit.record_failure()
    assert circuit.state == "closed"
    assert circuit.try_acquire() == (True, 0)
    circuit.record_failure()
    assert circuit.state == "open"
    assert circuit.try_acquire() == (False, 30)

    now[0] = 40.0
    assert circuit.try_acquire() == (True, 0)
    assert circuit.try_acquire() == (False, 1)
    circuit.record_success()
    assert circuit.state == "closed"


def test_drain_cancels_only_residual_registered_requests() -> None:
    async def scenario() -> None:
        controller = ApplicationDrainController()
        started = asyncio.Event()

        async def request() -> None:
            assert controller.try_register_current()
            started.set()
            try:
                await asyncio.Event().wait()
            finally:
                controller.unregister_current()

        task = asyncio.create_task(request())
        await started.wait()
        result = await controller.drain(
            completion_timeout_seconds=0.0,
            cancellation_timeout_seconds=0.1,
        )
        await asyncio.gather(task, return_exceptions=True)

        assert controller.is_draining is True
        assert controller.active == 0
        assert result.completed_requests == 0
        assert result.cancelled_requests == 1
        assert controller.try_register_current() is False

    asyncio.run(scenario())
