"""Zero-residue and repeated-shutdown coverage for W8-002."""

from __future__ import annotations

import asyncio
from pathlib import Path

from enterprise_ai_platform.api.runtime import ApplicationDrainController

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def test_repeated_shutdown_is_idempotent_and_leaves_no_async_tasks() -> None:
    async def scenario() -> None:
        controller = ApplicationDrainController()

        first = await controller.drain(
            completion_timeout_seconds=0.01,
            cancellation_timeout_seconds=0.01,
        )
        second = await controller.drain(
            completion_timeout_seconds=0.01,
            cancellation_timeout_seconds=0.01,
        )
        current = asyncio.current_task()

        assert first.completed_requests == first.cancelled_requests == 0
        assert second.completed_requests == second.cancelled_requests == 0
        assert {task for task in asyncio.all_tasks() if task is not current} == set()

    asyncio.run(scenario())


def test_w8_002_creates_no_duplicate_application_or_runtime_resource_path() -> None:
    source = (REPOSITORY_ROOT / "src" / "enterprise_ai_platform").rglob("*.py")
    factories = [path for path in source if "FastAPI(" in path.read_text(encoding="utf-8")]

    assert factories == [REPOSITORY_ROOT / "src" / "enterprise_ai_platform" / "app.py"]
    assert not (REPOSITORY_ROOT / "deploy" / "k8s" / "w8-002.yaml").exists()
