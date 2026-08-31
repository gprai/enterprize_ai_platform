"""Minimal provider-free smoke checks for both approved release profiles."""

from __future__ import annotations

import asyncio
from pathlib import Path

from enterprise_ai_platform.release_rollback.identity import (
    load_release_descriptor,
)
from enterprise_ai_platform.release_rollback.probe import LocalASGIReleaseProbe

ROOT = Path(__file__).resolve().parents[2]


def test_local_asgi_probe_observes_regression_and_restored_route_profile() -> None:
    probe = LocalASGIReleaseProbe()
    candidate = asyncio.run(
        probe.probe_candidate(
            load_release_descriptor("w4-synthetic-regression-v1")
        )
    )
    restored = asyncio.run(
        probe.probe_restored(load_release_descriptor("w4-known-good-v1"))
    )

    assert candidate.http_status == 501
    assert candidate.safe_error_code == "agent_disabled"
    assert candidate.network_activity is False
    assert restored.health_http_status == 200
    assert restored.health_status == "ok"
    assert restored.agent_route_http_status == 422
    assert restored.agent_disabled_observed is False
    assert restored.network_activity is False


def test_make_exposes_owner_ordered_rollback_and_smoke_targets() -> None:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    assert "rollback-release:" in makefile
    assert "smoke:" in makefile
    assert "tools/releasectl.py rollback-release" in makefile
    assert "tools/releasectl.py smoke" in makefile
    makefile_lines = makefile.splitlines()
    assert makefile_lines.index("rollback-release:") < makefile_lines.index("smoke:")
