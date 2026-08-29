"""Zero-residue checks for the in-process W4-001 API boundary."""

from __future__ import annotations

import ast
import socket
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from enterprise_ai_platform.app import create_app
from enterprise_ai_platform.config import Settings
from enterprise_ai_platform.rag.models import AbstentionResult
from enterprise_ai_platform.retrieval.models import (
    AuthContext,
    Classification,
    Role,
)
from tests.fakes.api import FakeAuthenticator, FakeRAGService, FakeReadinessProbe

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
API_SOURCE = REPOSITORY_ROOT / "src" / "enterprise_ai_platform" / "api"
RESIDUE_ROOTS = (
    REPOSITORY_ROOT / "reports",
    REPOSITORY_ROOT / ".pytest_cache",
    REPOSITORY_ROOT / ".mypy_cache",
    REPOSITORY_ROOT / ".ruff_cache",
)


def _auth() -> AuthContext:
    return AuthContext(
        subject_id="reader-a",
        tenant_id="tenant-a",
        roles=frozenset({Role.READER}),
        clearance=Classification.INTERNAL,
    )


def _snapshot() -> set[str]:
    paths: set[str] = set()
    for root in RESIDUE_ROOTS:
        if root.exists():
            paths.update(
                str(path.relative_to(REPOSITORY_ROOT))
                for path in root.rglob("*")
            )
    return paths


def test_api_source_creates_no_background_or_persistent_runtime_work() -> None:
    forbidden_calls = {
        "BackgroundTask",
        "BackgroundTasks",
        "Popen",
        "create_subprocess_exec",
        "create_subprocess_shell",
        "create_task",
        "ensure_future",
        "open_connection",
        "start_server",
    }
    findings: list[str] = []

    for path in API_SOURCE.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = getattr(node.func, "id", None) or getattr(
                    node.func,
                    "attr",
                    None,
                )
                if name in forbidden_calls:
                    findings.append(f"{path.name}:{name}")

    assert findings == []


def test_in_process_requests_leave_no_file_socket_or_process_residue(
    api_settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    before = _snapshot()

    def reject_socket(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("W4-001 attempted a socket connection")

    def reject_process(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("W4-001 attempted to start a process")

    with monkeypatch.context() as construction_guard:
        construction_guard.setattr(socket.socket, "connect", reject_socket)
        construction_guard.setattr(subprocess, "Popen", reject_process)
        application = create_app(
            api_settings,
            authenticator=FakeAuthenticator(_auth()),
            rag_service=FakeRAGService(
                [AbstentionResult(reason="insufficient_evidence")]
            ),
            readiness_probe=FakeReadinessProbe(),
        )

    with TestClient(application) as client:
        with monkeypatch.context() as request_guard:
            request_guard.setattr(socket.socket, "connect", reject_socket)
            request_guard.setattr(subprocess, "Popen", reject_process)
            assert client.get("/health/live").status_code == 200
            assert client.get("/health/ready").status_code == 200
            assert client.post(
                "/v1/query",
                json={"query": "clean local request"},
            ).status_code == 200
            assert client.post("/v1/agent").status_code == 501

    assert _snapshot() == before
    assert list(tmp_path.iterdir()) == []
    assert not (API_SOURCE / "__pycache__").exists()
    assert set(application.state._state) == {
        "settings",
        "api_authenticator",
        "api_rag_service",
        "api_readiness_probe",
        "api_query_limiter",
    }