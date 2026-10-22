"""Certificate-change monitoring fails readiness until restart."""

from __future__ import annotations

from pathlib import Path

import pytest

import enterprise_ai_platform.api.tls_rotation as tls


def test_monitor_marks_rotation_unready(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    identities = iter(["leaf-a", "leaf-b"])
    monkeypatch.setattr(tls, "certificate_identity", lambda *_args: next(identities))
    monitor = tls.TLSRotationMonitor(tmp_path / "cert", tmp_path / "key", tmp_path / "ca", "a" * 64)
    assert monitor.inspect() is True
    assert monitor.inspect() is False
    assert monitor.ready is False


def test_missing_or_invalid_material_fails_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def reject(*_args):
        raise ValueError("expired")

    monkeypatch.setattr(tls, "certificate_identity", reject)
    monitor = tls.TLSRotationMonitor(tmp_path / "cert", tmp_path / "key", tmp_path / "ca", "a" * 64)
    assert monitor.inspect() is False
    assert monitor.ready is False
