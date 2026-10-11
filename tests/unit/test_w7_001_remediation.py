"""Offline unit coverage for the W7-001 remediation contracts."""

from __future__ import annotations

import codecs
import io
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest
from tools.platformctl.contracts import ContractError
from tools.platformctl.lifecycle_io import validate_evidence_index
from tools.platformctl.lifecycle_models import (
    ControlMatrixRow,
    ControlResult,
    EvidenceDisposition,
    EvidenceIndexRecord,
    EvidenceLifecycle,
    EvidenceRef,
)
from tools.platformctl.process_runner import (
    ProcessClassification,
    ProcessResult,
    ResultCardinality,
    capture_process,
    decode_utf8_output,
    normalize_results,
)
from tools.platformctl.validate import validate_control_matrix


def test_zero_one_many_and_bom_safe_utf8_are_deterministic() -> None:
    assert normalize_results(None) == (ResultCardinality.ZERO, ())
    assert normalize_results("one") == (ResultCardinality.ONE, ("one",))
    assert normalize_results([1, 2]) == (ResultCardinality.MANY, (1, 2))
    assert decode_utf8_output(codecs.BOM_UTF8 + b"safe") == "safe"


def test_failed_timeout_and_cancellation_cannot_be_success() -> None:
    for classification in (
        ProcessClassification.FAILED,
        ProcessClassification.TIMED_OUT,
        ProcessClassification.CANCELLED,
        ProcessClassification.INDETERMINATE,
    ):
        assert not ProcessResult(1, "", "", classification=classification).succeeded
    assert ProcessResult(0, "", "", classification=ProcessClassification.SUCCEEDED).succeeded


class _RunningProcess:
    def __init__(self) -> None:
        self.returncode: int | None = None
        self.stdout = io.BytesIO()
        self.stderr = io.BytesIO()

    def poll(self) -> int | None:
        return self.returncode

    def kill(self) -> None:
        self.returncode = -9

    def wait(self, timeout: float | None = None) -> int:
        if self.returncode is None:
            raise subprocess.TimeoutExpired("offline", timeout)
        return self.returncode


def test_intercepted_process_timeout_and_cancellation_are_classified(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import tools.platformctl.process_runner as runner

    monkeypatch.setattr(runner.subprocess, "Popen", lambda *args, **kwargs: _RunningProcess())
    clock = iter((0.0, 2.0, 2.0))
    monkeypatch.setattr(runner.time, "monotonic", lambda: next(clock))
    timed_out = capture_process(
        (str((tmp_path / "tool.exe").resolve()),),
        cwd=tmp_path.resolve(),
        environment={},
        timeout_seconds=1,
    )
    assert timed_out.classification is ProcessClassification.TIMED_OUT
    assert not timed_out.succeeded

    class Cancelled:
        def is_cancelled(self) -> bool:
            return True

    clock = iter((0.0, 0.1))
    monkeypatch.setattr(runner.time, "monotonic", lambda: next(clock))
    cancelled = capture_process(
        (str((tmp_path / "tool.exe").resolve()),),
        cwd=tmp_path.resolve(),
        environment={},
        timeout_seconds=1,
        cancellation=Cancelled(),
    )
    assert cancelled.classification is ProcessClassification.CANCELLED
    assert not cancelled.succeeded


def test_non_utf8_output_fails_closed() -> None:
    with pytest.raises(ContractError, match="NOT_UTF8"):
        decode_utf8_output(b"\xff")


def test_mandatory_control_cannot_hide_not_run_or_no_data() -> None:
    for result in (ControlResult.NOT_RUN, ControlResult.NO_DATA, ControlResult.INDETERMINATE):
        row = ControlMatrixRow("control-1", True, "owner", "NONE", "PASS", None, (), result)
        with pytest.raises(ContractError, match="NOT_CONCLUSIVE"):
            validate_control_matrix((row,))


def test_evidence_identity_expiry_and_consumption_are_explicit() -> None:
    reference = EvidenceRef(
        "offline",
        "evidence.json",
        "a" * 64,
        1,
        "owner",
        "2026-10-11T00:00:00Z",
        "2026-10-12T00:00:00Z",
        "operation-1",
    )
    active = EvidenceIndexRecord(
        "record-1",
        EvidenceDisposition.CURRENT,
        EvidenceLifecycle.ACTIVE,
        "a" * 64,
        "b" * 64,
        "c" * 64,
        reference,
        None,
        None,
        "2026-10-12T00:00:00Z",
        "owner",
    )
    now = datetime(2026, 10, 11, tzinfo=UTC)
    assert validate_evidence_index((active,), now=now) == (active,)
    with pytest.raises(ContractError):
        validate_evidence_index(
            (EvidenceIndexRecord(**{**active.__dict__, "source_sha256": "tampered"}),),
            now=now,
        )
    consumed = EvidenceIndexRecord(
        **{
            **active.__dict__,
            "lifecycle": EvidenceLifecycle.CONSUMED,
        }
    )
    assert validate_evidence_index((consumed,), now=now) == (consumed,)
