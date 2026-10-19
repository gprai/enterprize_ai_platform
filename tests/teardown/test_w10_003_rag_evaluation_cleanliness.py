"""Cleanliness coverage for append-only external W10-003 evidence."""

from __future__ import annotations

import pytest

from enterprise_ai_platform.evaluation.errors import RAGSafetyEvidenceError
from enterprise_ai_platform.evaluation.rag_safety import write_exclusive_json


def test_exclusive_writer_leaves_no_temporary_file_and_refuses_overwrite(tmp_path) -> None:  # type: ignore[no-untyped-def]
    target = tmp_path / "run" / "report.json"
    write_exclusive_json(target, {"status": "PASS"})

    assert target.read_text(encoding="utf-8") == '{"status":"PASS"}\n'
    assert not tuple(target.parent.glob(".*.tmp"))
    with pytest.raises(RAGSafetyEvidenceError):
        write_exclusive_json(target, {"status": "FAIL"})
