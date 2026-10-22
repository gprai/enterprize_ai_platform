"""End-to-end local deterministic W3-004 rollback drill acceptance."""

from __future__ import annotations

import asyncio
import hashlib
import shutil
from pathlib import Path

import pytest

from enterprise_ai_platform.rag_rollback import identity as identity_module
from enterprise_ai_platform.rag_rollback.service import (
    activate_regression,
    cleanup,
    evaluate_regression,
    evaluate_restored,
    finalize,
    initialize,
    rollback,
    validate,
    verify_clean,
    verify_zero_residue,
)

ROOT = Path(__file__).resolve().parents[2]
AUTHORITIES = (
    "configs/rag/versions/known-good-v2.json",
    "configs/rag/versions/synthetic-regression-v2.json",
    "configs/eval/baselines/w3-002-v1.json",
    "configs/eval/golden.jsonl",
    "configs/eval/cited-rag-evaluation-policy.yaml",
    "configs/rag.yaml",
    "reports/eval.json",
    "reports/eval-repeat.json",
    "src/enterprise_ai_platform/evaluation/fixtures.py",
    "src/enterprise_ai_platform/guardrails/policy.py",
)
pytestmark = pytest.mark.skipif(
    not all(
        (ROOT / relative).is_file()
        for relative in ("reports/eval.json", "reports/eval-repeat.json")
    ),
    reason="ignored owner-local W3 evaluation reports are absent",
)


def _isolated_repository(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> Path:
    for relative in AUTHORITIES:
        source = ROOT / relative
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    monkeypatch.setattr(identity_module, "REPOSITORY_ROOT", tmp_path)
    return tmp_path


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_n_to_regression_to_restored_n_flow_is_exact_and_cleanable(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repository = _isolated_repository(monkeypatch, tmp_path)
    protected = {relative: _sha256(repository / relative) for relative in AUTHORITIES}

    validated = validate()
    initialized = initialize()
    activated = activate_regression()
    regression = asyncio.run(evaluate_regression())
    restored_state = rollback()
    restored = asyncio.run(evaluate_restored())
    record = finalize()
    clean = verify_clean()

    assert validated.status == "VALIDATED"
    assert initialized.active_identity == "known-good"
    assert activated.active_identity == "synthetic-regression"
    assert regression.status == "EXPECTED_REGRESSION_DETECTED"
    assert regression.absolute_gate_status == "FAIL"
    assert regression.baseline_comparison_status == "FAIL"
    assert not regression.release_eligible
    assert restored_state.active_identity == "known-good"
    assert restored.status == "RESTORED_BASELINE_PASS"
    assert restored.absolute_gate_status == "PASS"
    assert restored.baseline_comparison_status == "PASS"
    assert restored.release_eligible
    assert record.final_status == "PASS"
    assert clean.status == "CLEAN" and clean.approved_artifact_count == 4
    assert {relative: _sha256(repository / relative) for relative in AUTHORITIES} == protected

    cleanup_result = cleanup(external_archive_verified=True)
    zero = verify_zero_residue()
    assert cleanup_result.status == "ZERO_RESIDUE"
    assert zero.status == "ZERO_RESIDUE"
    assert not (repository / "reports/w3-004").exists()
