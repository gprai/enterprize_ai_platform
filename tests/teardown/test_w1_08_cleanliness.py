"""Teardown contracts for the W1-08 pre-commit security controls."""

from __future__ import annotations

import json
import os
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SYNTHETIC_MARKER_PARTS = ("AKIA", "W108SEC003TESTXY")


def test_pre_commit_control_leaves_no_repository_cache_or_fixture_residue() -> None:
    forbidden_paths = (
        REPOSITORY_ROOT / ".cache" / "pre-commit",
        REPOSITORY_ROOT / ".pre-commit-cache",
        REPOSITORY_ROOT / ".pre-commit",
        REPOSITORY_ROOT / "pre-commit.log",
        REPOSITORY_ROOT / "w1-08-synthetic-secret.txt",
        REPOSITORY_ROOT / ".secrets.baseline.tmp",
    )
    assert [
        path.relative_to(REPOSITORY_ROOT).as_posix() for path in forbidden_paths if path.exists()
    ] == []


def test_owner_pre_commit_cache_is_external_and_contains_no_synthetic_fixture() -> None:
    cache_value = os.environ.get("PRE_COMMIT_HOME")
    if not cache_value:
        return

    cache_path = Path(cache_value).resolve()
    assert not cache_path.is_relative_to(REPOSITORY_ROOT.resolve())
    if cache_path.exists():
        assert not any(path.name == "w1-08-synthetic-secret.txt" for path in cache_path.rglob("*"))


def test_secret_baseline_contains_only_hashed_reviewed_results_and_no_backup() -> None:
    baseline_path = REPOSITORY_ROOT / ".secrets.baseline"
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    results = baseline["results"]
    assert isinstance(results, dict) and results
    assert len(results) == 55
    assert sum(len(findings) for findings in results.values()) == 412
    for path, findings in results.items():
        assert isinstance(path, str)
        assert isinstance(findings, list) and findings
        for finding in findings:
            assert finding["filename"] == path
            assert set(finding) == {
                "type",
                "filename",
                "hashed_secret",
                "is_verified",
                "line_number",
            }
            assert isinstance(finding["hashed_secret"], str)
            assert len(finding["hashed_secret"]) == 40
    assert not (REPOSITORY_ROOT / ".secrets.baseline.bak").exists()


def test_complete_synthetic_value_is_not_persisted_in_w1_08_files() -> None:
    synthetic_value = "".join(SYNTHETIC_MARKER_PARTS)
    controlled_paths = (
        REPOSITORY_ROOT / "tools/secret_scan.py",
        REPOSITORY_ROOT / ".pre-commit-config.yaml",
        REPOSITORY_ROOT / ".secrets.baseline",
        REPOSITORY_ROOT / "tests/security/test_precommit_controls.py",
        REPOSITORY_ROOT / "tests/security/test_evidence_redaction.py",
        Path(__file__),
    )
    assert all(synthetic_value not in path.read_text(encoding="utf-8") for path in controlled_paths)
