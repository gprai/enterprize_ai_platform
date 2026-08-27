"""Zero-residue checks for the local-only W3-003 implementation."""

from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REPORT_ROOT = ROOT / "reports"
REPORT_HASHES = {
    "eval.json": "f259784666c180145c4dbb0f4757fbac2505eba059c6ee06510c6906cb3546cf",
    "eval-repeat.json": "d35c1ee13a54cda78e7514a84cd9af6e6086236a4095f7824f52cdbc46d2da1a",
}
BASELINE = ROOT / "configs" / "eval" / "baselines" / "w3-002-v1.json"
BASELINE_SHA256 = "4bbc8f24af911ba09356196e9285d261549926c713110f9549929e1e4ac9086f"
W3_004_RUNTIME_NAME = "w3-004"


def test_retained_reports_and_promoted_baseline_are_exact() -> None:
    present = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in REPORT_ROOT.iterdir()
        if path.is_file() and path.name in REPORT_HASHES
    }

    assert present == REPORT_HASHES
    assert hashlib.sha256(BASELINE.read_bytes()).hexdigest() == BASELINE_SHA256


def test_no_unexpected_report_cache_bytecode_or_temporary_residue() -> None:
    unexpected_reports = {
        path.name
        for path in REPORT_ROOT.iterdir()
        if path.name not in REPORT_HASHES and path.name != W3_004_RUNTIME_NAME
    }
    residue = {
        path
        for path in ROOT.rglob("*")
        if ".git" not in path.parts
        and (
            (
                path.is_dir()
                and path.name
                in {"__pycache__", ".pytest_cache", ".ruff_cache", ".mypy_cache"}
            )
            or (path.is_file() and path.suffix in {".pyc", ".pyo"})
            or (
                path.is_file()
                and path.name.startswith(".eval")
                and path.name.endswith(".tmp")
            )
        )
    }

    assert unexpected_reports == set()
    assert residue == set()
