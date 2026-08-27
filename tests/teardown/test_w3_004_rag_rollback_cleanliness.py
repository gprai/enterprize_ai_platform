"""Repository cleanliness and immutable-input protection for W3-004."""

from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUNTIME = ROOT / "reports/w3-004"
PROTECTED_HASHES = {
    "configs/eval/baselines/w3-002-v1.json": (
        "4bbc8f24af911ba09356196e9285d261549926c713110f9549929e1e4ac9086f"
    ),
    "configs/eval/golden.jsonl": (
        "809aac88f84dd44aeb96c676f3bad229164a0767c6fc9d0ebeeb01b6823c06c2"
    ),
    "configs/eval/w3-002.yaml": (
        "4564b1935c1c072281f90a63c1ac80315709e35e6aab8e0803d0a9abf5c189df"
    ),
    "configs/rag.yaml": (
        "5cb62932bbc0a0c11e494912bdcc5b4b48bd4195e3ca58bda2df27227070b27e"
    ),
    "reports/eval.json": (
        "f259784666c180145c4dbb0f4757fbac2505eba059c6ee06510c6906cb3546cf"
    ),
    "reports/eval-repeat.json": (
        "d35c1ee13a54cda78e7514a84cd9af6e6086236a4095f7824f52cdbc46d2da1a"
    ),
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_protected_authorities_and_retained_reports_are_byte_identical() -> None:
    assert {
        relative: _sha256(ROOT / relative) for relative in PROTECTED_HASHES
    } == PROTECTED_HASHES


def test_column_l_created_no_runtime_drill_or_temporary_residue() -> None:
    assert not RUNTIME.exists()
    assert tuple((ROOT / "reports").glob("w3-004/.*.tmp")) == ()


def test_ignore_boundary_is_exact_and_not_a_broad_reports_ignore() -> None:
    ignore_lines = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    expected = {
        "reports/w3-004/active.json",
        "reports/w3-004/regression.json",
        "reports/w3-004/restored.json",
        "reports/w3-004/rollback-record.json",
        "reports/w3-004/activation.lock",
        "reports/w3-004/.active.json.*.tmp",
        "reports/w3-004/.regression.json.*.tmp",
        "reports/w3-004/.restored.json.*.tmp",
        "reports/w3-004/.rollback-record.json.*.tmp",
    }
    assert expected.issubset(ignore_lines)
    assert "reports/" not in ignore_lines
    assert "reports/w3-004/" not in ignore_lines
