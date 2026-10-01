"""Cleanliness and external-output boundary tests for W6-001."""

from pathlib import Path

from tools import w6_001_k8s

ROOT = Path(__file__).resolve().parents[2]


def test_repository_template_validation_creates_no_generated_residue(tmp_path: Path) -> None:
    before = sorted(path.relative_to(ROOT).as_posix() for path in (ROOT / "deploy/k8s").rglob("*"))
    assert w6_001_k8s.validate_template(ROOT / "deploy/k8s") == w6_001_k8s.TEMPLATE_STATUS
    after = sorted(path.relative_to(ROOT).as_posix() for path in (ROOT / "deploy/k8s").rglob("*"))
    assert after == before
    assert list(tmp_path.iterdir()) == []


def test_no_release_package_or_evidence_is_committed() -> None:
    forbidden_names = {
        "release-binding.json",
        "release-hashes.json",
        "rendered.json",
        "w6-001-release-package",
    }
    observed = {path.name for path in ROOT.rglob("*") if path.is_file()}
    assert forbidden_names.isdisjoint(observed)


def test_binder_never_removes_or_repairs_a_colliding_output_root() -> None:
    source = Path(w6_001_k8s.__file__).read_text(encoding="utf-8")
    assert "reserve_operation_directory" in source
    assert ".rmtree(" not in source
    assert ".unlink(" not in source
    assert "chmod(" not in source
