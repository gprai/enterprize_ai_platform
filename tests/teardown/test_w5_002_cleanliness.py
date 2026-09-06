"""Repository cleanliness contract for W5-002 task-owned runtime residue."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
APPROVED_LOCKS = {
    Path("infra/bootstrap/.terraform.lock.hcl"),
    Path("infra/environments/sandbox/.terraform.lock.hcl"),
}


def test_no_w5_002_runtime_report_or_candidate_archive_is_in_repository() -> None:
    assert not (ROOT / "reports/w5-002").exists()
    findings = [
        path.relative_to(ROOT).as_posix()
        for path in ROOT.rglob("*")
        if ".git" not in path.relative_to(ROOT).parts
        and (
            path.suffix.casefold() == ".oci"
            or path.name in {"candidate.oci", "terraform-plan-summary.json"}
            or path.name in {"trivy-cache", "grype-db", ".scanner-db"}
        )
    ]
    assert findings == []


def test_only_two_provider_locks_are_allowed_without_terraform_runtime() -> None:
    lock_paths = {
        path.relative_to(ROOT)
        for path in ROOT.rglob(".terraform.lock.hcl")
        if ".git" not in path.relative_to(ROOT).parts
    }
    assert lock_paths == APPROVED_LOCKS
    assert not any(
        path.is_dir() and path.name == ".terraform"
        for path in ROOT.rglob(".terraform")
        if ".git" not in path.relative_to(ROOT).parts
    )


def test_no_task_cache_temp_state_plan_or_bytecode_residue_exists() -> None:
    forbidden_names = {
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tflint.d",
        "__pycache__",
        "terraform.tfstate",
        "terraform.tfstate.backup",
    }
    findings = [
        path.relative_to(ROOT).as_posix()
        for path in ROOT.rglob("*")
        if ".git" not in path.relative_to(ROOT).parts
        and (path.name in forbidden_names or path.suffix.casefold() in {".pyc", ".pyo", ".tfplan"})
    ]
    assert findings == []
