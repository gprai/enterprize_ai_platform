"""Repository cleanliness contract for W5-002 task-owned runtime residue."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from shutil import which

ROOT = Path(__file__).resolve().parents[2]
APPROVED_LOCKS = {
    Path("infra/bootstrap/.terraform.lock.hcl"),
    Path("infra/environments/sandbox/.terraform.lock.hcl"),
}
OWNER_PROTECTED_PREEXISTING_STATE = Path("infra/bootstrap/terraform.tfstate")


def test_w5_002_runtime_reports_are_gitignored_and_untracked() -> None:
    ignore_lines = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert "reports/w5-002/" in ignore_lines
    git = which("git")
    assert git is not None
    tracked = subprocess.run(  # noqa: S603 - fixed read-only Git inventory
        [git, "-c", f"safe.directory={ROOT}", "ls-files", "--", "reports/w5-002"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    assert tracked.stdout == ""
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
        and path.relative_to(ROOT) != OWNER_PROTECTED_PREEXISTING_STATE
        and (path.name in forbidden_names or path.suffix.casefold() in {".pyc", ".pyo", ".tfplan"})
    ]
    assert findings == []


def test_owner_protected_preexisting_bootstrap_state_is_not_task_residue() -> None:
    state = ROOT / OWNER_PROTECTED_PREEXISTING_STATE
    assert state.is_file()
    assert state.stat().st_size == 34206
    assert "*.tfstate" in (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()


def test_v2_cleanup_contract_preserves_shared_and_historical_resources() -> None:
    helper = (ROOT / "tools/w5_002_ci.py").read_text(encoding="utf-8")
    config = json.loads((ROOT / "configs/ci/w5-002.json").read_text(encoding="utf-8"))

    assert "w5-002.cleanup-retention.v2" in helper
    assert "reports/w5-002/cleanup-retention.json" in config["reports"]
    assert config["historical"]["w5_002_formal_status"] == "FAIL"


def test_cleanup_is_bounded_to_migration_created_paths_and_builder() -> None:
    workflow = (ROOT / ".github/workflows/security-scan.yml").read_text(encoding="utf-8")
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")

    cleanup = workflow.split("Remove only migration-created runtime resources", maxsplit=1)[1]
    assert 'echo "OCI_LAYOUT=$RUNNER_TEMP/w5-002-py313-oci-layout"' in workflow
    assert '"$OCI_LAYOUT"' in cleanup
    assert 'echo "OCI_ARCHIVE=$RUNNER_TEMP/w5-002-py313-candidate.oci"' in workflow
    assert '"$OCI_ARCHIVE"' in cleanup
    assert 'echo "RAW_DIR=$RUNNER_TEMP/w5-002-py313-raw"' in workflow
    assert 'echo "TRIVY_CACHE=$RUNNER_TEMP/w5-002-py313-trivy"' in workflow
    assert 'echo "GRYPE_CACHE=$RUNNER_TEMP/w5-002-py313-grype"' in workflow
    assert '} >> "$GITHUB_ENV"' in workflow
    assert "enterprise-ai-platform-w5-002-py313" in cleanup
    assert "reports/verification" not in cleanup
    assert "scanner-cache" not in cleanup
    assert "terraform-cache" not in cleanup
    assert "w5-002-clean-runtime:" in makefile
    assert "write-cleanup-retention" in makefile


def test_cleanup_report_is_not_a_cloud_teardown_or_rollback_claim() -> None:
    helper = (ROOT / "tools/w5_002_ci.py").read_text(encoding="utf-8")

    assert '"cloud_activity": "NOT RUN"' in helper
    assert '"deployment_status": "NOT RUN"' in helper
    assert '"rollback_status": "IDENTITY_RECORDED"' in helper


def test_remediation_policy_adds_no_runtime_or_cloud_cleanup_authority() -> None:
    config = json.loads((ROOT / "configs/ci/w5-002.json").read_text(encoding="utf-8"))
    assert config["remediation"]["waivers"]["new_waivers_allowed"] is False
    assert config["historical"]["w5_002_formal_status"] == "FAIL"
