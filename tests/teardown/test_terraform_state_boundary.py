"""Zero-residue contract for W5-001 Terraform construction."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_only_tracked_provider_locks_may_exist_without_runtime_residue() -> None:
    approved_provider_locks = {
        Path("infra/bootstrap/.terraform.lock.hcl"),
        Path("infra/environments/sandbox/.terraform.lock.hcl"),
    }
    forbidden_names = {
        ".terraform",
        ".tflint.d",
        "terraform.tfstate",
        "terraform.tfstate.backup",
    }
    findings = [
        path.relative_to(ROOT).as_posix()
        for path in ROOT.rglob("*")
        if ".git" not in path.relative_to(ROOT).parts
        and (
            path.name in forbidden_names
            or path.suffix == ".tfplan"
            or (
                path.name == ".terraform.lock.hcl"
                and path.relative_to(ROOT) not in approved_provider_locks
            )
        )
    ]

    assert findings == []


def test_no_real_plan_json_or_excluded_evidence_path_exists() -> None:
    assert not (ROOT / "docs/test-evidence/W5-terraform.txt").exists()
    assert not (ROOT / "reports/verification/bedrock-owner-test-result.json").exists()
    assert tuple(ROOT.rglob("terraform-plan*.json")) == ()


def test_w5_004_runtime_artifacts_are_external_only() -> None:
    forbidden_suffixes = (".tfplan", ".tfstate", ".tfstate.backup")
    findings = [
        path.relative_to(ROOT).as_posix()
        for path in ROOT.rglob("*")
        if path.is_file() and path.name.endswith(forbidden_suffixes)
    ]
    assert findings == []
