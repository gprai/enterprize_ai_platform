"""Zero-residue contract for W5-001 Terraform construction."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_no_state_plan_lock_or_repository_tool_cache_exists() -> None:
    forbidden_names = {
        ".terraform",
        ".terraform.lock.hcl",
        ".tflint.d",
        "terraform.tfstate",
        "terraform.tfstate.backup",
    }
    findings = [
        path.relative_to(ROOT).as_posix()
        for path in ROOT.rglob("*")
        if ".git" not in path.relative_to(ROOT).parts
        and (path.name in forbidden_names or path.suffix == ".tfplan")
    ]

    assert findings == []


def test_no_real_plan_json_or_excluded_evidence_path_exists() -> None:
    assert not (ROOT / "docs/test-evidence/W5-terraform.txt").exists()
    assert not (ROOT / "reports/verification/bedrock-owner-test-result.json").exists()
    assert tuple(ROOT.rglob("terraform-plan*.json")) == ()
