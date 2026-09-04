"""Rollback-boundary tests for the repository-only W5-003 policy pack."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

CREATED_PATHS = (
    ".checkov.yml",
    "policies/opa/exceptions.json",
    "tests/contract/test_policy_exception_contract.py",
    "tests/feature/test_policy_gate.py",
    "tests/rollback/test_policy_pack_rollback.py",
    "tests/security/test_policy_pack.py",
    "tests/teardown/test_policy_pack_cleanliness.py",
)
UPDATED_PATHS = (
    "Makefile",
    "feature-matrix.yaml",
    "tools/platformctl/validate.py",
    "tests/feature/test_feature_matrix.py",
    "tests/unit/test_platformctl.py",
    "policies/opa/terraform_plan.rego",
    "policies/opa/terraform_plan_test.rego",
    "tests/integration/test_dependency_contract.py",
    "infra/environments/sandbox/terraform.tfvars.example",
    "infra/environments/sandbox/variables.tf",
    "tests/contract/test_terraform_module_contract.py",
)
ROLLBACK_CANDIDATES = (*CREATED_PATHS, *UPDATED_PATHS)


def test_rollback_candidate_allowlist_is_the_exact_column_l_manifest() -> None:
    assert len(CREATED_PATHS) == 7
    assert len(UPDATED_PATHS) == 11
    assert len(ROLLBACK_CANDIDATES) == 18
    assert len(set(ROLLBACK_CANDIDATES)) == 18
    assert all((ROOT / path).is_file() for path in ROLLBACK_CANDIDATES)


def test_rollback_scope_excludes_state_plan_cloud_evidence_and_unrelated_paths() -> None:
    lowered = tuple(path.casefold() for path in ROLLBACK_CANDIDATES)

    assert not any(path.endswith((".tfstate", ".tfplan", ".plan")) for path in lowered)
    assert not any(path.startswith("docs/") for path in lowered)
    assert not any(path.startswith("reports/") for path in lowered)
    assert not any(path.startswith(".github/") for path in lowered)
    assert not any("bedrock_owner" in path for path in lowered)


def test_rollback_is_repository_byte_restoration_not_cloud_execution() -> None:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    target = makefile.split("w5-policy-rollback:", maxsplit=1)[1].split("\n\n", maxsplit=1)[0]

    assert "pytest" in target
    for forbidden in (
        "terraform apply",
        "terraform destroy",
        "aws ",
        "docker ",
        "git reset",
        "git clean",
        "remove-item",
    ):
        assert forbidden not in target.casefold()


def test_six_original_foundation_scenarios_remain_represented() -> None:
    source = (ROOT / "policies/opa/terraform_plan_test.rego").read_text(encoding="utf-8")
    foundation_tests = (
        "test_approved_inline_plan_has_no_denials",
        "test_wrong_region_is_denied",
        "test_public_subnet_is_denied",
        "test_nat_gateway_is_denied",
        "test_missing_mandatory_tag_is_denied",
        "test_unencrypted_ecr_is_denied",
    )

    assert all(f"{name} if" in source for name in foundation_tests)
