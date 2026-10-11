"""Repository and external-boundary cleanliness tests for W5-003."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OWNER_PROTECTED_STATE = ROOT / "infra/bootstrap/terraform.tfstate"
W5_TEMP = Path(r"E:\AI\.tmp\enterprise-ai-platform-w5-003")
W5_PRE_COMMIT_HOME = Path(r"E:\AI\.pre-commit-cache\enterprise-ai-platform-w5-003")
W5_001_REPORTS = ROOT / "reports/verification"
PROTECTED_D23_DIRECTORIES = (
    Path(
        r"E:\AI\.pre-commit-cache\enterprise-ai-platform-w5-001"
        r"\pytest-basetemp-focused-20260904"
    ),
    Path(
        r"E:\AI\.pre-commit-cache\enterprise-ai-platform-w5-001"
        r"\pytest-basetemp-full-20260904"
    ),
    Path(
        r"E:\AI\.pre-commit-cache\enterprise-ai-platform-w5-001"
        r"\pytest-basetemp-retry-20260904"
    ),
)


def _repository_residue() -> list[str]:
    residue: list[str] = []
    ignored_roots = {ROOT / ".git", W5_001_REPORTS}
    forbidden_directories = {
        ".pytest_cache",
        "__pycache__",
        ".mypy_cache",
        ".ruff_cache",
        ".terraform",
    }
    forbidden_suffixes = (".tfstate", ".tfplan", ".plan", ".sarif")
    for path in ROOT.rglob("*"):
        if any(path == ignored or ignored in path.parents for ignored in ignored_roots):
            continue
        if path == OWNER_PROTECTED_STATE:
            continue
        relative = path.relative_to(ROOT).as_posix()
        if path.is_dir() and path.name in forbidden_directories:
            residue.append(relative)
        elif path.is_file() and path.name.endswith(forbidden_suffixes):
            residue.append(relative)
        elif path.is_file() and (
            "checkov-report" in path.name.casefold()
            or "opa-bundle" in path.name.casefold()
            or "policy-report" in path.name.casefold()
        ):
            residue.append(relative)
    return sorted(residue)


def test_no_policy_cache_report_bundle_bytecode_state_or_plan_is_in_repository() -> None:
    assert _repository_residue() == []


def test_w5_003_cache_and_temp_boundaries_are_external() -> None:
    assert not W5_TEMP.is_relative_to(ROOT)
    assert not W5_PRE_COMMIT_HOME.is_relative_to(ROOT)
    assert W5_TEMP == Path(r"E:\AI\.tmp\enterprise-ai-platform-w5-003")
    assert W5_PRE_COMMIT_HOME == Path(r"E:\AI\.pre-commit-cache\enterprise-ai-platform-w5-003")


def test_w5_001_reports_and_shared_external_caches_are_protected() -> None:
    rollback_source = (ROOT / "tests/rollback/test_policy_pack_rollback.py").read_text(
        encoding="utf-8"
    )

    assert W5_001_REPORTS not in (W5_TEMP, W5_PRE_COMMIT_HOME)
    assert all(not path.is_relative_to(ROOT) for path in PROTECTED_D23_DIRECTORIES)
    assert all(str(path) not in rollback_source for path in PROTECTED_D23_DIRECTORIES)


def test_no_broad_deletion_or_external_teardown_is_encoded() -> None:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    target = makefile.split("w5-policy-rollback:", maxsplit=1)[1].split("\n\n", maxsplit=1)[0]

    for forbidden in (
        "rm -rf",
        "remove-item",
        "git clean",
        "terraform destroy",
        "aws ",
        "docker ",
    ):
        assert forbidden not in target.casefold()
