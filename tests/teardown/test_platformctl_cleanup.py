"""Teardown tests for W1-004 offline and resource-free guarantees."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from tools.platformctl.aws_inventory import UnavailableAwsInventoryProvider
from tools.platformctl.contracts import ExitCode
from tools.platformctl.verify_clean import verify_clean

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def uncommented_terraform(path: Path) -> str:
    return "\n".join(line.split("#", 1)[0] for line in path.read_text().splitlines())


def test_terraform_control_roots_are_provider_and_resource_free() -> None:
    root_files = (
        REPOSITORY_ROOT / "infra" / "bootstrap" / "versions.tf",
        REPOSITORY_ROOT / "infra" / "bootstrap" / "main.tf",
        REPOSITORY_ROOT / "infra" / "environments" / "sandbox" / "versions.tf",
        REPOSITORY_ROOT / "infra" / "environments" / "sandbox" / "main.tf",
    )
    combined = "\n".join(uncommented_terraform(path) for path in root_files)
    for forbidden_block in ("provider ", "backend ", "resource ", "module ", "data "):
        assert forbidden_block not in combined
    assert combined.count("required_version") == 2


def test_platformctl_contains_no_live_execution_import() -> None:
    source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (REPOSITORY_ROOT / "tools" / "platformctl").glob("*.py")
    )
    assert "import boto3" not in source
    assert "import subprocess" not in source
    assert "terraform apply" not in source.lower()
    assert "terraform destroy" not in source.lower()


def test_no_terraform_runtime_residue_is_required() -> None:
    assert not (REPOSITORY_ROOT / "infra" / "bootstrap" / ".terraform").exists()
    assert not (REPOSITORY_ROOT / "infra" / "environments" / "sandbox" / ".terraform").exists()


def test_unavailable_default_inventory_never_claims_cleanliness() -> None:
    result = verify_clean(
        UnavailableAwsInventoryProvider(),
        "sandbox",
        datetime(2026, 1, 1, tzinfo=UTC),
    )
    assert result.exit_code is ExitCode.PROVIDER_UNAVAILABLE
