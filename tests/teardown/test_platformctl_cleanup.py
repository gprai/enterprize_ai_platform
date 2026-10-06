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


def test_terraform_control_roots_have_empty_explicit_backend_contracts() -> None:
    root_files = (
        REPOSITORY_ROOT / "infra" / "bootstrap" / "versions.tf",
        REPOSITORY_ROOT / "infra" / "bootstrap" / "main.tf",
        REPOSITORY_ROOT / "infra" / "environments" / "sandbox" / "versions.tf",
        REPOSITORY_ROOT / "infra" / "environments" / "sandbox" / "main.tf",
    )
    combined = "\n".join(uncommented_terraform(path) for path in root_files)
    versions_only = "\n".join(
        uncommented_terraform(path)
        for path in (
            REPOSITORY_ROOT / "infra" / "bootstrap" / "versions.tf",
            REPOSITORY_ROOT / "infra" / "environments" / "sandbox" / "versions.tf",
        )
    )
    assert combined.count('provider "aws"') == 2
    assert combined.count('resource "terraform_data" "owner_expiry_gate"') == 2
    assert combined.count('module "') == 9
    assert combined.count('backend "local" {}') == 1
    assert combined.count('backend "s3" {}') == 1
    assert "bucket =" not in versions_only
    assert "key =" not in versions_only
    assert combined.count('var.mandatory_tags["ExpiresAt"] != "TODO_OWNER"') == 2
    assert combined.count("required_version") == 2


def test_platformctl_keeps_live_execution_inside_explicit_adapters() -> None:
    sources = {
        path.name: path.read_text(encoding="utf-8")
        for path in (REPOSITORY_ROOT / "tools" / "platformctl").glob("*.py")
    }
    source = "\n".join(sources.values())
    assert "import boto3" not in source
    assert "import subprocess" in sources["terraform_runner.py"]
    assert all(
        "import subprocess" not in module_source
        for name, module_source in sources.items()
        if name != "terraform_runner.py"
    )
    assert "terraform apply" not in source.lower()
    assert "terraform destroy" not in source.lower()
    assert "class Boto3AwsInventoryProvider" in source
    assert "class TerraformRunner" in source
    assert "class OperationLedger" in source


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
