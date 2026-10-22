"""Teardown tests for W1-004 offline and resource-free guarantees."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from tools.platformctl.aws_inventory import (
    UnavailableAwsInventoryProvider,
    validate_w12_binding_coverage,
)
from tools.platformctl.contracts import ContractError, ExitCode
from tools.platformctl.lifecycle_models import (
    W12ProtectedObject,
    W12PublishedObject,
    W12RetentionBinding,
)
from tools.platformctl.verify_clean import verify_clean

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def uncommented_terraform(path: Path) -> str:
    return "\n".join(line.split("#", 1)[0] for line in path.read_text().splitlines())


def test_terraform_control_roots_have_exact_hcp_workspace_contracts() -> None:
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
    assert combined.count('organization = "Enterprise_AI_AWS_Arch"') == 2
    assert 'name = "enterprise-ai-bootstrap"' in versions_only
    assert 'name = "enterprise-ai-sandbox"' in versions_only
    assert 'backend "local"' not in versions_only
    assert 'backend "s3"' not in versions_only
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
    assert "import subprocess" in sources["process_runner.py"]
    assert all(
        "import subprocess" not in module_source
        for name, module_source in sources.items()
        if name not in ("process_runner.py", "policy_runner.py")
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


def test_missing_lineage_derivative_is_indeterminate() -> None:
    from tools.capstone_release import _release_publication_key

    record_id = "123e4567-e89b-42d3-a456-426614174000"
    bucket = "w12-evidence-example"
    version = "synthetic-version-1"
    stamp = "2026-01-01T00:00:00Z"
    record_key = _release_publication_key(record_id, "verified_record")
    sidecar_key = _release_publication_key(record_id, "verified_sidecar")
    binding = W12RetentionBinding(
        record_id=record_id,
        operation="deploy",
        verified_record_sha256="a" * 64,
        verified_created_at_utc=stamp,
        verified_record_object=W12PublishedObject(bucket, record_key, version, "a" * 64, stamp),
        verified_sidecar_object=W12PublishedObject(bucket, sidecar_key, version, "b" * 64, stamp),
        publication_anchor_utc=stamp,
        retain_until_utc="2026-06-30T00:00:00Z",
        kms_key_arn="arn:aws:kms:ap-southeast-1:123456789012:key/synthetic",
        protected_objects=tuple(
            sorted(
                (
                    W12ProtectedObject(
                        bucket,
                        record_key,
                        version,
                        "a" * 64,
                        "verified_record",
                        "VERIFIED_SELF_PUBLICATION",
                    ),
                    W12ProtectedObject(
                        bucket,
                        sidecar_key,
                        version,
                        "b" * 64,
                        "verified_sidecar",
                        "VERIFIED_SELF_PUBLICATION",
                    ),
                ),
                key=lambda item: (item.bucket, item.key, item.version_id),
            )
        ),
    )
    with pytest.raises(ContractError, match="W12_PUBLICATION_COVERAGE_INCOMPLETE"):
        validate_w12_binding_coverage(binding)


def test_missing_publication_selector_is_indeterminate(tmp_path: Path) -> None:
    from tools.capstone_release import ReleaseError, validate_publication_proof

    with pytest.raises(ReleaseError) as error:
        validate_publication_proof(
            tmp_path,
            client=object(),
            kms_key_arn="synthetic",
            now=datetime(2026, 1, 1, tzinfo=UTC),
        )
    assert error.value.classification == "INDETERMINATE"


def test_standalone_verify_clean_requires_w12_proof_roots() -> None:
    source = (REPOSITORY_ROOT / "tools/platformctl/verify_clean.py").read_text()
    assert "W12RuntimeProofRoots" in source
    assert "w12_retention_bindings_from_proof_roots" in source
    assert "W12 residue lacks an exact proof root" in source


def test_w12_unexpired_versions_are_retained() -> None:
    source = (REPOSITORY_ROOT / "tools/platformctl/verify_clean.py").read_text()
    assert "RETAINED_BY_POLICY: verified W12 object versions" in source
    assert "now < parse_utc_timestamp(item.retain_until_utc" in source


def test_unknown_w12_retention_is_indeterminate() -> None:
    source = (REPOSITORY_ROOT / "tools/platformctl/verify_clean.py").read_text()
    assert "INDETERMINATE: W12 retention proof changed or is unavailable" in source
    assert "INDETERMINATE: W12 prefix inventory unavailable" in source


def test_verify_clean_requires_w12_kms_availability() -> None:
    source = (REPOSITORY_ROOT / "tools/platformctl/verify_clean.py").read_text()
    assert "W12_RETAINED_KMS_NOT_ENABLED" in source
    assert "W12_RELEASE_KMS_KEY_ARN" in source


def test_verify_clean_reports_w12_retained_resources() -> None:
    source = (REPOSITORY_ROOT / "tools/platformctl/verify_clean.py").read_text()
    assert "RETAINED_BY_POLICY" in source
    assert "verified W12 object versions and KMS dependency remain" in source


def test_kms_pending_deletion_requires_no_protected_w12_dependency() -> None:
    source = (REPOSITORY_ROOT / "tools/platformctl/verify_clean.py").read_text()
    assert "W12_RETAINED_KMS_NOT_ENABLED" in source
    assert "kms.describe_key" in source or "describe_key" in source
