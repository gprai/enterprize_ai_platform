from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from provision import hcp, lifecycle
from provision.cleanup import validate_destroy
from provision.services import ServiceError, Services

from tests.unit.test_lifecycle_orchestration import context


def test_expired_context_cannot_authorize_even_if_owner_would_confirm(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    value = context()
    value["created_at"] = (datetime.now(UTC) - timedelta(hours=2)).isoformat()
    value["expires_at"] = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
    monkeypatch.setattr(
        lifecycle, "_confirmation", lambda text: pytest.fail("must stop before prompt")
    )
    with pytest.raises(lifecycle.LifecycleError, match="RUN_CONTEXT_EXPIRED"):
        lifecycle._approve_current(value, "APPLY")


@pytest.mark.parametrize("kind", ["aws_iam_role", "aws_s3_bucket", "aws_kms_key"])
def test_destroy_cannot_delete_retained_resources_even_when_dependency_in_plan(kind: str) -> None:
    address = kind + ".retained"
    plan = {
        "resource_changes": [
            {
                "mode": "managed",
                "address": address,
                "type": kind,
                "change": {"actions": ["delete"], "before": {"id": "retained"}},
            }
        ]
    }
    with pytest.raises(ServiceError, match="DESTROY_OUTSIDE_EXACT_RETAINED_BOUNDARY"):
        validate_destroy(plan, {"targets": [address], "target": "sandbox"})


def test_unrequested_dependency_delete_is_rejected() -> None:
    plan = {
        "resource_changes": [
            {
                "mode": "managed",
                "address": "aws_vpc.other",
                "type": "aws_vpc",
                "change": {"actions": ["delete"], "before": {"id": "vpc-other"}},
            }
        ]
    }
    with pytest.raises(ServiceError, match="DESTROY_OUTSIDE_EXACT_RETAINED_BOUNDARY"):
        validate_destroy(plan, {"targets": ["aws_vpc.this"], "target": "sandbox"})


def test_fixed_activation_flags_cannot_be_overridden() -> None:
    with pytest.raises(ServiceError, match="STAGE_ACTIVATION_FLAG_MISMATCH"):
        hcp.stage_variables(
            {"stages": {"base": {"variables": {"w12_capstone_enabled": True}}}}, "base"
        )


def test_context_bytes_tampering_is_detected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(lifecycle, "REPOSITORY_ROOT", tmp_path / "repository")
    store = lifecycle.ContextStore(tmp_path / "external")
    value = context()
    path = store.create(value)
    path.write_text(path.read_text().replace('"PASS"', '"FAIL"'))
    with pytest.raises(lifecycle.LifecycleError, match="RUN_CONTEXT_INTEGRITY_MISMATCH"):
        store.load(value["run_id"])


def test_hcp_pagination_cannot_forward_credentials_to_other_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    services = object.__new__(Services)
    monkeypatch.setattr(
        services,
        "hcp",
        lambda path: {"data": [], "links": {"next": "https://untrusted.invalid/api/v2/runs"}},
    )
    with pytest.raises(ServiceError):
        services.hcp_pages("/runs")


def test_missing_verified_artifact_cannot_report_release_success(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    services = object.__new__(Services)
    monkeypatch.setattr(services, "github_pages", lambda *args: [])
    with pytest.raises(lifecycle.LifecycleError, match="VERIFIED_PUBLICATION_ARTIFACT"):
        lifecycle._collect_publication(services, {"record_id": "record"}, "a" * 64, 1, tmp_path, {})


def test_no_local_terraform_execution_in_adapters() -> None:
    # Architectural boundary in addition to request-level tests: Terraform CLI is never executed.
    import ast

    for path in Path("provision").glob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.List) and node.elts and isinstance(node.elts[0], ast.Constant):
                assert node.elts[0].value not in ("terraform", "terraform.exe")


@pytest.mark.parametrize(
    "address,kind,expected",
    [
        ("terraform_data.w12_activation_gate[0]", "terraform_data", True),
        ("terraform_data.unapproved", "terraform_data", False),
        ("terraform_data.w12_activation_gate[0]", "unapproved", False),
    ],
)
def test_opa_destroy_guard_only_accepts_exact_capstone_gate(
    address: str, kind: str, expected: bool
) -> None:
    from tests.security.test_w12_001_initial_plan_policy import _opa_value

    assert (
        _opa_value(
            {"address": address, "type": kind},
            "data.enterprise_ai.terraform.plan.operational_destroy_resource_valid(input)",
        )
        is expected
    )
