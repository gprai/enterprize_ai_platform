"""Unit tests for the bounded Infracost decision."""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest
from tools.platformctl.contracts import ContractError
from tools.platformctl.cost import (
    LIFECYCLE_CEILING,
    MONTHLY_CEILING,
    InfracostRunner,
    build_infracost_arguments,
    parse_infracost_output,
    validate_terraform_plan_json,
)
from tools.platformctl.lifecycle_models import CostResult, Outcome
from tools.platformctl.terraform_runner import (
    CommandRunner,
    ProcessResult,
    TerraformRunner,
)


def test_cycle_budget_authority_reaches_cost_producer_and_validator() -> None:
    from dataclasses import replace

    from tools.platformctl.cost import diagnostic_exposure_totals, validate_cost_result_v2

    from tests.fakes.platform_lifecycle import (
        FrozenClock,
        lifecycle_amendment_fixture,
        reviewed_package_fixture,
    )

    package, _, reader, _ = reviewed_package_fixture()
    cost, digest = lifecycle_amendment_fixture(package.cost, reader)
    context = {
        "reader": reader,
        "state_lineage": "7465ed2e-a39c-afdd-f172-5792d3ec2f85",
        "configuration_sha256": digest,
    }
    cost = replace(cost, incurred_usd="10.00")
    amounts = diagnostic_exposure_totals(cost, now=FrozenClock().now(), **context)
    assert amounts["lifecycle_ceiling_usd"] == "30.00"
    cost = replace(cost, headroom_usd=amounts["headroom_usd"])
    validate_cost_result_v2(cost, package.artifact.sha256, FrozenClock().now(), **context)
    with pytest.raises(ContractError):
        validate_cost_result_v2(
            replace(cost, lifecycle_amendment=None),
            package.artifact.sha256,
            FrozenClock().now(),
            **context,
        )
    with pytest.raises(ContractError):
        validate_cost_result_v2(
            replace(cost, incurred_usd="30.01"),
            package.artifact.sha256,
            FrozenClock().now(),
            **context,
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("cycle_id", "W5-CYCLE-B"),
        ("cycle_status", "CLOSED"),
        ("platform_lineage", "different"),
        ("operation_id", "different"),
        ("lifecycle_ceiling_usd", "300.00"),
        ("accounting_scope", "ADDITIONAL_ALLOWANCE"),
        ("configuration_sha256", "b" * 64),
        ("account_id", "111111111111"),
        ("valid_until", "2026-09-07T00:00:00Z"),
    ],
)
def test_cycle_budget_authority_rejects_forgery_and_reuse(field, value) -> None:
    from dataclasses import replace
    from hashlib import sha256

    from tools.platformctl.cost import validate_cost_result_v2
    from tools.platformctl.lifecycle_io import canonical_json_bytes, decode_operational_record
    from tools.platformctl.lifecycle_models import LifecycleBudgetAuthority

    from tests.fakes.platform_lifecycle import (
        FrozenClock,
        lifecycle_amendment_fixture,
        reviewed_package_fixture,
    )

    package, _, reader, _ = reviewed_package_fixture()
    cost, digest = lifecycle_amendment_fixture(package.cost, reader)
    ref = cost.lifecycle_amendment
    assert ref is not None
    authority = decode_operational_record(reader.payloads[ref.path], LifecycleBudgetAuthority)
    raw = canonical_json_bytes(replace(authority, **{field: value}))
    reader.payloads[ref.path] = raw
    cost = replace(
        cost, lifecycle_amendment=replace(ref, sha256=sha256(raw).hexdigest(), byte_count=len(raw))
    )
    with pytest.raises(ContractError):
        validate_cost_result_v2(
            cost,
            package.artifact.sha256,
            FrozenClock().now(),
            reader=reader,
            state_lineage="7465ed2e-a39c-afdd-f172-5792d3ec2f85",
            configuration_sha256=digest,
        )


def test_cycle_bound_monthly_exception_keeps_lifecycle_binding() -> None:
    from dataclasses import replace

    from tools.platformctl.cost import diagnostic_exposure_totals, validate_cost_result_v2

    from tests.fakes.platform_lifecycle import (
        FrozenClock,
        monthly_amendment_fixture,
        reviewed_package_fixture,
    )

    package, _, reader, _ = reviewed_package_fixture()
    expensive = replace(
        package.cost,
        coverage=(replace(package.cost.coverage[0], monthly_usd="195.184"),),
    )
    with pytest.raises(ContractError, match="COST_CEILING_EXCEEDED"):
        validate_cost_result_v2(expensive, package.artifact.sha256, FrozenClock().now())
    approved, configuration_hash = monthly_amendment_fixture(expensive, reader)
    context = {
        "reader": reader,
        "state_lineage": "7465ed2e-a39c-afdd-f172-5792d3ec2f85",
        "configuration_sha256": configuration_hash,
    }
    validate_cost_result_v2(approved, package.artifact.sha256, FrozenClock().now(), **context)
    with pytest.raises(ContractError, match="MONTHLY_AMENDMENT_AUTHORITY_REQUIRED"):
        validate_cost_result_v2(approved, package.artifact.sha256, FrozenClock().now())
    too_much = replace(approved, incurred_usd="3.01")
    with pytest.raises(ContractError, match="COST_CEILING_EXCEEDED"):
        validate_cost_result_v2(too_much, package.artifact.sha256, FrozenClock().now(), **context)
    assert diagnostic_exposure_totals(too_much)["replacement_ceiling_review_required"] is True
    missing = replace(approved, incurred_usd=None)
    assert diagnostic_exposure_totals(missing)["supported_total_usd"] is None
    assert diagnostic_exposure_totals(missing)["headroom_usd"] is None


@pytest.mark.parametrize(
    "field,value",
    [
        ("cycle_id", "W5-CYCLE-B"),
        ("cycle_status", "CLOSED"),
        ("account_id", "111111111111"),
        ("region", "us-east-1"),
        ("environment", "production"),
        ("operation_id", "different-operation"),
        ("platform_lineage", "different-state"),
        ("configuration_sha256", "b" * 64),
        ("valid_until", "2026-09-07T23:59:00Z"),
        ("approver", "another-owner"),
    ],
)
def test_monthly_amendment_drift_fails_closed(field: str, value: str) -> None:
    from dataclasses import replace
    from hashlib import sha256

    from tools.platformctl.cost import validate_cost_result_v2
    from tools.platformctl.lifecycle_io import canonical_json_bytes, decode_operational_record
    from tools.platformctl.lifecycle_models import MonthlyAmendmentAuthority

    from tests.fakes.platform_lifecycle import (
        FrozenClock,
        monthly_amendment_fixture,
        reviewed_package_fixture,
    )

    package, _, reader, _ = reviewed_package_fixture()
    cost, digest = monthly_amendment_fixture(package.cost, reader)
    reference = cost.monthly_amendment
    assert reference is not None
    authority = decode_operational_record(
        reader.payloads[reference.path],
        MonthlyAmendmentAuthority,
    )
    raw = canonical_json_bytes(replace(authority, **{field: value}))
    reader.payloads[reference.path] = raw
    cost = replace(
        cost,
        monthly_amendment=replace(reference, sha256=sha256(raw).hexdigest(), byte_count=len(raw)),
    )
    with pytest.raises(ContractError):
        validate_cost_result_v2(
            cost,
            package.artifact.sha256,
            FrozenClock().now(),
            reader=reader,
            state_lineage="7465ed2e-a39c-afdd-f172-5792d3ec2f85",
            configuration_sha256=digest,
        )


def test_legacy_cost_record_cannot_activate_monthly_exception() -> None:
    from dataclasses import asdict

    from tools.platformctl.lifecycle_io import canonical_json_bytes, decode_operational_record
    from tools.platformctl.lifecycle_models import CostResultV2

    from tests.fakes.platform_lifecycle import reviewed_package_fixture

    package, _, _, _ = reviewed_package_fixture()
    legacy = asdict(package.cost)
    legacy.pop("monthly_amendment")
    decoded = decode_operational_record(canonical_json_bytes(legacy), CostResultV2)
    assert decoded.monthly_amendment is None
    legacy["monthly_informational"] = True
    with pytest.raises(ContractError):
        decode_operational_record(canonical_json_bytes(legacy), CostResultV2)


@pytest.mark.parametrize("maximum_requests", [6, 7, True])
def test_diagnostic_query_allowance_requires_exact_source_bound_limit(
    maximum_requests: int,
) -> None:
    from dataclasses import replace
    from decimal import Decimal
    from hashlib import sha256

    from tools.platformctl.cost import diagnostic_query_exposure
    from tools.platformctl.lifecycle_io import canonical_json_bytes
    from tools.platformctl.lifecycle_models import (
        DIAGNOSTIC_SCHEMA_VERSION,
        DiagnosticQueryCostBasis,
    )

    from tests.fakes.platform_lifecycle import FrozenClock, reviewed_package_fixture

    package, _, reader, _ = reviewed_package_fixture()
    source_bytes = b"synthetic owner-reviewed query price source"
    source = replace(
        package.cost.raw_estimate,
        kind="query-price-source",
        path="query-source.txt",
        sha256=sha256(source_bytes).hexdigest(),
        byte_count=len(source_bytes),
    )
    reader.payloads[source.path] = source_bytes
    basis = DiagnosticQueryCostBasis(
        DIAGNOSTIC_SCHEMA_VERSION,
        package.operation_id,
        package.account_id,
        "0.01",
        maximum_requests,
        source,
        "https://aws.amazon.com/aws-cost-management/aws-cost-explorer/pricing/",
        "Gyan-Prakash-Rai",
        package.cost.observed_at,
        package.cost.valid_until,
    )
    raw = canonical_json_bytes(basis)
    reference = replace(
        source,
        kind="diagnostic-query-cost-basis",
        path="query-basis.json",
        sha256=sha256(raw).hexdigest(),
        byte_count=len(raw),
    )
    reader.payloads[reference.path] = raw
    if type(maximum_requests) is int and maximum_requests == 6:
        assert diagnostic_query_exposure(
            reference, reader, FrozenClock().now(), package.operation_id
        ) == Decimal("0.06")
    else:
        with pytest.raises(ContractError):
            diagnostic_query_exposure(reference, reader, FrozenClock().now(), package.operation_id)


def test_retained_pricing_does_not_become_current_spending_or_complete_coverage() -> None:
    from tools.platformctl.cost import diagnostic_pricing_summary
    from tools.platformctl.lifecycle_io import canonical_json_bytes

    raw = {
        "schema_version": "w5-004.pricing-breakdown-diagnostic.v1",
        "currency": "USD",
        "estimated_monthly_usd": "195.184",
        "recorded_cost_status": "FAIL",
        "counts": {
            "totalDetectedResources": 2,
            "totalSupportedResources": 1,
            "totalUnsupportedResources": 0,
            "totalUsageBasedResources": 1,
            "totalNoPriceResources": 1,
        },
        "resources": [
            {
                "address": "aws_s3_bucket.fixture",
                "resource_type": "aws_s3_bucket",
                "monthly_cost_usd": None,
                "components": [
                    {
                        "component_id": 1,
                        "unit": "GB",
                        "unit_price_usd": "0.025",
                        "usage_based": True,
                    }
                ],
            }
        ],
    }
    result = diagnostic_pricing_summary(
        canonical_json_bytes(raw),
        {"aws_s3_bucket.fixture": "aws_s3_bucket"},
    )
    assert result["recorded_cost_status"] == "FAIL"
    assert result["actual_spending"] == "NOT_ESTABLISHED"
    assert result["coverage"] == "INDETERMINATE"
    assert result["known_sum_matches_projection"] is False
    raw["counts"]["totalSupportedResources"] = 0
    with pytest.raises(ContractError):
        diagnostic_pricing_summary(
            canonical_json_bytes(raw),
            {"aws_s3_bucket.fixture": "aws_s3_bucket"},
        )


def test_existing_billable_resource_cannot_claim_zero_incurred_exposure() -> None:
    from dataclasses import replace

    from tools.platformctl.cost import reconcile_incurred_coverage

    from tests.fakes.platform_lifecycle import reviewed_package_fixture

    package, _, reader, _ = reviewed_package_fixture()
    present = replace(
        package.native,
        entries=(
            replace(
                package.native.entries[0],
                presence="PRESENT",
            ),
        ),
    )
    with pytest.raises(ContractError, match="INCURRED_OR_BILLING_LAG"):
        reconcile_incurred_coverage(package.cost, present, "platform", reader)
    reconcile_incurred_coverage(package.cost, package.native, "platform", reader)


def test_nested_infracost_components_are_not_silently_omitted() -> None:
    from tools.platformctl.cost import _resource_charging_components

    root_component = {"name": "node", "price": "1", "unit": "hours"}
    child_component = {"name": "storage", "price": "2", "unit": "GB"}
    resource = {
        "costComponents": [root_component],
        "subresources": [{"name": "volume", "costComponents": [child_component]}],
    }
    components = _resource_charging_components(resource)
    assert len(components) == 2
    assert root_component in components.values()
    assert child_component in components.values()
    resource["subresources"].append(resource["subresources"][0])
    with pytest.raises(ContractError, match="DUPLICATE"):
        _resource_charging_components(resource)


def test_incurred_coverage_accounts_for_billing_lag_without_double_counting() -> None:
    from dataclasses import replace
    from hashlib import sha256

    from tools.platformctl.cost import reconcile_incurred_coverage
    from tools.platformctl.lifecycle_io import canonical_json_bytes, decode_operational_record
    from tools.platformctl.lifecycle_models import ExposureBasis, ExposureComponent

    from tests.fakes.platform_lifecycle import reviewed_package_fixture

    package, _, reader, _ = reviewed_package_fixture()
    reference = next(
        item for item in package.cost.assumptions if item.kind == "lifecycle-exposure-basis"
    )
    basis = decode_operational_record(reader.payloads[reference.path], ExposureBasis)
    component = ExposureComponent(
        "platform",
        package.summary[0].address,
        "INCURRED",
        "2026-09-07T23:55:00Z",
        "2026-09-08T00:00:00Z",
        "0.05",
        reference,
    )
    basis = replace(
        basis,
        components=(component,),
        billing_lag_seconds=300,
        zero_categories=("RECOVERY_ONE_OFF", "TEARDOWN_RETENTION"),
    )
    encoded = canonical_json_bytes(basis)
    reader.payloads["new-exposure.json"] = encoded
    updated_ref = replace(
        reference,
        path="new-exposure.json",
        sha256=sha256(encoded).hexdigest(),
        byte_count=len(encoded),
    )
    result = replace(
        package.cost,
        incurred_usd="0.05",
        headroom_usd="2.80",
        billing_lag_seconds=300,
        assumptions=tuple(
            updated_ref if item == reference else item for item in package.cost.assumptions
        ),
    )
    native = replace(
        package.native, entries=(replace(package.native.entries[0], presence="PRESENT"),)
    )
    reconcile_incurred_coverage(result, native, "platform", reader)
    with pytest.raises(ContractError, match="BILLING_LAG"):
        reconcile_incurred_coverage(
            replace(result, billing_lag_seconds=301), native, "platform", reader
        )


def summary(
    *,
    detected: int = 1,
    supported: int = 1,
    unsupported: int = 0,
    usage_based: int = 0,
    no_price: int = 0,
) -> dict[str, int]:
    return {
        "totalDetectedResources": detected,
        "totalSupportedResources": supported,
        "totalUnsupportedResources": unsupported,
        "totalUsageBasedResources": usage_based,
        "totalNoPriceResources": no_price,
    }


def estimate(
    total: str | None,
    *,
    metadata: dict[str, object] | None = None,
    result_summary: dict[str, int] | None = None,
    project_summary: dict[str, int] | None = None,
) -> dict[str, object]:
    return {
        "currency": "USD",
        "totalMonthlyCost": total,
        "summary": result_summary or summary(),
        "projects": [
            {
                "metadata": metadata or {"usageBased": False},
                "summary": project_summary or summary(),
                "breakdown": {
                    "resources": [{"name": "approved-resource"}],
                    "totalMonthlyCost": total,
                },
            }
        ],
    }


def terraform_plan_json() -> bytes:
    return json.dumps(
        {
            "configuration": {"root_module": {}},
            "format_version": "1.2",
            "planned_values": {"root_module": {}},
            "resource_changes": [],
            "terraform_version": "1.16.1",
        }
    ).encode()


def test_monthly_estimate_without_duration_and_incurred_exposure_is_indeterminate() -> None:
    result = parse_infracost_output(estimate("2.50"))
    assert result.status is Outcome.INDETERMINATE
    assert result.estimated_lifecycle_cost is None
    assert result.lifecycle_ceiling == LIFECYCLE_CEILING
    assert result.monthly_ceiling == MONTHLY_CEILING


def test_estimate_above_monthly_and_lifecycle_ceiling_fails() -> None:
    result = parse_infracost_output(estimate("100.00"))
    assert result.status is Outcome.FAIL


def test_usage_based_or_missing_amount_is_indeterminate() -> None:
    result = parse_infracost_output(
        estimate(
            None,
            metadata={"usageBased": True},
            result_summary=summary(usage_based=1),
            project_summary=summary(usage_based=1),
        )
    )
    assert result.status is Outcome.INDETERMINATE


def test_inconsistent_project_total_is_indeterminate() -> None:
    value = estimate("2.00")
    project = cast(list[dict[str, object]], value["projects"])[0]
    breakdown = cast(dict[str, object], project["breakdown"])
    breakdown["totalMonthlyCost"] = "1.00"
    result = parse_infracost_output(value)
    assert result.status is Outcome.INDETERMINATE


def test_embedded_infracost_project_error_fails_closed() -> None:
    with pytest.raises(ContractError, match="estimation error"):
        parse_infracost_output(
            estimate(
                "0",
                metadata={
                    "type": "error",
                    "errors": [{"code": 106}],
                },
                result_summary=summary(detected=0, supported=0),
                project_summary=summary(detected=0, supported=0),
            )
        )


@pytest.mark.parametrize(
    "incomplete_summary",
    [
        summary(detected=0, supported=0),
        summary(detected=1, supported=0),
        summary(unsupported=1),
        summary(no_price=1),
        summary(usage_based=1),
    ],
)
def test_incomplete_infracost_coverage_cannot_pass(
    incomplete_summary: dict[str, int],
) -> None:
    result = parse_infracost_output(
        estimate(
            "0",
            result_summary=incomplete_summary,
            project_summary=incomplete_summary,
        )
    )
    assert result.status is Outcome.INDETERMINATE


def test_only_genuine_terraform_show_json_is_accepted() -> None:
    validate_terraform_plan_json(terraform_plan_json())
    with pytest.raises(ContractError, match="Terraform show JSON"):
        validate_terraform_plan_json(
            json.dumps(
                {
                    "evaluation_context": {},
                    "format_version": "1.2",
                    "resource_changes": [],
                    "terraform_version": "1.16.1",
                }
            ).encode()
        )


def test_infracost_command_uses_local_files_and_has_no_upload_mode() -> None:
    arguments = build_infracost_arguments(
        Path("plan.json"),
        Path("cost.json"),
    )
    assert "--path" in arguments
    assert "upload" not in arguments
    assert "dashboard" not in " ".join(arguments)


class SavedPlanReader:
    def __init__(self, raw: bytes) -> None:
        self.raw = raw

    def show_plan_json(self, terraform_root: Path, saved_plan: Path) -> bytes:
        del terraform_root, saved_plan
        return self.raw


class CostOutputRunner:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail

    def run(
        self,
        arguments: tuple[str, ...],
        *,
        cwd: Path,
        environment: dict[str, str],
        timeout_seconds: int,
    ) -> ProcessResult:
        del cwd, environment, timeout_seconds
        if "--version" in arguments:
            return ProcessResult(0, "Infracost v0.10.45\n", "")
        if self.fail:
            return ProcessResult(1, "", "sanitized failure")
        output = Path(arguments[arguments.index("--out-file") + 1])
        output.write_text(json.dumps(estimate("2.50")), encoding="utf-8")
        return ProcessResult(0, "", "")


@pytest.mark.parametrize("runner_fails", [False, True])
def test_saved_plan_estimate_removes_transient_json(
    tmp_path: Path,
    runner_fails: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    terraform_root = repository / "infra" / "environments" / "sandbox"
    terraform_root.mkdir(parents=True)
    external = tmp_path / "external"
    from tools.platformctl.lifecycle_io import reserve_operation_directory

    reserve_operation_directory(external, external, repository)
    saved_plan = external / "platform.tfplan"
    saved_plan.write_bytes(b"immutable plan")
    transient = external / "transient-plan.json"
    output = external / "infracost.json"
    runner = CostOutputRunner(fail=runner_fails)
    cost_runner = InfracostRunner(
        runner=cast(CommandRunner, runner),
        repository_root=repository,
        external_root=external,
    )
    from tools.platformctl import cost as cost_module

    fake_executable = external / "infracost.exe"
    fake_executable.write_bytes(b"fake executable not executed")
    monkeypatch.setattr(cost_module, "INFRACOST_EXECUTABLE", fake_executable)
    monkeypatch.setattr(
        cost_module, "INFRACOST_EXECUTABLE_SHA256", cost_module.sha256_file(fake_executable)
    )

    def action() -> CostResult:
        return cost_runner.estimate_saved_plan(
            terraform_runner=cast(TerraformRunner, SavedPlanReader(terraform_plan_json())),
            terraform_root=terraform_root,
            saved_plan=saved_plan,
            expected_saved_plan_sha256=(
                "ad41e7f236f51d495e13ae0ed6b1fe0f6ef70d213af018bb54186687a6b53ee5"
            ),
            transient_plan_json=transient,
            output_json=output,
            environment={"INFRACOST_API_KEY": "-".join(("test", "value")), "PATH": "test-path"},
        )

    if runner_fails:
        with pytest.raises(ContractError, match="estimate failed"):
            action()
    else:
        assert action().status is Outcome.INDETERMINATE
    assert not transient.exists()
    assert str(fake_executable) in build_infracost_arguments(transient, output)


def test_v2_cost_headroom_requires_all_exposure_components() -> None:
    from dataclasses import replace

    from tools.platformctl.cost import validate_cost_result_v2

    from tests.fakes.platform_lifecycle import FrozenClock, reviewed_package_fixture

    package, _, _, _ = reviewed_package_fixture()
    validate_cost_result_v2(package.cost, package.artifact.sha256, FrozenClock().now())
    for field in ("incurred_usd", "recovery_usd", "teardown_retention_usd", "headroom_usd"):
        with pytest.raises(ContractError):
            validate_cost_result_v2(
                replace(package.cost, **{field: None}), package.artifact.sha256, FrozenClock().now()
            )


def test_known_monthly_overrun_is_not_downgraded_by_incomplete_coverage() -> None:
    value = estimate("61.00")
    value["summary"]["totalUnsupportedResources"] = 1
    assert parse_infracost_output(value).status is Outcome.FAIL


def test_charging_basis_recomputes_units_and_rejects_relabelled_window() -> None:
    from dataclasses import replace

    from tools.platformctl.cost import reconcile_charging_bases

    from tests.fakes.platform_lifecycle import FrozenClock, reviewed_package_fixture

    package, _, reader, _ = reviewed_package_fixture()
    reconcile_charging_bases(package.cost, reader, FrozenClock().now())
    for altered in (
        replace(package.cost.coverage[0], remaining_usd="0.00"),
        replace(package.cost.coverage[0], duration_seconds=120),
        replace(package.cost.coverage[0], units="hours"),
    ):
        with pytest.raises(ContractError):
            reconcile_charging_bases(
                replace(package.cost, coverage=(altered,)), reader, FrozenClock().now()
            )


@pytest.mark.parametrize("location", ["root", "project", "metadata"])
def test_embedded_errors_never_establish_cost_coverage(location: str) -> None:
    value = estimate("0.00")
    target = value if location == "root" else value["projects"][0]
    if location == "metadata":
        target = target["metadata"]
    target["errors"] = [{"code": 106}]
    with pytest.raises(ContractError, match="estimation error"):
        parse_infracost_output(value)


def test_other_scope_inventory_cannot_be_omitted_or_double_counted() -> None:
    from dataclasses import replace

    from tools.platformctl.cost import reconcile_cost_inventory

    from tests.fakes.platform_lifecycle import FrozenClock, reviewed_package_fixture

    package, _, reader, _ = reviewed_package_fixture()
    reconcile_cost_inventory(package.cost, "platform", reader, FrozenClock().now())
    without_proof = replace(
        package.cost,
        assumptions=tuple(
            reference
            for reference in package.cost.assumptions
            if reference.kind != "current-bootstrap-inventory"
        ),
    )
    with pytest.raises(ContractError, match="INVENTORY_REQUIRED"):
        reconcile_cost_inventory(without_proof, "platform", reader, FrozenClock().now())
    extra = replace(package.cost.coverage[0], scope="bootstrap")
    with pytest.raises(ContractError, match="COVERAGE_MISMATCH"):
        reconcile_cost_inventory(
            replace(package.cost, coverage=(*package.cost.coverage, extra)),
            "platform",
            reader,
            FrozenClock().now(),
        )


def test_destroy_cost_shape_does_not_fabricate_a_zero_cost_apply_plan() -> None:
    from tools.platformctl.cost import _validate_cleanup_plan

    value = json.loads(terraform_plan_json())
    value["resource_changes"] = [
        {
            "address": "aws_s3_bucket.fixture",
            "type": "aws_s3_bucket",
            "change": {"actions": ["delete"], "before": {}, "after": None},
        }
    ]
    assert _validate_cleanup_plan(json.dumps(value).encode()) == {"aws_s3_bucket.fixture"}
    for actions in (["create"], ["update"], ["delete", "create"]):
        value["resource_changes"][0]["change"]["actions"] = actions
        with pytest.raises(ContractError, match="NOT_DESTRUCTIVE"):
            _validate_cleanup_plan(json.dumps(value).encode())


@pytest.mark.parametrize(
    "environment",
    [
        {"PATH": "first", "path": "second"},
        {"TEMP": "invalid\x00path"},
        {"INFRACOST_API_KEY": "\n".join(("synthetic", "value"))},
        {"INFRACOST_SKIP_UPDATE_CHECK": "false"},
        {"INFRACOST_PRICING_API_ENDPOINT": "https://example.invalid"},
        {"INFRACOST_ENABLE_CLOUD_UPLOAD": "true"},
        {"HOME": "unapproved-home"},
    ],
)
def test_cost_launch_rejects_ambient_or_ambiguous_settings(environment: dict[str, str]) -> None:
    from tools.platformctl.cost import validate_infracost_environment

    with pytest.raises(ContractError):
        validate_infracost_environment(environment, require_api_key=False)


def test_cost_version_never_passes_process_pricing_key_to_runner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from collections.abc import Mapping, Sequence

    from tools.platformctl import cost as cost_module

    observed: list[dict[str, str]] = []

    class VersionRunner:
        def run(
            self,
            arguments: Sequence[str],
            *,
            cwd: Path,
            environment: Mapping[str, str],
            timeout_seconds: int,
        ) -> ProcessResult:
            assert tuple(arguments[1:]) == ("--version",)
            observed.append(dict(environment))
            return ProcessResult(0, "Infracost v0.10.45\n", "")

    monkeypatch.setattr(
        cost_module, "sha256_file", lambda _: cost_module.INFRACOST_EXECUTABLE_SHA256
    )
    runner = InfracostRunner(
        runner=VersionRunner(), repository_root=tmp_path, external_root=tmp_path / "external"
    )
    runner.verify_version({"infracost_api_key": "-".join(("synthetic", "value")), "PATH": "tools"})
    assert observed == [{"PATH": "tools"}]


@pytest.mark.parametrize("legacy_entry", [False, True])
@pytest.mark.parametrize(
    "scenario",
    [
        "success",
        "partial_failure",
        "malformed",
        "embedded_error",
        "zero",
        "credential",
        "cleanup_failure",
    ],
)
def test_compatibility_output_is_private_cleaned_and_not_operational_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scenario: str, legacy_entry: bool
) -> None:
    from collections.abc import Mapping, Sequence

    from tools.platformctl import cost as cost_module
    from tools.platformctl.lifecycle_io import reserve_operation_directory, sha256_file

    repository = tmp_path / "repository"
    repository.mkdir()
    external = tmp_path / "external"
    reserve_operation_directory(external, external, repository)
    saved = external / "plan.tfplan"
    saved.write_bytes(b"synthetic immutable plan")
    transient = external / "plan.transient.json"
    report = external / "compatibility.json"
    raw_output = external / "compatibility.json.raw-transient"
    if scenario == "cleanup_failure":
        original_unlink = Path.unlink

        def deny_raw_cleanup(path: Path, missing_ok: bool = False) -> None:
            if path == raw_output:
                raise OSError("synthetic cleanup failure")
            original_unlink(path, missing_ok=missing_ok)

        monkeypatch.setattr(Path, "unlink", deny_raw_cleanup)
    marker = "-".join(("private", "fixture", "metadata"))
    credential = "-".join(("owner", "fixture", "key"))
    observed: list[Path] = []

    class OutputRunner:
        def run(
            self,
            arguments: Sequence[str],
            *,
            cwd: Path,
            environment: Mapping[str, str],
            timeout_seconds: int,
        ) -> ProcessResult:
            if "--version" in arguments:
                assert "INFRACOST_API_KEY" not in environment
                return ProcessResult(0, "Infracost v0.10.45\n", "")
            target = Path(arguments[arguments.index("--out-file") + 1])
            assert target == raw_output
            assert target.is_file() and target.read_bytes() == b""
            assert transient.is_file()
            observed.append(target)
            value = estimate("2.50", metadata={"description": marker})
            if scenario == "embedded_error":
                value["projects"][0]["metadata"]["type"] = "error"
            elif scenario == "zero":
                value = estimate("0", result_summary=summary(detected=0, supported=0))
            elif scenario == "credential":
                value["projects"][0]["metadata"]["description"] = credential
            target.write_text(
                "{" if scenario in {"malformed", "partial_failure"} else json.dumps(value),
                encoding="utf-8",
            )
            return ProcessResult(1 if scenario == "partial_failure" else 0, "", "")

    fake_executable = external / "infracost.exe"
    fake_executable.write_bytes(b"not executable")
    monkeypatch.setattr(cost_module, "INFRACOST_EXECUTABLE", fake_executable)
    monkeypatch.setattr(cost_module, "INFRACOST_EXECUTABLE_SHA256", sha256_file(fake_executable))
    adapter = InfracostRunner(
        runner=OutputRunner(), repository_root=repository, external_root=external
    )

    def invoke() -> CostResult:
        operation = (
            adapter.estimate_saved_plan
            if legacy_entry
            else adapter.estimate_saved_plan_compatibility
        )
        result = operation(
            terraform_runner=cast(TerraformRunner, SavedPlanReader(terraform_plan_json())),
            terraform_root=repository,
            saved_plan=saved,
            expected_saved_plan_sha256=sha256_file(saved),
            transient_plan_json=transient,
            output_json=report,
            environment={"INFRACOST_API_KEY": credential},
        )
        assert isinstance(result, CostResult)
        return result

    if scenario == "success":
        result = invoke()
        assert result.status is Outcome.INDETERMINATE
        text = report.read_text(encoding="utf-8")
        assert marker not in text and credential not in text
        value = json.loads(text)
        assert value["schema_version"] == "w5-004.cost-compatibility.v1"
        assert value["cost_approval"] == "NOT_ESTABLISHED"
        assert value["recovery_eligibility"] == "NOT_ESTABLISHED"
        assert value["saved_plan_sha256"] == sha256_file(saved)
        preserved = report.read_bytes()
        with pytest.raises(ContractError, match="OUTPUT_EXISTS"):
            invoke()
        assert report.read_bytes() == preserved
    else:
        with pytest.raises(ContractError):
            invoke()
        assert not report.exists()
    assert len(observed) == 1
    assert not transient.exists()
    assert raw_output.exists() is (scenario == "cleanup_failure")
    assert saved.read_bytes() == b"synthetic immutable plan"


def test_resolution_ledger_account_reservation_is_not_project_actual_or_headroom():
    from datetime import UTC, datetime, timedelta

    from tools.platformctl.cost import resolution_cost_ledger

    days = [
        {
            "start": (datetime(2026, 9, 8) + timedelta(days=i)).date().isoformat(),
            "end": (datetime(2026, 9, 9) + timedelta(days=i)).date().isoformat(),
            "amounts": [{"group": ["VPC", "endpoint-hour"], "unblended_usd": "2.00"}],
        }
        for i in range(5)
    ]
    data = {
        "complete": True,
        "start_inclusive": "2026-09-08",
        "end_exclusive": "2026-09-13",
        "days": days,
    }
    result = resolution_cost_ledger(data, datetime(2026, 9, 13, 5, tzinfo=UTC), 3)
    assert result.reported_account_usd == "10.00"
    assert (
        result.attributable_incurred_usd
        is result.available_headroom_usd
        is result.supported_upper_bound_usd
        is None
    )
    assert result.total_cycle_ceiling_usd == "30.00"
    assert result.execution_cost_approval == "NOT_ESTABLISHED"
    assert len(result.entries) == 5
    assert result.entries[0].end == result.entries[1].start
    assert result.entries[1].end == result.entries[2].start
    days[1]["start"] = days[0]["start"]
    with pytest.raises(ContractError):
        resolution_cost_ledger(data, datetime(2026, 9, 13, tzinfo=UTC), 3)


@pytest.mark.parametrize(
    ("cycle", "requests"), [("W5-CYCLE-B", 1), ("W5-CYCLE-A", 4), ("W5-CYCLE-A", True)]
)
def test_resolution_ledger_rejects_wrong_authority(cycle, requests):
    from datetime import UTC, datetime

    from tools.platformctl.cost import resolution_cost_ledger

    with pytest.raises(ContractError):
        resolution_cost_ledger({}, datetime(2026, 9, 13, tzinfo=UTC), requests, cycle=cycle)


def test_resolution_ledger_unknown_and_credits_never_prove_a_bound():
    from datetime import UTC, datetime

    from tools.platformctl.cost import resolution_cost_ledger

    result = resolution_cost_ledger({}, datetime(2026, 9, 13, tzinfo=UTC), 0)
    assert result.reported_account_usd is None
    assert all(entry.upper_bound_usd is None for entry in result.entries)


@pytest.mark.parametrize(
    "change", ["none", "cycle", "unknown", "overlap", "minima", "lag", "total", "expired"]
)
def test_prerequisite_cost_bound_requires_nonoverlapping_supported_basis(change):
    from dataclasses import replace
    from datetime import UTC, datetime
    from decimal import Decimal
    from hashlib import sha256

    from tools.platformctl.cost import validate_prerequisite_cost_bound
    from tools.platformctl.lifecycle_io import canonical_json_bytes
    from tools.platformctl.lifecycle_models import (
        CycleCostBoundBasis,
        EvidenceRef,
        ResolutionLedgerEntry,
    )

    from tests.fakes.platform_lifecycle import MemoryEvidenceReader

    reader = MemoryEvidenceReader()
    reference = EvidenceRef(
        "owner-reviewed-cost-evidence",
        "basis.json",
        sha256(b"{}").hexdigest(),
        2,
        "owner",
        "2026-09-13T00:00:00Z",
        "2026-09-22T00:00:00Z",
        "test",
    )
    reader.payloads[reference.path] = b"{}"
    cutoff, deadline = "2026-09-13T00:00:00Z", "2026-09-14T12:00:00Z"
    rows = (
        ResolutionLedgerEntry(
            "HISTORICAL_ACCOUNT_RESERVATION",
            "2026-09-08T00:00:00Z",
            cutoff,
            "ACCOUNT_NOT_PROJECT_ACTUAL",
            reference.path,
            None,
            "15",
            "",
        ),
        ResolutionLedgerEntry(
            "POST_CUTOFF_FIXED", cutoff, deadline, "W5_CYCLE_A", reference.path, None, "10", ""
        ),
        ResolutionLedgerEntry(
            "POST_CUTOFF_VARIABLE_AND_DIAGNOSTICS",
            cutoff,
            deadline,
            "W5_CYCLE_A",
            reference.path,
            None,
            "2",
            "",
        ),
        ResolutionLedgerEntry(
            "RETAINED_TAIL",
            deadline,
            "2026-09-21T12:00:00Z",
            "W5_CYCLE_A",
            reference.path,
            None,
            "3",
            "",
        ),
    )
    basis = CycleCostBoundBasis(
        "w5-004.lifecycle.v2",
        "W5-CYCLE-A",
        "USD",
        rows,
        (reference,),
        reference,
        True,
        True,
        cutoff,
    )
    if change == "cycle":
        basis = replace(basis, cycle="W5-CYCLE-B")
    elif change == "unknown":
        basis = replace(basis, entries=(replace(rows[0], upper_bound_usd=None), *rows[1:]))
    elif change == "overlap":
        basis = replace(basis, entries=(replace(rows[0], end=deadline), *rows[1:]))
    elif change == "minima":
        basis = replace(basis, charging_minima_verified=False)
    elif change == "lag":
        basis = replace(basis, billing_lag_bounded=False)
    elif change == "expired":
        basis = replace(basis, sources=(replace(reference, valid_until=cutoff),))
    total = Decimal("31" if change == "total" else "30")
    # Even the formerly positive case contains only flags and an empty source object.
    with pytest.raises(ContractError):
        validate_prerequisite_cost_bound(
            canonical_json_bytes(basis), total, datetime(2026, 9, 13, 10, tzinfo=UTC), reader
        )


def charging_fixture():
    from datetime import UTC, datetime
    from hashlib import sha256

    from tools.platformctl.lifecycle_io import canonical_json_bytes
    from tools.platformctl.lifecycle_models import CycleCharge, CycleChargingEvidence, EvidenceRef

    from tests.fakes.platform_lifecycle import MemoryEvidenceReader

    reader = MemoryEvidenceReader()

    def store(name, data):
        raw = canonical_json_bytes(data)
        reader.payloads[name] = raw
        return EvidenceRef(
            "verified-charging-evidence",
            name,
            sha256(raw).hexdigest(),
            len(raw),
            "fixture",
            "2026-09-13T00:00:00Z",
            "2026-09-22T00:00:00Z",
            "fixture",
        )

    components = []
    for index, (category, start, end, q) in enumerate(
        (
            (
                "HISTORICAL_ACCOUNT_RESERVATION",
                "2026-09-08T00:00:00Z",
                "2026-09-13T00:00:00Z",
                "15",
            ),
            ("POST_CUTOFF_FIXED", "2026-09-13T00:00:00Z", "2026-09-14T12:00:00Z", "10"),
            (
                "POST_CUTOFF_VARIABLE_AND_DIAGNOSTICS",
                "2026-09-13T00:00:00Z",
                "2026-09-14T12:00:00Z",
                "2",
            ),
            ("RETAINED_TAIL", "2026-09-14T12:00:00Z", "2026-09-21T12:00:00Z", "3"),
        )
    ):
        identifier = f"charge-{index}"
        rate = store(
            f"rate-{index}.json",
            {
                "component_id": identifier,
                "unit": "USD",
                "rate_usd": "1",
                "charge_basis": identifier,
                "quantum": "1",
                "minimum": "0",
                "cycle": "W5-CYCLE-A",
                "provenance": {"source": "synthetic"},
            },
        )
        quantity = store(
            f"quantity-{index}.json",
            {
                "component_id": identifier,
                "resource": "fixture",
                "quantity": q,
                "start": start,
                "end": end,
                "cycle": "W5-CYCLE-A",
                "basis": {"bounded": "synthetic"},
            },
        )
        components.append(
            CycleCharge(
                identifier,
                "fixture",
                identifier,
                category,
                start,
                end,
                "USD",
                q,
                "1",
                "1",
                "0",
                rate,
                quantity,
            )
        )
    terminal = store(
        "terminal.json", {"status": "APPROVED_FINITE_DISPOSITION", "end": "2026-09-21T12:00:00Z"}
    )
    basis = CycleChargingEvidence(
        "w5-004.lifecycle.v2",
        "W5-CYCLE-A",
        "USD",
        tuple(components),
        tuple(c.component_id for c in components),
        "2026-09-13T00:00:00Z",
        terminal,
    )
    return basis, reader, datetime(2026, 9, 13, 10, tzinfo=UTC)


@pytest.mark.parametrize(
    "change",
    [
        "none",
        "missing_rate",
        "missing_quantity",
        "wrong_cycle",
        "duplicate",
        "split",
        "nan",
        "negative",
        "boolean",
        "tampered_quantity",
        "missing_tail",
    ],
)
def test_cycle_charge_arithmetic_preserves_unknowns_and_sources(change):
    from dataclasses import replace

    from tools.platformctl.cost import calculate_cycle_charges

    basis, reader, now = charging_fixture()
    row = basis.components[0]
    if change == "wrong_cycle":
        basis = replace(basis, cycle="W5-CYCLE-B")
    elif change == "duplicate":
        basis = replace(basis, components=(*basis.components, row))
    elif change == "missing_tail":
        basis = replace(basis, terminal_disposition=None)
    elif change != "none":
        fields = {
            "missing_rate": {"rate_usd": None},
            "missing_quantity": {"quantity": None},
            "nan": {"quantity": "NaN"},
            "negative": {"quantity": "-1"},
            "boolean": {"quantity": True},
            "tampered_quantity": {"quantity": "1"},
            "split": {"charge_basis": basis.components[1].charge_basis},
        }
        basis = replace(basis, components=(replace(row, **fields[change]), *basis.components[1:]))
    if change in {"wrong_cycle", "duplicate", "split", "nan", "negative", "boolean"}:
        with pytest.raises(ContractError):
            calculate_cycle_charges(basis, reader=reader, now=now, final_requests=39)
        return
    result = calculate_cycle_charges(basis, reader=reader, now=now, final_requests=39)
    assert result["final_diagnostic_requests"] == 39
    assert result["status"] == ("PASS" if change == "none" else "INDETERMINATE")
    assert result["supported_total_bound_usd"] == ("30" if change == "none" else None)


@pytest.mark.parametrize("status", [200, 302, 403])
def test_public_charging_production_adapter_is_bounded_and_anonymous(tmp_path, monkeypatch, status):
    import http.client
    from io import BytesIO

    from tools.platformctl.cost import PUBLIC_CHARGING_PAGES, collect_public_charging_pages
    from tools.platformctl.lifecycle_io import reserve_operation_directory

    repository = tmp_path / "repo"
    repository.mkdir()
    external = tmp_path / "external"
    reserve_operation_directory(external, external, repository)
    parent = external / "consolidated-remediation-001"
    reserve_operation_directory(parent, external, repository)
    calls = []

    class Connection:
        sock = None

        def __init__(self, host, **kwargs):
            assert host in {"aws.amazon.com", "docs.aws.amazon.com"}
            assert 0 < kwargs["timeout"] <= 30
            self.host = host

        def request(self, method, path, headers):
            assert method == "GET"
            assert headers == {"Accept-Encoding": "identity"}
            calls.append("https://" + self.host + path)

        def getresponse(self):
            response = BytesIO(b"<p>Singapore: pricing may have minimum charges.</p>")
            response.status = status
            response.getheader = lambda _name, default: default
            return response

        def close(self):
            pass

    monkeypatch.setattr(http.client, "HTTPSConnection", Connection)
    collect_public_charging_pages(repository, external)
    assert calls == list(PUBLIC_CHARGING_PAGES)
    root = parent / "pricing-basis-002"
    assert {p.name for p in root.iterdir()} == {"charging-rates.json", "pricing-identity.json"}
    report = json.loads((root / "charging-rates.json").read_bytes())
    assert report["verified_rates"] == []
    assert len(report["sources"]) == 12
    if status == 302:
        assert all(row["status"] == "REDIRECT_NOT_FOLLOWED" for row in report["sources"])
    with pytest.raises(ContractError):
        collect_public_charging_pages(repository, external)
    assert len(calls) == 12


@pytest.mark.parametrize("mode", ["size", "time", "transport"])
def test_public_transport_enforces_limits_without_fallback(monkeypatch, mode):
    import http.client
    from types import SimpleNamespace

    from tools.platformctl import aws_live

    calls = []
    sizes = []
    elapsed = [0.0]

    class Connection:
        sock = None

        def __init__(self, host, **_kwargs):
            self.host = host

        def request(self, method, path, headers):
            calls.append((self.host, method, path, headers))
            if mode == "time":
                elapsed[0] = 300.0
            if mode == "transport":
                raise OSError("Synthetic private transport detail must not be reported")

        def getresponse(self):
            assert mode == "size"
            sizes.append(0)

            def read1(count):
                sizes[-1] += count
                return b"x" * count

            return SimpleNamespace(status=200, getheader=lambda _key, default: default, read1=read1)

        def close(self):
            pass

    monkeypatch.setattr(http.client, "HTTPSConnection", Connection)
    monkeypatch.setattr(aws_live, "time", SimpleNamespace(monotonic=lambda: elapsed[0]))
    rows, requests, seconds = aws_live.fetch_public_charging_pages()
    assert requests == len(calls) == len(rows) == (1 if mode == "time" else 12)
    assert seconds <= 300
    assert all("body" not in row for row in rows)
    assert "Synthetic private" not in str(rows)
    if mode == "size":
        assert sizes == [2097152] * 12
        assert all(row["status"] == "RESPONSE_LIMIT_REACHED_NOT_ACCEPTED" for row in rows)
    else:
        assert all(row["status"] == "TRANSPORT_OR_CONTENT_UNAVAILABLE" for row in rows)


def test_cycle_cost_minimum_rounding_is_recomputed():
    from dataclasses import replace
    from hashlib import sha256

    from tools.platformctl.cost import calculate_cycle_charges
    from tools.platformctl.lifecycle_io import canonical_json_bytes

    basis, reader, now = charging_fixture()
    component = basis.components[0]

    def update(ref, **fields):
        payload = json.loads(reader.payloads[ref.path])
        raw = canonical_json_bytes({**payload, **fields})
        reader.payloads[ref.path] = raw
        return replace(ref, sha256=sha256(raw).hexdigest(), byte_count=len(raw))

    component = replace(
        component,
        quantity="1.1",
        quantum="2",
        minimum="5",
        rate_source=update(component.rate_source, quantum="2", minimum="5"),
        quantity_source=update(component.quantity_source, quantity="1.1"),
    )
    result = calculate_cycle_charges(
        replace(basis, components=(component, *basis.components[1:])),
        reader=reader,
        now=now,
        final_requests=0,
    )
    assert result["components"][0]["supported_usd"] == "5"
    assert result["supported_total_bound_usd"] == "20"
