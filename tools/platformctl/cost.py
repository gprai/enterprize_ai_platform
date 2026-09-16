"""Bounded Infracost 0.10.45 estimate parsing and USD 3 stop gate."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import cast

from .aws_inventory import PUBLIC_CHARGING_PAGES as PUBLIC_CHARGING_PAGES
from .contracts import APPROVER, ContractError, EvidenceReader, parse_utc_timestamp, validate_sha256
from .lifecycle_io import (
    approved_lifecycle_exception,
    approved_monthly_exception,
    canonical_json_bytes,
    decode_json_strict,
    decode_operational_record,
    ensure_external_path,
    load_json_strict,
    load_lifecycle_config,
    private_transient_bytes,
    sha256_bytes,
    sha256_file,
)
from .lifecycle_models import (
    OPERATIONAL_SCHEMA_VERSION,
    ChargingBasis,
    CostComponent,
    CostResult,
    CostResultV2,
    CostReviewTerms,
    CoverageClass,
    EvidenceRef,
    InventoryResult,
    LifecycleBudgetAuthority,
    MonthlyAmendmentAuthority,
    Outcome,
    ResolutionCostLedger,
    ResolutionLedgerEntry,
    ToolIdentity,
)
from .terraform_runner import CommandRunner, TerraformRunner

INFRACOST_VERSION = "0.10.45"
INFRACOST_ARCHIVE_SHA256 = "7f627fac5cad9b7260e1123c1378d2fb4f308cdc64f78e99d6e69727d9549d06"
INFRACOST_CHECKSUM_SIDECAR_SHA256 = (
    "4a9668bab905dec316487ef1403e8f1ed59e6bbb897b4a08e521d3039f0aa413"
)
INFRACOST_LICENSE = "Apache-2.0"
INFRACOST_EXECUTABLE_SHA256 = "6a85c7a000eb5fb3e9a01df6a9ed4359580c07f5c7da9d13c1dfbe847bedf600"
INFRACOST_EXECUTABLE = Path(r"E:\AI\.tools\infracost\0.10.45\infracost.exe")
PRICING_ENDPOINT = "https://pricing.api.infracost.io"
DASHBOARD_ENDPOINT = "https://dashboard.api.infracost.io"
LIFECYCLE_CEILING = Decimal("3.00")
MONTHLY_CEILING = Decimal("60.00")
REQUIRED_TERRAFORM_PLAN_FIELDS = frozenset(
    {
        "configuration",
        "format_version",
        "planned_values",
        "resource_changes",
        "terraform_version",
    }
)
INFRACOST_SUMMARY_COUNT_FIELDS = (
    "totalDetectedResources",
    "totalSupportedResources",
    "totalUnsupportedResources",
    "totalUsageBasedResources",
    "totalNoPriceResources",
)


def validate_monthly_amendment(
    reference: EvidenceRef | None,
    *,
    reader: EvidenceReader | None,
    now: datetime,
    operation_id: str,
    scope: str,
    state_lineage: str | None,
    configuration_sha256: str | None,
    environment: str = "sandbox",
) -> bool:
    """No flag or historical estimate can activate the current-cycle exception."""
    if reference is None:
        return False
    if reader is None or configuration_sha256 is None:
        raise ContractError("MONTHLY_AMENDMENT_AUTHORITY_REQUIRED")
    validate_sha256(configuration_sha256)
    if (
        reference.kind != "mvp-monthly-amendment"
        or reference.operation_id != operation_id
        or not 0 < reference.byte_count <= 16384
        or scope not in {"bootstrap", "platform"}
        or environment != "sandbox"
    ):
        raise ContractError("MONTHLY_AMENDMENT_BINDING")
    authority = decode_operational_record(
        reader.read(reference.path, reference.sha256, reference.byte_count),
        MonthlyAmendmentAuthority,
    )
    expected = approved_monthly_exception()
    snapshot = authority.configuration_snapshot.encode("utf-8")
    configuration = decode_json_strict(snapshot)
    cost_configuration = configuration.get("cost") if isinstance(configuration, dict) else None
    lifecycle = configuration.get("lifecycle") if isinstance(configuration, dict) else None
    if (
        sha256_bytes(snapshot) != configuration_sha256
        or not isinstance(cost_configuration, dict)
        or cost_configuration.get("monthly_exception") != expected
        or cost_configuration.get("lifecycle_test_ceiling") != "3.00"
        or cost_configuration.get("monthly_sandbox_ceiling") != "60.00"
        or not isinstance(lifecycle, dict)
        or lifecycle.get("cycle") != "W5-CYCLE-A"
    ):
        raise ContractError("MONTHLY_AMENDMENT_CONFIGURATION_MISMATCH")
    for field in (
        "amendment_id",
        "cycle_id",
        "account_id",
        "region",
        "environment",
        "bootstrap_lineage",
        "platform_lineage",
    ):
        if getattr(authority, field) != expected[field]:
            raise ContractError("MONTHLY_AMENDMENT_CYCLE_MISMATCH")
    approved = parse_utc_timestamp(authority.approved_at, "monthly amendment approval")
    expiry = parse_utc_timestamp(authority.valid_until, "monthly amendment expiry")
    if (
        authority.operation_id != operation_id
        or authority.configuration_sha256 != configuration_sha256
        or authority.approver != APPROVER
        or authority.cycle_status != "OPEN"
        or state_lineage != expected[scope + "_lineage"]
        or not approved <= now < expiry <= approved + timedelta(hours=1)
        or expiry > parse_utc_timestamp(expected["valid_until"], "governance deadline")
        or reference.created_at != authority.approved_at
        or reference.valid_until != authority.valid_until
    ):
        raise ContractError("MONTHLY_AMENDMENT_STALE_OR_UNBOUND")
    return True


def verified_lifecycle_ceiling(
    reference: EvidenceRef | None,
    *,
    reader: EvidenceReader | None,
    now: datetime,
    operation_id: str,
    scope: str,
    state_lineage: str | None,
    configuration_sha256: str | None,
    environment: str = "sandbox",
) -> Decimal:
    """Resolve policy once; unbound or subsequent-cycle callers cannot select USD 30."""
    if reference is None:
        return LIFECYCLE_CEILING
    if (
        reader is None
        or configuration_sha256 is None
        or reference.kind != "lifecycle-budget-amendment"
        or reference.operation_id != operation_id
        or not 0 < reference.byte_count <= 16384
        or scope not in {"bootstrap", "platform"}
        or environment != "sandbox"
    ):
        raise ContractError("LIFECYCLE_AMENDMENT_BINDING_REQUIRED")
    authority = decode_operational_record(
        reader.read(reference.path, reference.sha256, reference.byte_count),
        LifecycleBudgetAuthority,
    )
    expected = approved_lifecycle_exception()
    snapshot = authority.configuration_snapshot.encode("utf-8")
    configuration = decode_json_strict(snapshot)
    cost = configuration.get("cost") if isinstance(configuration, dict) else None
    lifecycle = configuration.get("lifecycle") if isinstance(configuration, dict) else None
    if (
        sha256_bytes(snapshot) != configuration_sha256
        or authority.configuration_sha256 != configuration_sha256
        or not isinstance(cost, dict)
        or cost.get("lifecycle_test_ceiling") != "3.00"
        or cost.get("lifecycle_exception") != expected
        or not isinstance(lifecycle, dict)
        or lifecycle.get("cycle") != "W5-CYCLE-A"
        or any(
            getattr(authority, key) != value
            for key, value in expected.items()
            if key != "valid_until"
        )
    ):
        raise ContractError("LIFECYCLE_AMENDMENT_CYCLE_OR_CONFIGURATION_MISMATCH")
    approved = parse_utc_timestamp(authority.approved_at, "lifecycle approval")
    expiry = parse_utc_timestamp(authority.valid_until, "lifecycle authority expiry")
    if (
        authority.operation_id != operation_id
        or authority.approver != APPROVER
        or authority.cycle_status != "OPEN"
        or state_lineage != expected[scope + "_lineage"]
        or not approved <= now < expiry <= approved + timedelta(hours=1)
        or expiry > parse_utc_timestamp(expected["valid_until"], "governance deadline")
        or reference.created_at != authority.approved_at
        or reference.valid_until != authority.valid_until
    ):
        raise ContractError("LIFECYCLE_AMENDMENT_STALE_OR_UNBOUND")
    return Decimal(expected["lifecycle_ceiling_usd"])


def _decimal(value: object) -> Decimal | None:
    if value is None:
        return None
    try:
        parsed = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise ContractError("Infracost amount is malformed") from exc
    if not parsed.is_finite() or parsed < 0:
        raise ContractError("Infracost amount must be finite and non-negative")
    return parsed


def diagnostic_pricing_summary(
    raw: bytes, approved_resources: Mapping[str, str]
) -> dict[str, object]:
    """A retained projection is disclosure, never fresh prices or incurred spending."""
    value = decode_json_strict(raw)
    if not isinstance(value, dict) or (
        value.get("schema_version") != "w5-004.pricing-breakdown-diagnostic.v1"
        or value.get("currency") != "USD"
    ):
        raise ContractError("DIAGNOSTIC_PRICING_SCHEMA")
    monthly = _decimal(value.get("estimated_monthly_usd"))
    counts = _summary_counts(value.get("counts"))
    if (
        monthly is None
        or not counts["totalDetectedResources"]
        or not counts["totalSupportedResources"]
    ):
        raise ContractError("DIAGNOSTIC_PRICING_EMPTY")
    resources = value.get("resources")
    if not isinstance(resources, list) or len(resources) > 5000:
        raise ContractError("DIAGNOSTIC_PRICING_RESOURCES")
    seen: set[str] = set()
    output: list[dict[str, object]] = []
    known = Decimal("0")
    for resource in resources:
        if not isinstance(resource, dict) or not isinstance(resource.get("address"), str):
            raise ContractError("DIAGNOSTIC_PRICING_RESOURCE")
        address = resource["address"]
        if address in seen or approved_resources.get(address) != resource.get("resource_type"):
            raise ContractError("DIAGNOSTIC_PRICING_RESOURCE_SCOPE")
        seen.add(address)
        components = resource.get("components")
        if not isinstance(components, list) or not 0 < len(components) <= 100:
            raise ContractError("DIAGNOSTIC_PRICING_COMPONENTS")
        projected: list[dict[str, object]] = []
        for index, component in enumerate(components, 1):
            if not isinstance(component, dict) or component.get("component_id") != index:
                raise ContractError("DIAGNOSTIC_PRICING_COMPONENT_ID")
            unit = component.get("unit")
            if unit not in {
                "GB",
                "GB-months",
                "hours",
                "months",
                "Mbps",
                "requests",
                "1k requests",
                "10k requests",
            }:
                raise ContractError("DIAGNOSTIC_PRICING_UNIT_UNCLASSIFIED")
            selected: dict[str, object] = {"component_id": index, "unit": unit}
            for field in (
                "unit_price_usd",
                "unit_multiplier",
                "monthly_quantity",
                "hourly_quantity",
                "monthly_cost_usd",
                "hourly_cost_usd",
            ):
                amount = _decimal(component.get(field))
                selected[field] = None if amount is None else str(amount)
            usage = component.get("usage_based")
            if usage is not None and type(usage) is not bool:
                raise ContractError("DIAGNOSTIC_PRICING_USAGE")
            selected["usage_based"] = usage
            projected.append(selected)
        amount = _decimal(resource.get("monthly_cost_usd"))
        if amount is not None:
            known += amount
        output.append(
            {
                "address": address,
                "resource_type": approved_resources[address],
                "monthly_usd": None if amount is None else str(amount),
                "components": projected,
            }
        )
    recorded = value.get("recorded_cost_status")
    if recorded not in {"PASS", "FAIL", "INDETERMINATE"}:
        raise ContractError("DIAGNOSTIC_PRICING_HISTORICAL_STATUS")
    return {
        "historical_monthly_usd": str(monthly),
        "recorded_cost_status": recorded,
        "counts": counts,
        "resources": sorted(output, key=lambda item: str(item["address"])),
        "known_sum_matches_projection": known == monthly,
        "unitemized_addresses": sorted(set(approved_resources) - seen),
        "fresh_pricing": "NOT_ESTABLISHED",
        "actual_spending": "NOT_ESTABLISHED",
        "coverage": "INDETERMINATE",
        "monthly_default_usd": "60.00",
    }


def diagnostic_exposure_totals(
    result: CostResultV2,
    *,
    reader: EvidenceReader | None = None,
    now: datetime | None = None,
    state_lineage: str | None = None,
    configuration_sha256: str | None = None,
) -> dict[str, object]:
    """Disclose missing categories without converting unknown amounts to zero."""
    ceiling = LIFECYCLE_CEILING
    if result.lifecycle_amendment is not None:
        if now is None:
            raise ContractError("LIFECYCLE_AMENDMENT_CLOCK_REQUIRED")
        ceiling = verified_lifecycle_ceiling(
            result.lifecycle_amendment,
            reader=reader,
            now=now,
            operation_id=result.raw_estimate.operation_id,
            scope="platform",
            state_lineage=state_lineage,
            configuration_sha256=configuration_sha256,
        )
    contributors: list[dict[str, object]] = []
    remaining: Decimal | None = Decimal("0")
    for entry in result.coverage:
        amount = _decimal(entry.remaining_usd)
        if amount is None:
            remaining = None
        elif remaining is not None:
            remaining += amount
        contributors.append(
            {
                "scope": entry.scope,
                "address": entry.address,
                "remaining_usd": None if amount is None else str(amount),
                "charging_model": entry.charging_model,
                "duration_seconds": entry.duration_seconds,
            }
        )
    categories = {
        "incurred_usd": _decimal(result.incurred_usd),
        "remaining_usd": remaining,
        "recovery_one_off_usd": _decimal(result.recovery_usd),
        "teardown_retention_usd": _decimal(result.teardown_retention_usd),
    }
    total = (
        None
        if not result.coverage or any(value is None for value in categories.values())
        else sum((cast(Decimal, value) for value in categories.values()), Decimal("0"))
    )
    return {
        **{key: None if value is None else str(value) for key, value in categories.items()},
        "supported_total_usd": None if total is None else str(total),
        "lifecycle_ceiling_usd": str(ceiling),
        "headroom_usd": None if total is None else str(ceiling - total),
        "replacement_ceiling_review_required": total is not None and total > ceiling,
        "contributors": contributors,
        "billing_lag_seconds": result.billing_lag_seconds,
        "amounts_require_evidence_reconciliation": True,
    }


def diagnostic_query_exposure(
    reference: EvidenceRef, reader: EvidenceReader, now: datetime, operation_id: str
) -> Decimal:
    """A source-backed query allowance is additional exposure, not invented spending."""
    from .lifecycle_io import decode_diagnostic_record
    from .lifecycle_models import DiagnosticQueryCostBasis

    basis = decode_diagnostic_record(
        reader.read(reference.path, reference.sha256, reference.byte_count),
        DiagnosticQueryCostBasis,
    )
    if (
        basis.operation_id != operation_id
        or reference.operation_id != operation_id
        or reference.kind != "diagnostic-query-cost-basis"
        or basis.account_id != "526338061652"
        or basis.unit_price_usd != "0.01"
        or type(basis.maximum_requests) is not int
        or basis.maximum_requests != 6
        or basis.approver != APPROVER
        or not parse_utc_timestamp(basis.approved_at, "query approval")
        <= now
        < parse_utc_timestamp(basis.valid_until, "query expiry")
        or basis.source_url
        != ("https://aws.amazon.com/aws-cost-management/aws-cost-explorer/pricing/")
        or basis.source.operation_id != operation_id
        or parse_utc_timestamp(basis.source.valid_until, "query source expiry") <= now
    ):
        raise ContractError("DIAGNOSTIC_QUERY_COST_BASIS_INVALID")
    reader.read(basis.source.path, basis.source.sha256, basis.source.byte_count)
    return Decimal(basis.unit_price_usd) * basis.maximum_requests


def _summary_counts(value: object) -> dict[str, int]:
    if not isinstance(value, dict):
        raise ContractError("Infracost summary must be an object")
    summary = cast(dict[str, object], value)
    counts: dict[str, int] = {}
    for field in INFRACOST_SUMMARY_COUNT_FIELDS:
        count = summary.get(field)
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise ContractError("Infracost summary count is malformed")
        counts[field] = count
    return counts


def validate_terraform_plan_json(raw: bytes) -> None:
    """Require genuine Terraform show JSON rather than normalized policy JSON."""
    value = decode_json_strict(raw)
    if not isinstance(value, dict):
        raise ContractError("Terraform plan JSON must be an object")
    payload = cast(dict[str, object], value)
    if not REQUIRED_TERRAFORM_PLAN_FIELDS.issubset(payload):
        raise ContractError("Infracost input must be Terraform show JSON")
    if not isinstance(payload.get("format_version"), str) or not isinstance(
        payload.get("terraform_version"), str
    ):
        raise ContractError("Terraform plan identity is malformed")
    if not isinstance(payload.get("configuration"), dict) or not isinstance(
        payload.get("planned_values"), dict
    ):
        raise ContractError("Terraform plan values are malformed")
    if not isinstance(payload.get("resource_changes"), list):
        raise ContractError("Terraform resource changes are malformed")


def parse_infracost_output(value: object) -> CostResult:
    """Parse local CLI output; direct plan-JSON API upload is never used."""
    if not isinstance(value, dict):
        raise ContractError("Infracost output must be an object")
    payload = cast(dict[str, object], value)
    if payload.get("errors") not in (None, []):
        raise ContractError("Infracost output contains an estimation error")
    currency = payload.get("currency", "USD")
    if currency != "USD":
        raise ContractError("Infracost currency must be USD")
    total = _decimal(payload.get("totalMonthlyCost"))
    projects = payload.get("projects", [])
    if not isinstance(projects, list) or not projects:
        raise ContractError("Infracost projects must be a non-empty list")
    summary_counts = _summary_counts(payload.get("summary"))
    components: list[CostComponent] = []
    incomplete = (
        total is None
        or summary_counts["totalDetectedResources"] == 0
        or summary_counts["totalSupportedResources"] == 0
        or summary_counts["totalUnsupportedResources"] > 0
        or summary_counts["totalUsageBasedResources"] > 0
        or summary_counts["totalNoPriceResources"] > 0
    )
    known_component_total = Decimal("0")
    for index, project in enumerate(projects):
        if not isinstance(project, dict):
            raise ContractError("Infracost project is malformed")
        if project.get("errors") not in (None, []):
            raise ContractError("Infracost project contains an estimation error")
        metadata = project.get("metadata")
        if not isinstance(metadata, dict):
            raise ContractError("Infracost project metadata is malformed")
        project_metadata = cast(dict[str, object], metadata)
        errors = project_metadata.get("errors", [])
        if not isinstance(errors, list):
            raise ContractError("Infracost project errors are malformed")
        if project_metadata.get("type") == "error" or errors:
            raise ContractError("Infracost project contains an estimation error")
        breakdown = project.get("breakdown", {})
        if not isinstance(breakdown, dict):
            raise ContractError("Infracost breakdown is malformed")
        resources = breakdown.get("resources")
        if not isinstance(resources, list):
            raise ContractError("Infracost project resources are malformed")
        project_counts = _summary_counts(project.get("summary"))
        cost = _decimal(breakdown.get("totalMonthlyCost"))
        usage_based = bool(project_metadata.get("usageBased")) or (
            project_counts["totalUsageBasedResources"] > 0
        )
        components.append(CostComponent(f"project-{index + 1}", cost, usage_based))
        incomplete = (
            incomplete
            or cost is None
            or usage_based
            or project_counts["totalDetectedResources"] == 0
            or project_counts["totalSupportedResources"] == 0
            or project_counts["totalUnsupportedResources"] > 0
            or project_counts["totalNoPriceResources"] > 0
            or (project_counts["totalSupportedResources"] > 0 and not resources)
        )
        if cost is not None:
            known_component_total += cost
    if projects and total is not None and known_component_total != total:
        incomplete = True
    # Monthly output alone cannot establish duration, incurred exposure or headroom.
    lifecycle_cost = None
    if total is not None and total > MONTHLY_CEILING:
        status = Outcome.FAIL
    else:
        status = Outcome.INDETERMINATE
    if incomplete and status is not Outcome.FAIL:
        status = Outcome.INDETERMINATE
    return CostResult(
        status=status,
        currency="USD",
        estimated_monthly_cost=total,
        estimated_lifecycle_cost=lifecycle_cost,
        monthly_ceiling=MONTHLY_CEILING,
        lifecycle_ceiling=LIFECYCLE_CEILING,
        components=tuple(components),
        source_sha256=sha256_bytes(canonical_json_bytes(payload)),
        tool=ToolIdentity("infracost", INFRACOST_VERSION, INFRACOST_EXECUTABLE_SHA256),
    )


def validate_infracost_environment(
    environment: Mapping[str, str], *, require_api_key: bool = True
) -> None:
    """Ensure credential material cannot be copied into reports or command output."""
    prohibited = {
        key
        for key in environment
        if key.casefold()
        not in {
            "infracost_api_key",
            "path",
            "systemroot",
            "windir",
            "temp",
            "tmp",
        }
    }
    if prohibited:
        raise ContractError("unapproved Infracost environment variables are present")
    normalized: dict[str, str] = {}
    for key, value in environment.items():
        name = key.casefold()
        if name in normalized or any(character in value for character in ("\x00", "\r", "\n")):
            raise ContractError("INFRACOST_ENVIRONMENT_AMBIGUOUS_OR_MALFORMED")
        normalized[name] = value
    if require_api_key and not normalized.get("infracost_api_key"):
        raise ContractError("external Infracost API key is unavailable")


def build_infracost_arguments(plan_json: Path, output_json: Path) -> tuple[str, ...]:
    """Build the approved local-file CLI flow; no direct API upload command exists."""
    return (
        str(INFRACOST_EXECUTABLE),
        "breakdown",
        "--path",
        str(plan_json),
        "--format",
        "json",
        "--out-file",
        str(output_json),
    )


class InfracostRunner:
    """Execute exact local-file estimates without direct plan JSON API upload."""

    def __init__(
        self,
        *,
        runner: CommandRunner,
        repository_root: Path,
        external_root: Path,
    ) -> None:
        self._runner = runner
        self._repository_root = repository_root.resolve(strict=True)
        self._external_root = external_root.resolve(strict=False)

    def verify_version(self, environment: Mapping[str, str]) -> None:
        """Require exact Infracost 0.10.45 before estimating."""
        validate_infracost_environment(environment, require_api_key=False)
        if sha256_file(INFRACOST_EXECUTABLE) != INFRACOST_EXECUTABLE_SHA256:
            raise ContractError("INFRACOST_EXECUTABLE_IDENTITY")
        result = self._runner.run(
            (str(INFRACOST_EXECUTABLE), "--version"),
            cwd=self._repository_root,
            environment={
                key: value
                for key, value in environment.items()
                if key.upper() != "INFRACOST_API_KEY"
            },
            timeout_seconds=60,
        )
        if result.returncode != 0 or result.stdout.splitlines()[:1] != [
            f"Infracost v{INFRACOST_VERSION}"
        ]:
            raise ContractError("Infracost version must be exactly 0.10.45")

    def estimate(
        self,
        plan_json: Path,
        output_json: Path,
        environment: Mapping[str, str],
    ) -> None:
        """Historical path-only entry point cannot establish eligible pricing."""
        del plan_json, output_json, environment
        raise ContractError("SAVED_BINARY_COST_ADAPTER_REQUIRED")

    def _estimate_private(
        self,
        plan_json: Path,
        output_json: Path,
        environment: Mapping[str, str],
        *,
        transient_output: bool = False,
    ) -> object:
        """Called only inside the exact saved-binary private-input adapter."""
        validate_infracost_environment(environment)
        self.verify_version(
            {key: value for key, value in environment.items() if key.upper() != "INFRACOST_API_KEY"}
        )
        plan = ensure_external_path(plan_json, self._external_root, self._repository_root)
        output = ensure_external_path(output_json, self._external_root, self._repository_root)
        if not plan.is_file():
            raise ContractError("redacted plan JSON is unavailable")
        validate_terraform_plan_json(plan.read_bytes())
        if output.exists():
            raise ContractError("Infracost output target already exists")

        def produce(target: Path) -> None:
            result = self._runner.run(
                build_infracost_arguments(plan, target),
                cwd=self._repository_root,
                environment=environment,
                timeout_seconds=300,
            )
            if result.returncode != 0 or not target.is_file():
                raise ContractError("Infracost estimate failed")

        if transient_output:
            from .lifecycle_io import capture_private_tool_json

            return capture_private_tool_json(
                output,
                produce,
                allowed_root=self._external_root,
                repository_root=self._repository_root,
            )
        produce(output)
        return None

    def _saved_plan_input(
        self,
        terraform_runner: TerraformRunner,
        terraform_root: Path,
        saved_plan: Path,
        expected_saved_plan_sha256: str,
        transient_plan_json: Path,
    ) -> tuple[Path, Path, bytes]:
        plan = ensure_external_path(saved_plan, self._external_root, self._repository_root)
        transient = ensure_external_path(
            transient_plan_json, self._external_root, self._repository_root
        )
        if sha256_file(plan) != expected_saved_plan_sha256:
            raise ContractError("saved plan bytes do not match the cost-review identity")
        if transient.exists():
            raise ContractError("transient Terraform plan JSON target already exists")
        raw = terraform_runner.show_plan_json(terraform_root, plan)
        validate_terraform_plan_json(raw)
        if sha256_file(plan) != expected_saved_plan_sha256:
            raise ContractError("saved plan identity changed during cost preparation")
        return plan, transient, raw

    def estimate_saved_plan_compatibility(
        self,
        *,
        terraform_runner: TerraformRunner,
        terraform_root: Path,
        saved_plan: Path,
        expected_saved_plan_sha256: str,
        transient_plan_json: Path,
        output_json: Path,
        environment: Mapping[str, str],
    ) -> CostResult:
        """Retain only a sanitized compatibility report, never operational cost evidence."""
        from .lifecycle_io import write_canonical_json_atomic

        validate_infracost_environment(environment)
        output = ensure_external_path(output_json, self._external_root, self._repository_root)
        raw_output = output.with_name(output.name + ".raw-transient")
        paths = (saved_plan, transient_plan_json, output, raw_output)
        if len({str(path.resolve(strict=False)).casefold() for path in paths}) != len(paths):
            raise ContractError("COST_COMPATIBILITY_PATH_COLLISION")
        if output.exists() or raw_output.exists():
            raise ContractError("COST_COMPATIBILITY_OUTPUT_EXISTS")
        plan, transient, raw = self._saved_plan_input(
            terraform_runner,
            terraform_root,
            saved_plan,
            expected_saved_plan_sha256,
            transient_plan_json,
        )
        with private_transient_bytes(
            transient, raw, allowed_root=self._external_root, repository_root=self._repository_root
        ):
            parsed = self._estimate_private(
                transient, raw_output, environment, transient_output=True
            )
            result = parse_infracost_output(parsed)
            payload = cast(dict[str, object], parsed)
            counts = _summary_counts(payload.get("summary"))
            projects = cast(list[dict[str, object]], payload["projects"])
            summaries = [counts]
            summaries.extend(_summary_counts(project.get("summary")) for project in projects)
            if any(
                item["totalDetectedResources"] == 0 or item["totalSupportedResources"] == 0
                for item in summaries
            ):
                raise ContractError("COST_ZERO_RECOGNIZED_RESOURCES")
            key = next(
                value for name, value in environment.items() if name.upper() == "INFRACOST_API_KEY"
            )
            if key.encode("utf-8") in canonical_json_bytes(payload):
                raise ContractError("COST_CREDENTIAL_EXPOSURE_DETECTED")
        if transient.exists() or raw_output.exists():
            raise ContractError("COST_COMPATIBILITY_TRANSIENT_RESIDUE")
        if sha256_file(plan) != expected_saved_plan_sha256:
            raise ContractError("COST_SAVED_PLAN_CHANGED")
        write_canonical_json_atomic(
            output,
            {
                "schema_version": "w5-004.cost-compatibility.v1",
                "compatibility": "PASS",
                "saved_plan_sha256": expected_saved_plan_sha256,
                "cost_approval": "NOT_ESTABLISHED",
                "recovery_eligibility": "NOT_ESTABLISHED",
                "counts": counts,
                "result": result,
            },
            allowed_root=self._external_root,
            repository_root=self._repository_root,
        )
        return result

    def estimate_saved_plan(
        self,
        *,
        terraform_runner: TerraformRunner,
        terraform_root: Path,
        saved_plan: Path,
        expected_saved_plan_sha256: str,
        transient_plan_json: Path,
        output_json: Path,
        environment: Mapping[str, str],
        coverage_review: CostResultV2 | None = None,
        review_terms: CostReviewTerms | None = None,
        evidence_reader: EvidenceReader | None = None,
        now: datetime | None = None,
        cleanup_review: bool = False,
        state_lineage: str | None = None,
    ) -> CostResult | CostResultV2:
        """Estimate exact saved-plan bytes and always remove sensitive transient JSON."""
        if coverage_review is None and review_terms is None:
            if cleanup_review:
                raise ContractError("COST_CLEANUP_REVIEW_TERMS_REQUIRED")
            return self.estimate_saved_plan_compatibility(
                terraform_runner=terraform_runner,
                terraform_root=terraform_root,
                saved_plan=saved_plan,
                expected_saved_plan_sha256=expected_saved_plan_sha256,
                transient_plan_json=transient_plan_json,
                output_json=output_json,
                environment=environment,
            )
        monthly_reference = (
            review_terms.monthly_amendment
            if review_terms is not None
            else coverage_review.monthly_amendment
            if coverage_review is not None
            else None
        )
        lifecycle_reference = (
            review_terms.lifecycle_amendment
            if review_terms is not None
            else coverage_review.lifecycle_amendment
            if coverage_review is not None
            else None
        )
        configuration_sha256: str | None = None
        monthly_informational = False
        if monthly_reference is not None:
            if now is None:
                raise ContractError("MONTHLY_AMENDMENT_CLOCK_REQUIRED")
            configuration_path = self._repository_root / "configs/lifecycle/w5-004.json"
            configuration = load_lifecycle_config(configuration_path)
            if cast(dict[str, object], configuration["cost"]).get("monthly_exception") != (
                approved_monthly_exception()
            ):
                raise ContractError("MONTHLY_EXCEPTION_NOT_ENABLED")
            configuration_sha256 = sha256_file(configuration_path)
            monthly_informational = validate_monthly_amendment(
                monthly_reference,
                reader=evidence_reader,
                now=now,
                operation_id=monthly_reference.operation_id,
                scope=review_terms.scope if review_terms is not None else "platform",
                state_lineage=state_lineage,
                configuration_sha256=configuration_sha256,
            )
            if (
                review_terms is not None
                and monthly_reference.operation_id != review_terms.operation_id
            ):
                raise ContractError("MONTHLY_AMENDMENT_OPERATION_MISMATCH")
        lifecycle_ceiling = LIFECYCLE_CEILING
        if lifecycle_reference is not None:
            if now is None:
                raise ContractError("LIFECYCLE_AMENDMENT_CLOCK_REQUIRED")
            configuration_path = self._repository_root / "configs/lifecycle/w5-004.json"
            load_lifecycle_config(configuration_path)
            configuration_sha256 = sha256_file(configuration_path)
            lifecycle_ceiling = verified_lifecycle_ceiling(
                lifecycle_reference,
                reader=evidence_reader,
                now=now,
                operation_id=(
                    review_terms.operation_id
                    if review_terms is not None
                    else cast(CostResultV2, coverage_review).raw_estimate.operation_id
                ),
                scope=review_terms.scope if review_terms is not None else "platform",
                state_lineage=state_lineage,
                configuration_sha256=configuration_sha256,
            )
        plan, transient, raw = self._saved_plan_input(
            terraform_runner,
            terraform_root,
            saved_plan,
            expected_saved_plan_sha256,
            transient_plan_json,
        )
        if cleanup_review:
            _validate_cleanup_plan(raw)
        if sha256_file(plan) != expected_saved_plan_sha256:
            raise ContractError("saved plan identity changed during cost preparation")

        with private_transient_bytes(
            transient,
            raw,
            allowed_root=self._external_root,
            repository_root=self._repository_root,
        ):
            self._estimate_private(transient, output_json, environment)
            parsed = load_json_strict(output_json)
            historical_result = parse_infracost_output(parsed)
            if sha256_file(plan) != expected_saved_plan_sha256:
                raise ContractError("COST_SAVED_PLAN_CHANGED")
            if review_terms is not None:
                if coverage_review is not None or now is None or evidence_reader is None:
                    raise ContractError("COST_REVIEW_TERMS_OR_READER_INVALID")
                output = ensure_external_path(
                    output_json, self._external_root, self._repository_root
                )
                timestamp = now.replace(microsecond=0).isoformat().replace("+00:00", "Z")
                reference = EvidenceRef(
                    "infracost-estimate",
                    output.name,
                    sha256_file(output),
                    output.stat().st_size,
                    "infracost-0.10.45",
                    timestamp,
                    review_terms.valid_until,
                    review_terms.operation_id,
                )
                values = (
                    review_terms.incurred_usd,
                    review_terms.recovery_usd,
                    review_terms.teardown_retention_usd,
                    *(entry.remaining_usd for entry in review_terms.coverage),
                )
                amounts = tuple(_decimal(value) for value in values)
                total = (
                    None
                    if any(value is None for value in amounts)
                    else sum(cast(tuple[Decimal, ...], amounts), Decimal("0"))
                )
                complete = (
                    bool(review_terms.coverage)
                    and total is not None
                    and all(
                        entry.classification
                        in {
                            CoverageClass.PRICED_FIXED,
                            CoverageClass.PRICED_USAGE_WITH_APPROVED_ASSUMPTIONS,
                            CoverageClass.NON_BILLABLE_VERIFIED,
                        }
                        for entry in review_terms.coverage
                    )
                )
                status = Outcome.PASS if complete else Outcome.INDETERMINATE
                reported = _summary_counts(cast(dict[str, object], parsed).get("summary"))
                if reported["totalUnsupportedResources"] or reported["totalNoPriceResources"]:
                    status = Outcome.INDETERMINATE
                if cleanup_review:
                    # Desired-state zero after deletion is not a cleanup-spend estimate.
                    status = Outcome.INDETERMINATE
                if (historical_result.status is Outcome.FAIL and not monthly_informational) or (
                    total is not None and total > lifecycle_ceiling
                ):
                    status = Outcome.FAIL
                headroom = (
                    str(lifecycle_ceiling - total)
                    if total is not None and total <= lifecycle_ceiling
                    else None
                )
                coverage_review = CostResultV2(
                    OPERATIONAL_SCHEMA_VERSION,
                    status,
                    "USD",
                    expected_saved_plan_sha256,
                    reference,
                    review_terms.coverage,
                    review_terms.assumptions,
                    review_terms.incurred_usd,
                    review_terms.recovery_usd,
                    review_terms.teardown_retention_usd,
                    headroom,
                    timestamp,
                    review_terms.valid_until,
                    review_terms.billing_observed_at,
                    review_terms.billing_lag_seconds,
                    review_terms.monthly_amendment,
                    review_terms.lifecycle_amendment,
                )
                reconcile_cost_coverage(
                    raw,
                    parsed,
                    coverage_review,
                    scope=review_terms.scope,
                    cleanup_review=cleanup_review,
                )
                if status is Outcome.PASS:
                    validate_cost_result_v2(
                        coverage_review,
                        expected_saved_plan_sha256,
                        now,
                        reader=evidence_reader,
                        scope=review_terms.scope,
                        state_lineage=state_lineage,
                        configuration_sha256=configuration_sha256,
                    )
                    reconcile_charging_bases(
                        coverage_review, evidence_reader, now, scope=review_terms.scope
                    )
                return coverage_review
            if coverage_review is None:
                return historical_result
            if now is None or evidence_reader is None:
                raise ContractError("COST_REVIEW_CLOCK_AND_EVIDENCE_REQUIRED")
            if sha256_file(output_json) != coverage_review.raw_estimate.sha256:
                raise ContractError("COST_RAW_ESTIMATE_BINDING")
            reconcile_cost_coverage(raw, parsed, coverage_review)
            validate_cost_result_v2(
                coverage_review,
                expected_saved_plan_sha256,
                now,
                reader=evidence_reader,
                state_lineage=state_lineage,
                configuration_sha256=configuration_sha256,
            )
            reconcile_charging_bases(coverage_review, evidence_reader, now)
            return coverage_review


def validate_cost_result_v2(
    result: CostResultV2,
    artifact_sha256: str,
    now: datetime,
    *,
    reader: EvidenceReader | None = None,
    scope: str = "platform",
    state_lineage: str | None = None,
    configuration_sha256: str | None = None,
    environment: str = "sandbox",
) -> None:
    """Require complete resource coverage and independently bounded remaining exposure."""
    validate_sha256(artifact_sha256)
    monthly_informational = validate_monthly_amendment(
        result.monthly_amendment,
        reader=reader,
        now=now,
        operation_id=result.raw_estimate.operation_id,
        scope=scope,
        state_lineage=state_lineage,
        configuration_sha256=configuration_sha256,
        environment=environment,
    )
    lifecycle_ceiling = verified_lifecycle_ceiling(
        result.lifecycle_amendment,
        reader=reader,
        now=now,
        operation_id=result.raw_estimate.operation_id,
        scope=scope,
        state_lineage=state_lineage,
        configuration_sha256=configuration_sha256,
        environment=environment,
    )
    if (
        result.schema_version != OPERATIONAL_SCHEMA_VERSION
        or result.currency != "USD"
        or result.saved_plan_sha256 != artifact_sha256
        or result.status is not Outcome.PASS
        or not result.coverage
    ):
        raise ContractError("COST_INDETERMINATE")
    observed = parse_utc_timestamp(result.observed_at, "pricing observation")
    if not 0 <= (now - observed).total_seconds() <= 3600 or (
        parse_utc_timestamp(result.valid_until, "pricing expiry") <= now
    ):
        raise ContractError("COST_NOT_FRESH")
    if result.billing_observed_at is None or result.billing_lag_seconds is None:
        raise ContractError("INCURRED_EXPOSURE_INDETERMINATE")
    if type(result.billing_lag_seconds) is not int or result.billing_lag_seconds < 0:
        raise ContractError("BILLING_LAG_INVALID")
    if parse_utc_timestamp(result.billing_observed_at, "billing observation") > now:
        raise ContractError("BILLING_OBSERVATION_FUTURE")
    addresses: set[tuple[str, str]] = set()
    remaining = Decimal("0")
    monthly = Decimal("0")
    for entry in result.coverage:
        identity = (entry.scope, entry.address)
        if (
            identity in addresses
            or not entry.address
            or entry.scope not in {"bootstrap", "platform"}
        ):
            raise ContractError("COST_COVERAGE_DUPLICATE_OR_SCOPE")
        addresses.add(identity)
        if entry.classification not in {
            CoverageClass.PRICED_FIXED,
            CoverageClass.PRICED_USAGE_WITH_APPROVED_ASSUMPTIONS,
            CoverageClass.NON_BILLABLE_VERIFIED,
        }:
            raise ContractError("COST_COVERAGE_INDETERMINATE")
        if (
            entry.basis is None
            or not entry.charging_model
            or not entry.units
            or type(entry.duration_seconds) is not int
            or not 0 < entry.duration_seconds <= 86400
            or not isinstance(entry.monthly_usd, str)
            or not isinstance(entry.remaining_usd, str)
        ):
            raise ContractError("COST_BASIS_INDETERMINATE")
        monthly_value = _decimal(entry.monthly_usd)
        remaining_value = _decimal(entry.remaining_usd)
        if monthly_value is None or remaining_value is None:
            raise ContractError("COST_VALUE_MISSING")
        if entry.classification is CoverageClass.NON_BILLABLE_VERIFIED and (
            monthly_value != 0 or remaining_value != 0
        ):
            raise ContractError("NON_BILLABLE_COST_CONFLICT")
        monthly += monthly_value
        remaining += remaining_value
    components = (
        result.incurred_usd,
        result.recovery_usd,
        result.teardown_retention_usd,
        result.headroom_usd,
    )
    if any(not isinstance(value, str) for value in components):
        raise ContractError("LIFECYCLE_HEADROOM_INDETERMINATE")
    amounts = tuple(_decimal(value) for value in components)
    if any(value is None for value in amounts):
        raise ContractError("LIFECYCLE_HEADROOM_INDETERMINATE")
    incurred, incremental, retained, headroom = cast(
        tuple[Decimal, Decimal, Decimal, Decimal], amounts
    )
    # Coverage is the whole desired-state running exposure. Incremental recovery is
    # separately evidenced one-off exposure, never the running coverage a second time.
    exposure = incurred + remaining + incremental + retained
    if exposure > lifecycle_ceiling or (monthly > MONTHLY_CEILING and not monthly_informational):
        raise ContractError("COST_CEILING_EXCEEDED")
    if headroom != lifecycle_ceiling - exposure:
        raise ContractError("COST_HEADROOM_MISMATCH")


def reconcile_cost_coverage(
    raw_plan: bytes,
    output: object,
    review: CostResultV2,
    *,
    scope: str = "platform",
    cleanup_review: bool = False,
) -> None:
    """Bind coverage to the whole desired plan, not merely recovery create actions."""
    validate_terraform_plan_json(raw_plan)
    plan = cast(dict[str, object], decode_json_strict(raw_plan))
    desired: set[str] = set()

    def collect(module: object) -> None:
        if not isinstance(module, dict):
            raise ContractError("COST_DESIRED_MODULE_MALFORMED")
        resources = module.get("resources", [])
        children = module.get("child_modules", [])
        if not isinstance(resources, list) or not isinstance(children, list):
            raise ContractError("COST_DESIRED_MODULE_MALFORMED")
        for resource in resources:
            if not isinstance(resource, dict) or not isinstance(resource.get("address"), str):
                raise ContractError("COST_DESIRED_RESOURCE_MALFORMED")
            if resource.get("mode") == "data":
                continue
            address = resource["address"]
            if address in desired:
                raise ContractError("COST_DESIRED_DUPLICATE")
            desired.add(address)
        for child in children:
            collect(child)

    values = cast(dict[str, object], plan["planned_values"])
    collect(values.get("root_module"))
    if cleanup_review:
        desired.update(_validate_cleanup_plan(raw_plan))
    if scope not in {"platform", "bootstrap"}:
        raise ContractError("COST_ESTIMATE_SCOPE_INVALID")
    if desired != {entry.address for entry in review.coverage if entry.scope == scope}:
        raise ContractError("COST_DESIRED_COVERAGE_MISMATCH")
    parse_infracost_output(output)
    payload = cast(dict[str, object], output)
    counts = _summary_counts(payload.get("summary"))
    if cleanup_review:
        if review.status is Outcome.PASS:
            raise ContractError("DESTROY_REQUIRES_SEPARATE_CLEANUP_SPENDING_REVIEW")
        return
    if counts["totalDetectedResources"] == 0 or counts["totalSupportedResources"] == 0:
        raise ContractError("COST_ZERO_RECOGNIZED_RESOURCES")
    if review.status is Outcome.PASS:
        if counts["totalUnsupportedResources"] or counts["totalNoPriceResources"]:
            raise ContractError("COST_RAW_COVERAGE_REMAINS_INDETERMINATE")
        projects = cast(list[dict[str, object]], payload["projects"])
        totals = {name: 0 for name in counts}
        project_monthly = Decimal("0")
        for project in projects:
            for name, count in _summary_counts(project.get("summary")).items():
                totals[name] += count
            breakdown = project.get("breakdown")
            amount = (
                _decimal(breakdown.get("totalMonthlyCost")) if isinstance(breakdown, dict) else None
            )
            if amount is None:
                raise ContractError("COST_PROJECT_MONTHLY_TOTAL_MISSING")
            project_monthly += amount
        if totals != counts:
            raise ContractError("COST_PROJECT_COVERAGE_TOTAL_MISMATCH")
        if project_monthly != _decimal(payload.get("totalMonthlyCost")):
            raise ContractError("COST_PROJECT_MONTHLY_TOTAL_MISMATCH")
        own_monthly = tuple(
            _decimal(entry.monthly_usd) for entry in review.coverage if entry.scope == scope
        )
        if any(amount is None for amount in own_monthly) or sum(
            cast(tuple[Decimal, ...], own_monthly), Decimal("0")
        ) != _decimal(payload.get("totalMonthlyCost")):
            raise ContractError("COST_RESOURCE_MONTHLY_TOTAL_MISMATCH")
    prices: dict[str, Decimal | None] = {}
    projects = cast(list[dict[str, object]], payload["projects"])
    for project in projects:
        breakdown = cast(dict[str, object], project["breakdown"])
        for item in cast(list[dict[str, object]], breakdown["resources"]):
            if not isinstance(item, dict):
                raise ContractError("COST_RESOURCE_PRICE_MALFORMED")
            address = item.get("name")
            if not isinstance(address, str):
                raise ContractError("COST_RESOURCE_PRICE_MALFORMED")
            if address in prices:
                raise ContractError("COST_RESOURCE_PRICE_DUPLICATE")
            prices[address] = _decimal(item.get("monthlyCost"))
    for entry in review.coverage:
        if entry.scope != scope or entry.classification is CoverageClass.NON_BILLABLE_VERIFIED:
            continue
        if (
            entry.classification
            in {
                CoverageClass.UNSUPPORTED,
                CoverageClass.NO_PRICE,
                CoverageClass.USAGE_UNBOUNDED,
            }
            and review.status is not Outcome.PASS
        ):
            continue
        if (
            entry.address not in prices
            or prices[entry.address] is None
            or (prices[entry.address] != _decimal(entry.monthly_usd))
        ):
            raise ContractError("COST_RESOURCE_PRICE_NOT_BOUND")


def _validate_cleanup_plan(raw: bytes) -> set[str]:
    """A destroy-cost review covers removed resources as well as retained desired state."""
    value = decode_json_strict(raw)
    if not isinstance(value, dict) or not isinstance(value.get("resource_changes"), list):
        raise ContractError("CLEANUP_COST_PLAN_MALFORMED")
    deleted: set[str] = set()
    for resource in value["resource_changes"]:
        if not isinstance(resource, dict) or not isinstance(resource.get("change"), dict):
            raise ContractError("CLEANUP_COST_CHANGE_MALFORMED")
        change = resource["change"]
        if change.get("actions") not in (["delete"], ["no-op"], ["read"]):
            raise ContractError("CLEANUP_COST_ACTION_NOT_DESTRUCTIVE")
        if change.get("actions") == ["delete"]:
            address = resource.get("address")
            if (
                not isinstance(address, str)
                or address in deleted
                or change.get("after") is not None
            ):
                raise ContractError("CLEANUP_COST_DELETION_MALFORMED")
            if not isinstance(change.get("before"), dict):
                raise ContractError("CLEANUP_COST_PREVIOUS_RESOURCE_REQUIRED")
            deleted.add(address)
    if not deleted:
        raise ContractError("CLEANUP_COST_DELETION_REQUIRED")
    return deleted


def reconcile_charging_bases(
    result: CostResultV2,
    reader: EvidenceReader,
    now: datetime,
    *,
    scope: str = "platform",
) -> None:
    """Recompute every approved resource window from its own immutable charging rule."""
    raw = decode_json_strict(
        reader.read(
            result.raw_estimate.path, result.raw_estimate.sha256, result.raw_estimate.byte_count
        )
    )
    parse_infracost_output(raw)
    if not isinstance(raw, dict):
        raise ContractError("COST_RAW_ESTIMATE_MALFORMED")
    resource_prices: dict[str, dict[str, object]] = {}

    def collect(resources: object) -> None:
        if not isinstance(resources, list):
            raise ContractError("COST_PRICE_RESOURCE_STRUCTURE")
        for item in resources:
            if not isinstance(item, dict) or not isinstance(item.get("name"), str):
                raise ContractError("COST_PRICE_RESOURCE_STRUCTURE")
            name = item["name"]
            if name in resource_prices:
                raise ContractError("COST_PRICE_DUPLICATE")
            resource_prices[name] = item
            if "subresources" in item:
                collect(item["subresources"])

    for project in cast(list[dict[str, object]], raw["projects"]):
        collect(cast(dict[str, object], project["breakdown"]).get("resources"))
    seen: set[tuple[str, str]] = set()
    for entry in result.coverage:
        identity = entry.scope, entry.address
        if identity in seen or entry.basis is None:
            raise ContractError("COST_BASIS_MISSING_OR_DUPLICATED")
        seen.add(identity)
        basis = decode_operational_record(
            reader.read(entry.basis.path, entry.basis.sha256, entry.basis.byte_count), ChargingBasis
        )
        start = parse_utc_timestamp(basis.window_start, "charge window start")
        end = parse_utc_timestamp(basis.window_end, "charge window end")
        if (
            basis.operation_id != result.raw_estimate.operation_id
            or (basis.scope, basis.address) != identity
            or basis.classification is not entry.classification
            or basis.approver != APPROVER
            or parse_utc_timestamp(basis.approved_at, "charge approval") > now
            or parse_utc_timestamp(basis.expires_at, "charge expiry") < end
            or not 0 < (end - start).total_seconds() <= 86400
            or int((end - start).total_seconds()) != entry.duration_seconds
            or start > parse_utc_timestamp(result.observed_at, "pricing observation")
            or end < parse_utc_timestamp(result.valid_until, "pricing review expiry")
            or entry.charging_model != "RESOURCE_SPECIFIC_BILLING_QUANTA"
            or entry.units != "USD"
        ):
            raise ContractError("COST_CHARGING_BASIS_BINDING")
        authority = basis.authority
        if (
            authority.operation_id != basis.operation_id
            or authority.kind not in {"approved-pricing-basis", "verified-non-billable-basis"}
            or parse_utc_timestamp(authority.valid_until, "basis expiry") < end
        ):
            raise ContractError("COST_PRICING_AUTHORITY_BINDING")
        from .lifecycle_models import PricingAuthority

        price_authority = decode_operational_record(
            reader.read(authority.path, authority.sha256, authority.byte_count), PricingAuthority
        )
        if (
            price_authority.operation_id != basis.operation_id
            or price_authority.account_id != "526338061652"
            or price_authority.region != "ap-southeast-1"
            or (price_authority.scope, price_authority.address) != identity
            or price_authority.currency != "USD"
            or price_authority.classification is not entry.classification
            or price_authority.components != basis.components
            or price_authority.approver != APPROVER
            or parse_utc_timestamp(price_authority.observed_at, "price observation") > now
            or parse_utc_timestamp(price_authority.expires_at, "price authority expiry") < end
            or not price_authority.source_url.startswith(
                (
                    "https://aws.amazon.com/",
                    "https://docs.aws.amazon.com/",
                    "https://pricing.api.infracost.io/",
                )
            )
        ):
            raise ContractError("COST_RESOURCE_AUTHORITY_NOT_BOUND")
        validate_sha256(price_authority.source_sha256)
        source_references = tuple(
            reference
            for reference in (result.raw_estimate, *result.assumptions)
            if reference.sha256 == price_authority.source_sha256
        )
        if len(source_references) != 1:
            raise ContractError("PRICING_SOURCE_EVIDENCE_REQUIRED")
        source_reference = source_references[0]
        reader.read(source_reference.path, source_reference.sha256, source_reference.byte_count)
        if source_reference.operation_id != basis.operation_id or (
            parse_utc_timestamp(source_reference.created_at, "price source time") > now
            or parse_utc_timestamp(source_reference.valid_until, "price source expiry") < end
        ):
            raise ContractError("PRICING_SOURCE_NOT_CURRENT")
        if entry.classification is CoverageClass.NON_BILLABLE_VERIFIED:
            if (
                basis.components
                or authority.kind != "verified-non-billable-basis"
                or not price_authority.non_billable_reason
            ):
                raise ContractError("COST_NON_BILLABLE_BASIS_CONFLICT")
            continue
        price = resource_prices.get(entry.address) if entry.scope == scope else None
        if price is not None and price_authority.source_sha256 != result.raw_estimate.sha256:
            raise ContractError("PRICING_AUTHORITY_RAW_ESTIMATE_MISMATCH")
        if entry.scope != scope:
            candidates = tuple(
                reference
                for reference in result.assumptions
                if reference.kind == entry.scope + "-infracost-estimate"
                and reference.sha256 == price_authority.source_sha256
            )
            if len(candidates) != 1:
                raise ContractError("BOOTSTRAP_PRICE_CONTRIBUTION_REQUIRED")
            reference = candidates[0]
            other = decode_json_strict(
                reader.read(reference.path, reference.sha256, reference.byte_count)
            )
            parse_infracost_output(other)
            if not isinstance(other, dict):
                raise ContractError("BOOTSTRAP_PRICE_STRUCTURE")
            matching = [
                resource
                for project in cast(list[dict[str, object]], other["projects"])
                for resource in cast(
                    list[dict[str, object]],
                    cast(dict[str, object], project["breakdown"])["resources"],
                )
                if resource.get("name") == entry.address
            ]
            if len(matching) != 1:
                raise ContractError("BOOTSTRAP_PRICE_COVERAGE")
            price = matching[0]
        if price is None:
            raise ContractError("COST_RESOURCE_PRICE_MISSING")
        actual = _resource_charging_components(price)
        if not actual or not basis.components:
            raise ContractError("COST_CHARGING_COMPONENTS_MISSING")
        if set(actual) != {component.name for component in basis.components} or (
            len(actual) != len(basis.components)
        ):
            raise ContractError("COST_CHARGING_COMPONENT_COVERAGE")
        monthly = Decimal("0")
        remaining = Decimal("0")
        for component in basis.components:
            raw_component = actual[component.name]
            rate = _decimal(component.price_usd)
            quantity = _decimal(component.quantity_per_period)
            monthly_quantity = _decimal(component.monthly_quantity)
            if (
                rate is None
                or quantity is None
                or monthly_quantity is None
                or component.unit != raw_component.get("unit")
                or rate != _decimal(raw_component.get("price"))
                or monthly_quantity != _decimal(raw_component.get("monthlyQuantity"))
                or type(component.period_seconds) is not int
                or component.period_seconds <= 0
                or type(component.minimum_periods) is not int
                or component.minimum_periods < 0
            ):
                raise ContractError("COST_CHARGING_UNITS_OR_PRICE")
            component_monthly = rate * monthly_quantity
            if component_monthly != _decimal(raw_component.get("monthlyCost")):
                raise ContractError("COST_COMPONENT_ARITHMETIC")
            periods = max(
                component.minimum_periods,
                (entry.duration_seconds + component.period_seconds - 1) // component.period_seconds,
            )
            monthly += component_monthly
            remaining += rate * quantity * periods
        if monthly != _decimal(entry.monthly_usd) or remaining != _decimal(entry.remaining_usd):
            raise ContractError("COST_WINDOW_ARITHMETIC_MISMATCH")
    reconcile_exposure_basis(result, reader, now)


def _resource_charging_components(price: dict[str, object]) -> dict[str, dict[str, object]]:
    """Include child storage/usage charges without counting their parent total twice."""
    actual: dict[str, dict[str, object]] = {}

    def collect(resource: dict[str, object], path: tuple[str, ...]) -> None:
        components = resource.get("costComponents", [])
        children = resource.get("subresources", [])
        if not isinstance(components, list) or not isinstance(children, list):
            raise ContractError("COST_CHARGING_COMPONENT_STRUCTURE")
        for component in components:
            if not isinstance(component, dict) or not isinstance(component.get("name"), str):
                raise ContractError("COST_CHARGING_COMPONENT_MALFORMED")
            name = component["name"]
            # Tuple encoding preserves exact child spelling and avoids slash collisions.
            identity = (
                canonical_json_bytes((*path, name)).decode("utf-8").removesuffix("\n")
                if path
                else name
            )
            if not name or identity in actual:
                raise ContractError("COST_CHARGING_COMPONENT_DUPLICATED")
            actual[identity] = component
        child_names: set[str] = set()
        for child in children:
            if not isinstance(child, dict) or not isinstance(child.get("name"), str):
                raise ContractError("COST_SUBRESOURCE_STRUCTURE")
            name = child["name"]
            if not name or name in child_names:
                raise ContractError("COST_SUBRESOURCE_DUPLICATED")
            child_names.add(name)
            collect(child, (*path, name))

    collect(price, ())
    return actual


def reconcile_cost_inventory(
    result: CostResultV2,
    scope: str,
    reader: EvidenceReader,
    now: datetime,
) -> None:
    """Retained bootstrap/platform resources cannot disappear from lifecycle accounting."""
    from .lifecycle_models import InventoryResult

    other_scope = "bootstrap" if scope == "platform" else "platform"
    proofs = [
        reference
        for reference in result.assumptions
        if reference.kind == f"current-{other_scope}-inventory"
    ]
    if len(proofs) != 1:
        raise ContractError("OTHER_SCOPE_COST_INVENTORY_REQUIRED")
    proof = proofs[0]
    inventory = decode_operational_record(
        reader.read(proof.path, proof.sha256, proof.byte_count), InventoryResult
    )
    if (
        inventory.operation_id != result.raw_estimate.operation_id
        or inventory.account_id != "526338061652"
        or (
            inventory.region != "ap-southeast-1"
            or inventory.incomplete_services
            or not inventory.covered_services
            or not 0
            <= (
                now - parse_utc_timestamp(inventory.observed_at, "cost inventory observation")
            ).total_seconds()
            <= 900
            or parse_utc_timestamp(inventory.valid_until, "cost inventory expiry") <= now
            or len({entry.address for entry in inventory.entries}) != len(inventory.entries)
            or any(
                entry.ownership != "PROJECT_MANAGED"
                or entry.presence
                not in {"PRESENT", "ABSENT", "PENDING_DELETION", "EVALUATION_ONLY"}
                for entry in inventory.entries
            )
        )
    ):
        raise ContractError("OTHER_SCOPE_COST_INVENTORY_INCOMPLETE")
    required = {
        entry.address
        for entry in inventory.entries
        if entry.presence in {"PRESENT", "PENDING_DELETION"}
    }
    if required != {entry.address for entry in result.coverage if entry.scope == other_scope}:
        raise ContractError("OTHER_SCOPE_COST_COVERAGE_MISMATCH")


def reconcile_exposure_basis(result: CostResultV2, reader: EvidenceReader, now: datetime) -> None:
    """Validate separate incurred/recovery/retention totals and reject duplicate exposure."""
    from .lifecycle_models import ExposureBasis

    references = tuple(
        reference
        for reference in result.assumptions
        if reference.kind == "lifecycle-exposure-basis"
    )
    if len(references) != 1:
        raise ContractError("LIFECYCLE_EXPOSURE_BASIS_REQUIRED")
    reference = references[0]
    basis = decode_operational_record(
        reader.read(reference.path, reference.sha256, reference.byte_count), ExposureBasis
    )
    if (
        basis.operation_id != result.raw_estimate.operation_id
        or basis.account_id != "526338061652"
        or basis.currency != "USD"
        or basis.approver != APPROVER
        or basis.billing_observed_at != result.billing_observed_at
        or basis.billing_lag_seconds != result.billing_lag_seconds
        or parse_utc_timestamp(basis.approved_at, "exposure approval") > now
        or parse_utc_timestamp(basis.expires_at, "exposure expiry")
        < parse_utc_timestamp(result.valid_until, "cost expiry")
    ):
        raise ContractError("LIFECYCLE_EXPOSURE_BINDING")
    totals = {
        "INCURRED": Decimal("0"),
        "RECOVERY_ONE_OFF": Decimal("0"),
        "TEARDOWN_RETENTION": Decimal("0"),
    }
    windows: dict[tuple[str, str], tuple[datetime, datetime]] = {}
    for entry in result.coverage:
        if entry.basis is None:
            raise ContractError("EXPOSURE_RESOURCE_WINDOW_REQUIRED")
        charge = decode_operational_record(
            reader.read(entry.basis.path, entry.basis.sha256, entry.basis.byte_count), ChargingBasis
        )
        windows[(entry.scope, entry.address)] = (
            parse_utc_timestamp(charge.window_start, "remaining start"),
            parse_utc_timestamp(charge.window_end, "remaining end"),
        )
    intervals: dict[tuple[str, str, str], list[tuple[datetime, datetime]]] = {}
    for component in basis.components:
        if (
            component.category not in totals
            or component.scope not in {"bootstrap", "platform"}
            or not component.address
        ):
            raise ContractError("EXPOSURE_COMPONENT_SCOPE")
        amount = _decimal(component.amount_usd)
        start = parse_utc_timestamp(component.start, "exposure start")
        end = parse_utc_timestamp(component.end, "exposure end")
        if amount is None or end < start or component.source.operation_id != basis.operation_id:
            raise ContractError("EXPOSURE_COMPONENT_INVALID")
        window = windows.get((component.scope, component.address))
        if window is None:
            raise ContractError("EXPOSURE_RESOURCE_NOT_COVERED")
        if component.category == "INCURRED" and end > window[0]:
            raise ContractError("INCURRED_EXPOSURE_OVERLAPS_REMAINING")
        if component.category == "TEARDOWN_RETENTION" and start < window[1]:
            raise ContractError("RETENTION_EXPOSURE_OVERLAPS_REMAINING")
        reader.read(component.source.path, component.source.sha256, component.source.byte_count)
        key = component.scope, component.address, component.category
        prior = intervals.setdefault(key, [])
        if (
            any(start < other_end and other_start < end for other_start, other_end in prior)
            or (start, end) in prior
        ):
            raise ContractError("EXPOSURE_DOUBLE_COUNTED")
        prior.append((start, end))
        totals[component.category] += amount
        if component.category == "INCURRED" and end > parse_utc_timestamp(
            result.observed_at, "cost observation"
        ):
            raise ContractError("INCURRED_EXPOSURE_OVERLAPS_REMAINING")
    represented = {component.category for component in basis.components}
    if (
        len(set(basis.zero_categories)) != len(basis.zero_categories)
        or represented.intersection(basis.zero_categories)
        or represented.union(basis.zero_categories) != set(totals)
    ):
        raise ContractError("EXPOSURE_CATEGORY_COVERAGE")
    if (totals["INCURRED"], totals["RECOVERY_ONE_OFF"], totals["TEARDOWN_RETENTION"]) != (
        _decimal(result.incurred_usd),
        _decimal(result.recovery_usd),
        _decimal(result.teardown_retention_usd),
    ):
        raise ContractError("EXPOSURE_TOTAL_MISMATCH")


def reconcile_incurred_coverage(
    result: CostResultV2,
    native: InventoryResult,
    scope: str,
    reader: EvidenceReader,
) -> None:
    """Existing billable resources need exposure through the remaining-window boundary."""
    from .lifecycle_models import ExposureBasis

    exposure_refs = tuple(
        ref for ref in result.assumptions if ref.kind == "lifecycle-exposure-basis"
    )
    other_scope = "bootstrap" if scope == "platform" else "platform"
    other_refs = tuple(
        ref for ref in result.assumptions if ref.kind == f"current-{other_scope}-inventory"
    )
    if len(exposure_refs) != 1 or len(other_refs) != 1:
        raise ContractError("INCURRED_RESOURCE_EVIDENCE_REQUIRED")
    exposure_ref, other_ref = exposure_refs[0], other_refs[0]
    basis = decode_operational_record(
        reader.read(
            exposure_ref.path,
            exposure_ref.sha256,
            exposure_ref.byte_count,
        ),
        ExposureBasis,
    )
    other = decode_operational_record(
        reader.read(
            other_ref.path,
            other_ref.sha256,
            other_ref.byte_count,
        ),
        InventoryResult,
    )
    existing = {
        (inventory_scope, entry.address)
        for inventory_scope, inventory in ((scope, native), (other_scope, other))
        for entry in inventory.entries
        if entry.presence in {"PRESENT", "PENDING_DELETION"}
    }
    if result.billing_observed_at is None or type(result.billing_lag_seconds) is not int:
        raise ContractError("BILLING_OBSERVATION_OR_LAG_UNKNOWN")
    if result.billing_lag_seconds < 0:
        raise ContractError("BILLING_LAG_INVALID")
    observed = parse_utc_timestamp(result.billing_observed_at, "billing observation")
    billing_cutoff = observed - timedelta(seconds=result.billing_lag_seconds)
    for entry in result.coverage:
        if (entry.scope, entry.address) not in existing or (
            entry.classification is CoverageClass.NON_BILLABLE_VERIFIED
        ):
            continue
        if entry.basis is None:
            raise ContractError("INCURRED_RESOURCE_WINDOW_REQUIRED")
        charge = decode_operational_record(
            reader.read(
                entry.basis.path,
                entry.basis.sha256,
                entry.basis.byte_count,
            ),
            ChargingBasis,
        )
        remaining_start = parse_utc_timestamp(charge.window_start, "remaining start")
        intervals = sorted(
            (
                parse_utc_timestamp(item.start, "incurred start"),
                parse_utc_timestamp(item.end, "incurred end"),
            )
            for item in basis.components
            if (item.scope, item.address, item.category) == (entry.scope, entry.address, "INCURRED")
        )
        if (
            not intervals
            or intervals[0][0] > billing_cutoff
            or (
                intervals[-1][1] != remaining_start
                or any(
                    left[1] != right[0]
                    for left, right in zip(
                        intervals,
                        intervals[1:],
                        strict=False,
                    )
                )
            )
        ):
            raise ContractError("INCURRED_OR_BILLING_LAG_EXPOSURE_UNCOVERED")


def collect_public_charging_pages(repository: Path, external: Path) -> tuple[str, str]:
    """One anonymous, redirect-free approved retrieval; no page becomes an attested rate."""
    import re
    from datetime import UTC
    from html.parser import HTMLParser

    from .aws_live import fetch_public_charging_pages
    from .lifecycle_io import reserve_operation_directory, write_canonical_json_atomic

    class PageText(HTMLParser):
        def __init__(self) -> None:
            super().__init__()
            self.ignored = 0
            self.parts: list[str] = []

        def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
            if tag in {"script", "style"}:
                self.ignored += 1

        def handle_endtag(self, tag: str) -> None:
            if tag in {"script", "style"}:
                self.ignored = max(0, self.ignored - 1)

        def handle_data(self, data: str) -> None:
            if not self.ignored:
                clean = " ".join(data.split())
                if clean and re.search(
                    r"\$|Singapore|minimum|deletion|prorat|hour|storage", clean, re.I
                ):
                    self.parts.append(clean[:1000])

    root = external / "consolidated-remediation-001" / "pricing-basis-002"
    ensure_external_path(root, external, repository)
    request = {
        "urls": PUBLIC_CHARGING_PAGES,
        "requests": 12,
        "bytes_per_response": 2097152,
        "seconds": 300,
        "authentication": False,
        "redirects": False,
    }
    request_hash = sha256_bytes(canonical_json_bytes(request))
    reserve_operation_directory(root, external, repository)
    rows, requests, elapsed = fetch_public_charging_pages()
    for row in rows:
        row.update(verified_rate=None, applicability="NOT_ESTABLISHED")
        body = row.pop("body", None)
        if isinstance(body, bytes):
            parser = PageText()
            parser.feed(body.decode("utf-8", errors="replace"))
            row.update(
                response_bytes=len(body),
                response_sha256=sha256_bytes(body),
                excerpts=parser.parts[:30],
            )
    observed = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    report_hash = write_canonical_json_atomic(
        root / "charging-rates.json",
        {
            "schema_version": "w5-004.public-charging.v1",
            "cycle": "W5-CYCLE-A",
            "observed_at": observed,
            "request_sha256": request_hash,
            "sources": rows,
            "unrequested_urls": list(PUBLIC_CHARGING_PAGES[len(rows) :]),
            "verified_rates": [],
            "cost_eligibility": "NOT_ESTABLISHED",
        },
        allowed_root=external,
        repository_root=repository,
    )
    identity_hash = write_canonical_json_atomic(
        root / "pricing-identity.json",
        {
            "request": request,
            "request_sha256": request_hash,
            "report_sha256": report_hash,
            "requests": requests,
            "elapsed_seconds": elapsed,
            "raw_html_retained": False,
            "credentials_accessed": False,
        },
        allowed_root=external,
        repository_root=repository,
    )
    return report_hash, identity_hash


def cycle_required_charge_ids() -> frozenset[str]:
    """Minimum known billable inventory; caller-provided totals cannot shrink coverage."""
    groups = {
        "module.ecr.aws_ecr_repository.this": 1,
        "module.kms.aws_kms_key.this": 4,
        "module.opensearch.aws_opensearch_domain.this": 3,
        "module.storage.aws_s3_bucket.this": 5,
    }
    for name in ("application", "audit", "index_slow", "search_slow"):
        groups[f'module.opensearch.aws_cloudwatch_log_group.this["{name}"]'] = 3
    for name in (
        "Bedrock Runtime",
        "CloudWatch Logs",
        "ECR API",
        "ECR DKR",
        "EKS",
        "KMS",
        "STS",
        "Secrets Manager",
    ):
        groups[f'module.network.aws_vpc_endpoint.interface["{name}"]'] = 2
    return frozenset(
        [
            f"{address}/component-{number}"
            for address, count in groups.items()
            for number in range(1, count + 1)
        ]
        + [
            "historical-account-reservation",
            "bootstrap-storage",
            "bootstrap-requests",
            "bootstrap-dynamodb",
            "bootstrap-kms",
            "diagnostic-requests",
            "data-transfer",
            "ecr-scanning",
            "terminal-s3",
            "terminal-kms",
            "terminal-archive",
        ]
    )


def calculate_cycle_charges(
    basis: object, *, reader: EvidenceReader, now: datetime, final_requests: int
) -> dict[str, object]:
    """Recompute supported components; unknown exposure and allowances never become zero."""
    from decimal import ROUND_CEILING

    from .lifecycle_models import CycleChargingEvidence

    categories = (
        "HISTORICAL_ACCOUNT_RESERVATION",
        "POST_CUTOFF_FIXED",
        "POST_CUTOFF_VARIABLE_AND_DIAGNOSTICS",
        "RETAINED_TAIL",
    )
    if (
        not isinstance(basis, CycleChargingEvidence)
        or basis.cycle != "W5-CYCLE-A"
        or basis.currency != "USD"
    ):
        raise ContractError("CYCLE_CHARGING_SCOPE")
    if type(final_requests) is not int or final_requests < 0:
        raise ContractError("CYCLE_CHARGING_REQUESTS")
    if parse_utc_timestamp(basis.observed_at, "charging observation") > now:
        raise ContractError("CYCLE_CHARGING_FUTURE_EVIDENCE")
    required = set(basis.required_components)
    if not required or len(required) != len(basis.required_components):
        raise ContractError("CYCLE_CHARGING_REQUIRED_COVERAGE")
    seen: set[str] = set()
    intervals: dict[tuple[str, str], list[tuple[datetime, datetime]]] = {}
    totals = dict.fromkeys(categories, Decimal(0))
    rows: list[dict[str, object]] = []
    missing: list[dict[str, str]] = []

    def source(ref: EvidenceRef | None) -> dict[str, object] | None:
        if ref is None:
            return None
        if parse_utc_timestamp(ref.valid_until, "charging validity") <= now:
            return None
        value = decode_json_strict(reader.read(ref.path, ref.sha256, ref.byte_count))
        return value if isinstance(value, dict) else None

    for item in basis.components:
        if (
            item.component_id in seen
            or item.component_id not in required
            or item.category not in categories
        ):
            raise ContractError("CYCLE_CHARGING_DUPLICATE_OR_SCOPE")
        seen.add(item.component_id)
        absent: list[str] = []
        start = parse_utc_timestamp(item.start, "charge start")
        end = parse_utc_timestamp(item.end, "charge end") if item.end is not None else None
        if end is None:
            absent.append("FINITE_END")
        else:
            if end <= start:
                raise ContractError("CYCLE_CHARGING_INTERVAL")
            cutoff = parse_utc_timestamp("2026-09-13T00:00:00Z", "cutoff")
            boundary = parse_utc_timestamp("2026-09-14T12:00:00Z", "retention")
            if (
                (
                    item.category == categories[0]
                    and (
                        start < parse_utc_timestamp("2026-09-08T00:00:00Z", "start") or end > cutoff
                    )
                )
                or (item.category in categories[1:3] and (start < cutoff or end > boundary))
                or (item.category == categories[3] and start < boundary)
            ):
                raise ContractError("CYCLE_CHARGING_INTERVAL")
            # Component identity is the stable charging basis, not the reporting bucket.
            key = (item.resource, item.charge_basis)
            prior = intervals.setdefault(key, [])
            if prior:
                # The producer must consolidate a charge basis before applying its minimum.
                raise ContractError("CYCLE_CHARGING_OVERLAP_OR_SPLIT_MINIMUM")
            prior.append((start, end))
        numbers: list[Decimal | None] = []
        for field, value in (
            ("QUANTITY", item.quantity),
            ("RATE", item.rate_usd),
            ("QUANTUM", item.quantum),
            ("MINIMUM", item.minimum),
        ):
            if value is None:
                absent.append(field)
                numbers.append(None)
                continue
            if not isinstance(value, str):
                raise ContractError("CYCLE_CHARGING_NUMBER")
            number = _decimal(value)
            if (
                number is None
                or not number.is_finite()
                or number < 0
                or (field == "QUANTUM" and number == 0)
            ):
                raise ContractError("CYCLE_CHARGING_NUMBER")
            numbers.append(number)
        price, quantity = source(item.rate_source), source(item.quantity_source)
        if (
            price is None
            or any(
                price.get(k) != v
                for k, v in (
                    ("component_id", item.component_id),
                    ("unit", item.unit),
                    ("rate_usd", item.rate_usd),
                    ("charge_basis", item.charge_basis),
                    ("quantum", item.quantum),
                    ("minimum", item.minimum),
                    ("cycle", "W5-CYCLE-A"),
                )
            )
            or not isinstance(price.get("provenance"), dict)
            or not price["provenance"]
        ):
            absent.append("SUPPORTED_RATE_AND_MINIMA")
        if (
            quantity is None
            or any(
                quantity.get(k) != v
                for k, v in (
                    ("component_id", item.component_id),
                    ("resource", item.resource),
                    ("quantity", item.quantity),
                    ("start", item.start),
                    ("end", item.end),
                    ("cycle", "W5-CYCLE-A"),
                )
            )
            or not isinstance(quantity.get("basis"), dict)
            or not quantity["basis"]
        ):
            absent.append("SUPPORTED_QUANTITY")
        if item.allowance and (
            quantity is None
            or quantity.get("approver") != APPROVER
            or not quantity.get("covered_uncertainty")
        ):
            absent.append("JUSTIFIED_ALLOWANCE")
        if item.category == "RETAINED_TAIL":
            terminal = source(basis.terminal_disposition)
            if (
                terminal is None
                or terminal.get("status") != "APPROVED_FINITE_DISPOSITION"
                or terminal.get("end") != item.end
            ):
                absent.append("TERMINAL_DISPOSITION")
        if item.component_id == "diagnostic-requests" and (
            quantity is None
            or type(quantity.get("requests_including_preservation")) is not int
            or cast(int, quantity["requests_including_preservation"]) < final_requests
        ):
            absent.append("FINAL_REQUESTS_NOT_COVERED")
        amount: Decimal | None = None
        if not absent:
            q, rate, quantum, minimum = cast(list[Decimal], numbers)
            amount = (
                max(minimum, (q / quantum).to_integral_value(rounding=ROUND_CEILING) * quantum)
                * rate
            )
            totals[item.category] += amount
        rows.append(
            {
                "component_id": item.component_id,
                "resource": item.resource,
                "category": item.category,
                "supported_usd": str(amount) if amount is not None else None,
                "unit": item.unit,
                "rate_usd": item.rate_usd,
                "quantity": item.quantity,
                "quantum": item.quantum,
                "minimum": item.minimum,
                "start": item.start,
                "end": item.end,
                "allowance": item.allowance,
                "attribution": "ACCOUNT_NOT_PROJECT_ACTUAL"
                if item.category == categories[0]
                else "W5_CYCLE_A_EXPOSURE",
                "missing": absent,
            }
        )
        missing.extend({"component_id": item.component_id, "missing": field} for field in absent)
    missing.extend(
        {"component_id": name, "missing": "COMPONENT_NOT_SUPPLIED"}
        for name in sorted(required - seen)
    )
    total = sum(totals.values())
    # Each accounting partition must be supported, including justified zero exposure.
    for category in categories:
        if not any(item.category == category for item in basis.components):
            missing.append({"component_id": category, "missing": "CATEGORY_NOT_SUPPLIED"})
    return {
        "cycle": "W5-CYCLE-A",
        "currency": "USD",
        "ceiling_usd": "30.00",
        "components": rows,
        "category_supported_subtotals": {k: str(v) for k, v in totals.items()},
        "supported_partial_total_usd": str(total),
        "missing": missing,
        "supported_total_bound_usd": str(total) if not missing else None,
        "available_headroom_usd": str(Decimal(30) - total) if not missing and total <= 30 else None,
        "status": "FAIL" if total > 30 else "INDETERMINATE" if missing else "PASS",
        "final_diagnostic_requests": final_requests,
        "attributable_incurred_usd": None,
    }


def validate_prerequisite_cost_bound(
    raw: bytes,
    total: Decimal,
    now: datetime,
    reader: EvidenceReader,
) -> None:
    """Four disjoint charging scopes; allocations and unknown values cannot be bounds."""
    from .lifecycle_io import decode_operational_record
    from .lifecycle_models import CycleCostBoundBasis

    basis = decode_operational_record(raw, CycleCostBoundBasis)
    if basis.charging_evidence is None:
        raise ContractError("CYCLE_COST_ARITHMETIC_EVIDENCE_REQUIRED")
    from .lifecycle_models import CycleChargingEvidence

    ref = basis.charging_evidence
    if parse_utc_timestamp(ref.valid_until, "charging evidence validity") <= now:
        raise ContractError("CYCLE_COST_AUTHORITY_EXPIRED")
    charging = decode_operational_record(
        reader.read(ref.path, ref.sha256, ref.byte_count), CycleChargingEvidence
    )
    if not cycle_required_charge_ids() <= set(charging.required_components):
        raise ContractError("CYCLE_COST_RESOURCE_COVERAGE_INCOMPLETE")
    calculated = calculate_cycle_charges(charging, reader=reader, now=now, final_requests=0)
    if calculated["status"] != "PASS" or _decimal(calculated["supported_total_bound_usd"]) != total:
        raise ContractError("CYCLE_COST_ARITHMETIC_NOT_RECONCILED")
    categories = (
        "HISTORICAL_ACCOUNT_RESERVATION",
        "POST_CUTOFF_FIXED",
        "POST_CUTOFF_VARIABLE_AND_DIAGNOSTICS",
        "RETAINED_TAIL",
    )
    if (
        basis.cycle != "W5-CYCLE-A"
        or basis.currency != "USD"
        or tuple(row.category for row in basis.entries) != categories
        or not basis.charging_minima_verified
        or not basis.billing_lag_bounded
        or parse_utc_timestamp(basis.observed_at, "cost basis") > now
        or not basis.sources
    ):
        raise ContractError("CYCLE_COST_BASIS_UNSUPPORTED")
    sources = {ref.path: ref for ref in basis.sources}
    if len(sources) != len(basis.sources):
        raise ContractError("CYCLE_COST_BASIS_DUPLICATED")
    for ref in (*basis.sources, basis.retained_terminal_disposition):
        if parse_utc_timestamp(ref.valid_until, "cost authority expiry") <= now:
            raise ContractError("CYCLE_COST_AUTHORITY_EXPIRED")
        reader.read(ref.path, ref.sha256, ref.byte_count)
    cutoff = parse_utc_timestamp("2026-09-13T00:00:00Z", "billing cutoff")
    boundary = parse_utc_timestamp("2026-09-14T12:00:00Z", "retention deadline")
    amounts: list[Decimal] = []
    for index, row in enumerate(basis.entries):
        amount = _decimal(row.upper_bound_usd)
        if (
            amount is None
            or row.limitation
            or row.source not in sources
            or (row.start is None or row.end is None)
        ):
            raise ContractError("CYCLE_COST_EXPOSURE_UNBOUNDED")
        start = parse_utc_timestamp(row.start, "exposure start")
        end = parse_utc_timestamp(row.end, "exposure end")
        expected_start = (
            parse_utc_timestamp("2026-09-08T00:00:00Z", "history start")
            if index == 0
            else boundary
            if index == 3
            else cutoff
        )
        if (
            start != expected_start
            or end <= start
            or (index == 0 and end != cutoff)
            or (index in {1, 2} and end != boundary)
            or (row.scope != ("ACCOUNT_NOT_PROJECT_ACTUAL" if index == 0 else "W5_CYCLE_A"))
        ):
            raise ContractError("CYCLE_COST_INTERVAL_OR_SCOPE_OVERLAP")
        amounts.append(amount)
        subtotals = cast(dict[str, str], calculated["category_supported_subtotals"])
        if amount != _decimal(subtotals[row.category]):
            raise ContractError("CYCLE_COST_CATEGORY_NOT_RECONCILED")
    if not total.is_finite() or not 0 <= total <= Decimal("30") or sum(amounts) != total:
        raise ContractError("CYCLE_COST_TOTAL_NOT_RECONCILED")


def resolution_cost_ledger(
    billing: Mapping[str, object], now: datetime, requests: int, *, cycle: str = "W5-CYCLE-A"
) -> ResolutionCostLedger:
    """One billing view, disjoint periods; no account-to-project attribution fiction."""
    if cycle != "W5-CYCLE-A" or type(requests) is not int or not 0 <= requests <= 3:
        raise ContractError("RESOLUTION_COST_AUTHORITY_INVALID")
    end = parse_utc_timestamp("2026-09-13T00:00:00Z", "billing end")
    if now.tzinfo is None or now < end:
        raise ContractError("RESOLUTION_COST_INTERVAL_INVALID")
    account: Decimal | None = None
    if billing.get("complete") is True:
        if (
            billing.get("start_inclusive") != "2026-09-08"
            or billing.get("end_exclusive") != "2026-09-13"
        ):
            raise ContractError("RESOLUTION_COST_INTERVAL_INVALID")
        days = billing.get("days")
        if not isinstance(days, list) or len(days) != 5:
            raise ContractError("RESOLUTION_COST_INTERVAL_INVALID")
        intervals: set[str] = set()
        account = Decimal("0")
        for day in days:
            if not isinstance(day, dict) or not isinstance(day.get("start"), str):
                raise ContractError("RESOLUTION_COST_INTERVAL_INVALID")
            start = day["start"]
            if start in intervals:
                raise ContractError("RESOLUTION_COST_OVERLAP")
            intervals.add(start)
            expected_end = datetime.fromisoformat(start) + timedelta(days=1)
            if (
                day.get("end") != expected_end.date().isoformat()
                or not "2026-09-08" <= start < "2026-09-13"
            ):
                raise ContractError("RESOLUTION_COST_INTERVAL_INVALID")
            amounts = day.get("amounts")
            if not isinstance(amounts, list):
                raise ContractError("RESOLUTION_COST_AMOUNT_INVALID")
            keys: set[tuple[str, ...]] = set()
            for row in amounts:
                if not isinstance(row, dict) or not isinstance(row.get("group"), list):
                    raise ContractError("RESOLUTION_COST_AMOUNT_INVALID")
                key = tuple(row["group"])
                if key in keys:
                    raise ContractError("RESOLUTION_COST_OVERLAP")
                keys.add(key)
                try:
                    value = Decimal(row["unblended_usd"])
                except (InvalidOperation, TypeError, KeyError) as exc:
                    raise ContractError("RESOLUTION_COST_AMOUNT_INVALID") from exc
                if not value.is_finite():
                    raise ContractError("RESOLUTION_COST_AMOUNT_INVALID")
                account += value
    observed = str(account) if account is not None else None
    timestamp = now.isoformat()
    entries = (
        ResolutionLedgerEntry(
            "HISTORICAL_ACCOUNT_RESERVATION",
            "2026-09-08T00:00:00Z",
            "2026-09-13T00:00:00Z",
            "ACCOUNT_NOT_PROJECT_ACTUAL",
            "billing/usage",
            observed,
            None,
            "ESTIMATED_NET_ACCOUNT_TOTAL_CREDITS_AND_LAG_PREVENT_PROVEN_UPPER_BOUND",
        ),
        ResolutionLedgerEntry(
            "LATER_INCURRED_EXPOSURE",
            "2026-09-13T00:00:00Z",
            timestamp,
            "W5_CYCLE_A",
            "COLLECTION_CUTOFF",
            None,
            None,
            "UNCOVERED_INCLUDES_UNBILLED_DIAGNOSTICS_DO_NOT_ADD_THEM_TWICE",
        ),
        ResolutionLedgerEntry(
            "REMAINING_EXECUTION_TESTING",
            timestamp,
            None,
            "W5_CYCLE_A",
            "HISTORICAL_PRICING_NOT_CURRENT_USAGE_BOUND",
            None,
            None,
            "FUTURE_PLAN_TIMES_AND_USAGE_NOT_APPROVED",
        ),
        ResolutionLedgerEntry(
            "TEARDOWN",
            None,
            None,
            "W5_CYCLE_A",
            "SEPARATE_TEARDOWN_DECISION",
            None,
            None,
            "NO_APPROVED_START_END_OR_CHARGING_BOUND",
        ),
        ResolutionLedgerEntry(
            "RETAINED_AFTER_TEARDOWN",
            None,
            None,
            "W5_CYCLE_A",
            "SEPARATE_RETENTION_DECISION",
            None,
            None,
            "BOOTSTRAP_AND_OTHER_RETENTION_EXPOSURE_UNBOUNDED",
        ),
    )
    return ResolutionCostLedger(
        "w5-004.resolution-cost-ledger.v1",
        cycle,
        "USD",
        "30.00",
        "INFORMATIONAL",
        entries,
        observed,
        None,
        None,
        None,
        requests,
    )
