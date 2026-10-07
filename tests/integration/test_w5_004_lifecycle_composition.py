"""Integration tests for Terraform argv, plan JSON, policy, and cost composition."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import cast

import pytest
from tools.platformctl import deploy
from tools.platformctl.contracts import ApprovalRecord, ContractError, MutationRequest
from tools.platformctl.cost import parse_infracost_output, validate_terraform_plan_json
from tools.platformctl.lifecycle_io import canonical_json_bytes
from tools.platformctl.lifecycle_models import Outcome
from tools.platformctl.operation_state import OperationLedger
from tools.platformctl.policy_runner import (
    PLATFORM_POLICY_DOCUMENT_BINDINGS,
    PLATFORM_POLICY_DOCUMENT_CALL_EXPRESSION_SHA256,
    PLATFORM_POLICY_DOCUMENT_EXPRESSION_SHA256,
    PLATFORM_POLICY_DOCUMENT_PLANNED_INPUT_SHA256,
    normalize_plan,
    summarize_plan,
)
from tools.platformctl.terraform_runner import ProcessResult, TerraformRunner

from tests.fakes.platform_lifecycle import FakeCommandRunner
from tests.security import test_w5_004_lifecycle_security as lifecycle_security_tests
from tests.security.test_w5_004_lifecycle_security import (
    ecr_kms_reference_plan,
    opensearch_log_reference_plan,
)

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize(
    "failure", ["none", "resource", "routing", "state_drift", "missing_context"]
)
@pytest.mark.parametrize("correction", [False, True])
def test_prerequisite_production_dispatch_to_preserved_reports(
    tmp_path, monkeypatch, capsys, failure, correction
):
    from io import BytesIO

    from tools.platformctl import cli, lifecycle_io
    from tools.platformctl import plan as production
    from tools.platformctl.aws_inventory import (
        PREREQUISITE_CHECK_IDS,
        PREREQUISITE_CORRECTION_CHECK_IDS,
        PREREQUISITE_CORRECTION_DIRECTORY,
        PREREQUISITE_CORRECTION_OPERATION,
        PREREQUISITE_DIRECTORY,
        PREREQUISITE_OPERATION_ID,
        PREREQUISITE_POLICY,
        PREREQUISITE_ROLES,
        PREREQUISITE_ROUTES,
        RESOLUTION_FOLLOWUP_DIRECTORY,
        RESOLUTION_FOLLOWUP_OPERATION_ID,
        diagnostic_discovery_profile,
        diagnostic_policy_templates,
        diagnostic_resource_profile,
    )
    from tools.platformctl.aws_live import (
        PREREQUISITE_METHODS,
        Boto3AwsInventoryProvider,
        DiagnosticFatalError,
        DiagnosticReadError,
    )
    from tools.platformctl.lifecycle_models import (
        DIAGNOSTIC_SCHEMA_VERSION,
        DiagnosticRequest,
        DiagnosticRuntimeConfiguration,
    )

    from tests.fakes.platform_lifecycle import (
        CompleteDiagnosticAwsFixture,
        reviewed_package_fixture,
    )

    repository, external = tmp_path / "repo", tmp_path / "external"
    repository.mkdir()
    external.mkdir()
    parent = external / "consolidated-remediation-001"
    lifecycle_io.reserve_operation_directory(parent, external, repository)
    previous = parent / (PREREQUISITE_DIRECTORY if correction else RESOLUTION_FOLLOWUP_DIRECTORY)
    lifecycle_io.reserve_operation_directory(previous, external, repository)
    source_rows = [
        {"resource": name, "relationship": "INSUFFICIENT_EVIDENCE"}
        for name in (*PREREQUISITE_ROLES, PREREQUISITE_POLICY, PREREQUISITE_ROUTES[1])
    ]
    old = {
        "schema_version": "w5-004.prerequisite-resolution.v1"
        if correction
        else "w5-004.targeted-resolution.v2",
        "operation_id": PREREQUISITE_OPERATION_ID
        if correction
        else RESOLUTION_FOLLOWUP_OPERATION_ID,
        "checks": [{"check_id": "retained", "details": [["resources", json.dumps(source_rows)]]}],
    }
    raw = canonical_json_bytes(old)
    identity = canonical_json_bytes(
        {
            "schema_version": old["schema_version"],
            "operation_id": old["operation_id"],
            "report_sha256": sha256(raw).hexdigest(),
        }
    )
    bindings = []
    for name, data in (("resolution.json", raw), ("resolution-identity.json", identity)):
        lifecycle_io.write_canonical_json_atomic(
            previous / name, json.loads(data), allowed_root=external, repository_root=repository
        )
        bindings.append(
            ("prerequisite/previous/" + name, str(previous / name), sha256(data).hexdigest())
        )
    fixture = CompleteDiagnosticAwsFixture()
    platform_state = cast(dict[str, object], json.loads(fixture.states["platform"]))
    platform_resources = cast(list[dict[str, object]], platform_state["resources"])
    kms_resource = next(
        row
        for row in platform_resources
        if row.get("module") == "module.kms"
        and row.get("type") == "aws_kms_key"
        and row.get("name") == "this"
    )
    kms_policy = diagnostic_policy_templates("platform")["kms"]
    kms_instances = cast(list[dict[str, object]], kms_resource["instances"])
    kms_attributes = cast(dict[str, object], kms_instances[0]["attributes"])
    kms_attributes["policy"] = json.dumps(kms_policy)
    fixture.states["platform"] = canonical_json_bytes(platform_state)
    projection = production._state_identity_projection(fixture.states["platform"])
    real_reply = fixture.reply
    state_reads = []

    def reply(service, method, args):
        assert method in PREREQUISITE_METHODS[service]
        if method == "describe_route_tables":
            if failure == "routing":
                raise DiagnosticFatalError("DIAGNOSTIC_INITIAL_HOST_NOT_APPROVED")
            return {
                "RouteTables": [
                    {
                        "RouteTableId": value,
                        "OwnerId": "526338061652",
                        "VpcId": projection["module.network.aws_vpc.this"]["id"],
                        "Associations": [{"Main": value == PREREQUISITE_ROUTES[1]}],
                    }
                    for value in PREREQUISITE_ROUTES
                ]
            }
        if method == "get_role":
            if failure == "resource" and args["RoleName"] == PREREQUISITE_ROLES[0]:
                raise DiagnosticReadError("AccessDenied")
            return {
                "Role": {
                    "RoleName": args["RoleName"],
                    "Arn": "arn:aws:iam::526338061652:role/" + args["RoleName"],
                }
            }
        if method == "list_entities_for_policy":
            return {
                "PolicyRoles": [{"RoleName": PREREQUISITE_ROLES[-1]}],
                "PolicyUsers": [],
                "PolicyGroups": [],
                "IsTruncated": False,
            }
        if method == "get_user":
            if correction and failure == "routing":
                raise DiagnosticFatalError("DIAGNOSTIC_INITIAL_HOST_NOT_APPROVED")
            return {"User": {"Arn": "arn:aws:iam::526338061652:user/finopsinfra"}}
        if method == "get_context_keys_for_principal_policy":
            return {"ContextKeyNames": ["aws:RequestedRegion", "aws:RequestTag/ExpiresAt"]}
        if method == "simulate_principal_policy":
            import botocore.parsers
            import botocore.session

            from tests.security.test_w5_004_lifecycle_security import iam_simulation_xml

            shape = (
                botocore.session.Session()
                .get_service_model("iam")
                .operation_model("SimulatePrincipalPolicy")
                .output_shape
            )
            wire = iam_simulation_xml(
                args["ActionNames"][0],
                args["ResourceArns"],
                change="context" if failure == "missing_context" else "none",
            )
            return botocore.parsers.create_parser("query").parse(
                {"status_code": 200, "headers": {}, "body": wire}, shape
            )
        if method == "get_key_policy":
            return {"Policy": json.dumps(kms_policy)}
        if method == "describe_key":
            return {
                "KeyMetadata": {
                    "Arn": args["KeyId"],
                    "AWSAccountId": "526338061652",
                    "KeyState": "Enabled",
                    "KeyUsage": "ENCRYPT_DECRYPT",
                    "KeySpec": "SYMMETRIC_DEFAULT",
                }
            }
        if method == "list_object_versions":
            return {"Versions": [{"Size": 7}], "IsTruncated": False}
        if method == "list_multipart_uploads":
            return {
                "Uploads": [{"Key": "never-report-key", "UploadId": "never-report-upload"}],
                "IsTruncated": False,
            }
        if method == "list_parts":
            return {"Parts": [{"Size": 5}], "IsTruncated": False}
        if method == "describe_images":
            return {"imageDetails": [{"imageSizeInBytes": 11}]}
        if method == "describe_table":
            return {"Table": {"TableName": args["TableName"], "TableSizeBytes": 13}}
        if method == "get_cost_and_usage":
            return {
                "ResultsByTime": [
                    {
                        "TimePeriod": {
                            "Start": f"2026-09-{day:02d}",
                            "End": f"2026-09-{day + 1:02d}",
                        },
                        "Estimated": True,
                        "Groups": [
                            {
                                "Keys": ["VPC", "Usage"],
                                "Metrics": {"UnblendedCost": {"Amount": "2", "Unit": "USD"}},
                            }
                        ],
                    }
                    for day in range(8, 13)
                ]
            }
        if method == "get_object":
            state_reads.append(True)
            data = fixture.states["platform"] + (
                b" " if failure == "state_drift" and len(state_reads) > 1 else b""
            )
            return {
                "Body": BytesIO(data),
                "VersionId": "synthetic-version",
                "ETag": '"synthetic-etag"',
            }
        return real_reply(service, method, args)

    fixture.reply = reply
    source_provider = fixture.session(resolution_only=True)._source
    monkeypatch.setattr(
        Boto3AwsInventoryProvider, "from_profile", lambda **_kwargs: source_provider
    )
    package, _, _, _ = reviewed_package_fixture()
    if correction:
        price_root = parent / "pricing-breakdown-001"
        lifecycle_io.reserve_operation_directory(price_root, external, repository)
        lifecycle_io.write_canonical_json_atomic(
            price_root / "resource-pricing-breakdown.json",
            {"resources": []},
            allowed_root=external,
            repository_root=repository,
        )
        approval = external / "approval.txt"
        approval.write_text("synthetic owner approval")

        class PreparationClock:
            def now(self):
                return datetime(2026, 9, 13, 9, tzinfo=UTC)

        outputs = production.prepare_prerequisite_correction_inputs(
            repository,
            external,
            approval,
            sha256(approval.read_bytes()).hexdigest(),
            clock=PreparationClock(),
            source_sha256="a" * 64,
        )
        bindings.extend(("correction/" + Path(path).name, path, digest) for path, digest in outputs)
    configuration = DiagnosticRuntimeConfiguration(
        DIAGNOSTIC_SCHEMA_VERSION,
        (),
        (),
        (),
        (),
        tuple(bindings),
        str(external),
        "backend",
        "a" * 64,
        canonical_json_bytes(diagnostic_resource_profile("platform")).decode(),
        canonical_json_bytes(diagnostic_resource_profile("bootstrap")).decode(),
        canonical_json_bytes(diagnostic_discovery_profile()).decode(),
        production.diagnostic_rules("platform"),
        production.diagnostic_rules("bootstrap"),
        None,
        None,
        (),
        None,
    )
    root = parent / (PREREQUISITE_CORRECTION_DIRECTORY if correction else PREREQUISITE_DIRECTORY)
    request = DiagnosticRequest(
        DIAGNOSTIC_SCHEMA_VERSION,
        PREREQUISITE_CORRECTION_OPERATION if correction else PREREQUISITE_OPERATION_ID,
        "sandbox",
        "platform",
        str(root),
        "backend",
        "a" * 64,
        package.identities,
        tuple(
            (
                scope,
                json.loads(data)["lineage"],
                json.loads(data)["serial"],
                sha256(data).hexdigest(),
            )
            for scope, data in fixture.states.items()
        ),
    )
    config = lifecycle_io.load_lifecycle_config(ROOT / "configs/lifecycle/w5-004.json")
    config["external_paths"]["temporary_root"] = str(external)
    monkeypatch.setattr(cli, "repository_root", lambda: repository)
    monkeypatch.setattr(cli, "load_lifecycle_config", lambda _path: config)

    def produce(
        repo, outside, digest, *, resolution_only=False, prerequisite_hashes=None, **options
    ):
        assert options.get("correction", False) is correction
        assert repo == repository and outside == external and digest == "a" * 64
        assert resolution_only and prerequisite_hashes == (
            sha256(raw).hexdigest(),
            sha256(identity).hexdigest(),
        )
        return configuration, request, None

    monkeypatch.setattr(production, "_build_owner_diagnostic_inputs", produce)
    monkeypatch.setattr(
        production, "read_private_state", lambda *_a, **_k: fixture.states["bootstrap"]
    )
    monkeypatch.setattr(
        production.RepositoryDiagnosticCoordinator, "identities", lambda *_a: package.identities
    )

    class Clock:
        def now(self):
            return datetime(2026, 9, 13, 10, tzinfo=UTC)

    args = [
        "aws-verify",
        "--environment",
        "sandbox",
        "--target",
        "platform",
        "--diagnostic",
        "--prerequisite-resolution",
        "--execute",
        "--source-sha256",
        "a" * 64,
        "--evidence-sha256",
        sha256(raw).hexdigest(),
        "--evidence-identity-sha256",
        sha256(identity).hexdigest(),
    ]
    if correction:
        args.append("--prerequisite-correction")
    assert cli.main(args, clock=Clock()) == 1
    report_bytes = (root / "resolution.json").read_bytes()
    report = json.loads(report_bytes)
    checks = {row["check_id"]: row for row in report["checks"]}
    assert set(checks) == set(
        PREREQUISITE_CORRECTION_CHECK_IDS if correction else PREREQUISITE_CHECK_IDS
    )
    assert len(checks) == len(report["checks"])
    assert report["mutation_started"] is False
    assert report["terraform"] == report["pricing"] == "NOT_RUN"
    assert checks["bootstrap_retention"]["status"] == "PASS"
    if failure != "routing":
        assert checks["authorization/kms"]["status"] == "PASS"
    assert checks["lifecycle_bound"]["status"] == "INDETERMINATE"
    assert checks["final_preservation"]["status"] == "PASS"
    assert report["aws_requests"] <= 80 and report["billing_requests"] <= 3
    assert all(count <= 3 for count in report["enumeration_pages"])
    assert b"never-report-key" not in report_bytes and b"never-report-upload" not in report_bytes
    if correction:
        assert report["billing_requests"] == 0 and report["aws_requests"] <= 40
        assert all(
            method not in {"get_role", "describe_route_tables", "get_cost_and_usage"}
            for _service, method, _args in fixture.calls
        )
        if failure != "routing":
            detail = dict(checks["authorization/" + "logs:CreateLogGroup"]["details"])
            assert len(json.loads(detail["findings"])) == 4
        cost_detail = dict(checks["lifecycle_bound"]["details"])
        assert json.loads(cost_detail["final_diagnostic_requests"]) == report["aws_requests"]
    elif failure == "routing":
        assert report["billing_requests"] == 0
    else:
        assert report["billing_requests"] == 1
        assert checks["storage/platform/versions"]["status"] == "PASS"
        assert checks["storage/platform/uploads"]["status"] == "PASS"
        assert checks["platform_state_preserved"]["status"] == (
            "FAIL" if failure == "state_drift" else "PASS"
        )
        if failure == "missing_context":
            assert checks["authorization/summary"]["status"] == "INDETERMINATE"
    assert {path.name for path in root.iterdir()} == {"resolution.json", "resolution-identity.json"}
    assert (previous / "resolution.json").read_bytes() == raw
    assert (previous / "resolution-identity.json").read_bytes() == identity
    count = len(fixture.calls)
    assert cli.main(args, clock=Clock()) == 1
    assert len(fixture.calls) == count
    assert "PREREQUISITE_EXACT_SCOPE" in capsys.readouterr().err


offline_dynamodb_sdk = lifecycle_security_tests.offline_dynamodb_sdk


def test_diagnostic_aggregation_preserves_independence_and_sanitizes_exceptions() -> None:
    from tools.platformctl.aws_live import DiagnosticAwsSession
    from tools.platformctl.lifecycle_models import DiagnosticStatus
    from tools.platformctl.plan import DiagnosticChecks

    from tests.fakes.platform_lifecycle import DiagnosticAwsFixture, FrozenClock

    session = cast(DiagnosticAwsSession, DiagnosticAwsFixture().session())
    results = DiagnosticChecks(FrozenClock(), session)
    invoked: list[str] = []

    def failed() -> tuple[DiagnosticStatus, str, dict[str, object]]:
        raise RuntimeError("private service detail must not be reported")

    def independent() -> tuple[DiagnosticStatus, str, dict[str, object]]:
        invoked.append("independent")
        return DiagnosticStatus.PASS, "VERIFIED", {}

    results.run("first", failed)
    results.run("dependent", independent, dependencies=("first",))
    results.run("independent", independent)
    assert invoked == ["independent"]
    assert [item.status for item in results.checks] == [
        DiagnosticStatus.INDETERMINATE,
        DiagnosticStatus.BLOCKED,
        DiagnosticStatus.PASS,
    ]
    assert results.exit_code == 1
    assert b"private service detail" not in canonical_json_bytes(results.checks)
    session.fatal_reason = "DIAGNOSTIC_AWS_IDENTITY_MISMATCH"
    results.run("remote", independent, remote=True)
    assert results.checks[-1].status is DiagnosticStatus.BLOCKED
    assert invoked == ["independent"]


def test_diagnostic_aggregation_has_a_real_resolved_branch() -> None:
    from tools.platformctl.aws_live import DiagnosticAwsSession
    from tools.platformctl.lifecycle_models import DiagnosticStatus
    from tools.platformctl.plan import DiagnosticChecks

    from tests.fakes.platform_lifecycle import DiagnosticAwsFixture, FrozenClock

    checks = DiagnosticChecks(
        FrozenClock(),
        cast(DiagnosticAwsSession, DiagnosticAwsFixture().session()),
    )
    checks.run("identity", lambda: (DiagnosticStatus.PASS, "VERIFIED", {}))
    checks.run("state", lambda: (DiagnosticStatus.PASS, "VERIFIED", {}), dependencies=("identity",))
    checks.run(
        "historical_projection",
        lambda: (DiagnosticStatus.INDETERMINATE, "HISTORICAL_ONLY", {}),
        mandatory=False,
    )
    assert checks.exit_code == 0
    with pytest.raises(ContractError, match="DEPENDENCY_GRAPH"):
        checks.run(
            "missing", lambda: (DiagnosticStatus.PASS, "VERIFIED", {}), dependencies=("unknown",)
        )


@pytest.mark.parametrize("case", ["empty_prefix", "nonempty_prefix", "routing"])
def test_sdk_routing_and_lifecycle_comparison_coordinate_without_hiding_failures(
    offline_dynamodb_sdk, case: str
) -> None:
    from copy import deepcopy
    from dataclasses import replace

    from tools.platformctl.aws_inventory import diagnostic_resource_profile
    from tools.platformctl.aws_live import diagnose_native_target
    from tools.platformctl.contracts import stable_cleanup_tags
    from tools.platformctl.lifecycle_models import DiagnosticStatus
    from tools.platformctl.plan import DiagnosticChecks

    from tests.fakes.platform_lifecycle import DiagnosticAwsFixture, FrozenClock

    run = offline_dynamodb_sdk(
        destination="https://unapproved.invalid/" if case == "routing" else None
    )
    checks = DiagnosticChecks(FrozenClock(), run.session)
    target = next(
        row
        for row in diagnostic_resource_profile("bootstrap").targets
        if row.resource_type == "aws_s3_bucket_lifecycle_configuration"
    )
    ownership_tags = {
        **stable_cleanup_tags("sandbox"),
        "ExpiresAt": "2026-09-12T23:45:00Z",
    }
    target = replace(
        target,
        assertions=(
            replace(
                target.assertions[0],
                expected_fields_json=canonical_json_bytes({"TagSet": ownership_tags}).decode(),
            ),
            target.assertions[1],
        ),
    )
    rules = json.loads(target.assertions[1].expected_fields_json)["Rules.@unordered"]
    rules[0]["Filter"] = {"Prefix": "private/" if case == "nonempty_prefix" else ""}
    original_rules = deepcopy(rules)
    native_fixture = DiagnosticAwsFixture()
    native_fixture.responses[("s3", "get_bucket_lifecycle_configuration")] = [{"Rules": rules}] * 4
    tag_rows = [{"Key": key, "Value": value} for key, value in ownership_tags.items()]
    native_fixture.responses[("s3", "get_bucket_tagging")] = [{"TagSet": tag_rows}] * 2

    def tags() -> tuple[DiagnosticStatus, str, dict[str, object]]:
        run.session.call(
            "dynamodb",
            "list_tags_of_resource",
            {"ResourceArn": "arn:aws:dynamodb:ap-southeast-1:526338061652:table/synthetic"},
        )
        return DiagnosticStatus.PASS, "VERIFIED", {}

    def lifecycle() -> tuple[DiagnosticStatus, str, dict[str, object]]:
        result, details = diagnose_native_target(
            native_fixture.session(),
            target,
            operation_id="diagnostic-fixture",
            observed_at="2026-09-12T00:00:00Z",
            valid_until="2026-09-12T00:15:00Z",
        )
        return (
            DiagnosticStatus.PASS if result is not None else DiagnosticStatus.FAIL,
            "NATIVE_VERIFIED" if result is not None else "NATIVE_CONFIGURATION_MISMATCH",
            {"assertions": details},
        )

    independent_calls: list[str] = []

    def independent() -> tuple[DiagnosticStatus, str, dict[str, object]]:
        independent_calls.append("called")
        return DiagnosticStatus.PASS, "VERIFIED", {}

    checks.run("dynamodb", tags, remote=True)
    checks.run("lifecycle", lifecycle, remote=True)
    for name in ("sandbox", "billing", "platform_state_preserved"):
        checks.run(name, independent, remote=True)
    states = {row.check_id: row.status for row in checks.checks}
    if case == "routing":
        assert independent_calls == []
        assert states["lifecycle"] is DiagnosticStatus.BLOCKED
        assert states["platform_state_preserved"] is DiagnosticStatus.BLOCKED
        assert checks.exit_code == 1
        assert run.transported == []
    else:
        assert len(independent_calls) == 3
        assert states["dynamodb"] is DiagnosticStatus.PASS
        assert states["lifecycle"] is (
            DiagnosticStatus.PASS if case == "empty_prefix" else DiagnosticStatus.FAIL
        )
        assert checks.exit_code == (0 if case == "empty_prefix" else 1)
        assert states["platform_state_preserved"] is DiagnosticStatus.PASS
        assert len(run.transported) == 1
    assert rules == original_rules
    assert b"private/" not in canonical_json_bytes(checks.checks)


@pytest.mark.parametrize(
    "command",
    ["platform-plan", "platform-apply", "platform-destroy", "purge-sandbox"],
)
def test_direct_diagnostic_coordinator_never_dispatches_operations(command: str) -> None:
    from tools.platformctl.plan import RepositoryDiagnosticCoordinator

    coordinator = object.__new__(RepositoryDiagnosticCoordinator)
    coordinator._started = False
    with pytest.raises(ContractError, match="SINGLE_READ_ONLY_DISPATCH"):
        coordinator.execute_request(command, b"{}")


@pytest.mark.parametrize(
    "failure",
    [
        "missing_inputs",
        "native_read",
        "routing",
        "state_drift",
        "inventory",
        "inventory_resource",
        "inventory_routing",
        "inventory_identity",
    ],
)
def test_complete_diagnostic_failure_report_is_not_execution_ready(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    from dataclasses import replace

    from tools.platformctl import plan as plan_module
    from tools.platformctl.aws_inventory import (
        diagnostic_discovery_profile,
        diagnostic_resource_profile,
    )
    from tools.platformctl.aws_live import DiagnosticAwsSession, DiagnosticReadError
    from tools.platformctl.lifecycle_io import (
        reserve_operation_directory,
        write_canonical_json_atomic,
    )
    from tools.platformctl.lifecycle_models import (
        DIAGNOSTIC_SCHEMA_VERSION,
        DiagnosticRequest,
        DiagnosticRuntimeConfiguration,
    )
    from tools.platformctl.plan import RepositoryDiagnosticCoordinator
    from tools.platformctl.terraform_runner import GitObservationRunner

    from tests.fakes.platform_lifecycle import (
        CompleteDiagnosticAwsFixture,
        DiagnosticAwsFixture,
        FrozenClock,
        reviewed_package_fixture,
    )

    repository, external = tmp_path / "repository", tmp_path / "external"
    repository.mkdir()
    external.mkdir()
    parent = external / "consolidated-remediation-001"
    root = parent / "codex-diagnostic-001/attempt-002"
    reserve_operation_directory(parent, external, repository)
    reserve_operation_directory(root.parent, external, repository)
    reserve_operation_directory(root, external, repository)
    package, _, _, _ = reviewed_package_fixture()
    full_inventory = failure.startswith("inventory")
    full_fixture = (
        CompleteDiagnosticAwsFixture(failure.removeprefix("inventory_")) if full_inventory else None
    )
    states = {
        scope: canonical_json_bytes(
            {
                "version": 4,
                "serial": serial,
                "lineage": lineage,
                "resources": []
                if failure == "missing_inputs"
                else [
                    {
                        "mode": "managed",
                        "type": "terraform_data",
                        "name": "owner_expiry_gate",
                        "instances": [{"attributes": {"input": "2026-09-07T00:00:00Z"}}],
                    }
                ],
            }
        )
        for scope, lineage, serial in (
            ("bootstrap", "c446f9a2-77d4-9954-20fa-523205d86a8a", 17),
            ("platform", "7465ed2e-a39c-afdd-f172-5792d3ec2f85", 4),
        )
    }
    if full_fixture is not None:
        states = full_fixture.states
    backend = external / "bootstrap.backend.hcl"
    backend.write_text("synthetic backend identity", encoding="utf-8")
    configuration = DiagnosticRuntimeConfiguration(
        schema_version=DIAGNOSTIC_SCHEMA_VERSION,
        tools=(),
        child_environment=(),
        protected_files=(),
        authorized_status=(),
        input_files=(),
        terraform_data_root=str(external),
        bootstrap_backend_path=str(backend),
        bootstrap_backend_sha256=sha256(backend.read_bytes()).hexdigest(),
        native_targets_json=canonical_json_bytes(diagnostic_resource_profile("platform")).decode(),
        bootstrap_targets_json=canonical_json_bytes(
            diagnostic_resource_profile("bootstrap")
        ).decode(),
        native_scans_json=canonical_json_bytes(diagnostic_discovery_profile()).decode(),
        platform_rules=plan_module.diagnostic_rules("platform"),
        bootstrap_rules=plan_module.diagnostic_rules("bootstrap"),
        retained_pricing=None,
        exposure=None,
        evidence_sources=(),
        failure_resolution=None,
    )
    request = DiagnosticRequest(
        DIAGNOSTIC_SCHEMA_VERSION,
        "w5-004-codex-diagnostic-001-attempt-002",
        "sandbox",
        "platform",
        str(root),
        str(backend),
        configuration.bootstrap_backend_sha256,
        package.identities,
        tuple(
            (
                scope,
                json.loads(raw)["lineage"],
                json.loads(raw)["serial"],
                sha256(raw).hexdigest(),
            )
            for scope, raw in states.items()
        ),
    )
    runtime_path = root / "inputs/diagnostic-runtime.json"
    runtime_hash = write_canonical_json_atomic(
        runtime_path,
        configuration,
        allowed_root=external,
        repository_root=repository,
    )
    write_canonical_json_atomic(
        root / "inputs/diagnostic-request.json",
        request,
        allowed_root=external,
        repository_root=repository,
    )
    fixture = full_fixture if full_fixture is not None else DiagnosticAwsFixture()
    if full_fixture is not None:
        import botocore.parsers
        import botocore.session

        from tests.security.test_w5_004_lifecycle_security import iam_simulation_xml

        previous_reply = fixture.reply

        def sdk_shaped_reply(service, method, arguments):
            if method != "simulate_principal_policy":
                return previous_reply(service, method, arguments)
            wire = iam_simulation_xml(arguments["ActionNames"][0], arguments["ResourceArns"])
            shape = (
                botocore.session.Session()
                .get_service_model("iam")
                .operation_model("SimulatePrincipalPolicy")
                .output_shape
            )
            return botocore.parsers.create_parser("query").parse(
                {"status_code": 200, "headers": {}, "body": wire}, shape
            )

        monkeypatch.setattr(fixture, "reply", sdk_shaped_reply)
    session = cast(DiagnosticAwsSession, fixture.session())
    state_reads: list[str] = []

    def read_platform() -> tuple[bytes, str]:
        state_reads.append("platform")
        if failure == "state_drift" and len(state_reads) > 1:
            return states["platform"] + b"\n", "synthetic-version"
        return states["platform"], "synthetic-version"

    if not full_inventory:
        monkeypatch.setattr(session, "state_bytes", read_platform)
    monkeypatch.setattr(
        plan_module, "read_private_state", lambda *_args, **_kwargs: states["bootstrap"]
    )
    native_reads: list[str] = []
    if failure != "missing_inputs" and not full_inventory:
        # The coordinator graph is exercised independently of state-reference resolution.
        monkeypatch.setattr(
            plan_module,
            "resolve_post_execution_targets",
            lambda targets, *_args, **_kwargs: targets,
        )

        def native(_session, target, **_kwargs):
            native_reads.append(target.address)
            if target.address == "aws_dynamodb_table.terraform_lock":
                if failure == "routing":
                    session.reject("DIAGNOSTIC_REDIRECT_NOT_APPROVED")
                raise DiagnosticReadError("AccessDeniedException")
            return None, ({"check": "CONFIGURATION", "status": "INDETERMINATE"},)

        monkeypatch.setattr(plan_module, "diagnose_native_target", native)
    fixture.responses[("ce", "get_cost_and_usage")] = [{"ResultsByTime": []}] * 2
    fixture.responses[("ce", "list_cost_allocation_tags")] = [{"CostAllocationTags": []}]

    class DiagnosticClock(FrozenClock):
        def now(self) -> datetime:
            return datetime(2026, 9, 12, tzinfo=UTC)

    coordinator = RepositoryDiagnosticCoordinator(
        configuration,
        repository=repository,
        external=external,
        clock=DiagnosticClock(),
        git=cast(GitObservationRunner, None),
        session=session,
        runtime_identity=(str(runtime_path), runtime_hash),
    )
    monkeypatch.setattr(coordinator, "identities", lambda _request: package.identities)
    for invalid_request in (
        replace(
            request,
            operation_root=str(parent / "consolidated-prerequisite-diagnostic-004"),
        ),
        replace(request, operation_id="w5-004-consolidated-prerequisite-diagnostic-004"),
        replace(
            request,
            operation_root=str(parent / "consolidated-prerequisite-diagnostic-006"),
        ),
        replace(request, operation_id="w5-004-consolidated-prerequisite-diagnostic-006"),
    ):
        with pytest.raises(ContractError, match="DIAGNOSTIC_EXACT_SCOPE_REQUIRED"):
            coordinator.execute_request("aws-verify", canonical_json_bytes(invalid_request))
        assert not fixture.calls
        assert not state_reads
        assert not (root / "run-001").exists()
    code, reason = coordinator.execute_request("aws-verify", canonical_json_bytes(request))
    assert code == 1
    assert reason == "DIAGNOSTIC_PREREQUISITES_UNRESOLVED"
    report = json.loads((root / "run-001/diagnostic.json").read_bytes())
    assert report["recovery_eligibility"] == "NOT_ESTABLISHED"
    assert report["mutation_started"] is False
    assert report["exit_code"] == 1
    observed = {item["check_id"]: item["status"] for item in report["checks"]}
    assert observed["bootstrap_state"] == observed["platform_state"] == "PASS"
    assert observed["bootstrap_templates"] == (
        "INDETERMINATE" if failure == "missing_inputs" else "PASS"
    )
    if not full_inventory:
        assert observed["orphan_reconciliation"] == "BLOCKED_DEPENDENCY"
    assert "billing/account" in observed
    assert "simulation/logs:TagResource" in observed
    assert observed["final_preservation"] == "PASS"
    assert observed["bootstrap_state_preserved"] == "PASS"
    if full_fixture is not None:
        expected_native = {
            scope + "/" + target.address
            for scope in ("bootstrap", "platform")
            for target in diagnostic_resource_profile(scope).targets
        }
        expected_discovery = {
            "discovery/" + scan.coverage for scan in diagnostic_discovery_profile().scans
        }
        assert len(report["checks"]) == len(observed) == 115
        assert expected_native | expected_discovery <= set(observed)
        assert set(observed.values()) <= {"PASS", "FAIL", "INDETERMINATE", "BLOCKED_DEPENDENCY"}
        assert observed["bootstrap_templates"] == observed["platform_templates"] == "PASS"
        if failure in {"inventory_routing", "inventory_identity"}:
            assert observed["platform_state_preserved"] == "BLOCKED_DEPENDENCY"
            assert observed["billing/account"] == "BLOCKED_DEPENDENCY"
            assert not any(
                service in {"ecr", "cloudwatch", "ce"} for service, _, _ in fixture.calls
            )
            assert session.fatal_reason is not None
        else:
            assert session.fatal_reason is None
            assert all(observed[key] == "PASS" for key in expected_discovery)
            assert all(observed[key] != "BLOCKED_DEPENDENCY" for key in expected_native)
            if failure == "inventory":
                assert all(observed[key] == "PASS" for key in expected_native), {
                    row["check_id"]: row
                    for row in report["checks"]
                    if row["check_id"] in expected_native and row["status"] != "PASS"
                }
            else:
                assert observed["bootstrap/aws_dynamodb_table.terraform_lock"] == "INDETERMINATE"
            for key in (
                "owner_managed_service_role",
                "caller_policy_dependencies",
                "billing/account",
                "billing/project_tag",
                "billing/tag_status",
                "platform_state_preserved",
            ):
                assert observed[key] == "PASS"
            assert {"ecr", "cloudwatch", "iam", "ce"} <= {
                service for service, _, _ in fixture.calls
            }
            assert all(observed[key] == "PASS" for key in observed if key.startswith("simulation/"))
            assert (
                sum(
                    (service, method) == ("s3", "get_object")
                    for service, method, _ in fixture.calls
                )
                == 2
            )
        assert report["recovery_eligibility"] == "NOT_ESTABLISHED"
    elif failure == "routing":
        assert observed["platform_state_preserved"] == "BLOCKED_DEPENDENCY"
        assert observed["billing/account"] == "BLOCKED_DEPENDENCY"
        assert not any(address.startswith("module.") for address in native_reads)
        assert len(state_reads) == 1
        assert not any(service == "ce" for service, _, _ in fixture.calls)
    else:
        assert observed["platform_state_preserved"] == (
            "FAIL" if failure == "state_drift" else "PASS"
        )
        assert len(state_reads) == 2
        assert any(service == "ce" for service, _, _ in fixture.calls)
        assert observed["billing/tag_status"] == "PASS"
        if failure != "missing_inputs":
            assert any(address.startswith("module.") for address in native_reads)
            assert observed["bootstrap_expiry"] == observed["platform_expiry"] == "FAIL"
            rows = {item["check_id"]: item for item in report["checks"]}
            assert rows["bootstrap/aws_dynamodb_table.terraform_lock"]["reason_code"] == (
                "NATIVE_ACCESS_DENIED"
            )
    assert report["recovery_eligibility"] == "NOT_ESTABLISHED"
    assert all(
        not method.startswith(("create", "delete", "put", "update"))
        for _, method, _ in fixture.calls
    )
    with pytest.raises(ContractError, match="SINGLE_READ_ONLY_DISPATCH"):
        coordinator.execute_request("aws-verify", canonical_json_bytes(request))


@pytest.mark.parametrize(
    "failed_phase",
    [
        None,
        "identities",
        "state",
        "evidence",
        "inventory",
        "expiry",
        "version",
        "plan",
        "show",
        "normalize",
        "policy",
        "cost",
        "final-identities",
    ],
)
def test_coordinator_preparation_sequence_never_dispatches_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failed_phase: str | None,
) -> None:
    """Exercise the repository coordinator with deterministic ports, not external tools."""
    from dataclasses import replace
    from types import SimpleNamespace

    from tools.platformctl import plan as plan_module
    from tools.platformctl.lifecycle_models import (
        OPERATIONAL_SCHEMA_VERSION,
        OperationPhase,
        ReviewRequest,
    )

    from tests.fakes.platform_lifecycle import FrozenClock, reviewed_package_fixture

    package, _, _, _ = reviewed_package_fixture()
    external = tmp_path / "external"
    external.mkdir(mode=0o700)
    operation = external / "operation"
    variables = external / "inputs.json"
    backend = external / "backend.hcl"
    variables.write_bytes(b"{}\n")
    backend.write_bytes(b"synthetic backend; never executed")
    ledger = OperationLedger(external / "ledger", ROOT)
    events: list[str] = []
    mutations: list[str] = []

    def visit(phase: str) -> None:
        events.append(phase)
        if phase == failed_phase:
            raise ContractError("SYNTHETIC_PHASE_FAILURE")

    def identities(request: object) -> object:
        del request
        visit("final-identities" if "identities" in events else "identities")
        return package.identities

    def state(request: object) -> object:
        del request
        visit("state")
        return package.state

    def inventory(request: object, current: object) -> object:
        del request, current
        visit("inventory")
        return package.native

    def copy_evidence(request: object) -> None:
        del request
        visit("evidence")

    def expiry(request: object, prepared: datetime, root: Path) -> object:
        del request
        visit("expiry")
        return plan_module.prepare_resource_expiry_input(
            path=root / "resource-expiry.tfvars.json",
            external_root=external,
            repository_root=ROOT,
            plan_preparation_time=prepared,
            environment="sandbox",
        )

    def version(root: Path) -> None:
        del root
        visit("version")

    def generate(root: Path, **arguments: object) -> None:
        del root
        visit("plan")
        cast(Path, arguments["output_file"]).write_bytes(b"synthetic reviewed plan")

    def show(root: Path, artifact: Path) -> bytes:
        del root, artifact
        visit("show")
        return b"{}"

    def normalized(raw: object, *, evaluation_time: str) -> dict[str, object]:
        del raw
        visit("normalize")
        rule = package.summary[0]
        return {
            "evaluation_context": {"evaluation_time": evaluation_time},
            "resource_changes": [
                {
                    "address": rule.address,
                    "type": rule.resource_type,
                    "change": {"actions": list(rule.actions)},
                }
            ],
        }

    def policy(path: Path) -> dict[str, object]:
        visit("policy")
        return {
            "schema_version": "w5-004.policy-result.v2",
            "allow": True,
            "findings": [],
            "input_sha256": sha256(path.read_bytes()).hexdigest(),
            "policy_sha256": "a" * 64,
            "exceptions_sha256": "a" * 64,
        }

    def cost(request: object, artifact: Path, digest: str) -> object:
        del request, artifact
        visit("cost")
        return replace(package.cost, status=Outcome.INDETERMINATE, saved_plan_sha256=digest)

    services = SimpleNamespace(
        clock=FrozenClock(),
        external_root=external,
        repository_root=ROOT,
        ledger=ledger,
        identities=identities,
        state=state,
        copy_evidence=copy_evidence,
        inventory=inventory,
        expiry_input=expiry,
        cost=cost,
        terraform=SimpleNamespace(
            verify_version=version,
            create_saved_plan=generate,
            show_plan_json=show,
            apply_saved_plan=mutations.append,
        ),
        policy=SimpleNamespace(evaluate_decision=policy),
    )
    request = ReviewRequest(
        OPERATIONAL_SCHEMA_VERSION,
        package.operation_id,
        package.action,
        package.target,
        package.environment,
        package.identities,
        package.profile,
        str(variables),
        sha256(variables.read_bytes()).hexdigest(),
        str(backend),
        sha256(backend.read_bytes()).hexdigest(),
        str(operation),
    )
    monkeypatch.setattr(plan_module, "normalize_plan", normalized)
    if failed_phase is None:
        review = plan_module.prepare_review(request, services)
        assert review.eligibility is Outcome.INDETERMINATE
        assert not (operation / "review.json").exists()
        assert (operation / "candidate-review.json").is_file()
        assert ledger.journal(package.operation_id)[-1]["state"] == OperationPhase.PREPARED.value
        assert events == [
            "identities",
            "state",
            "evidence",
            "inventory",
            "expiry",
            "version",
            "plan",
            "show",
            "normalize",
            "policy",
            "cost",
            "final-identities",
        ]
    else:
        with pytest.raises(ContractError, match="SYNTHETIC_PHASE_FAILURE"):
            plan_module.prepare_review(request, services)
        assert events[-1] == failed_phase
        assert (
            ledger.journal(package.operation_id)[-1]["state"] == OperationPhase.REVIEW_FAILED.value
        )
        assert not (operation / "review.json").exists()
    assert mutations == []


def test_low_level_apply_requires_verified_context_before_any_process(tmp_path: Path) -> None:
    fake = FakeCommandRunner(
        results=[
            ProcessResult(
                0,
                json.dumps({"terraform_version": "1.16.1", "platform": "windows_amd64"}),
                "",
            )
        ]
    )
    runner = TerraformRunner(
        executable=Path(r"E:\AI\.tools\terraform\1.16.1\terraform.exe"),
        repository_root=ROOT,
        external_root=tmp_path,
        runner=fake,
    )
    terraform_root = ROOT / "infra/environments/sandbox"
    saved_plan = tmp_path / "platform.tfplan"
    saved_plan.write_bytes(b"reviewed-plan-bytes")
    with pytest.raises(ContractError, match="VERIFIED_EXECUTION_CONTEXT"):
        runner.apply_saved_plan(
            terraform_root, saved_plan, sha256(b"reviewed-plan-bytes").hexdigest()
        )
    assert fake.calls == []


def test_saved_plan_uses_generated_expiry_override_last(tmp_path: Path) -> None:
    fake = FakeCommandRunner()
    executable = tmp_path / "terraform.exe"
    executable.write_bytes(b"synthetic executable never run")
    runner = TerraformRunner(
        executable=executable,
        executable_sha256=sha256(executable.read_bytes()).hexdigest(),
        repository_root=ROOT,
        external_root=tmp_path,
        runner=fake,
    )
    base_variables = tmp_path / "approved-input.tfvars.json"
    expiry_variables = tmp_path / "resource-expiry.auto.tfvars.json"
    base_variables.write_text("{}\n", encoding="utf-8")
    expiry_variables.write_text('{"mandatory_tags":{}}\n', encoding="utf-8")

    runner.create_saved_plan(
        ROOT / "infra/bootstrap",
        variables_file=base_variables,
        resource_expiry_file=expiry_variables,
        output_file=tmp_path / "bootstrap.tfplan",
    )

    arguments = fake.calls[-1][0]
    variable_arguments = [argument for argument in arguments if "-var-file=" in argument]
    assert variable_arguments == [
        f"-var-file={base_variables}",
        f"-var-file={expiry_variables}",
    ]


def test_real_plan_shape_normalizes_before_policy_use() -> None:
    normalized = normalize_plan(
        {
            "format_version": "1.2",
            "terraform_version": "1.16.1",
            "variables": {"aws_region": {"value": "ap-southeast-1"}},
            "resource_changes": [],
        },
        evaluation_time="2026-09-08T00:00:00Z",
    )
    assert summarize_plan(normalized).initially_eligible


@pytest.mark.parametrize(
    ("factory", "relationship", "source_count"),
    (
        (ecr_kms_reference_plan, "platform-ecr-kms-key-reference", 1),
        (opensearch_log_reference_plan, "opensearch-log-groups-reference", 4),
    ),
)
def test_platform_reference_unknowns_are_structurally_normalized(
    factory: Callable[[], dict[str, object]],
    relationship: str,
    source_count: int,
) -> None:
    raw = factory()
    original = json.loads(json.dumps(raw))

    normalized = normalize_plan(raw, evaluation_time="2026-09-08T00:00:00Z")

    assert raw == original
    context = cast(dict[str, object], normalized["evaluation_context"])
    records = cast(list[dict[str, object]], context["resource_reference_unknowns"])
    assert len(records) == 1
    assert records[0]["relationship"] == relationship
    assert len(cast(list[str], records[0]["source_addresses"])) == source_count
    context = cast(dict[str, object], normalized["evaluation_context"])
    assert context["evaluation_time"] == "2026-09-08T00:00:00Z"


def test_real_s3_provider_shape_records_only_proven_computed_policy() -> None:
    bucket_address = "module.storage.aws_s3_bucket.terraform_state"
    policy_address = "module.storage.aws_s3_bucket_policy.terraform_state_tls"
    kms_address = "module.storage.aws_kms_key.terraform_state"
    encryption_address = (
        "module.storage.aws_s3_bucket_server_side_encryption_configuration.terraform_state"
    )
    raw: dict[str, object] = {
        "format_version": "1.2",
        "terraform_version": "1.16.1",
        "variables": {"aws_region": {"value": "ap-southeast-1"}},
        "configuration": {
            "root_module": {
                "resources": [],
                "module_calls": {
                    "storage": {
                        "expressions": {},
                        "module": {
                            "resources": [
                                {
                                    "address": "aws_s3_bucket.terraform_state",
                                    "mode": "managed",
                                    "type": "aws_s3_bucket",
                                    "expressions": {
                                        "bucket": {"constant_value": "approved-bucket"}
                                    },
                                },
                                {
                                    "address": "aws_s3_bucket_policy.terraform_state_tls",
                                    "mode": "managed",
                                    "type": "aws_s3_bucket_policy",
                                    "expressions": {
                                        "bucket": {
                                            "references": ["aws_s3_bucket.terraform_state.id"]
                                        },
                                        "policy": {
                                            "references": [
                                                "data.aws_iam_policy_document."
                                                "terraform_state_tls.json"
                                            ]
                                        },
                                    },
                                },
                                {
                                    "address": "aws_kms_key.terraform_state",
                                    "mode": "managed",
                                    "type": "aws_kms_key",
                                    "expressions": {
                                        "policy": {
                                            "references": [
                                                "data.aws_iam_policy_document."
                                                "terraform_state_key.json"
                                            ]
                                        }
                                    },
                                },
                                {
                                    "address": (
                                        "aws_s3_bucket_server_side_encryption_configuration."
                                        "terraform_state"
                                    ),
                                    "mode": "managed",
                                    "type": "aws_s3_bucket_server_side_encryption_configuration",
                                    "expressions": {
                                        "bucket": {
                                            "references": ["aws_s3_bucket.terraform_state.id"]
                                        },
                                        "rule": [
                                            {
                                                "apply_server_side_encryption_by_default": [
                                                    {
                                                        "kms_master_key_id": {
                                                            "references": [
                                                                "aws_kms_key.terraform_state.arn"
                                                            ]
                                                        },
                                                        "sse_algorithm": {
                                                            "constant_value": "aws:kms"
                                                        },
                                                    }
                                                ]
                                            }
                                        ],
                                    },
                                },
                            ]
                        },
                    }
                },
            }
        },
        "resource_changes": [
            {
                "address": bucket_address,
                "type": "aws_s3_bucket",
                "change": {
                    "actions": ["create"],
                    "before": None,
                    "after": {"bucket": "approved-bucket", "policy": None},
                    "after_unknown": {"id": True, "policy": True},
                    "after_sensitive": {},
                },
            },
            {
                "address": policy_address,
                "type": "aws_s3_bucket_policy",
                "change": {
                    "actions": ["create"],
                    "before": None,
                    "after": {
                        "bucket": "approved-bucket",
                        "policy": (
                            '{"Statement":[{"Effect":"Deny",'
                            '"Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}'
                        ),
                    },
                    "after_unknown": {},
                    "after_sensitive": {},
                },
            },
            {
                "address": kms_address,
                "type": "aws_kms_key",
                "change": {
                    "actions": ["create"],
                    "before": None,
                    "after": {"policy": '{"Statement":[]}'},
                    "after_unknown": {"arn": True, "key_id": True},
                    "after_sensitive": {},
                },
            },
            {
                "address": encryption_address,
                "type": "aws_s3_bucket_server_side_encryption_configuration",
                "change": {
                    "actions": ["create"],
                    "before": None,
                    "after": {
                        "rule": [
                            {
                                "apply_server_side_encryption_by_default": [
                                    {"sse_algorithm": "aws:kms"}
                                ],
                                "bucket_key_enabled": True,
                            }
                        ]
                    },
                    "after_unknown": {
                        "bucket": True,
                        "id": True,
                        "rule": [
                            {
                                "apply_server_side_encryption_by_default": [
                                    {"kms_master_key_id": True}
                                ],
                                "blocked_encryption_types": True,
                            }
                        ],
                    },
                    "after_sensitive": {},
                },
            },
        ],
    }

    normalized = normalize_plan(raw, evaluation_time="2026-09-08T00:00:00Z")

    changes = cast(list[dict[str, object]], normalized["resource_changes"])
    bucket_change = cast(dict[str, object], changes[0]["change"])
    assert bucket_change["after_unknown"] == {"id": True}
    context = cast(dict[str, object], normalized["evaluation_context"])
    assert context["provider_computed_unknowns"] == [
        {
            "address": bucket_address,
            "type": "aws_s3_bucket",
            "unknown_paths": ["policy"],
        },
        {
            "address": encryption_address,
            "type": "aws_s3_bucket_server_side_encryption_configuration",
            "unknown_paths": ["rule[].apply_server_side_encryption_by_default[].kms_master_key_id"],
        },
    ]
    assert context["s3_bucket_policy_bindings"] == [
        {
            "bucket_address": bucket_address,
            "policy_address": policy_address,
        }
    ]
    assert context["s3_kms_encryption_bindings"] == [
        {
            "bucket_address": bucket_address,
            "encryption_address": encryption_address,
            "kms_key_address": kms_address,
            "field_path": ("rule[].apply_server_side_encryption_by_default[].kms_master_key_id"),
        }
    ]
    assert context["resource_reference_unknowns"] == []
    assert context["policy_document_bindings"] == []
    assert summarize_plan(normalized).initially_eligible


@pytest.mark.parametrize("existing_role", (False, True))
def test_opensearch_password_metadata_requires_exact_module_output_role_chain(
    existing_role: bool,
) -> None:
    role_address = "module.iam.aws_iam_role.opensearch_administrator"
    domain_address = "module.opensearch.aws_opensearch_domain.this"
    raw: dict[str, object] = {
        "format_version": "1.2",
        "terraform_version": "1.16.1",
        "variables": {"aws_region": {"value": "ap-southeast-1"}},
        "configuration": {
            "root_module": {
                "resources": [],
                "module_calls": {
                    "iam": {
                        "expressions": {},
                        "module": {
                            "resources": [
                                {
                                    "address": "aws_iam_role.opensearch_administrator",
                                    "mode": "managed",
                                    "type": "aws_iam_role",
                                    "expressions": {"name": {"constant_value": "approved-role"}},
                                }
                            ],
                            "outputs": {
                                "opensearch_administrator_role_arn": {
                                    "expression": {
                                        "references": [
                                            "aws_iam_role.opensearch_administrator",
                                            "aws_iam_role.opensearch_administrator.arn",
                                        ]
                                    }
                                }
                            },
                        },
                    },
                    "opensearch": {
                        "expressions": {
                            "administrator_role_arn": {
                                "references": [
                                    "module.iam",
                                    "module.iam.opensearch_administrator_role_arn",
                                ]
                            }
                        },
                        "module": {
                            "resources": [
                                {
                                    "address": "aws_opensearch_domain.this",
                                    "mode": "managed",
                                    "type": "aws_opensearch_domain",
                                    "expressions": {
                                        "advanced_security_options": [
                                            {
                                                "enabled": {"constant_value": True},
                                                "internal_user_database_enabled": {
                                                    "constant_value": False
                                                },
                                                "master_user_options": [
                                                    {
                                                        "master_user_arn": {
                                                            "references": [
                                                                "var.administrator_role_arn"
                                                            ]
                                                        }
                                                    }
                                                ],
                                            }
                                        ]
                                    },
                                }
                            ]
                        },
                    },
                },
            }
        },
        "resource_changes": [
            {
                "address": role_address,
                "type": "aws_iam_role",
                "change": {
                    "actions": ["create"],
                    "before": None,
                    "after": {"name": "approved-role"},
                    "after_unknown": {"arn": True},
                    "after_sensitive": {},
                },
            },
            {
                "address": domain_address,
                "type": "aws_opensearch_domain",
                "change": {
                    "actions": ["create"],
                    "before": None,
                    "after": {
                        "advanced_security_options": [
                            {
                                "enabled": True,
                                "internal_user_database_enabled": False,
                                "master_user_options": [
                                    {
                                        "master_user_arn": None,
                                        "master_user_password": None,
                                    }
                                ],
                            }
                        ]
                    },
                    "after_unknown": {
                        "advanced_security_options": [
                            {"master_user_options": [{"master_user_arn": True}]}
                        ]
                    },
                    "after_sensitive": {
                        "advanced_security_options": [
                            {"master_user_options": [{"master_user_password": True}]}
                        ]
                    },
                },
            },
        ],
    }

    expected_relationship = "omitted-null-password-with-structurally-resolved-admin-role"
    if existing_role:
        role_arn = "arn:aws:iam::526338061652:role/enterprise-ai-sandbox-opensearch-admin"
        trust_policy = '{"Statement":[],"Version":"2012-10-17"}'
        changes = cast(list[dict[str, object]], raw["resource_changes"])
        role_body = cast(dict[str, object], changes[0]["change"])
        previous_tags = {
            "Environment": "sandbox",
            "ExpiresAt": "2026-09-07T23:45:00Z",
        }
        current_tags = {
            "Environment": "sandbox",
            "ExpiresAt": "2026-09-08T23:45:00Z",
        }
        role_body.update(
            {
                "actions": ["update"],
                "before": {
                    "arn": role_arn,
                    "assume_role_policy": trust_policy,
                    "name": "approved-role",
                    "tags": previous_tags,
                    "tags_all": previous_tags,
                },
                "after": {
                    "arn": role_arn,
                    "assume_role_policy": trust_policy,
                    "name": "approved-role",
                    "tags": current_tags,
                    "tags_all": current_tags,
                },
                "after_unknown": {},
                "after_sensitive": {},
            }
        )
        domain_body = cast(dict[str, object], changes[1]["change"])
        after = cast(dict[str, object], domain_body["after"])
        advanced = cast(list[dict[str, object]], after["advanced_security_options"])[0]
        master = cast(list[dict[str, object]], advanced["master_user_options"])[0]
        master["master_user_arn"] = role_arn
        unknown = cast(dict[str, object], domain_body["after_unknown"])
        unknown_advanced = cast(list[dict[str, object]], unknown["advanced_security_options"])[0]
        unknown_master = cast(list[dict[str, object]], unknown_advanced["master_user_options"])[0]
        unknown_master.clear()
        expected_relationship = "omitted-null-password-with-existing-admin-role"

    normalized = normalize_plan(raw, evaluation_time="2026-09-08T00:00:00Z")

    context = cast(dict[str, object], normalized["evaluation_context"])
    assert context["provider_sensitive_nulls"] == [
        {
            "address": domain_address,
            "type": "aws_opensearch_domain",
            "field_path": (
                "advanced_security_options[].master_user_options[].master_user_password"
            ),
            "relationship": expected_relationship,
            "source_address": role_address,
        }
    ]
    normalized_changes = cast(list[dict[str, object]], normalized["resource_changes"])
    domain_body = cast(dict[str, object], normalized_changes[1]["change"])
    assert domain_body["after_sensitive"] == {
        "advanced_security_options": [{"master_user_options": [{}]}]
    }
    assert summarize_plan(normalized).initially_eligible is not existing_role


@pytest.mark.parametrize(
    ("module_name", "resource_address", "resource_type", "field_path", "document_name", "sid"),
    (
        (
            "iam",
            "aws_iam_role.runtime",
            "aws_iam_role",
            "assume_role_policy",
            "runtime_trust",
            "ExactPodIdentityRuntimeTrust",
        ),
        (
            "iam",
            "aws_iam_role.ingestion",
            "aws_iam_role",
            "assume_role_policy",
            "ingestion_trust",
            "ExactPodIdentityIngestionTrust",
        ),
        (
            "iam",
            "aws_iam_role.opensearch_administrator",
            "aws_iam_role",
            "assume_role_policy",
            "administrator_trust",
            "TimeBoundExactSandboxAdministrator",
        ),
        (
            "iam",
            "aws_iam_role.github_oidc",
            "aws_iam_role",
            "assume_role_policy",
            "github_trust",
            "ExactGitHubEnvironmentTrust",
        ),
        (
            "opensearch",
            "aws_opensearch_domain.this",
            "aws_opensearch_domain",
            "access_policies",
            "domain_access",
            "ExactSandboxRoleDataPlaneAccess",
        ),
        (
            "opensearch",
            "aws_cloudwatch_log_resource_policy.opensearch",
            "aws_cloudwatch_log_resource_policy",
            "policy_document",
            "log_delivery",
            "ExactOpenSearchLogDelivery",
        ),
    ),
)
def test_exact_platform_policy_document_relationship_is_normalized(
    monkeypatch: pytest.MonkeyPatch,
    module_name: str,
    resource_address: str,
    resource_type: str,
    field_path: str,
    document_name: str,
    sid: str,
) -> None:
    full_resource_address = f"module.{module_name}.{resource_address}"
    local_document_address = f"data.aws_iam_policy_document.{document_name}"
    full_document_address = f"module.{module_name}.{local_document_address}"
    raw: dict[str, object] = {
        "format_version": "1.2",
        "terraform_version": "1.16.1",
        "variables": {"aws_region": {"value": "ap-southeast-1"}},
        "configuration": {
            "root_module": {
                "resources": [],
                "module_calls": {
                    module_name: {
                        "expressions": {},
                        "module": {
                            "resources": [
                                {
                                    "address": local_document_address,
                                    "mode": "data",
                                    "type": "aws_iam_policy_document",
                                    "expressions": {
                                        "statement": [{"sid": {"constant_value": sid}}]
                                    },
                                },
                                {
                                    "address": resource_address,
                                    "mode": "managed",
                                    "type": resource_type,
                                    "expressions": {
                                        field_path: {
                                            "references": [f"{local_document_address}.json"]
                                        }
                                    },
                                },
                            ]
                        },
                    }
                },
            }
        },
        "resource_changes": [
            {
                "address": full_document_address,
                "type": "aws_iam_policy_document",
                "change": {
                    "actions": ["read"],
                    "before": None,
                    "after": {},
                    "after_unknown": {
                        "id": True,
                        "json": True,
                        "minified_json": True,
                    },
                    "after_sensitive": {},
                },
            },
            {
                "address": full_resource_address,
                "type": resource_type,
                "change": {
                    "actions": ["create"],
                    "before": None,
                    "after": {field_path: None},
                    "after_unknown": {field_path: True},
                    "after_sensitive": {},
                },
            },
        ],
    }
    original = json.loads(json.dumps(raw))
    configuration = cast(dict[str, object], raw["configuration"])
    root_module = cast(dict[str, object], configuration["root_module"])
    module_calls = cast(dict[str, object], root_module["module_calls"])
    module_call = cast(dict[str, object], module_calls[module_name])
    module = cast(dict[str, object], module_call["module"])
    resources = cast(list[dict[str, object]], module["resources"])
    policy_expressions = cast(dict[str, object], resources[0]["expressions"])
    monkeypatch.setitem(
        PLATFORM_POLICY_DOCUMENT_EXPRESSION_SHA256,
        full_document_address,
        sha256(canonical_json_bytes(policy_expressions)).hexdigest(),
    )
    call_expressions = cast(dict[str, object], module_call["expressions"])
    monkeypatch.setitem(
        PLATFORM_POLICY_DOCUMENT_CALL_EXPRESSION_SHA256,
        full_document_address,
        (
            f"module.{module_name}",
            sha256(canonical_json_bytes(call_expressions)).hexdigest(),
        ),
    )
    monkeypatch.setitem(
        PLATFORM_POLICY_DOCUMENT_PLANNED_INPUT_SHA256,
        full_document_address,
        frozenset({sha256(canonical_json_bytes({})).hexdigest()}),
    )
    binding_key = (full_resource_address, field_path)
    binding = PLATFORM_POLICY_DOCUMENT_BINDINGS[binding_key]
    monkeypatch.setitem(
        PLATFORM_POLICY_DOCUMENT_BINDINGS,
        binding_key,
        (binding[0], binding[1], frozenset({sid})),
    )

    normalized = normalize_plan(raw, evaluation_time="2026-09-08T00:00:00Z")

    assert raw == original
    changes = cast(list[dict[str, object]], normalized["resource_changes"])
    consumer_body = cast(dict[str, object], changes[1]["change"])
    assert consumer_body["after_unknown"] == {}
    context = cast(dict[str, object], normalized["evaluation_context"])
    assert context["policy_document_bindings"] == [
        {
            "resource_address": full_resource_address,
            "resource_type": resource_type,
            "field_path": field_path,
            "policy_document_address": full_document_address,
            "relationship": "exact-policy-document",
        }
    ]


def test_v1_approval_alone_cannot_consume_or_dispatch(tmp_path: Path) -> None:
    saved_plan = tmp_path / "platform.tfplan"
    saved_plan.write_bytes(b"approved-plan")
    artifact_sha256 = sha256(b"approved-plan").hexdigest()
    approval = ApprovalRecord.from_mapping(
        {
            "schema_version": "1.0",
            "approval_id": "w5-004-platform-apply-001",
            "action": "PLATFORM-APPLY",
            "environment": "sandbox",
            "aws_account_id": "526338061652",
            "aws_region": "ap-southeast-1",
            "target": "platform",
            "artifact_sha256": artifact_sha256,
            "approver": "Gyan-Prakash-Rai",
            "approved_at": "2026-09-08T00:00:00Z",
            "expires_at": "2026-09-08T00:30:00Z",
        }
    )
    request = MutationRequest(
        action=approval.action,
        environment="sandbox",
        aws_account_id="526338061652",
        aws_region="ap-southeast-1",
        target="platform",
        artifact_sha256=artifact_sha256,
        confirmation=approval.confirmation_text(),
        executor="Gyan-Prakash-Rai",
    )
    ledger = OperationLedger(tmp_path / "ledger", ROOT)
    fake = FakeCommandRunner()
    runner = TerraformRunner(
        executable=Path(r"E:\AI\.tools\terraform\1.16.1\terraform.exe"),
        repository_root=ROOT,
        external_root=tmp_path,
        runner=fake,
    )
    now = datetime(2026, 9, 8, 0, 10, tzinfo=UTC)
    with pytest.raises(ContractError, match="VERIFIED_EXECUTION_CONTEXT"):
        deploy.apply_approved_platform_plan(
            request,
            approval,
            ledger,
            now,
            runner=runner,
            terraform_root=ROOT / "infra/environments/sandbox",
            saved_plan=saved_plan,
        )
    assert not ledger.is_used(approval.approval_id)
    assert fake.calls == []


def test_real_plan_and_complete_infracost_coverage_compose() -> None:
    validate_terraform_plan_json(
        json.dumps(
            {
                "configuration": {"root_module": {}},
                "format_version": "1.2",
                "planned_values": {"root_module": {}},
                "resource_changes": [],
                "terraform_version": "1.16.1",
            }
        ).encode()
    )
    summary = {
        "totalDetectedResources": 2,
        "totalSupportedResources": 2,
        "totalUnsupportedResources": 0,
        "totalUsageBasedResources": 0,
        "totalNoPriceResources": 0,
    }
    result = parse_infracost_output(
        {
            "currency": "USD",
            "totalMonthlyCost": "45.00",
            "summary": summary,
            "projects": [
                {
                    "metadata": {"usageBased": False},
                    "summary": summary,
                    "breakdown": {
                        "resources": [{"name": "endpoint"}, {"name": "opensearch"}],
                        "totalMonthlyCost": "45.00",
                    },
                }
            ],
        }
    )
    assert result.status is Outcome.INDETERMINATE


def test_verified_low_level_dispatch_uses_only_exact_saved_bytes(tmp_path: Path) -> None:
    from dataclasses import replace

    from tools.platformctl.contracts import authorize_mutation

    from tests.fakes.platform_lifecycle import FrozenClock, reviewed_package_fixture

    package, approval, reader, revalidator = reviewed_package_fixture()
    executable = tmp_path / "terraform.exe"
    executable.write_bytes(b"synthetic executable")
    executable_hash = sha256(executable.read_bytes()).hexdigest()
    inputs = dict(package.identities.inputs)
    inputs["runtime/terraform-root"] = sha256(
        canonical_json_bytes(str((ROOT / "infra/environments/sandbox").resolve()))
    ).hexdigest()
    inputs["runtime/terraform-environment"] = sha256(
        canonical_json_bytes(
            {
                "TF_DATA_DIR": str(tmp_path / "terraform-data" / "sandbox"),
                "TF_IN_AUTOMATION": "1",
            }
        )
    ).hexdigest()
    identity = replace(
        package.identities,
        tools=tuple(item for item in package.identities.tools if item[0] != "terraform")
        + (("terraform", str(executable), "1.16.1", executable_hash),),
        inputs=tuple(sorted(inputs.items())),
    )
    package = replace(package, identities=identity)
    approval = replace(approval, review_sha256=sha256(canonical_json_bytes(package)).hexdigest())
    revalidator.observation = replace(revalidator.observation, identities=identity)
    context = authorize_mutation(
        package, approval, reader=reader, revalidator=revalidator, clock=FrozenClock()
    )
    revalidator.consumed = True
    binary = tmp_path / "plan.tfplan"
    binary.write_bytes(reader.payloads[package.artifact.path])
    fake = FakeCommandRunner()
    runner = TerraformRunner(
        executable=executable,
        executable_sha256=executable_hash,
        repository_root=ROOT,
        external_root=tmp_path,
        runner=fake,
    )
    runner.apply_saved_plan(
        ROOT / "infra/environments/sandbox",
        binary,
        package.artifact.sha256,
        execution_context=context,
    )
    assert len(fake.calls) == 1
    assert fake.calls[0][0][1:] == ("apply", "-input=false", "-auto-approve", str(binary))
    with pytest.raises(ContractError, match="CAPABILITY_DISPATCH_ALREADY_STARTED"):
        runner.apply_saved_plan(
            ROOT / "infra/environments/sandbox",
            binary,
            package.artifact.sha256,
            execution_context=context,
        )
    assert len(fake.calls) == 1


@pytest.mark.parametrize("tool", ["terraform", "infracost"])
@pytest.mark.parametrize("failure", [False, True])
def test_real_launch_boundary_isolates_tool_configuration_without_running_tools(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tool: str, failure: bool
) -> None:
    from collections.abc import Mapping, Sequence

    from tools.platformctl.terraform_runner import SubprocessCommandRunner

    repository = tmp_path / "repository"
    repository.mkdir()
    external = tmp_path / "external"
    external.mkdir()
    observed: list[dict[str, str]] = []

    def capture(
        arguments: Sequence[str],
        *,
        cwd: Path,
        environment: Mapping[str, str],
        timeout_seconds: int,
    ) -> ProcessResult:
        observed.append(dict(environment))
        home = Path(environment["USERPROFILE"])
        assert home.parent == external
        assert environment["HOME"] == str(home)
        assert environment["APPDATA"] == str(home)
        assert environment["TEMP"] == str(home)
        assert "INFRACOST_API_KEY" not in environment
        assert "AWS_ACCESS_KEY_ID" not in environment
        if tool == "terraform":
            assert cwd == repository
            assert environment["CHECKPOINT_DISABLE"] == "1"
            assert Path(environment["TF_CLI_CONFIG_FILE"]).read_bytes() == (
                b"disable_checkpoint = true\nprovider_installation {\n  direct {}\n}\n"
            )
        else:
            assert cwd == home
            assert environment["INFRACOST_SKIP_UPDATE_CHECK"] == "true"
            assert environment["INFRACOST_DISABLE_ENVFILE"] == "true"
            assert environment["INFRACOST_ENABLE_CLOUD"] == "false"
            assert environment["INFRACOST_ENABLE_CLOUD_UPLOAD"] == "false"
            assert environment["INFRACOST_PRICING_CACHE_DISABLED"] == "true"
            assert environment["INFRACOST_PRICING_API_ENDPOINT"] == (
                "https://pricing.api.infracost.io"
            )
            assert not (home / ".config/infracost/credentials.yml").exists()
            assert (home / ".config/infracost/.state.json").is_file()
        if failure:
            raise RuntimeError("SYNTHETIC_PROCESS_FAILURE")
        return ProcessResult(0, "synthetic version", "")

    monkeypatch.setattr(SubprocessCommandRunner, "_capture", staticmethod(capture))
    monkeypatch.setenv("INFRACOST_API_KEY", "-".join(("ambient", "synthetic")))
    runner = SubprocessCommandRunner(repository_root=repository, external_root=external)

    def action() -> ProcessResult:
        return runner.run(
            (str(tmp_path / f"{tool}.exe"), "--version" if tool == "infracost" else "version"),
            cwd=repository,
            environment={},
            timeout_seconds=10,
        )

    if failure:
        with pytest.raises(RuntimeError, match="SYNTHETIC_PROCESS_FAILURE"):
            action()
    else:
        assert action().returncode == 0
    assert len(observed) == 1
    assert not list(external.iterdir())


def test_isolated_terraform_preserves_only_the_explicit_aws_profile_files(tmp_path: Path) -> None:
    import os

    from tools.platformctl.terraform_runner import SubprocessCommandRunner

    repository = tmp_path / "repository"
    repository.mkdir()
    external = tmp_path / "external"
    external.mkdir()
    profile_home = tmp_path / "approved-owner-home"
    profile_home.mkdir()
    supplied = {
        "USERPROFILE" if os.name == "nt" else "HOME": str(profile_home),
        "AWS_PROFILE": "default",
        "AWS_REGION": "ap-southeast-1",
        "TF_PLUGIN_CACHE_DIR": str(tmp_path / "provider-cache"),
    }
    before = dict(supplied)
    runner = SubprocessCommandRunner(repository_root=repository, external_root=external)
    with runner._isolated_tool_launch("terraform", "plan", repository, supplied) as launch:
        cwd, child = launch
        assert cwd == repository
        assert child["AWS_PROFILE"] == "default"
        assert child["AWS_REGION"] == "ap-southeast-1"
        assert child["AWS_SHARED_CREDENTIALS_FILE"] == str(profile_home / ".aws/credentials")
        assert child["AWS_CONFIG_FILE"] == str(profile_home / ".aws/config")
        assert child["HOME"] != str(profile_home)
        assert child["TF_PLUGIN_CACHE_DIR"] == supplied["TF_PLUGIN_CACHE_DIR"]
    assert supplied == before
    assert not list(external.iterdir())


def test_isolated_pricing_launch_preserves_only_the_supplied_process_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from collections.abc import Mapping, Sequence

    from tools.platformctl.terraform_runner import SubprocessCommandRunner

    repository = tmp_path / "repository"
    repository.mkdir()
    external = tmp_path / "external"
    external.mkdir()
    supplied = {"INFRACOST_API_KEY": "-".join(("owner", "synthetic"))}
    observed: list[Path] = []

    def capture(
        arguments: Sequence[str],
        *,
        cwd: Path,
        environment: Mapping[str, str],
        timeout_seconds: int,
    ) -> ProcessResult:
        assert environment["INFRACOST_API_KEY"] == supplied["INFRACOST_API_KEY"]
        assert environment["INFRACOST_PRICING_API_ENDPOINT"] == "https://pricing.api.infracost.io"
        assert cwd.parent == external
        assert all(not key.startswith("AWS_") for key in environment)
        observed.append(cwd)
        return ProcessResult(0, "", "")

    monkeypatch.setattr(SubprocessCommandRunner, "_capture", staticmethod(capture))
    runner = SubprocessCommandRunner(repository_root=repository, external_root=external)
    arguments = (
        str(tmp_path / "infracost.exe"),
        "breakdown",
        "--path",
        str(external / "input.json"),
        "--format",
        "json",
        "--out-file",
        str(external / "result.json"),
    )
    result = runner.run(arguments, cwd=repository, environment=supplied, timeout_seconds=10)
    assert result.returncode == 0
    assert len(observed) == 1
    assert not list(external.iterdir())
    with pytest.raises(ContractError, match="PROCESS_PRICING_CREDENTIAL_UNAVAILABLE"):
        runner.run(arguments, cwd=repository, environment={}, timeout_seconds=10)
    assert len(observed) == 1
    assert not list(external.iterdir())


@pytest.mark.parametrize("failure", [False, True])
def test_private_pricing_output_is_removed_before_returning_to_consumer(
    tmp_path: Path, failure: bool
) -> None:
    from tools.platformctl.lifecycle_io import (
        capture_private_tool_json,
        reserve_operation_directory,
    )

    repository = tmp_path / "repository"
    repository.mkdir()
    external = tmp_path / "external"
    reserve_operation_directory(external, external, repository)
    target = external / "raw-output.json"

    def produce(path: Path) -> None:
        assert path.read_bytes() == b""
        path.write_bytes(b'{"count":1}')
        if failure:
            raise RuntimeError("SYNTHETIC_TOOL_FAILURE")

    if failure:
        with pytest.raises(RuntimeError, match="SYNTHETIC_TOOL_FAILURE"):
            capture_private_tool_json(
                target, produce, allowed_root=external, repository_root=repository
            )
    else:
        result = capture_private_tool_json(
            target, produce, allowed_root=external, repository_root=repository
        )
        assert result == {"count": 1}
    assert not target.exists()


@pytest.mark.parametrize("scope,native_count", [("bootstrap", 10), ("platform", 41)])
def test_diagnostic_profiles_are_complete_typed_and_deterministic(
    scope: str, native_count: int
) -> None:
    from tools.platformctl.aws_inventory import NativeTargetBundle, diagnostic_resource_profile
    from tools.platformctl.lifecycle_io import decode_operational_record
    from tools.platformctl.plan import diagnostic_rules

    bundle = diagnostic_resource_profile(scope)
    raw = canonical_json_bytes(bundle)
    assert decode_operational_record(raw, NativeTargetBundle) == bundle
    assert raw == canonical_json_bytes(diagnostic_resource_profile(scope))
    assert len(bundle.targets) == native_count
    assert len({item.address for item in bundle.targets}) == native_count
    assert len(diagnostic_rules(scope)) == native_count + 1
    assert all(rule.delta_rule == "DIAGNOSTIC_ONLY" for rule in diagnostic_rules(scope))
    assert b"aws_iam_service_linked_role" not in raw


@pytest.mark.parametrize(
    "failure", ["none", "resource", "routing", "state_drift", "missing_evidence"]
)
def test_targeted_resolution_complete_production_coordinator(tmp_path, monkeypatch, failure):
    from dataclasses import replace
    from io import BytesIO

    from tools.platformctl import lifecycle_io
    from tools.platformctl import plan as plan_module
    from tools.platformctl.aws_inventory import (
        RESOLUTION_DIRECTORY,
        RESOLUTION_EVIDENCE_SHA256,
        RESOLUTION_OPERATION_ID,
        diagnostic_discovery_profile,
        diagnostic_resource_profile,
    )
    from tools.platformctl.aws_live import (
        RESOLUTION_METHODS,
        DiagnosticFatalError,
        DiagnosticReadError,
    )
    from tools.platformctl.lifecycle_models import (
        DIAGNOSTIC_SCHEMA_VERSION,
        DiagnosticRequest,
        DiagnosticRuntimeConfiguration,
    )

    from tests.fakes.platform_lifecycle import (
        CompleteDiagnosticAwsFixture,
        FrozenClock,
        reviewed_package_fixture,
    )

    repository, external = tmp_path / "repository", tmp_path / "external"
    repository.mkdir()
    parent = external / "consolidated-remediation-001"
    external.mkdir()
    lifecycle_io.reserve_operation_directory(parent, external, repository)
    root = parent / RESOLUTION_DIRECTORY
    fixture = CompleteDiagnosticAwsFixture()
    package, _, _, _ = reviewed_package_fixture()
    real_reply = fixture.reply
    state_reads = []

    def reply(service, method, arguments):
        assert method in RESOLUTION_METHODS[service], "Unapproved collection or mutation"
        if method == "describe_vpc_endpoints":
            if failure == "resource":
                raise DiagnosticReadError("AccessDeniedException")
            if failure == "routing":
                raise DiagnosticFatalError("DIAGNOSTIC_INITIAL_HOST_NOT_APPROVED")
            return {
                "VpcEndpoints": [
                    {
                        "VpcEndpointId": identity,
                        "PolicyDocument": {
                            "Version": "2008-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": "*",
                                    "Action": "*",
                                    "Resource": "*",
                                }
                            ],
                        },
                    }
                    for identity in arguments["VpcEndpointIds"]
                ]
            }
        if method == "get_object":
            state_reads.append("platform")
            raw = fixture.states["platform"]
            if failure == "state_drift" and len(state_reads) > 1:
                raw += b"\n"
            return {
                "Body": BytesIO(raw),
                "VersionId": "synthetic-version",
                "ETag": '"synthetic-etag"',
            }
        if method == "list_buckets":
            return {"Buckets": []}
        if method == "get_cost_and_usage":
            return {"ResultsByTime": []}
        return real_reply(service, method, arguments)

    fixture.reply = reply
    session = fixture.session(resolution_only=True)
    binding = (
        "resolution/completed-diagnostic.json",
        str(parent / "codex-diagnostic-001/attempt-002/run-001/diagnostic.json"),
        RESOLUTION_EVIDENCE_SHA256,
    )
    configuration = DiagnosticRuntimeConfiguration(
        DIAGNOSTIC_SCHEMA_VERSION,
        (),
        (),
        (),
        (),
        (binding,),
        str(external),
        "backend",
        "a" * 64,
        canonical_json_bytes(diagnostic_resource_profile("platform")).decode(),
        canonical_json_bytes(diagnostic_resource_profile("bootstrap")).decode(),
        canonical_json_bytes(diagnostic_discovery_profile()).decode(),
        plan_module.diagnostic_rules("platform"),
        plan_module.diagnostic_rules("bootstrap"),
        None,
        None,
        (),
        None,
    )
    if failure == "missing_evidence":
        configuration = replace(configuration, input_files=())
    request = DiagnosticRequest(
        DIAGNOSTIC_SCHEMA_VERSION,
        RESOLUTION_OPERATION_ID,
        "sandbox",
        "platform",
        str(root),
        "backend",
        "a" * 64,
        package.identities,
        tuple(
            (scope, json.loads(raw)["lineage"], json.loads(raw)["serial"], sha256(raw).hexdigest())
            for scope, raw in fixture.states.items()
        ),
    )
    actual_config = lifecycle_io.load_lifecycle_config(Path("configs/lifecycle/w5-004.json"))
    monkeypatch.setattr(lifecycle_io, "load_lifecycle_config", lambda _path: actual_config)
    monkeypatch.setattr(
        plan_module, "read_private_state", lambda *_args, **_kwargs: fixture.states["bootstrap"]
    )
    coordinator = plan_module.RepositoryDiagnosticCoordinator(
        configuration,
        repository=repository,
        external=external,
        clock=FrozenClock(),
        git=None,
        session=session,
        runtime_identity=None,
    )
    monkeypatch.setattr(coordinator, "identities", lambda _request: package.identities)
    if failure == "missing_evidence":
        with pytest.raises(ContractError, match="RETAINED_EVIDENCE"):
            coordinator.execute_request("aws-verify", canonical_json_bytes(request))
        assert fixture.calls == [] and not root.exists()
        return
    code, _ = coordinator.execute_request("aws-verify", canonical_json_bytes(request))
    assert code == 1
    assert {path.name for path in root.iterdir()} == {"resolution.json", "resolution-identity.json"}
    report = json.loads((root / "resolution.json").read_bytes())
    identity = json.loads((root / "resolution-identity.json").read_bytes())
    checks = {row["check_id"]: row for row in report["checks"]}
    assert len(checks) == 31
    assert sum(key.startswith("endpoint/") for key in checks) == 8
    assert sum(key.startswith("discovery/") for key in checks) == 9
    assert checks["final_preservation"]["status"] == "PASS"
    assert checks["bootstrap_state_preserved"]["status"] == "PASS"
    assert checks["lifecycle_accounting"]["status"] == "INDETERMINATE"
    assert "endpoint_collection" in checks and "owner_managed_service_role" in checks
    assert "historical_log_failures" in checks and "sandbox_expiry" in checks
    assert report["mutation_started"] is False and report["terraform"] == "NOT_RUN"
    assert report["limits"]["requests"] == 200
    assert report["limits"]["pages"] == 3 and report["limits"]["elapsed_seconds"] == 900
    assert identity
    if failure == "routing":
        assert report["billing_requests"] == 0
        assert checks["platform_state_preserved"]["status"] == "BLOCKED_DEPENDENCY"
        assert fixture.calls[-1][1] == "describe_vpc_endpoints"
    else:
        assert report["billing_requests"] == 3
        assert all(
            checks["billing/" + kind]["status"] == "INDETERMINATE"
            for kind in ("account", "service", "usage")
        )
        assert checks["platform_state_preserved"]["status"] == (
            "FAIL" if failure == "state_drift" else "PASS"
        )
    with pytest.raises(ContractError):
        coordinator.execute_request("aws-verify", canonical_json_bytes(request))


def test_diagnostic_profiles_cover_only_implemented_read_apis() -> None:
    from tools.platformctl.aws_inventory import (
        diagnostic_discovery_profile,
        diagnostic_resource_profile,
    )
    from tools.platformctl.aws_live import _READ_METHODS, diagnostic_discovery_coverage

    scans = diagnostic_discovery_profile()
    assert len(scans.scans) == 26
    assert {scan.coverage for scan in scans.scans} == diagnostic_discovery_coverage()
    for scan in scans.scans:
        assert scan.method in _READ_METHODS[scan.service]
        for method in (scan.detail_method, scan.tag_method):
            assert method is None or method in _READ_METHODS[scan.service]
    for scope in ("bootstrap", "platform"):
        for target in diagnostic_resource_profile(scope).targets:
            for probe in (target.presence, *(item.probe for item in target.assertions)):
                assert probe.method in _READ_METHODS[probe.service]
                assert 1 <= probe.maximum_pages <= 10
                assert probe.maximum_items <= 5000


def test_diagnostic_missing_resources_do_not_need_missing_state_ids() -> None:
    from tools.platformctl.aws_inventory import diagnostic_resource_profile

    missing = {
        'module.opensearch.aws_cloudwatch_log_group.this["application"]',
        'module.opensearch.aws_cloudwatch_log_group.this["audit"]',
        'module.opensearch.aws_cloudwatch_log_group.this["index_slow"]',
        'module.opensearch.aws_cloudwatch_log_group.this["search_slow"]',
        "module.opensearch.aws_opensearch_domain.this",
    }
    selected = [
        item for item in diagnostic_resource_profile("platform").targets if item.address in missing
    ]
    assert len(selected) == 5
    for target in selected:
        encoded = canonical_json_bytes(target).decode()
        for absent in missing:
            assert "state://" + absent + "#" not in encoded


def test_local_diagnostic_preparation_publishes_only_typed_review_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from dataclasses import replace

    from tools.platformctl import plan as plan_module
    from tools.platformctl.aws_inventory import (
        diagnostic_discovery_profile,
        diagnostic_resource_profile,
    )
    from tools.platformctl.lifecycle_io import (
        decode_diagnostic_record,
        reserve_operation_directory,
    )
    from tools.platformctl.lifecycle_models import (
        DIAGNOSTIC_SCHEMA_VERSION,
        DiagnosticRequest,
        DiagnosticRuntimeConfiguration,
    )
    from tools.platformctl.terraform_runner import GitObservationRunner

    from tests.fakes.platform_lifecycle import reviewed_package_fixture

    repository, external = tmp_path / "repository", tmp_path / "external"
    repository.mkdir()
    external.mkdir()
    parent = external / "consolidated-remediation-001"
    reserve_operation_directory(parent, external, repository)
    package, _, _, _ = reviewed_package_fixture()
    configuration = DiagnosticRuntimeConfiguration(
        DIAGNOSTIC_SCHEMA_VERSION,
        (),
        (),
        (),
        (),
        (),
        str(external),
        "bootstrap",
        "a" * 64,
        canonical_json_bytes(diagnostic_resource_profile("platform")).decode(),
        canonical_json_bytes(diagnostic_resource_profile("bootstrap")).decode(),
        canonical_json_bytes(diagnostic_discovery_profile()).decode(),
        plan_module.diagnostic_rules("platform"),
        plan_module.diagnostic_rules("bootstrap"),
        None,
        None,
        (),
        None,
    )
    expected_states = (
        ("bootstrap", "c446f9a2-77d4-9954-20fa-523205d86a8a", 17, "b" * 64),
        ("platform", "7465ed2e-a39c-afdd-f172-5792d3ec2f85", 4, "c" * 64),
    )

    def observe(_configuration: object, request: DiagnosticRequest, **_kwargs: object) -> object:
        return request.approved_identities

    monkeypatch.setattr(plan_module, "observe_repository_identities", observe)
    historical = parent / "consolidated-prerequisite-diagnostic-001"
    historical.mkdir()
    historical_input = historical / "preserved-fixture.json"
    historical_input.write_bytes(b'{"historical":true}')
    latest_historical = parent / "consolidated-prerequisite-diagnostic-002"
    latest_historical.mkdir()
    diagnostic_input = latest_historical / "preserved-fixture.json"
    diagnostic_input.write_bytes(b'{"unresolved":true}')
    previous = parent / "consolidated-prerequisite-diagnostic-003"
    previous.mkdir()
    previous_input = previous / "preserved-fixture.json"
    previous_input.write_bytes(b'{"routing_failure":true}')
    previous_run = parent / "consolidated-prerequisite-diagnostic-004"
    previous_run.mkdir()
    previous_report = previous_run / "diagnostic.json"
    previous_report.write_bytes(b'{"prerequisites":"unresolved"}')
    last_owner_run = parent / "consolidated-prerequisite-diagnostic-005"
    last_owner_run.mkdir()
    last_owner_report = last_owner_run / "diagnostic.json"
    last_owner_report.write_bytes(b'{"routing":"unresolved"}')
    override_parent = parent / "codex-diagnostic-001"
    reserve_operation_directory(override_parent, external, repository)
    prior = override_parent / "attempt-001"
    reserve_operation_directory(prior, external, repository)
    reserve_operation_directory(prior / "inputs", external, repository)
    prior_hashes = {}
    for name in plan_module.DIAGNOSTIC_PRIOR_INPUTS:
        value = canonical_json_bytes({"historical_input": name})
        (prior / "inputs" / name).write_bytes(value)
        prior_hashes[name] = sha256(value).hexdigest()
    monkeypatch.setattr(plan_module, "DIAGNOSTIC_PRIOR_INPUTS", prior_hashes)
    artifacts = plan_module.prepare_diagnostic_artifacts(
        configuration,
        repository=repository,
        external=external,
        git=cast(GitObservationRunner, None),
        approved_source=package.identities,
        backend_path=external / "platform.backend.hcl",
        backend_sha256="d" * 64,
        expected_states=expected_states,
    )
    assert len(artifacts) == 2
    assert historical_input.read_bytes() == b'{"historical":true}'
    assert diagnostic_input.read_bytes() == b'{"unresolved":true}'
    assert previous_input.read_bytes() == b'{"routing_failure":true}'
    for path, digest in artifacts:
        assert sha256(Path(path).read_bytes()).hexdigest() == digest
    request = decode_diagnostic_record(Path(artifacts[0][0]).read_bytes(), DiagnosticRequest)
    runtime = decode_diagnostic_record(
        Path(artifacts[1][0]).read_bytes(), DiagnosticRuntimeConfiguration
    )
    assert runtime == configuration
    assert runtime.exposure is None
    assert Path(request.operation_root).parts[-2:] == ("codex-diagnostic-001", "attempt-002")
    assert request.operation_id == "w5-004-codex-diagnostic-001-attempt-002"
    assert request.expected_states == expected_states
    assert dict(request.approved_identities.inputs)["runtime/configuration.json"] == artifacts[1][1]
    assert request.approved_identities == replace(
        package.identities,
        inputs=tuple(
            sorted((*package.identities.inputs, ("runtime/configuration.json", artifacts[1][1])))
        ),
    )
    assert not (Path(request.operation_root) / "run-001").exists()
    assert previous_report.read_bytes() == b'{"prerequisites":"unresolved"}'
    assert last_owner_report.read_bytes() == b'{"routing":"unresolved"}'
    with pytest.raises(ContractError, match="DIRECTORY_ALREADY_EXISTS"):
        plan_module.prepare_diagnostic_artifacts(
            configuration,
            repository=repository,
            external=external,
            git=cast(GitObservationRunner, None),
            approved_source=package.identities,
            backend_path=external / "platform.backend.hcl",
            backend_sha256="d" * 64,
            expected_states=expected_states,
        )
    assert previous_report.read_bytes() == b'{"prerequisites":"unresolved"}'
    for path, digest in artifacts:
        assert sha256(Path(path).read_bytes()).hexdigest() == digest

    # Exercise the real CLI runtime loader, not only the injected coordinator.
    from tools.platformctl import lifecycle_io

    from tests.fakes.platform_lifecycle import FrozenClock

    monkeypatch.setattr(
        lifecycle_io,
        "load_lifecycle_config",
        lambda _path: {"external_paths": {"temporary_root": str(external)}},
    )

    def forbidden_provider(**_kwargs: object) -> None:
        raise AssertionError("Runtime root tests must not discover credentials or contact AWS")

    monkeypatch.setattr(plan_module.Boto3AwsInventoryProvider, "from_profile", forbidden_provider)
    # This minimal runtime deliberately lacks Git: the next identity gate must run.
    with pytest.raises(ContractError, match="GIT_RUNTIME_IDENTITY_REQUIRED"):
        plan_module.production_coordinator(
            Path(artifacts[1][0]),
            artifacts[1][1],
            request_payload=canonical_json_bytes(request),
            repository=repository,
            clock=FrozenClock(),
        )
    for rejected_root in (
        parent,
        parent / "attempt-002",
        override_parent / "attempt-001",
        override_parent / "attempt-003",
        parent / "other-diagnostic/attempt-002",
    ):
        with pytest.raises(ContractError, match="SINGLE_USE_OPERATION_ROOT_REQUIRED"):
            plan_module.production_coordinator(
                Path(artifacts[1][0]),
                artifacts[1][1],
                request_payload=canonical_json_bytes(
                    replace(request, operation_root=str(rejected_root))
                ),
                repository=repository,
                clock=FrozenClock(),
            )
    for path, digest in artifacts:
        assert sha256(Path(path).read_bytes()).hexdigest() == digest


@pytest.mark.parametrize("failure", ["none", "resource", "routing", "state_drift"])
def test_followup_production_cli_to_two_reports(tmp_path, monkeypatch, capsys, failure):
    from datetime import UTC, datetime, timedelta
    from io import BytesIO

    from tools.platformctl import cli, lifecycle_io
    from tools.platformctl import plan as production
    from tools.platformctl.aws_inventory import (
        RESOLUTION_DIRECTORY,
        RESOLUTION_EVIDENCE_SHA256,
        RESOLUTION_FOLLOWUP_DIRECTORY,
        RESOLUTION_FOLLOWUP_OPERATION_ID,
        diagnostic_discovery_profile,
        diagnostic_resource_profile,
    )
    from tools.platformctl.aws_live import (
        FOLLOWUP_METHODS,
        FOLLOWUP_NETWORK,
        Boto3AwsInventoryProvider,
        DiagnosticFatalError,
        DiagnosticReadError,
    )
    from tools.platformctl.lifecycle_models import (
        DIAGNOSTIC_SCHEMA_VERSION,
        DiagnosticRequest,
        DiagnosticRuntimeConfiguration,
    )

    from tests.fakes.platform_lifecycle import (
        CompleteDiagnosticAwsFixture,
        reviewed_package_fixture,
    )
    from tests.security.test_w5_004_lifecycle_security import followup_retained_fixture

    raw, identity_raw = followup_retained_fixture(monkeypatch)
    repository, external = tmp_path / "repo", tmp_path / "external"
    repository.mkdir()
    external.mkdir()
    parent = external / "consolidated-remediation-001"
    lifecycle_io.reserve_operation_directory(parent, external, repository)
    previous = parent / RESOLUTION_DIRECTORY
    lifecycle_io.reserve_operation_directory(previous, external, repository)
    for name, contents in (("resolution.json", raw), ("resolution-identity.json", identity_raw)):
        lifecycle_io.write_canonical_json_atomic(
            previous / name, json.loads(contents), allowed_root=external, repository_root=repository
        )
    root = parent / RESOLUTION_FOLLOWUP_DIRECTORY
    fixture = CompleteDiagnosticAwsFixture()
    state = json.loads(fixture.states["platform"])
    for row in state["resources"]:
        if row["type"] == "aws_vpc":
            row["instances"][0]["attributes"]["id"] = "vpc-" + "0" * 17
    fixture.states["platform"] = canonical_json_bytes(state)
    package, _, _, _ = reviewed_package_fixture()
    real_reply = fixture.reply
    reads = []

    def reply(service, method, arguments):
        assert method in FOLLOWUP_METHODS.get(service, ()), "Not an approved follow-up read"
        if method == "describe_vpc_endpoints":
            if failure == "resource":
                raise DiagnosticReadError("AccessDeniedException")
            if failure == "routing":
                raise DiagnosticFatalError("DIAGNOSTIC_INITIAL_HOST_NOT_APPROVED")
            return {
                "VpcEndpoints": [
                    {
                        "VpcEndpointId": value,
                        "VpcId": "vpc-" + "0" * 17,
                        "NetworkInterfaceIds": [f"eni-{index:017x}"],
                        "SubnetIds": ["subnet-" + "0" * 17],
                        "Groups": [{"GroupId": "sg-" + "0" * 17}],
                        "PolicyDocument": {
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": "*",
                                    "Action": "*",
                                    "Resource": "*",
                                }
                            ]
                        },
                    }
                    for index, value in enumerate(arguments["VpcEndpointIds"])
                ]
            }
        if service == "ec2":
            spec = next(row for row in FOLLOWUP_NETWORK.values() if row[0] == method)
            return {
                spec[2]: [
                    {
                        spec[3]: value,
                        "VpcId": value if method == "describe_vpcs" else "vpc-" + "0" * 17,
                        "OwnerId": "526338061652",
                        "Tags": [],
                        "RequesterManaged": True,
                        "SubnetId": value if method == "describe_subnets" else "subnet-" + "0" * 17,
                        "Groups": [{"GroupId": "sg-" + "0" * 17}],
                    }
                    for value in arguments[spec[1]]
                ]
            }
        if method == "get_role":
            name = arguments["RoleName"]
            if name == "AWSServiceRoleForAmazonOpenSearchService":
                raise DiagnosticReadError("NoSuchEntity")
            return {
                "Role": {
                    "RoleName": name,
                    "Arn": "arn:aws:iam::526338061652:role/" + name,
                    "Path": "/",
                    "AssumeRolePolicyDocument": {"Statement": []},
                }
            }
        if method == "list_entities_for_policy":
            return {"PolicyRoles": [], "PolicyUsers": [], "PolicyGroups": [], "IsTruncated": False}
        if method == "get_object":
            reads.append("platform")
            data = fixture.states["platform"] + (
                b"\\n" if failure == "state_drift" and len(reads) > 1 else b""
            )
            return {
                "Body": BytesIO(data),
                "VersionId": "synthetic-version",
                "ETag": '"synthetic-etag"',
            }
        if method == "get_cost_and_usage":
            return {
                "ResultsByTime": [
                    {
                        "TimePeriod": {
                            "Start": (datetime(2026, 9, 8) + timedelta(days=i)).date().isoformat(),
                            "End": (datetime(2026, 9, 9) + timedelta(days=i)).date().isoformat(),
                        },
                        "Estimated": True,
                        "Groups": [
                            {
                                "Keys": ["VPC", "Endpoint-Hours"],
                                "Metrics": {"UnblendedCost": {"Amount": "2.00", "Unit": "USD"}},
                            }
                        ],
                    }
                    for i in range(5)
                ]
            }
        return real_reply(service, method, arguments)

    fixture.reply = reply
    source_provider = fixture.session(resolution_only=True)._source
    monkeypatch.setattr(
        Boto3AwsInventoryProvider, "from_profile", lambda **_kwargs: source_provider
    )
    binding = (
        "resolution/completed-diagnostic.json",
        str(parent / "codex-diagnostic-001/attempt-002/run-001/diagnostic.json"),
        RESOLUTION_EVIDENCE_SHA256,
    )
    bindings = (
        binding,
        (
            "resolution/previous/resolution.json",
            str(previous / "resolution.json"),
            sha256(raw).hexdigest(),
        ),
        (
            "resolution/previous/resolution-identity.json",
            str(previous / "resolution-identity.json"),
            sha256(identity_raw).hexdigest(),
        ),
    )
    configuration = DiagnosticRuntimeConfiguration(
        DIAGNOSTIC_SCHEMA_VERSION,
        (),
        (),
        (),
        (),
        bindings,
        str(external),
        "backend",
        "a" * 64,
        canonical_json_bytes(diagnostic_resource_profile("platform")).decode(),
        canonical_json_bytes(diagnostic_resource_profile("bootstrap")).decode(),
        canonical_json_bytes(diagnostic_discovery_profile()).decode(),
        production.diagnostic_rules("platform"),
        production.diagnostic_rules("bootstrap"),
        None,
        None,
        (),
        None,
    )
    request = DiagnosticRequest(
        DIAGNOSTIC_SCHEMA_VERSION,
        RESOLUTION_FOLLOWUP_OPERATION_ID,
        "sandbox",
        "platform",
        str(root),
        "backend",
        "a" * 64,
        package.identities,
        tuple(
            (
                scope,
                json.loads(value)["lineage"],
                json.loads(value)["serial"],
                sha256(value).hexdigest(),
            )
            for scope, value in fixture.states.items()
        ),
    )
    config = lifecycle_io.load_lifecycle_config(Path("configs/lifecycle/w5-004.json"))
    config["external_paths"]["temporary_root"] = str(external)
    monkeypatch.setattr(cli, "repository_root", lambda: repository)
    monkeypatch.setattr(cli, "load_lifecycle_config", lambda _path: config)
    monkeypatch.setattr(lifecycle_io, "load_lifecycle_config", lambda _path: config)

    def produce(repo, outside, source, *, resolution_only=False, followup=False):
        assert repo == repository and outside == external and source == "a" * 64
        assert resolution_only and followup
        return configuration, request, None

    monkeypatch.setattr(production, "_build_owner_diagnostic_inputs", produce)
    monkeypatch.setattr(
        production, "read_private_state", lambda *_a, **_k: fixture.states["bootstrap"]
    )
    monkeypatch.setattr(
        production.RepositoryDiagnosticCoordinator, "identities", lambda *_a: package.identities
    )

    class Clock:
        def now(self):
            return datetime(2026, 9, 13, 5, tzinfo=UTC)

    arguments = [
        "aws-verify",
        "--environment",
        "sandbox",
        "--target",
        "platform",
        "--diagnostic",
        "--resolution-followup",
        "--execute",
        "--source-sha256",
        "a" * 64,
        "--evidence-sha256",
        sha256(raw).hexdigest(),
    ]
    assert cli.main(arguments, clock=Clock()) == 1
    report = json.loads((root / "resolution.json").read_bytes())
    assert {path.name for path in root.iterdir()} == {"resolution.json", "resolution-identity.json"}
    checks = {item["check_id"]: item for item in report["checks"]}
    assert len(checks) == 30
    assert checks["bootstrap_expiry_disposition"]["status"] == "FAIL"
    assert checks["owner_managed_service_role"]["status"] in {"FAIL", "BLOCKED_DEPENDENCY"}
    assert checks["lifecycle_accounting"]["status"] == "INDETERMINATE"
    assert checks["final_preservation"]["status"] == "PASS"
    assert report["operation_id"] == RESOLUTION_FOLLOWUP_OPERATION_ID
    assert report["terraform"] == report["pricing"] == "NOT_RUN"
    assert report["mutation_started"] is False
    if failure == "routing":
        assert report["billing_requests"] == 0
        assert checks["platform_state_preserved"]["status"] == "BLOCKED_DEPENDENCY"
    else:
        assert report["billing_requests"] == 1
        assert checks["billing/usage"]["status"] == "PASS"
        assert checks["platform_state_preserved"]["status"] == (
            "FAIL" if failure == "state_drift" else "PASS"
        )
        if failure == "none":
            assert all(
                row["status"] == "PASS"
                for key, row in checks.items()
                if key.startswith("endpoint/")
            )
    assert (previous / "resolution.json").read_bytes() == raw
    count = len(fixture.calls)
    assert cli.main(arguments, clock=Clock()) == 1
    assert len(fixture.calls) == count
    assert "RESOLUTION_DIRECTORY_ALREADY_USED" in capsys.readouterr().err


@pytest.mark.parametrize("invalid", [None, "hash", "cycle"])
def test_correction_preparation_consumes_typed_charging_records(tmp_path, invalid):
    from datetime import UTC, datetime

    from tools.platformctl.cost import cycle_required_charge_ids
    from tools.platformctl.lifecycle_io import (
        reserve_operation_directory,
        write_canonical_json_atomic,
    )
    from tools.platformctl.lifecycle_models import CycleChargingEvidence
    from tools.platformctl.plan import prepare_prerequisite_correction_inputs

    repository, external = tmp_path / "repository", tmp_path / "external"
    repository.mkdir()
    reserve_operation_directory(external, external, repository)
    parent = external / "consolidated-remediation-001"
    reserve_operation_directory(parent, external, repository)
    for folder, name, payload in (
        ("prerequisite-evidence-001", "resolution.json", {}),
        ("pricing-breakdown-001", "resource-pricing-breakdown.json", {"resources": []}),
    ):
        reserve_operation_directory(parent / folder, external, repository)
        write_canonical_json_atomic(
            parent / folder / name, payload, allowed_root=external, repository_root=repository
        )
    approval = external / "owner.txt"
    approval.write_text("synthetic scoped declaration")
    # Empty quantities are valid diagnostic input, never an execution-ready cost bound.
    basis = CycleChargingEvidence(
        "w5-004.lifecycle.v2",
        "W5-CYCLE-B" if invalid == "cycle" else "W5-CYCLE-A",
        "USD",
        (),
        tuple(sorted(cycle_required_charge_ids())),
        "2026-09-13T00:00:00Z",
        None,
    )
    basis_path = external / "reviewed-charging.json"
    basis_hash = write_canonical_json_atomic(
        basis_path, basis, allowed_root=external, repository_root=repository
    )

    class Clock:
        def now(self):
            return datetime(2026, 9, 13, 9, tzinfo=UTC)

    arguments = dict(
        clock=Clock(),
        source_sha256="a" * 64,
        charging_input=(basis_path, "b" * 64 if invalid == "hash" else basis_hash),
    )
    if invalid:
        with pytest.raises(ContractError):
            prepare_prerequisite_correction_inputs(
                repository,
                external,
                approval,
                sha256(approval.read_bytes()).hexdigest(),
                **arguments,
            )
        assert not (parent / "prerequisite-correction-inputs-001").exists()
    else:
        outputs = prepare_prerequisite_correction_inputs(
            repository, external, approval, sha256(approval.read_bytes()).hexdigest(), **arguments
        )
        assert len(outputs) == 3
        generated = json.loads(Path(outputs[1][0]).read_bytes())
        assert generated["required_components"] == list(basis.required_components)
        assert generated["components"] == []


def test_plan_artifact_cli_dispatch_is_non_mutating(monkeypatch, capsys, tmp_path: Path) -> None:
    from tools.platformctl import cli

    calls: list[tuple[Path, str, Path]] = []

    def prepare(owner_input, owner_hash, operation_root, *, external_root, repository_root):
        calls.append((owner_input, owner_hash, operation_root))
        return ((str(operation_root / "inputs" / "request.json"), "a" * 64),)

    monkeypatch.setattr(cli.plan_artifact_producer, "prepare_plan_artifacts", prepare)
    owner_input = tmp_path / "owner.json"
    arguments = [
        "prepare-plan-artifacts",
        "--owner-input-file",
        str(owner_input),
        "--owner-input-sha256",
        "b" * 64,
        "--operation-root",
        str(tmp_path / "saved-plan-009"),
    ]
    assert cli.main(arguments) == 0
    assert calls and calls[0][1] == "b" * 64
    assert "TERRAFORM=NOT_RUN" in capsys.readouterr().out


def test_plan_owner_envelope_cli_dispatch_is_non_mutating(
    monkeypatch, capsys, tmp_path: Path
) -> None:
    from tools.platformctl import cli

    calls: list[tuple[Path, str, Path]] = []

    def prepare(
        confirmation,
        confirmation_hash,
        state,
        state_hash,
        variables,
        variables_hash,
        backend,
        backend_hash,
        operation_root,
        *,
        external_root,
        repository_root,
    ):
        del state, state_hash, variables, variables_hash, backend, backend_hash
        del external_root, repository_root
        calls.append((confirmation, confirmation_hash, operation_root))
        return ((str(tmp_path / "owner-input.json"), "a" * 64),)

    monkeypatch.setattr(cli.plan_artifact_producer, "prepare_owner_envelope", prepare)
    arguments = [
        "prepare-plan-owner-envelope",
        "--owner-confirmation-file",
        str(tmp_path / "confirmation.json"),
        "--owner-confirmation-sha256",
        "b" * 64,
        "--state-evidence-file",
        str(tmp_path / "state.json"),
        "--state-evidence-sha256",
        "c" * 64,
        "--variables-example-file",
        str(tmp_path / "terraform.tfvars.example"),
        "--variables-example-sha256",
        "d" * 64,
        "--backend-example-file",
        str(tmp_path / "backend.hcl.example"),
        "--backend-example-sha256",
        "e" * 64,
        "--operation-root",
        str(tmp_path / "saved-plan-009"),
    ]
    assert cli.main(arguments) == 0
    assert calls and calls[0][1] == "b" * 64
    output = capsys.readouterr().out
    assert "PLAN_OWNER_ENVELOPE_PREPARATION=PASS" in output
    assert "TERRAFORM=NOT_RUN; AWS=NOT_RUN; BILLING=NOT_RUN" in output
