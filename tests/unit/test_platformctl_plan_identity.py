"""Unit tests for immutable saved-plan identity and plan classification."""

from __future__ import annotations

import json
from dataclasses import asdict, replace
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

import pytest
from tools.platformctl.contracts import Action, ContractError, generated_resource_expires_at
from tools.platformctl.lifecycle_io import (
    lifecycle_scope,
    parse_git_index,
    parse_git_status,
    working_manifest,
)
from tools.platformctl.lifecycle_models import (
    ChangeProfile,
    CostReviewTerms,
    EvidenceRef,
    IdentityBundle,
    PlanAction,
    PlanIdentity,
    RecoveryProfile,
    ResourceChangeRule,
    RuntimeConfiguration,
)
from tools.platformctl.plan import prepare_resource_expiry_input, validate_plan_identity
from tools.platformctl.plan_artifact_producer import prepare_owner_envelope, prepare_plan_artifacts
from tools.platformctl.policy_runner import normalize_plan, summarize_plan

HASH = "a" * 64
ROOT = Path(__file__).resolve().parents[2]


def _owner_envelope_inputs(external_root: Path) -> tuple[dict[str, object], dict[str, object]]:
    expiry = "2026-09-16T05:00:00Z"
    reference = EvidenceRef(
        "owner-decision",
        "decision.json",
        HASH,
        1,
        "owner",
        "2026-09-15T00:00:00Z",
        expiry,
        "saved-plan-009",
    )
    profile = RecoveryProfile(
        ChangeProfile.PARTIAL_RECOVERY,
        Action.PLATFORM_APPLY,
        (
            ResourceChangeRule(
                "module.network.aws_vpc.this",
                "aws_vpc",
                ("create",),
                (),
                "EXACT",
            ),
        ),
        (reference,),
        expiry,
        "OWNER_MANAGED",
        "OWNER_VERIFIED",
        None,
        None,
        None,
    )
    identities = IdentityBundle(
        "w5-004.lifecycle-content.v1",
        HASH,
        HASH,
        HASH,
        HASH,
        "78576879b2c1d13507680872f471345c7b9b6be0",
        (("python", "python.exe", "3.13.15", HASH),),
        (("current/source", HASH),),
        HASH,
    )
    runtime = RuntimeConfiguration(
        "w5-004.lifecycle.v2",
        (("python", "python.exe", "3.13.15", HASH),),
        (("PYTHONDONTWRITEBYTECODE", "1"),),
        (("protected.txt", HASH),),
        ((" M", "Makefile", None),),
        (),
        str(external_root / "terraform-data"),
        "[]",
        "[]",
        "[]",
        CostReviewTerms(
            "w5-004.cost-terms.v2",
            "saved-plan-009",
            "platform",
            (),
            (reference,),
            "0.00",
            "0.00",
            "0.00",
            "2026-09-15T00:00:00Z",
            0,
            expiry,
        ),
        (),
        "lineage-009",
        9,
        "{}",
        None,
        None,
    )
    confirmation = {
        "schema_version": "w5-004.plan-owner-confirmation.v1",
        "operation_id": "saved-plan-009",
        "account_id": "526338061652",
        "region": "ap-southeast-1",
        "principal_arn": "arn:aws:iam::526338061652:user/finopsinfra",
        "environment": "sandbox",
        "target": "platform",
        "variable_overrides": {"mandatory_tags.ExpiresAt": expiry},
        "profile": asdict(profile),
        "approved_identities": asdict(identities),
        "runtime": asdict(runtime),
        "owner_bindings": {
            "account_id": "526338061652",
            "region": "ap-southeast-1",
            "principal_arn": "arn:aws:iam::526338061652:user/finopsinfra",
            "environment": "sandbox",
            "target": "platform",
            "lifecycle_ceiling_usd": "3.00",
            "source_member_count": 518,
            "protected_member_count": 504,
            "source_sha256": HASH,
            "policy_sha256": HASH,
            "protected_sha256": HASH,
            "tools_sha256": HASH,
            "state_content_sha256": "b" * 64,
            "state_lineage": "lineage-009",
            "state_serial": 9,
            "expiry_authority": {"status": "OWNER_SUPPLIED", "value": expiry},
            "cost_authority": {
                "status": "OWNER_SUPPLIED",
                "currency": "USD",
                "lifecycle_ceiling_usd": "3.00",
                "scope": "TOTAL_CYCLE",
            },
        },
    }
    state = {
        "schema_version": "w5-004.plan-state-evidence.v1",
        "operation_id": "saved-plan-009",
        "account_id": "526338061652",
        "region": "ap-southeast-1",
        "environment": "sandbox",
        "target": "platform",
        "lineage": "lineage-009",
        "serial": 9,
        "content_sha256": "b" * 64,
        "observed_at": "2026-09-15T00:00:00Z",
    }
    return confirmation, state


def test_owner_envelope_uses_examples_and_keeps_operation_root_unused(tmp_path: Path) -> None:
    external = tmp_path / "external"
    parent = external / "consolidated-remediation-001"
    parent.mkdir(parents=True)
    confirmation, state = _owner_envelope_inputs(external)
    confirmation_path = external / "confirmation.json"
    state_path = external / "state.json"
    confirmation_path.write_text(json.dumps(confirmation), encoding="utf-8")
    state_path.write_text(json.dumps(state), encoding="utf-8")
    variables = ROOT / "infra/environments/sandbox/terraform.tfvars.example"
    backend = ROOT / "infra/environments/sandbox/backend.hcl.example"
    operation = parent / "saved-plan-009"

    outputs = prepare_owner_envelope(
        confirmation_path,
        sha256(confirmation_path.read_bytes()).hexdigest(),
        state_path,
        sha256(state_path.read_bytes()).hexdigest(),
        variables,
        sha256(variables.read_bytes()).hexdigest(),
        backend,
        sha256(backend.read_bytes()).hexdigest(),
        operation,
        external_root=external,
        repository_root=ROOT,
    )

    assert len(outputs) == 3
    assert not operation.exists()
    envelope = json.loads(Path(outputs[-1][0]).read_bytes())
    assert envelope["request"]["operation_root"] == str(operation)
    assert json.loads(Path(outputs[0][0]).read_bytes())["mandatory_tags"]["ExpiresAt"] == (
        "2026-09-16T05:00:00Z"
    )


@pytest.mark.parametrize("change", ["todo", "historical", "root", "state"])
def test_owner_envelope_rejects_unapproved_or_drifted_inputs(tmp_path: Path, change: str) -> None:
    external = tmp_path / "external"
    parent = external / "consolidated-remediation-001"
    parent.mkdir(parents=True)
    confirmation, state = _owner_envelope_inputs(external)
    operation = parent / "saved-plan-009"
    if change == "todo":
        confirmation["variable_overrides"] = {}
    elif change == "historical":
        confirmation["operation_id"] = "saved-plan-007"
    elif change == "root":
        operation = external / "saved-plan-009"
    else:
        state["serial"] = 10
    confirmation_path = external / "confirmation.json"
    state_path = external / "state.json"
    confirmation_path.write_text(json.dumps(confirmation), encoding="utf-8")
    state_path.write_text(json.dumps(state), encoding="utf-8")
    variables = ROOT / "infra/environments/sandbox/terraform.tfvars.example"
    backend = ROOT / "infra/environments/sandbox/backend.hcl.example"

    with pytest.raises(ContractError):
        prepare_owner_envelope(
            confirmation_path,
            sha256(confirmation_path.read_bytes()).hexdigest(),
            state_path,
            sha256(state_path.read_bytes()).hexdigest(),
            variables,
            sha256(variables.read_bytes()).hexdigest(),
            backend,
            sha256(backend.read_bytes()).hexdigest(),
            operation,
            external_root=external,
            repository_root=ROOT,
        )
    assert not (parent / "saved-plan-009-preparation").exists()


def test_plan_artifact_producer_rejects_missing_typed_owner_envelope(tmp_path: Path) -> None:
    external_root = tmp_path / "external"
    repository_root = tmp_path / "repository"
    external_root.mkdir()
    repository_root.mkdir()
    owner_input = external_root / "owner-input.json"
    owner_input.write_text("{}\n", encoding="utf-8")
    with pytest.raises(ContractError, match="PLAN_ARTIFACT_REQUEST_OBJECT_REQUIRED"):
        prepare_plan_artifacts(
            owner_input,
            sha256(owner_input.read_bytes()).hexdigest(),
            external_root / "saved-plan-009",
            external_root=external_root,
            repository_root=repository_root,
        )


def test_plan_artifact_producer_rejects_reused_operation_root(tmp_path: Path) -> None:
    external_root = tmp_path / "external"
    repository_root = tmp_path / "repository"
    external_root.mkdir()
    repository_root.mkdir()
    owner_input = external_root / "owner-input.json"
    owner_input.write_text("{}\n", encoding="utf-8")
    root = external_root / "saved-plan-009"
    root.mkdir()
    with pytest.raises(ContractError, match="PLAN_ARTIFACT_REQUEST_OBJECT_REQUIRED"):
        prepare_plan_artifacts(
            owner_input,
            sha256(owner_input.read_bytes()).hexdigest(),
            root,
            external_root=external_root,
            repository_root=repository_root,
        )


def test_v2_status_keeps_leading_space_and_rename_direction() -> None:
    records = parse_git_status(b" M tools/a.py\x00R  tools/new.py\x00tools/old.py\x00")
    assert records == ((" M", "tools/a.py", None), ("R ", "tools/new.py", "tools/old.py"))


def test_v2_index_keeps_mode_and_rejects_unmerged_stages() -> None:
    object_id = b"a" * 40
    record = b"100755 " + object_id + b" 0\ttools/ leading.py\x00"
    assert parse_git_index(record) == (("100755", object_id.decode(), 0, "tools/ leading.py"),)
    with pytest.raises(ContractError):
        parse_git_index(b"100644 " + object_id + b" 2\ttools/a.py\x00")


def test_v2_scope_is_365_immutable_members_plus_20_admitted() -> None:
    baseline = b"".join(f"src/member-{index}.py\0".encode() for index in range(365))
    assert len(lifecycle_scope(baseline)) == 385
    assert "tools/secret_scan.py" in lifecycle_scope(baseline)
    assert "tools/platformctl/plan_artifact_producer.py" in lifecycle_scope(baseline)
    with pytest.raises(ContractError, match="MEMBERSHIP"):
        lifecycle_scope(baseline + b"src/extra.py\x00")


def test_v2_working_manifest_records_deletion_and_raw_line_endings(tmp_path: Path) -> None:
    path = tmp_path / "source.txt"
    path.write_bytes(b"line\r\n")
    first = working_manifest(tmp_path, ("source.txt", "deleted.txt"))
    assert first[0] == ("deleted.txt", "DELETED", None, None)
    path.write_bytes(b"line\n")
    assert working_manifest(tmp_path, ("source.txt",))[0][3] != first[1][3]


@pytest.mark.parametrize(
    "raw", [b" M a.py", b"R  new.py\x00", b" M A.py\x00 M a.py\x00", b"UU a.py\x00"]
)
def test_v2_git_ambiguity_fails_closed(raw: bytes) -> None:
    with pytest.raises(ContractError):
        parse_git_status(raw)


def identity() -> PlanIdentity:
    return PlanIdentity(
        schema_version="w5-004.lifecycle.v1",
        task_id="W5-004",
        lifecycle_cycle_id="W5-CYCLE-A",
        repository_head="78576879b2c1d13507680872f471345c7b9b6be0",
        source_composition_sha256=HASH,
        terraform_root="infra/environments/sandbox",
        terraform_version="1.16.1",
        provider_lock_sha256=HASH,
        backend_config_sha256=HASH,
        input_sha256=HASH,
        resource_expiry_input_sha256=HASH,
        resource_expires_at="2026-09-08T23:45:00Z",
        state_lineage="lineage-1",
        state_serial=0,
        aws_account_id="526338061652",
        aws_region="ap-southeast-1",
        environment="sandbox",
        saved_plan_sha256=HASH,
        plan_json_sha256=HASH,
        policy_result_sha256=HASH,
        cost_result_sha256=HASH,
        created_at="2026-09-08T00:00:00Z",
        expires_at="2026-09-08T01:00:00Z",
    )


def test_exact_identity_is_valid_until_expiry() -> None:
    approved = identity()
    validate_plan_identity(
        approved,
        approved,
        datetime(2026, 9, 8, 0, 30, tzinfo=UTC),
    )


def test_any_governed_drift_invalidates_saved_plan() -> None:
    approved = identity()
    current = replace(approved, input_sha256="b" * 64)
    with pytest.raises(ContractError, match="input_sha256"):
        validate_plan_identity(
            approved,
            current,
            datetime(2026, 9, 8, 0, 30, tzinfo=UTC),
        )


def test_resource_expiry_is_generated_once_into_external_input(tmp_path: Path) -> None:
    repository_root = tmp_path / "repository"
    external_root = tmp_path / "external"
    repository_root.mkdir()
    output = external_root / "inputs" / "resource-expiry.auto.tfvars.json"
    from tools.platformctl.lifecycle_io import reserve_operation_directory

    reserve_operation_directory(external_root, external_root, repository_root)
    prepared_at = datetime(2026, 9, 8, 2, 30, 45, 999999, tzinfo=UTC)

    prepared = prepare_resource_expiry_input(
        path=output,
        external_root=external_root,
        repository_root=repository_root,
        plan_preparation_time=prepared_at,
        environment="sandbox",
    )

    assert prepared.prepared_at == "2026-09-08T02:30:45Z"
    assert prepared.environment == "sandbox"
    assert prepared.resource_expires_at == "2026-09-09T02:15:45Z"
    assert prepared.resource_expires_at == generated_resource_expires_at(
        datetime(2026, 9, 8, 2, 30, 45, tzinfo=UTC)
    )
    payload = output.read_bytes()
    assert prepared.sha256 == sha256(payload).hexdigest()
    assert json.loads(payload)["mandatory_tags"]["ExpiresAt"] == prepared.resource_expires_at
    with pytest.raises(ContractError, match="already exists"):
        prepare_resource_expiry_input(
            path=output,
            external_root=external_root,
            repository_root=repository_root,
            plan_preparation_time=prepared_at,
            environment="sandbox",
        )


def test_resource_expiry_cannot_reach_governance_deadline() -> None:
    with pytest.raises(ContractError, match="governance deadline"):
        generated_resource_expires_at(datetime(2026, 12, 9, 1, 0, tzinfo=UTC))


def test_resource_expiry_rejects_unapproved_environment_before_write(tmp_path: Path) -> None:
    repository_root = tmp_path / "repository"
    external_root = tmp_path / "external"
    repository_root.mkdir()
    output = external_root / "resource-expiry.auto.tfvars.json"

    with pytest.raises(ContractError, match="environment is not approved"):
        prepare_resource_expiry_input(
            path=output,
            external_root=external_root,
            repository_root=repository_root,
            plan_preparation_time=datetime(2026, 9, 8, tzinfo=UTC),
            environment="production",
        )

    assert not output.exists()


def test_noop_is_valid_and_update_is_not_initially_eligible() -> None:
    normalized = normalize_plan(
        {
            "format_version": "1.2",
            "terraform_version": "1.16.1",
            "variables": {"aws_region": {"value": "ap-southeast-1"}},
            "resource_changes": [
                {
                    "address": "aws_vpc.main",
                    "type": "aws_vpc",
                    "change": {"actions": ["no-op"], "before": {}, "after": {}},
                },
                {
                    "address": "aws_subnet.private",
                    "type": "aws_subnet",
                    "change": {"actions": ["update"], "before": {}, "after": {}},
                },
            ],
        },
        evaluation_time="2026-09-08T00:00:00Z",
    )
    summary = summarize_plan(normalized)
    assert summary.count(PlanAction.NO_OP) == 1
    assert summary.count(PlanAction.UPDATE) == 1
    assert not summary.initially_eligible


def test_state_identity_keeps_module_and_index_without_recording_values() -> None:
    from tools.platformctl.plan import state_inventory

    raw = {
        "version": 4,
        "lineage": "synthetic-lineage",
        "serial": 17,
        "resources": [
            {
                "module": "module.opensearch",
                "mode": "managed",
                "type": "aws_cloudwatch_log_group",
                "name": "this",
                "instances": [{"index_key": "audit", "attributes": {"private": "not recorded"}}],
            },
            {
                "mode": "managed",
                "type": "terraform_data",
                "name": "owner_expiry_gate",
                "instances": [{}],
            },
        ],
    }
    lineage, serial, entries = state_inventory(json.dumps(raw).encode())
    assert (lineage, serial) == ("synthetic-lineage", 17)
    assert entries == [
        {
            "address": 'module.opensearch.aws_cloudwatch_log_group.this["audit"]',
            "resource_type": "aws_cloudwatch_log_group",
        },
        {"address": "terraform_data.owner_expiry_gate", "resource_type": "terraform_data"},
    ]
    assert "not recorded" not in json.dumps(entries)
    raw["resources"][0]["instances"].append(raw["resources"][0]["instances"][0])
    with pytest.raises(ContractError, match="DUPLICATE"):
        state_inventory(json.dumps(raw).encode())


@pytest.mark.parametrize(
    "reference",
    [
        "state://aws_s3_bucket.fixture#id",
        "state://aws_s3_bucket.fixture#arn",
    ],
)
def test_post_execution_identity_comes_from_exact_state(reference: str) -> None:
    from tools.platformctl.aws_inventory import NativeReadSpec, NativeTarget
    from tools.platformctl.lifecycle_models import ResourceChangeRule
    from tools.platformctl.plan import resolve_post_execution_targets

    raw = json.dumps(
        {
            "version": 4,
            "lineage": "fixture",
            "serial": 1,
            "resources": [
                {
                    "mode": "managed",
                    "type": "aws_s3_bucket",
                    "name": "fixture",
                    "instances": [
                        {
                            "attributes": {
                                "id": "fixture-bucket",
                                "arn": "arn:aws:s3:::fixture-bucket",
                            }
                        }
                    ],
                }
            ],
        }
    ).encode()
    probe = NativeReadSpec(
        "aws_s3_bucket.fixture",
        "aws_s3_bucket",
        "s3",
        "head_bucket",
        json.dumps({"Bucket": reference}),
        "",
        None,
        None,
        1,
        1,
        reference,
        "",
    )
    target = NativeTarget(probe.address, probe.resource_type, probe, (), True)
    rule = ResourceChangeRule(probe.address, probe.resource_type, ("create",), (), "NONE")
    resolved = resolve_post_execution_targets((target,), raw, (rule,), None)
    expected = "fixture-bucket" if reference.endswith("#id") else "arn:aws:s3:::fixture-bucket"
    assert resolved[0].presence.expected_native_identity == expected
    assert json.loads(resolved[0].presence.arguments_json) == {"Bucket": expected}
    assert target.presence.expected_native_identity == reference
    assert json.loads(raw)["resources"][0]["instances"][0]["attributes"]["id"] == "fixture-bucket"


@pytest.mark.parametrize(
    "reference",
    [
        "state://aws_s3_bucket.unapproved#id",
        "state://aws_s3_bucket.fixture#private_value",
        "state://aws_s3_bucket.fixture#id",
        "review://aws_s3_bucket.fixture",
        "expiry://resource",
    ],
)
def test_unresolved_post_execution_identity_fails_without_native_calls(reference: str) -> None:
    from tools.platformctl.aws_inventory import NativeReadSpec, NativeTarget
    from tools.platformctl.lifecycle_models import ResourceChangeRule
    from tools.platformctl.plan import resolve_post_execution_targets

    probe = NativeReadSpec(
        "aws_s3_bucket.fixture",
        "aws_s3_bucket",
        "s3",
        "head_bucket",
        json.dumps({"Bucket": reference}),
        "",
        None,
        None,
        1,
        1,
        reference,
        "",
    )
    target = NativeTarget(probe.address, probe.resource_type, probe, (), True)
    rule = ResourceChangeRule(probe.address, probe.resource_type, ("delete",), (), "NONE")
    with pytest.raises(ContractError, match="REFERENCE"):
        resolve_post_execution_targets((target,), None, (rule,), None)


def test_post_policy_template_uses_frozen_expiry_without_guessing_a_future_hash() -> None:
    from tools.platformctl.aws_inventory import NativeAssertion, NativeReadSpec, NativeTarget
    from tools.platformctl.lifecycle_io import canonical_json_bytes, sha256_bytes
    from tools.platformctl.lifecycle_models import ResourceChangeRule
    from tools.platformctl.plan import resolve_post_execution_targets
    from tools.platformctl.policy_runner import policy_semantic_value

    address = "module.iam.aws_iam_role_policy.runtime"
    template = {
        "Statement": [
            {
                "Sid": "FixtureExpiry",
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": ["arn:aws:s3:::fixture-bucket/*"],
                "Condition": {"DateLessThan": {"aws:CurrentTime": "expiry://resource"}},
            }
        ]
    }
    probe = NativeReadSpec(
        address,
        "aws_iam_role_policy",
        "iam",
        "get_role_policy",
        '{"RoleName":"fixture-role","PolicyName":"fixture-policy"}',
        "",
        None,
        None,
        1,
        1,
        "fixture-role",
        "RoleName",
    )
    target = NativeTarget(
        address,
        probe.resource_type,
        probe,
        (
            NativeAssertion(
                "CONFIGURATION", probe, json.dumps({"PolicyDocument.@policy_sha256": template})
            ),
        ),
        False,
    )
    rule = ResourceChangeRule(address, probe.resource_type, ("update",), (), "NONE")
    expiry = "2026-09-08T23:45:00Z"
    resolved = resolve_post_execution_targets(
        (target,),
        None,
        (rule,),
        None,
        frozen_expiry=expiry,
    )
    expected = policy_semantic_value(json.dumps(template).replace("expiry://resource", expiry))
    assert json.loads(resolved[0].assertions[0].expected_fields_json) == {
        "PolicyDocument.@policy_sha256": sha256_bytes(canonical_json_bytes(expected)),
    }
    assert "expiry://resource" in target.assertions[0].expected_fields_json
