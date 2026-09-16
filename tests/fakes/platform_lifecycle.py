"""Deterministic W5-004 process, clock, identity, and inventory fakes."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

from tools.platformctl.aws_inventory import InventoryResource, ServiceIdentifier
from tools.platformctl.contracts import Action, ContractError
from tools.platformctl.lifecycle_io import canonical_json_bytes
from tools.platformctl.lifecycle_models import (
    OPERATIONAL_SCHEMA_VERSION,
    ApprovalRecordV2,
    ChangeProfile,
    ChargingBasis,
    ChargingComponent,
    CostCoverage,
    CostResultV2,
    CoverageClass,
    DispatchObservation,
    EvidenceRef,
    IdentityBundle,
    InventoryEntry,
    InventoryResult,
    Outcome,
    RecoveryProfile,
    ResourceChangeRule,
    ReviewPackage,
    StateEvidence,
)
from tools.platformctl.terraform_runner import ProcessResult


@dataclass
class FakeCommandRunner:
    """Record argv calls and return queued non-networked results."""

    results: list[ProcessResult] = field(default_factory=list)
    calls: list[tuple[tuple[str, ...], Path, dict[str, str], int]] = field(default_factory=list)

    def run(
        self,
        arguments: Sequence[str],
        *,
        cwd: Path,
        environment: Mapping[str, str],
        timeout_seconds: int,
    ) -> ProcessResult:
        self.calls.append((tuple(arguments), cwd, dict(environment), timeout_seconds))
        if self.results:
            return self.results.pop(0)
        return ProcessResult(0, "", "")


class FrozenClock:
    """Stable UTC clock."""

    def now(self) -> datetime:
        return datetime(2026, 9, 8, 0, 0, tzinfo=UTC)


@dataclass
class FakeStsClient:
    """Return only approved non-secret STS identity fields."""

    account: str = "526338061652"
    arn: str = "arn:aws:iam::526338061652:user/finopsinfra"

    def get_caller_identity(self) -> Mapping[str, object]:
        return {"Account": self.account, "Arn": self.arn, "UserId": "synthetic"}


@dataclass
class FakeNativeServiceLister:
    """Return caller-supplied native service inventory."""

    resources: Mapping[ServiceIdentifier, tuple[InventoryResource, ...]] = field(
        default_factory=dict
    )
    calls: list[ServiceIdentifier] = field(default_factory=list)

    def list_resources(self, service: ServiceIdentifier) -> Sequence[InventoryResource]:
        self.calls.append(service)
        return self.resources.get(service, ())


@dataclass
class MemoryEvidenceReader:
    """Verified byte fixtures; no network, real tools, credentials or files."""

    payloads: dict[str, bytes] = field(default_factory=dict)

    def read(self, relative_path: str, expected_sha256: str, byte_count: int) -> bytes:
        payload = self.payloads[relative_path]
        if len(payload) != byte_count or sha256(payload).hexdigest() != expected_sha256:
            raise ContractError("EVIDENCE_IDENTITY_MISMATCH")
        return payload


@dataclass
class FakeRevalidator:
    """Explicit observations and consumption state, never an eligibility Boolean."""

    observation: DispatchObservation
    consumed: bool = False
    calls: int = 0

    def observe(self, package: ReviewPackage) -> DispatchObservation:
        del package
        self.calls += 1
        return self.observation

    def approval_consumed(self, operation_id: str, approval_id: str) -> bool:
        del operation_id, approval_id
        return self.consumed


def reviewed_package_fixture() -> tuple[
    ReviewPackage, ApprovalRecordV2, MemoryEvidenceReader, FakeRevalidator
]:
    """One complete synthetic v2 package for gate and negative mutation tests."""
    start = "2026-09-08T00:00:00Z"
    end = "2026-09-08T00:15:00Z"
    digest = "a" * 64
    reader = MemoryEvidenceReader()
    operation = "fixture-operation"

    def evidence(kind: str, payload: bytes) -> EvidenceRef:
        path = f"{kind}.json"
        reader.payloads[path] = payload
        return EvidenceRef(
            kind, path, sha256(payload).hexdigest(), len(payload), "fixture", start, end, operation
        )

    artifact = evidence("saved-plan", b"synthetic immutable plan")
    inventory_ref = evidence("state-inventory", b"{}\n")
    counts = {
        "totalDetectedResources": 1,
        "totalSupportedResources": 1,
        "totalUnsupportedResources": 0,
        "totalUsageBasedResources": 0,
        "totalNoPriceResources": 0,
    }
    price_ref = evidence(
        "raw-estimate",
        canonical_json_bytes(
            {
                "currency": "USD",
                "totalMonthlyCost": "1.00",
                "summary": counts,
                "projects": [
                    {
                        "metadata": {},
                        "summary": counts,
                        "breakdown": {
                            "totalMonthlyCost": "1.00",
                            "resources": [
                                {
                                    "name": "aws_s3_bucket.fixture",
                                    "monthlyCost": "1.00",
                                    "costComponents": [
                                        {
                                            "name": "fixture fixed unit",
                                            "unit": "units",
                                            "price": "0.01",
                                            "monthlyQuantity": "100",
                                            "monthlyCost": "1.00",
                                        }
                                    ],
                                }
                            ],
                        },
                    }
                ],
            }
        ),
    )
    from tools.platformctl.lifecycle_models import ExposureBasis, PricingAuthority

    components = (ChargingComponent("fixture fixed unit", "units", "0.01", "100", "1", 60, 1),)
    authority = evidence(
        "approved-pricing-basis",
        canonical_json_bytes(
            PricingAuthority(
                OPERATIONAL_SCHEMA_VERSION,
                operation,
                "526338061652",
                "ap-southeast-1",
                "platform",
                "aws_s3_bucket.fixture",
                "USD",
                CoverageClass.PRICED_FIXED,
                components,
                None,
                "https://pricing.api.infracost.io/",
                price_ref.sha256,
                start,
                end,
                "Gyan-Prakash-Rai",
            )
        ),
    )
    exposure = evidence(
        "lifecycle-exposure-basis",
        canonical_json_bytes(
            ExposureBasis(
                OPERATIONAL_SCHEMA_VERSION,
                operation,
                "526338061652",
                "USD",
                (),
                ("INCURRED", "RECOVERY_ONE_OFF", "TEARDOWN_RETENTION"),
                start,
                0,
                "Gyan-Prakash-Rai",
                start,
                end,
            )
        ),
    )
    bootstrap_inventory = evidence(
        "current-bootstrap-inventory",
        canonical_json_bytes(
            InventoryResult(
                OPERATIONAL_SCHEMA_VERSION,
                operation,
                "526338061652",
                "ap-southeast-1",
                (),
                ("s3", "kms", "dynamodb"),
                (),
                start,
                end,
            )
        ),
    )
    basis = evidence(
        "owner-cost-basis",
        canonical_json_bytes(
            ChargingBasis(
                OPERATIONAL_SCHEMA_VERSION,
                operation,
                "aws_s3_bucket.fixture",
                "platform",
                CoverageClass.PRICED_FIXED,
                start,
                end,
                (ChargingComponent("fixture fixed unit", "units", "0.01", "100", "1", 60, 1),),
                "Gyan-Prakash-Rai",
                start,
                end,
                authority,
            )
        ),
    )
    policy = evidence(
        "policy-result",
        canonical_json_bytes(
            {
                "schema_version": "w5-004.policy-result.v2",
                "allow": True,
                "findings": [],
                "input_sha256": digest,
                "policy_sha256": digest,
                "exceptions_sha256": digest,
            }
        ),
    )
    identity = IdentityBundle(
        "w5-004.lifecycle-content.v1",
        digest,
        digest,
        digest,
        digest,
        "a" * 40,
        (
            ("git", "synthetic-git", "fixture-version", digest),
            ("infracost", "synthetic-infracost", "0.10.45", digest),
            ("opa", "synthetic-opa", "1.20.0", digest),
            ("terraform", "synthetic-tool", "1.16.1", digest),
        ),
        (
            ("policies/opa/exceptions.json", digest),
            ("policies/opa/terraform_plan.rego", digest),
            ("review/normalized-plan.json", digest),
        ),
        digest,
    )
    rule = ResourceChangeRule("aws_s3_bucket.fixture", "aws_s3_bucket", ("create",), (), "NONE")
    profile = RecoveryProfile(
        ChangeProfile.INITIAL,
        Action.PLATFORM_APPLY,
        (rule,),
        (),
        end,
        "EXCLUDED",
        "VERIFIED",
        None,
        None,
        None,
    )
    native = InventoryResult(
        OPERATIONAL_SCHEMA_VERSION,
        operation,
        "526338061652",
        "ap-southeast-1",
        (
            InventoryEntry(
                rule.address,
                rule.resource_type,
                None,
                None,
                "PROJECT_MANAGED",
                "ABSENT",
                Outcome.NOT_RUN,
                True,
                start,
            ),
        ),
        ("s3",),
        (),
        start,
        end,
    )
    state = StateEvidence("s3", None, None, digest, start, None, inventory_ref)
    cost = CostResultV2(
        OPERATIONAL_SCHEMA_VERSION,
        Outcome.PASS,
        "USD",
        artifact.sha256,
        price_ref,
        (
            CostCoverage(
                rule.address,
                "platform",
                CoverageClass.PRICED_FIXED,
                "1.00",
                "0.15",
                "RESOURCE_SPECIFIC_BILLING_QUANTA",
                "USD",
                900,
                basis,
            ),
        ),
        (basis, exposure, bootstrap_inventory),
        "0.00",
        "0.00",
        "0.00",
        "2.85",
        start,
        end,
        start,
        0,
    )
    package = ReviewPackage(
        OPERATIONAL_SCHEMA_VERSION,
        operation,
        Action.PLATFORM_APPLY,
        "platform",
        "sandbox",
        "526338061652",
        "ap-southeast-1",
        "arn:aws:iam::526338061652:user/finopsinfra",
        profile,
        identity,
        artifact,
        state,
        native,
        policy,
        cost,
        (rule,),
        start,
        "2026-09-08T23:45:00Z",
        end,
        Outcome.PASS,
    )
    approval_id = "fixture-approval"
    approval = ApprovalRecordV2(
        OPERATIONAL_SCHEMA_VERSION,
        approval_id,
        "Gyan-Prakash-Rai",
        "Gyan-Prakash-Rai",
        package.action,
        profile.profile,
        package.account_id,
        package.region,
        "sandbox",
        "platform",
        sha256(canonical_json_bytes(package)).hexdigest(),
        "saved-plan",
        artifact.sha256,
        start,
        end,
        f"CONFIRM PLATFORM-APPLY sandbox platform {artifact.sha256} {approval_id}",
    )
    observed = DispatchObservation(
        identity, state, native, package.account_id, package.region, package.caller, start
    )
    return package, approval, reader, FakeRevalidator(observed)


class DiagnosticAwsFixture:
    """Scripted SDK boundary: owner tests never need credentials or a network."""

    def __init__(self) -> None:
        from types import SimpleNamespace

        self.calls: list[tuple[str, str, dict[str, object]]] = []
        self.responses: dict[tuple[str, str], list[dict[str, object] | Exception]] = {}
        self.events = SimpleNamespace(
            register=lambda *_args, **_kwargs: None,
            register_first=lambda *_args, **_kwargs: None,
        )

    def client(self, service: str, region: str) -> object:
        from types import SimpleNamespace

        fixture = self
        name = {
            "ecr": "api.ecr",
            "cloudwatch": "monitoring",
            "opensearch": "es",
            "elbv2": "elasticloadbalancing",
            "resourcegroupstaggingapi": "tagging",
            "stepfunctions": "states",
        }.get(service, service)
        host = "iam.amazonaws.com" if service == "iam" else name + "." + region + ".amazonaws.com"

        class Client:
            meta = SimpleNamespace(
                endpoint_url="https://" + host,
                events=fixture.events,
                config=SimpleNamespace(retries={"total_max_attempts": 1}),
            )

            def __getattr__(self, method: str) -> object:
                def call(**arguments: object) -> dict[str, object]:
                    fixture.calls.append((service, method, arguments))
                    rows = fixture.responses.get((service, method), [])
                    if rows:
                        result = rows.pop(0)
                        if isinstance(result, Exception):
                            raise result
                        return result
                    if (service, method) == ("sts", "get_caller_identity"):
                        return {
                            "Account": "526338061652",
                            "Arn": "arn:aws:iam::526338061652:user/finopsinfra",
                        }
                    return fixture.reply(service, method, arguments)

                return call

        return Client()

    def reply(self, service: str, method: str, arguments: dict[str, object]) -> dict[str, object]:
        raise ContractError("UNSCRIPTED_DIAGNOSTIC_READ")

    def session(self, *, resolution_only: bool = False) -> object:
        from tools.platformctl.aws_live import Boto3AwsInventoryProvider, DiagnosticAwsSession

        provider = Boto3AwsInventoryProvider(
            client_factory=self.client,
            native_lister=None,
            region="ap-southeast-1",
            account_id="526338061652",
            caller_arn="arn:aws:iam::526338061652:user/finopsinfra",
        )
        return DiagnosticAwsSession(
            provider, monotonic=lambda: 0.0, resolution_only=resolution_only
        )


def monthly_amendment_fixture(
    cost: CostResultV2,
    reader: MemoryEvidenceReader,
) -> tuple[CostResultV2, str]:
    """Synthetic owner-bound W5-CYCLE-A authority with exact configuration bytes."""
    from dataclasses import replace

    from tools.platformctl.lifecycle_io import (
        approved_lifecycle_exception,
        approved_monthly_exception,
    )
    from tools.platformctl.lifecycle_models import MonthlyAmendmentAuthority

    configuration = canonical_json_bytes(
        {
            "lifecycle": {"cycle": "W5-CYCLE-A"},
            "cost": {
                "lifecycle_test_ceiling": "3.00",
                "monthly_sandbox_ceiling": "60.00",
                "monthly_exception": approved_monthly_exception(),
                "lifecycle_exception": approved_lifecycle_exception(),
            },
        }
    )
    digest = sha256(configuration).hexdigest()
    authority = MonthlyAmendmentAuthority(
        OPERATIONAL_SCHEMA_VERSION,
        cost.raw_estimate.operation_id,
        "w5-004-cycle-a-temporary-mvp-monthly",
        "W5-CYCLE-A",
        "526338061652",
        "ap-southeast-1",
        "sandbox",
        "c446f9a2-77d4-9954-20fa-523205d86a8a",
        "7465ed2e-a39c-afdd-f172-5792d3ec2f85",
        digest,
        configuration.decode(),
        "Gyan-Prakash-Rai",
        cost.observed_at,
        cost.valid_until,
        "OPEN",
    )
    raw = canonical_json_bytes(authority)
    path = "monthly-amendment.json"
    reader.payloads[path] = raw
    reference = EvidenceRef(
        "mvp-monthly-amendment",
        path,
        sha256(raw).hexdigest(),
        len(raw),
        "owner",
        cost.observed_at,
        cost.valid_until,
        cost.raw_estimate.operation_id,
    )
    return replace(cost, monthly_amendment=reference), digest


def lifecycle_amendment_fixture(
    cost: CostResultV2,
    reader: MemoryEvidenceReader,
) -> tuple[CostResultV2, str]:
    """Synthetic operation-bound total-cycle authority, not live owner evidence."""
    from dataclasses import asdict, replace

    from tools.platformctl.lifecycle_io import (
        approved_lifecycle_exception,
        decode_operational_record,
    )
    from tools.platformctl.lifecycle_models import (
        LifecycleBudgetAuthority,
        MonthlyAmendmentAuthority,
    )

    cost, digest = monthly_amendment_fixture(cost, reader)
    assert cost.monthly_amendment is not None
    monthly = decode_operational_record(
        reader.payloads[cost.monthly_amendment.path], MonthlyAmendmentAuthority
    )
    expected = approved_lifecycle_exception()
    authority = LifecycleBudgetAuthority(
        **{**asdict(monthly), "amendment_id": expected["amendment_id"]},
        lifecycle_ceiling_usd="30.00",
        accounting_scope=expected["accounting_scope"],
    )
    raw = canonical_json_bytes(authority)
    path = "lifecycle-amendment.json"
    reader.payloads[path] = raw
    reference = replace(
        cost.monthly_amendment,
        kind="lifecycle-budget-amendment",
        path=path,
        sha256=sha256(raw).hexdigest(),
        byte_count=len(raw),
    )
    return replace(cost, lifecycle_amendment=reference), digest


class CompleteDiagnosticAwsFixture(DiagnosticAwsFixture):
    """Whole-inventory SDK responses; real coordinator, readers and comparison consumers.

    Responses are synthesized from the un-hashed assertion templates (not PASS results).
    Dedicated comparison/routing tests independently challenge those templates. Discovery
    is explicitly empty in this fixture; it is not a claim about any live account.
    """

    def __init__(self, failure: str = "none") -> None:
        import json
        import re
        from copy import deepcopy
        from functools import partial

        from tools.platformctl.aws_inventory import (
            diagnostic_discovery_profile,
            diagnostic_resource_profile,
        )
        from tools.platformctl.plan import _state_identity_projection, diagnostic_rules

        super().__init__()
        self.failure = failure
        self.states = {}
        self.queries = {}
        self.discovery = {}
        self.native_addresses = set()
        self.query_addresses = {}
        for scope, lineage, serial in (
            ("bootstrap", "c446f9a2-77d4-9954-20fa-523205d86a8a", 17),
            ("platform", "7465ed2e-a39c-afdd-f172-5792d3ec2f85", 4),
        ):
            resources = []
            for index, rule in enumerate(diagnostic_rules(scope)):
                match = re.fullmatch(
                    r"(.*?)(aws_[a-z0-9_]+|terraform_data)\.([a-z0-9_]+)(?:\[(.+)\])?",
                    rule.address,
                )
                assert match is not None
                module, kind, name, key = match.groups()
                identity = f"synthetic-{scope}-{index}"
                if kind == "aws_vpc_endpoint":
                    identity = f"vpce-{index:017x}"
                arn = f"arn:aws:kms:ap-southeast-1:526338061652:key/{identity}"
                if kind == "aws_iam_role":
                    arn = f"arn:aws:iam::526338061652:role/{identity}"
                attributes = {
                    "id": identity,
                    "arn": arn,
                    "name": identity,
                    "bucket": identity,
                    "prefix_list_id": f"pl-{index:08d}",
                }
                if kind == "terraform_data":
                    attributes["input"] = "2026-09-07T00:00:00Z"
                instance = {"attributes": attributes}
                if key is not None:
                    instance["index_key"] = json.loads(key)
                resource = {
                    "mode": "managed",
                    "type": kind,
                    "name": name,
                    "instances": [instance],
                }
                if module:
                    resource["module"] = module.rstrip(".")
                resources.append(resource)
            self.states[scope] = canonical_json_bytes(
                {"version": 4, "serial": serial, "lineage": lineage, "resources": resources}
            )
            selected = _state_identity_projection(self.states[scope])

            resolve = partial(self._resolve, selected=selected)
            for target in diagnostic_resource_profile(scope).targets:
                for probe, fields in (
                    (target.presence, {}),
                    *(
                        (row.probe, json.loads(row.expected_fields_json))
                        for row in target.assertions
                    ),
                ):
                    arguments = resolve(json.loads(probe.arguments_json))
                    query = (probe.service, probe.method, canonical_json_bytes(arguments))
                    self.query_addresses.setdefault(query, set()).add(target.address)
                    result_key, items = self.queries.setdefault(query, (probe.result_key, {}))
                    assert result_key == probe.result_key
                    identity = resolve(probe.expected_native_identity)
                    single = result_key in {
                        "",
                        "KeyMetadata",
                        "Table",
                        "ContinuousBackupsDescription",
                        "Role",
                        "DomainStatus",
                    }
                    item = items.setdefault("single" if single else identity, {})
                    if probe.identity_key:
                        self._assign(item, probe.identity_key, identity)
                    if probe == target.presence and target.ownership_binding is not None:
                        self._assign(
                            item,
                            target.ownership_binding.consumer_field,
                            resolve(target.ownership_binding.parent_identity),
                        )
                    for path, value in fields.items():
                        value = deepcopy(resolve(value))
                        if ".@json" in path:
                            path = path.split(".@json")[0]
                            value = json.dumps(value)
                        else:
                            path = path.split(".@")[0]
                        self._assign(item, path, value)
        for scan in diagnostic_discovery_profile().scans:
            query = (
                scan.service,
                scan.method,
                canonical_json_bytes(json.loads(scan.arguments_json)),
            )
            response = {}
            if scan.coverage == "CLOUDWATCH_ALARMS":
                response = {"MetricAlarms": [], "CompositeAlarms": []}
            else:
                self._assign(response, scan.result_key, [])
            self.discovery[query] = response

    @staticmethod
    def _resolve(value, *, selected):
        if value == "expiry://resource":
            return "2026-09-07T00:00:00Z"
        if isinstance(value, str) and value.startswith("state://"):
            address, field = value.removeprefix("state://").rsplit("#", 1)
            return selected[address][field]
        if isinstance(value, dict):
            return {
                key: CompleteDiagnosticAwsFixture._resolve(child, selected=selected)
                for key, child in value.items()
            }
        if isinstance(value, list):
            return [
                CompleteDiagnosticAwsFixture._resolve(child, selected=selected) for child in value
            ]
        return value

    @staticmethod
    def _assign(root, path, value):
        """Expand literal native assertion paths, preserving all supplied fields."""
        parts = path.split(".")
        current = root
        for index, part in enumerate(parts):
            key = int(part) if isinstance(current, list) else part
            if isinstance(current, list):
                while len(current) <= key:
                    current.append({})
            if index == len(parts) - 1:
                current[key] = value
                return
            if isinstance(current, dict) and key not in current:
                current[key] = [] if parts[index + 1].isdecimal() else {}
            current = current[key]

    def reply(self, service, method, arguments):
        from copy import deepcopy
        from io import BytesIO

        from tools.platformctl.aws_live import DiagnosticFatalError, DiagnosticReadError

        query = (service, method, canonical_json_bytes(arguments))
        if service == "dynamodb" and method == "describe_table":
            if self.failure == "routing":
                raise DiagnosticFatalError("DIAGNOSTIC_REDIRECT_NOT_APPROVED")
            if self.failure == "identity":
                raise DiagnosticFatalError("DIAGNOSTIC_AWS_IDENTITY_MISMATCH")
            if self.failure == "resource":
                raise DiagnosticReadError("AccessDeniedException")
        self.native_addresses.update(self.query_addresses.get(query, ()))
        if service == "s3" and method in {"head_object", "get_object"}:
            metadata = {"VersionId": "synthetic-version", "ETag": '"synthetic-etag"'}
            if method == "get_object":
                metadata["Body"] = BytesIO(self.states["platform"])
            return metadata
        if query in self.queries:
            result_key, rows = self.queries[query]
            items = deepcopy(list(rows.values()))
            if result_key == "":
                assert len(items) == 1
                return items[0]
            if result_key in {
                "KeyMetadata",
                "Table",
                "ContinuousBackupsDescription",
                "Role",
                "DomainStatus",
            }:
                assert len(items) == 1
                return {result_key: items[0]}
            return {result_key: items}
        if query in self.discovery:
            return deepcopy(self.discovery[query])
        if service == "cloudtrail" and method == "lookup_events":
            return {"Events": []}
        if service == "ce":
            if method == "list_cost_allocation_tags":
                return {"CostAllocationTags": [{"TagKey": "Project", "Status": "Inactive"}]}
            return {"ResultsByTime": []}  # No attribution/headroom invented.
        if service == "iam":
            return self._iam(method, arguments)
        return super().reply(service, method, arguments)

    @staticmethod
    def _iam(method, arguments):
        role = "AWSServiceRoleForAmazonOpenSearchService"
        policy = "arn:aws:iam::aws:policy/aws-service-role/AmazonOpenSearchServiceRolePolicy"
        if method == "get_role" and arguments == {"RoleName": role}:
            return {
                "Role": {
                    "Arn": (
                        "arn:aws:iam::526338061652:role/aws-service-role/"
                        "opensearchservice.amazonaws.com/" + role
                    ),
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "sts:AssumeRole",
                                "Principal": {"Service": "opensearchservice.amazonaws.com"},
                            }
                        ],
                    },
                }
            }
        if method == "list_attached_role_policies" and arguments.get("RoleName") == role:
            return {"AttachedPolicies": [{"PolicyArn": policy}], "IsTruncated": False}
        if method == "get_policy" and arguments.get("PolicyArn") == policy:
            return {"Policy": {"DefaultVersionId": "v1"}}
        if method == "get_policy_version" and arguments.get("PolicyArn") == policy:
            return {"PolicyVersion": {"Document": {"Statement": []}}}
        if method == "get_user":
            return {"User": {"Arn": "arn:aws:iam::526338061652:user/finopsinfra"}}
        if method == "list_groups_for_user":
            return {"Groups": [], "IsTruncated": False}
        if method == "list_attached_user_policies":
            return {"AttachedPolicies": [], "IsTruncated": False}
        if method in {"list_user_policies", "list_role_policies"}:
            return {"PolicyNames": [], "IsTruncated": False}
        if method == "simulate_principal_policy":
            return {
                "EvaluationResults": [
                    {
                        "EvalActionName": arguments["ActionNames"][0],
                        "EvalDecision": "allowed",
                        "EvalResourceName": resource,
                        "MissingContextValues": [],
                    }
                    for resource in arguments["ResourceArns"]
                ]
            }
        raise ContractError("UNSCRIPTED_DIAGNOSTIC_IAM_READ")
