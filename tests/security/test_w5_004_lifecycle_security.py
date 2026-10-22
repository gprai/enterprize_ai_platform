"""Security tests for W5-004 redaction, path, input, and identity boundaries."""

from __future__ import annotations

import json
from copy import deepcopy
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import cast

import pytest
from tools.platformctl.aws_live import CompleteNativeServiceLister
from tools.platformctl.contracts import ContractError
from tools.platformctl.cost import parse_infracost_output, validate_terraform_plan_json
from tools.platformctl.lifecycle_io import (
    canonical_json_bytes,
    ensure_external_path,
    sha256_bytes,
    write_canonical_json_atomic,
)
from tools.platformctl.policy_runner import (
    PLATFORM_POLICY_DOCUMENT_CALL_EXPRESSION_SHA256,
    PLATFORM_POLICY_DOCUMENT_EXPRESSION_SHA256,
    PLATFORM_POLICY_DOCUMENT_PLANNED_INPUT_SHA256,
    POLICY_CRITICAL_UNKNOWN_KEYS,
    normalize_plan,
)


@pytest.mark.parametrize("port", ["", ":443"])
@pytest.mark.parametrize("suffix", ["", "/", "/bound-key?versionId=synthetic", "?list-type=2"])
def test_diagnostic_url_requires_exact_https_authority(port: str, suffix: str) -> None:
    from tools.platformctl.aws_live import _diagnostic_url_allowed

    host = "s3.ap-southeast-1.amazonaws.com"
    value = "https://" + host + port + suffix
    assert _diagnostic_url_allowed(value, {host})
    assert _diagnostic_url_allowed(value, {host}, endpoint=True) == (suffix in {"", "/"})
    bucket_host = "governed-bucket." + host
    assert not _diagnostic_url_allowed("https://" + bucket_host + "/key", {host})
    assert _diagnostic_url_allowed("https://" + bucket_host + "/key", {host, bucket_host})


@pytest.mark.parametrize(
    "value",
    [
        None,
        b"https://iam.amazonaws.com",
        "http://iam.amazonaws.com",
        "https://iam.amazonaws.com.evil.invalid/",
        "https://iam.amazonaws.com@evil.invalid/",
        "https://user@iam.amazonaws.com/",
        "https://iam.amazonaws.com:444/",
        "https://iam.amazonaws.com:invalid/",
        "https://iam.amazonaws.com./",
        "https://iam.amazonaws.com%2fevil.invalid/",
        "https://iam.amazonaws.com\\evil.invalid/",
        "https://iam.amazonaws.com/#fragment",
        "https://iam.amazonaws.com/\n",
        "https://iam.amazonaws.com/\t",
        "https://iam.amazonaws.com/\x7f",
        "https://iam.amazonaws.com/\u00a0",
        "https://iam.us-west-2.amazonaws.com/",
    ],
)
def test_diagnostic_url_rejects_ambiguous_or_unapproved_destinations(value: object) -> None:
    from tools.platformctl.aws_live import _diagnostic_url_allowed

    for endpoint in (False, True):
        assert not _diagnostic_url_allowed(value, {"iam.amazonaws.com"}, endpoint=endpoint)


@pytest.mark.parametrize(
    "service,method,arguments",
    [
        (
            "iam",
            "create_service_linked_role",
            {"AWSServiceName": "opensearchservice.amazonaws.com"},
        ),
        (
            "s3",
            "get_object",
            {
                "Bucket": "unrelated",
                "Key": "application-data",
                "ExpectedBucketOwner": "526338061652",
            },
        ),
        (
            "secretsmanager",
            "get_secret_value",
            {"SecretId": "unrelated"},  # pragma: allowlist secret
        ),
        ("logs", "filter_log_events", {"logGroupName": "unrelated"}),
        ("iam", "get_user", {"UserName": "another-user"}),
        ("ce", "get_cost_and_usage", {}),
    ],
)
def test_diagnostic_read_adapter_rejects_unapproved_access_before_dispatch(
    service: str,
    method: str,
    arguments: dict[str, object],
) -> None:
    from tools.platformctl.aws_live import DiagnosticAwsSession, DiagnosticFatalError

    from tests.fakes.platform_lifecycle import DiagnosticAwsFixture

    fixture = DiagnosticAwsFixture()
    session = cast(DiagnosticAwsSession, fixture.session())
    with pytest.raises(DiagnosticFatalError):
        session.call(service, method, arguments)
    assert all(
        (kind, operation) == ("sts", "get_caller_identity") for kind, operation, _ in fixture.calls
    )
    count = len(fixture.calls)
    with pytest.raises(DiagnosticFatalError):
        session.verify_identity()
    assert len(fixture.calls) == count


def test_diagnostic_identity_mismatch_latches_remote_stop() -> None:
    from tools.platformctl.aws_live import DiagnosticAwsSession, DiagnosticFatalError

    from tests.fakes.platform_lifecycle import DiagnosticAwsFixture

    fixture = DiagnosticAwsFixture()
    fixture.responses[("sts", "get_caller_identity")] = [
        {"Account": "111111111111", "Arn": "unapproved"}
    ]
    session = cast(DiagnosticAwsSession, fixture.session())
    with pytest.raises(DiagnosticFatalError):
        session.verify_identity()
    with pytest.raises(DiagnosticFatalError):
        session.call("iam", "get_role", {"RoleName": "AWSServiceRoleForAmazonOpenSearchService"})
    assert len(fixture.calls) == 1


def test_diagnostic_pagination_and_billing_budget_cannot_be_expanded() -> None:
    from datetime import UTC, datetime

    from tools.platformctl.aws_live import DiagnosticAwsSession

    from tests.fakes.platform_lifecycle import DiagnosticAwsFixture

    fixture = DiagnosticAwsFixture()
    fixture.responses[("ce", "list_cost_allocation_tags")] = [
        {"CostAllocationTags": [], "NextToken": str(index)} for index in range(7)
    ]
    session = cast(DiagnosticAwsSession, fixture.session())
    with pytest.raises(ContractError, match="BILLING_LIMIT"):
        session.billing(datetime(2026, 9, 12, tzinfo=UTC), "tag_status")
    assert session.billing_requests == 6
    assert sum(service == "ce" for service, _, _ in fixture.calls) == 6


def test_diagnostic_role_absence_does_not_create_either_service_role() -> None:
    from tools.platformctl.aws_live import DiagnosticAwsSession, DiagnosticReadError

    from tests.fakes.platform_lifecycle import DiagnosticAwsFixture

    fixture = DiagnosticAwsFixture()
    fixture.responses[("iam", "get_role")] = [DiagnosticReadError("NoSuchEntity")]
    result = cast(DiagnosticAwsSession, fixture.session()).service_role()
    assert result == {"presence": "ABSENT", "ownership": "OWNER_MANAGED"}
    assert [arguments for service, method, arguments in fixture.calls if service == "iam"] == [
        {"RoleName": "AWSServiceRoleForAmazonOpenSearchService"}
    ]
    assert all(
        not method.startswith(("create", "delete", "put", "update"))
        for _, method, _ in fixture.calls
    )


@pytest.mark.parametrize("corruption", ["service", "period", "estimated", "metrics"])
def test_diagnostic_billing_rejects_unclassified_response_fields(corruption: str) -> None:
    from datetime import UTC, datetime

    from tools.platformctl.aws_live import DiagnosticAwsSession

    from tests.fakes.platform_lifecycle import DiagnosticAwsFixture

    group = {
        "Keys": ["Amazon Virtual Private Cloud"],
        "Metrics": {"UnblendedCost": {"Unit": "USD", "Amount": "1.25"}},
    }
    row = {
        "TimePeriod": {"Start": "2026-09-10", "End": "2026-09-11"},
        "Estimated": True,
        "Groups": [group],
    }
    if corruption == "service":
        group["Keys"] = ["unexpected\nresponse"]
    elif corruption == "period":
        row["TimePeriod"] = {"Start": "2026-09-10", "End": "2026-09-13"}
    elif corruption == "estimated":
        row["Estimated"] = "true"
    else:
        group["Metrics"] = []
    fixture = DiagnosticAwsFixture()
    fixture.responses[("ce", "get_cost_and_usage")] = [{"ResultsByTime": [row]}]
    with pytest.raises(ContractError, match="DIAGNOSTIC_BILLING"):
        cast(DiagnosticAwsSession, fixture.session()).billing(
            datetime(2026, 9, 12, tzinfo=UTC), "account"
        )


def test_diagnostic_billing_never_labels_account_projection_as_project_spending() -> None:
    from datetime import UTC, datetime

    from tools.platformctl.aws_live import DiagnosticAwsSession

    from tests.fakes.platform_lifecycle import DiagnosticAwsFixture

    fixture = DiagnosticAwsFixture()
    fixture.responses[("ce", "get_cost_and_usage")] = [
        {
            "ResultsByTime": [
                {
                    "TimePeriod": {"Start": "2026-09-10", "End": "2026-09-11"},
                    "Estimated": True,
                    "Groups": [
                        {
                            "Keys": ["Amazon Virtual Private Cloud"],
                            "Metrics": {"UnblendedCost": {"Unit": "USD", "Amount": "1.25"}},
                        }
                    ],
                }
            ],
        }
    ]
    result = cast(DiagnosticAwsSession, fixture.session()).billing(
        datetime(2026, 9, 12, tzinfo=UTC), "account"
    )
    assert result["w5_incurred_usd"] is None
    assert result["billing_lag_seconds"] is None
    assert result["today_excluded"] is True
    assert result["account"] == [
        {
            "period": {"Start": "2026-09-10", "End": "2026-09-11"},
            "service": "Amazon Virtual Private Cloud",
            "usd": "1.25",
            "estimated": True,
        }
    ]


def test_diagnostic_resource_specific_simulation_is_not_cartesian_assumed() -> None:
    from tools.platformctl.aws_live import DiagnosticAwsSession

    from tests.fakes.platform_lifecycle import DiagnosticAwsFixture

    fixture = DiagnosticAwsFixture()
    session = cast(DiagnosticAwsSession, fixture.session())
    names = tuple(
        "/aws/OpenSearchService/domains/enterprise-ai-sandbox/" + suffix
        for suffix in ("application-logs", "audit-logs", "index-slow-logs", "search-slow-logs")
    )
    session.bind_authorization_targets(names, "enterprise-ai-sandbox")
    fixture.responses[("iam", "simulate_principal_policy")] = [
        {
            "EvaluationResults": [
                {
                    "EvalActionName": "logs:TagResource",
                    "EvalDecision": "allowed",
                    "ResourceSpecificResults": [
                        {
                            "EvalResourceName": (
                                "arn:aws:logs:ap-southeast-1:526338061652:log-group:" + name
                            ),
                            "EvalResourceDecision": "allowed",
                        }
                        for name in names
                    ],
                }
            ],
            "IsTruncated": False,
        }
    ]
    result = session.simulate("logs:TagResource")
    assert result["allowed"] is True
    assert result["live_authorization_guarantee"] is False
    fixture.responses[("iam", "simulate_principal_policy")] = [
        {"EvaluationResults": [], "IsTruncated": False}
    ]
    unavailable = session.simulate("logs:TagResource")
    assert unavailable["allowed"] is None
    assert unavailable["assessment"] == "INDETERMINATE"
    assert unavailable["coverage_complete"] is False
    assert all(row["decision"] is None for row in unavailable["findings"])


def test_private_decoder_does_not_serialize_sensitive_fields() -> None:
    from tools.platformctl.lifecycle_io import decode_json_strict

    assert decode_json_strict(b'{"password":null}') == {"password": None}


@pytest.mark.parametrize("raw", [b'{"a":NaN}', b'{"a":1e999}', b'{"a":1,"a":2}'])
def test_nonfinite_json_and_duplicate_keys_fail_closed(raw: bytes) -> None:
    from tools.platformctl.lifecycle_io import decode_json_strict

    with pytest.raises(ContractError):
        decode_json_strict(raw)


@pytest.mark.parametrize("field", ["before_sensitive", "after_sensitive"])
def test_sensitive_values_in_either_snapshot_fail_closed(field: str) -> None:
    body = {"actions": ["create"], "before": None, "after": {}, field: {"reviewed": True}}
    with pytest.raises(ContractError):
        normalize_plan(plan(body), evaluation_time="2026-09-08T00:00:00Z")


def test_sensitive_outputs_fail_before_security_projection() -> None:
    raw = plan({"actions": ["create"], "before": None, "after": {}})
    raw["output_changes"] = {"value": {"after_sensitive": True}}
    with pytest.raises(ContractError, match="OUTPUT_SENSITIVITY"):
        normalize_plan(raw, evaluation_time="2026-09-08T00:00:00Z")


def plan(change: dict[str, object]) -> dict[str, object]:
    return {
        "format_version": "1.2",
        "terraform_version": "1.16.1",
        "variables": {"aws_region": {"value": "ap-southeast-1"}},
        "resource_changes": [{"address": "aws_vpc.main", "type": "aws_vpc", "change": change}],
    }


@pytest.mark.parametrize("field", ("before_sensitive", "after_sensitive"))
@pytest.mark.parametrize(
    "sensitive",
    (
        [],
        [False],
        "false",
        0,
        None,
        {"tags": {"ExpiresAt": "false"}},
        {"tags": {"ExpiresAt": 0}},
        {"tags": {"ExpiresAt": None}},
        {"blocks": [{"enabled": "false"}]},
    ),
)
def test_normalization_rejects_malformed_sensitivity_metadata(
    field: str,
    sensitive: object,
) -> None:
    with pytest.raises(ContractError, match="sensitivity metadata is malformed"):
        normalize_plan(
            plan(
                {
                    "actions": ["create"],
                    "before": None,
                    "after": {},
                    "after_unknown": {},
                    field: sensitive,
                }
            ),
            evaluation_time="2026-09-04T00:00:00Z",
        )


@pytest.mark.parametrize("field", ("before_sensitive", "after_sensitive"))
@pytest.mark.parametrize("sensitive", (False, {}, {"blocks": [{}, {"enabled": False}]}))
def test_normalization_preserves_valid_false_only_resource_sensitivity(
    field: str,
    sensitive: object,
) -> None:
    raw = plan(
        {
            "actions": ["no-op"],
            "before": {"blocks": [{}, {"enabled": True}]},
            "after": {"blocks": [{}, {"enabled": True}]},
            "after_unknown": {},
            field: sensitive,
        }
    )
    original = deepcopy(raw)
    normalized = normalize_plan(raw, evaluation_time="2026-09-04T00:00:00Z")
    expected = {} if sensitive is False else sensitive
    assert normalized["resource_changes"][0]["change"][field] == expected
    assert raw == original


def test_domain_access_policy_inputs_are_limited_to_initial_and_exact_recovery_shapes() -> None:
    assert PLATFORM_POLICY_DOCUMENT_PLANNED_INPUT_SHA256[
        "module.opensearch.data.aws_iam_policy_document.domain_access"
    ] == frozenset(
        {
            "5b666964e1082ebf6d3c27c8cb72d8ee230aba5507d3cbb47f804abd84753f02",
            "bfa08d10467373bc1f96fba528a0b1a92e5a29304b3aa414e4d7b03223a7baab",
        }
    )


def test_policy_data_modules_are_not_deferred_by_owner_expiry_gate() -> None:
    sandbox_main = (
        Path(__file__).resolve().parents[2] / "infra/environments/sandbox/main.tf"
    ).read_text(encoding="utf-8")
    module_order = ("kms", "storage", "secrets", "iam", "opensearch", "ecr")
    starts = {name: sandbox_main.index(f'module "{name}" {{') for name in module_order}

    for name, following in (
        ("kms", "storage"),
        ("storage", "secrets"),
        ("opensearch", "ecr"),
    ):
        module_body = sandbox_main[starts[name] : starts[following]]
        assert "depends_on" not in module_body

    assert 'resource "terraform_data" "owner_expiry_gate"' in sandbox_main
    assert 'var.mandatory_tags["ExpiresAt"]' in sandbox_main


def s3_provider_computed_policy_plan() -> dict[str, object]:
    bucket_address = "aws_s3_bucket.terraform_state"
    policy_address = "aws_s3_bucket_policy.terraform_state_tls"
    return {
        "format_version": "1.2",
        "terraform_version": "1.16.1",
        "variables": {"aws_region": {"value": "ap-southeast-1"}},
        "configuration": {
            "root_module": {
                "resources": [
                    {
                        "address": bucket_address,
                        "mode": "managed",
                        "type": "aws_s3_bucket",
                        "expressions": {"bucket": {"constant_value": "approved-bucket"}},
                    },
                    {
                        "address": policy_address,
                        "mode": "managed",
                        "type": "aws_s3_bucket_policy",
                        "expressions": {
                            "bucket": {"references": [f"{bucket_address}.id"]},
                            "policy": {
                                "references": [
                                    "data.aws_iam_policy_document.terraform_state_tls.json"
                                ]
                            },
                        },
                    },
                ]
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
        ],
    }


def s3_provider_computed_kms_plan() -> dict[str, object]:
    bucket_address = "aws_s3_bucket.terraform_state"
    kms_address = "aws_kms_key.terraform_state"
    encryption_address = "aws_s3_bucket_server_side_encryption_configuration.terraform_state"
    return {
        "format_version": "1.2",
        "terraform_version": "1.16.1",
        "variables": {"aws_region": {"value": "ap-southeast-1"}},
        "configuration": {
            "root_module": {
                "resources": [
                    {
                        "address": bucket_address,
                        "mode": "managed",
                        "type": "aws_s3_bucket",
                        "expressions": {"bucket": {"constant_value": "approved-bucket"}},
                    },
                    {
                        "address": kms_address,
                        "mode": "managed",
                        "type": "aws_kms_key",
                        "expressions": {
                            "policy": {
                                "references": [
                                    "data.aws_iam_policy_document.terraform_state_key.json"
                                ]
                            }
                        },
                    },
                    {
                        "address": encryption_address,
                        "mode": "managed",
                        "type": "aws_s3_bucket_server_side_encryption_configuration",
                        "expressions": {
                            "bucket": {"references": [f"{bucket_address}.id"]},
                            "rule": [
                                {
                                    "apply_server_side_encryption_by_default": [
                                        {
                                            "kms_master_key_id": {
                                                "references": [f"{kms_address}.arn"]
                                            },
                                            "sse_algorithm": {"constant_value": "aws:kms"},
                                        }
                                    ]
                                }
                            ],
                        },
                    },
                ]
            }
        },
        "resource_changes": [
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
            {
                "address": bucket_address,
                "type": "aws_s3_bucket",
                "change": {
                    "actions": ["create"],
                    "before": None,
                    "after": {"bucket": "approved-bucket"},
                    "after_unknown": {"id": True},
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
        ],
    }


def configured_resources(raw: dict[str, object]) -> list[dict[str, object]]:
    configuration = cast(dict[str, object], raw["configuration"])
    root_module = cast(dict[str, object], configuration["root_module"])
    return cast(list[dict[str, object]], root_module["resources"])


def resource_changes(raw: dict[str, object]) -> list[dict[str, object]]:
    return cast(list[dict[str, object]], raw["resource_changes"])


def change_body(resource: dict[str, object]) -> dict[str, object]:
    return cast(dict[str, object], resource["change"])


def patch_fixture_policy_expression_hashes(
    monkeypatch: pytest.MonkeyPatch,
    raw: dict[str, object],
) -> None:
    configuration = cast(dict[str, object], raw["configuration"])
    root = cast(dict[str, object], configuration["root_module"])
    calls = cast(dict[str, object], root["module_calls"])
    for module_name in ("iam", "opensearch"):
        module_call = cast(dict[str, object], calls[module_name])
        call_expressions = cast(dict[str, object], module_call["expressions"])
        module = cast(dict[str, object], module_call["module"])
        resources = cast(list[dict[str, object]], module["resources"])
        for resource in resources:
            local_address = resource["address"]
            full_address = f"module.{module_name}.{local_address}"
            if full_address not in PLATFORM_POLICY_DOCUMENT_EXPRESSION_SHA256:
                continue
            expressions = resource["expressions"]
            monkeypatch.setitem(
                PLATFORM_POLICY_DOCUMENT_EXPRESSION_SHA256,
                full_address,
                sha256_bytes(canonical_json_bytes(expressions)),
            )
            monkeypatch.setitem(
                PLATFORM_POLICY_DOCUMENT_CALL_EXPRESSION_SHA256,
                full_address,
                (
                    f"module.{module_name}",
                    sha256_bytes(canonical_json_bytes(call_expressions)),
                ),
            )
            policy_change = next(
                change for change in resource_changes(raw) if change["address"] == full_address
            )
            planned_after = cast(dict[str, object], change_body(policy_change)["after"])
            planned_inputs = {
                key: value
                for key, value in planned_after.items()
                if key not in {"id", "json", "minified_json"}
            }
            monkeypatch.setitem(
                PLATFORM_POLICY_DOCUMENT_PLANNED_INPUT_SHA256,
                full_address,
                frozenset({sha256_bytes(canonical_json_bytes(planned_inputs))}),
            )


def module_aware_platform_unknown_plan() -> dict[str, object]:
    def reference(value: str) -> dict[str, object]:
        return {"references": [value]}

    def policy_document(name: str, sids: tuple[str, ...]) -> dict[str, object]:
        return {
            "address": f"data.aws_iam_policy_document.{name}",
            "mode": "data",
            "type": "aws_iam_policy_document",
            "expressions": {"statement": [{"sid": {"constant_value": sid}} for sid in sids]},
        }

    changes: list[dict[str, object]] = []

    def add_change(
        address: str,
        resource_type: str,
        after: dict[str, object],
        unknowns: dict[str, object],
        *,
        actions: tuple[str, ...] = ("create",),
    ) -> None:
        changes.append(
            {
                "address": address,
                "type": resource_type,
                "change": {
                    "actions": list(actions),
                    "before": None,
                    "after": after,
                    "after_unknown": unknowns,
                    "after_sensitive": {},
                },
            }
        )

    network_resources: list[dict[str, object]] = [
        {
            "address": "aws_vpc.this",
            "mode": "managed",
            "type": "aws_vpc",
            "expressions": {},
        },
        {
            "address": "aws_default_security_group.restricted",
            "mode": "managed",
            "type": "aws_default_security_group",
            "expressions": {"vpc_id": reference("aws_vpc.this.id")},
        },
        {
            "address": "aws_subnet.private",
            "mode": "managed",
            "type": "aws_subnet",
            "expressions": {"vpc_id": reference("aws_vpc.this.id")},
        },
        {
            "address": "aws_route_table.private",
            "mode": "managed",
            "type": "aws_route_table",
            "expressions": {"vpc_id": reference("aws_vpc.this.id")},
        },
        {
            "address": "aws_route_table_association.private",
            "mode": "managed",
            "type": "aws_route_table_association",
            "expressions": {"subnet_id": reference("aws_subnet.private")},
        },
        {
            "address": "aws_security_group.endpoints",
            "mode": "managed",
            "type": "aws_security_group",
            "expressions": {"vpc_id": reference("aws_vpc.this.id")},
        },
        {
            "address": "aws_vpc_endpoint.gateway",
            "mode": "managed",
            "type": "aws_vpc_endpoint",
            "expressions": {"vpc_id": reference("aws_vpc.this.id")},
        },
        {
            "address": "aws_vpc_endpoint.interface",
            "mode": "managed",
            "type": "aws_vpc_endpoint",
            "expressions": {
                "vpc_id": reference("aws_vpc.this.id"),
                "subnet_ids": reference("aws_subnet.private"),
                "security_group_ids": reference("aws_security_group.endpoints.id"),
            },
        },
    ]
    add_change("module.network.aws_vpc.this", "aws_vpc", {}, {"id": True})
    for address, resource_type in (
        ("module.network.aws_default_security_group.restricted", "aws_default_security_group"),
        ("module.network.aws_route_table.private", "aws_route_table"),
        ("module.network.aws_security_group.endpoints", "aws_security_group"),
    ):
        add_change(address, resource_type, {}, {"vpc_id": True})
    for index in range(2):
        add_change(
            f"module.network.aws_subnet.private[{index}]",
            "aws_subnet",
            {},
            {"vpc_id": True},
        )
        add_change(
            f"module.network.aws_route_table_association.private[{index}]",
            "aws_route_table_association",
            {},
            {"subnet_id": True},
        )
    gateway_names = ("DynamoDB", "S3")
    for name in gateway_names:
        add_change(
            f'module.network.aws_vpc_endpoint.gateway["{name}"]',
            "aws_vpc_endpoint",
            {"vpc_endpoint_type": "Gateway"},
            {
                "policy": True,
                "security_group_ids": True,
                "subnet_ids": True,
                "vpc_id": True,
            },
        )
    interface_names = (
        "Bedrock Runtime",
        "CloudWatch Logs",
        "ECR API",
        "ECR DKR",
        "EKS",
        "KMS",
        "STS",
        "Secrets Manager",
    )
    for name in interface_names:
        add_change(
            f'module.network.aws_vpc_endpoint.interface["{name}"]',
            "aws_vpc_endpoint",
            {"vpc_endpoint_type": "Interface"},
            {
                "policy": True,
                "security_group_ids": True,
                "subnet_ids": True,
                "vpc_id": True,
            },
        )

    kms_resources = [
        policy_document(
            "this",
            (
                "EnableExactAccountKeyAdministration",
                "AllowExactWorkloadCryptography",
                "AllowExactOpenSearchLogEncryption",
                "AllowExactBedrockInvocationLogEncryption",
            ),
        ),
        {
            "address": "aws_kms_key.this",
            "mode": "managed",
            "type": "aws_kms_key",
            "expressions": {"policy": reference("data.aws_iam_policy_document.this.json")},
        },
    ]
    add_change(
        "module.kms.data.aws_iam_policy_document.this",
        "aws_iam_policy_document",
        {},
        {"json": True},
        actions=("read",),
    )
    add_change(
        "module.kms.aws_kms_key.this",
        "aws_kms_key",
        {"enable_key_rotation": True, "deletion_window_in_days": 7, "policy": None},
        {"arn": True, "policy": True},
    )

    storage_resources = [
        policy_document(
            "tls_only",
            ("DenyNonTLSPlatformAccess", "AllowExactBedrockInvocationLogDelivery"),
        ),
        {
            "address": "aws_s3_bucket.this",
            "mode": "managed",
            "type": "aws_s3_bucket",
            "expressions": {},
        },
        {
            "address": "aws_s3_bucket_policy.tls_only",
            "mode": "managed",
            "type": "aws_s3_bucket_policy",
            "expressions": {
                "bucket": reference("aws_s3_bucket.this.id"),
                "policy": reference("data.aws_iam_policy_document.tls_only.json"),
            },
        },
        {
            "address": "aws_s3_bucket_server_side_encryption_configuration.this",
            "mode": "managed",
            "type": "aws_s3_bucket_server_side_encryption_configuration",
            "expressions": {
                "bucket": reference("aws_s3_bucket.this.id"),
                "rule": [
                    {
                        "apply_server_side_encryption_by_default": [
                            {
                                "kms_master_key_id": reference("var.kms_key_arn"),
                                "sse_algorithm": {"constant_value": "aws:kms"},
                            }
                        ]
                    }
                ],
            },
        },
    ]
    add_change(
        "module.storage.data.aws_iam_policy_document.tls_only",
        "aws_iam_policy_document",
        {},
        {"json": True},
        actions=("read",),
    )
    add_change(
        "module.storage.aws_s3_bucket.this",
        "aws_s3_bucket",
        {"policy": None},
        {"policy": True},
    )
    add_change(
        "module.storage.aws_s3_bucket_policy.tls_only",
        "aws_s3_bucket_policy",
        {"policy": None},
        {"policy": True},
    )
    add_change(
        "module.storage.aws_s3_bucket_server_side_encryption_configuration.this",
        "aws_s3_bucket_server_side_encryption_configuration",
        {"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "aws:kms"}]}]},
        {"rule": [{"apply_server_side_encryption_by_default": [{"kms_master_key_id": True}]}]},
    )

    iam_policy_sids = {
        "runtime": (
            "InvokeExactGlobalInferenceProfile",
            "InvokeExactGlobalInferenceProfileRegionalModel",
            "InvokeExactGlobalInferenceProfileGlobalModel",
            "RuntimeReadGovernedObjects",
            "RuntimeListGovernedObjects",
            "RuntimeUsePlatformKey",
            "RuntimeOpenSearchHealthRead",
            "RuntimeOpenSearchExactIndexQuery",
            "RuntimeWriteSafeApplicationLogs",
            "RuntimeWriteBoundedMetrics",
            "RuntimeWriteXRayTelemetry",
        ),
        "ingestion": (
            "IngestionReadRawObjects",
            "IngestionWriteQuarantineObjects",
            "IngestionWriteProcessedAndEvidenceObjects",
            "IngestionListPlatformBucket",
            "IngestionUsePlatformKey",
            "IngestionOpenSearchDataPlane",
        ),
    }
    iam_resources: list[dict[str, object]] = []
    iam_trust_bindings = {
        "runtime": ("runtime_trust", ("ExactPodIdentityRuntimeTrust",)),
        "ingestion": ("ingestion_trust", ("ExactPodIdentityIngestionTrust",)),
        "opensearch_administrator": (
            "administrator_trust",
            ("TimeBoundExactSandboxAdministrator",),
        ),
        "github_oidc": ("github_trust", ("ExactGitHubEnvironmentTrust",)),
    }
    for role_name, (document_name, sids) in iam_trust_bindings.items():
        iam_resources.extend(
            [
                policy_document(document_name, sids),
                {
                    "address": f"aws_iam_role.{role_name}",
                    "mode": "managed",
                    "type": "aws_iam_role",
                    "expressions": {
                        "assume_role_policy": reference(
                            f"data.aws_iam_policy_document.{document_name}.json"
                        )
                    },
                },
            ]
        )
        add_change(
            f"module.iam.data.aws_iam_policy_document.{document_name}",
            "aws_iam_policy_document",
            {},
            {"id": True, "json": True, "minified_json": True},
            actions=("read",),
        )
        add_change(
            f"module.iam.aws_iam_role.{role_name}",
            "aws_iam_role",
            {"assume_role_policy": None},
            {"assume_role_policy": True},
        )
    for name, sids in iam_policy_sids.items():
        iam_resources.extend(
            [
                policy_document(name, sids),
                {
                    "address": f"aws_iam_role_policy.{name}",
                    "mode": "managed",
                    "type": "aws_iam_role_policy",
                    "expressions": {
                        "policy": reference(f"data.aws_iam_policy_document.{name}.json")
                    },
                },
            ]
        )
        add_change(
            f"module.iam.data.aws_iam_policy_document.{name}",
            "aws_iam_policy_document",
            {},
            {"json": True},
            actions=("read",),
        )
        add_change(
            f"module.iam.aws_iam_role_policy.{name}",
            "aws_iam_role_policy",
            {"policy": None},
            {"policy": True},
        )

    opensearch_resources: list[dict[str, object]] = [
        policy_document(
            "domain_access",
            ("ExactSandboxRoleDataPlaneAccess", "RuntimeExactReadAccess"),
        ),
        policy_document("log_delivery", ("ExactOpenSearchLogDelivery",)),
        {
            "address": "aws_cloudwatch_log_group.this",
            "mode": "managed",
            "type": "aws_cloudwatch_log_group",
            "expressions": {"kms_key_id": reference("var.kms_key_arn")},
        },
        {
            "address": "aws_cloudwatch_log_resource_policy.opensearch",
            "mode": "managed",
            "type": "aws_cloudwatch_log_resource_policy",
            "expressions": {
                "policy_document": reference("data.aws_iam_policy_document.log_delivery.json")
            },
        },
        {
            "address": "aws_opensearch_domain.this",
            "mode": "managed",
            "type": "aws_opensearch_domain",
            "expressions": {
                "access_policies": reference("data.aws_iam_policy_document.domain_access.json"),
                "encrypt_at_rest": [{"kms_key_id": reference("var.kms_key_arn")}],
                "vpc_options": [
                    {
                        "subnet_ids": reference("var.subnet_id"),
                        "security_group_ids": reference("var.security_group_id"),
                    }
                ],
            },
        },
    ]
    for name in ("application", "audit", "index_slow", "search_slow"):
        add_change(
            f'module.opensearch.aws_cloudwatch_log_group.this["{name}"]',
            "aws_cloudwatch_log_group",
            {},
            {"kms_key_id": True},
        )
    add_change(
        "module.opensearch.data.aws_iam_policy_document.domain_access",
        "aws_iam_policy_document",
        {},
        {
            "id": True,
            "json": True,
            "minified_json": True,
            "statement": [{"principals": [{"identifiers": True}]}],
        },
        actions=("read",),
    )
    add_change(
        "module.opensearch.data.aws_iam_policy_document.log_delivery",
        "aws_iam_policy_document",
        {},
        {"id": True, "json": True, "minified_json": True},
        actions=("read",),
    )
    add_change(
        "module.opensearch.aws_cloudwatch_log_resource_policy.opensearch",
        "aws_cloudwatch_log_resource_policy",
        {"policy_document": None},
        {"policy_document": True},
    )
    add_change(
        "module.opensearch.aws_opensearch_domain.this",
        "aws_opensearch_domain",
        {
            "access_policies": None,
            "encrypt_at_rest": [{"enabled": True}],
            "vpc_options": [{}],
        },
        {
            "access_policies": True,
            "encrypt_at_rest": [{"kms_key_id": True}],
            "vpc_options": [
                {
                    "security_group_ids": True,
                    "subnet_ids": True,
                    "vpc_id": True,
                }
            ],
        },
    )

    return {
        "format_version": "1.2",
        "terraform_version": "1.16.1",
        "variables": {"aws_region": {"value": "ap-southeast-1"}},
        "configuration": {
            "root_module": {
                "resources": [],
                "module_calls": {
                    "network": {
                        "expressions": {},
                        "module": {
                            "resources": network_resources,
                            "outputs": {
                                "private_subnet_ids": {
                                    "expression": reference("aws_subnet.private")
                                },
                                "endpoint_security_group_id": {
                                    "expression": reference("aws_security_group.endpoints.id")
                                },
                                "vpc_id": {"expression": reference("aws_vpc.this.id")},
                            },
                        },
                    },
                    "kms": {
                        "expressions": {},
                        "module": {
                            "resources": kms_resources,
                            "outputs": {
                                "key_arn": {"expression": reference("aws_kms_key.this.arn")}
                            },
                        },
                    },
                    "storage": {
                        "expressions": {"kms_key_arn": reference("module.kms.key_arn")},
                        "module": {"resources": storage_resources},
                    },
                    "iam": {
                        "expressions": {"kms_key_arn": reference("module.kms.key_arn")},
                        "module": {"resources": iam_resources},
                    },
                    "opensearch": {
                        "expressions": {
                            "kms_key_arn": reference("module.kms.key_arn"),
                            "subnet_id": reference("module.network.private_subnet_ids"),
                            "security_group_id": reference(
                                "module.network.endpoint_security_group_id"
                            ),
                        },
                        "module": {"resources": opensearch_resources},
                    },
                },
            }
        },
        "resource_changes": changes,
    }


def ecr_kms_reference_plan() -> dict[str, object]:
    kms_address = "module.kms.aws_kms_key.this"
    ecr_address = "module.ecr.aws_ecr_repository.this"
    return {
        "format_version": "1.2",
        "terraform_version": "1.16.1",
        "variables": {"aws_region": {"value": "ap-southeast-1"}},
        "configuration": {
            "root_module": {
                "resources": [],
                "module_calls": {
                    "kms": {
                        "expressions": {},
                        "module": {
                            "resources": [
                                {
                                    "address": "aws_kms_key.this",
                                    "mode": "managed",
                                    "type": "aws_kms_key",
                                    "expressions": {},
                                }
                            ],
                            "outputs": {
                                "key_arn": {
                                    "expression": {
                                        "references": [
                                            "aws_kms_key.this.arn",
                                            "aws_kms_key.this",
                                        ]
                                    }
                                }
                            },
                        },
                    },
                    "ecr": {
                        "expressions": {
                            "kms_key_arn": {"references": ["module.kms.key_arn", "module.kms"]}
                        },
                        "module": {
                            "resources": [
                                {
                                    "address": "aws_ecr_repository.this",
                                    "mode": "managed",
                                    "type": "aws_ecr_repository",
                                    "expressions": {
                                        "encryption_configuration": [
                                            {
                                                "encryption_type": {"constant_value": "KMS"},
                                                "kms_key": {"references": ["var.kms_key_arn"]},
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
                "address": kms_address,
                "type": "aws_kms_key",
                "change": {
                    "actions": ["create"],
                    "before": None,
                    "after": {},
                    "after_unknown": {"arn": True},
                    "after_sensitive": {},
                },
            },
            {
                "address": ecr_address,
                "type": "aws_ecr_repository",
                "change": {
                    "actions": ["create"],
                    "before": None,
                    "after": {"encryption_configuration": [{"encryption_type": "KMS"}]},
                    "after_unknown": {"encryption_configuration": [{"kms_key": True}]},
                    "after_sensitive": {"encryption_configuration": [{}]},
                },
            },
        ],
    }


def opensearch_log_reference_plan() -> dict[str, object]:
    names = {
        "application": "ES_APPLICATION_LOGS",
        "audit": "AUDIT_LOGS",
        "index_slow": "INDEX_SLOW_LOGS",
        "search_slow": "SEARCH_SLOW_LOGS",
    }
    configured_logs = [
        {
            "enabled": {"constant_value": True},
            "log_type": {"constant_value": log_type},
            "cloudwatch_log_group_arn": {
                "references": [
                    f'aws_cloudwatch_log_group.this["{name}"].arn',
                    f'aws_cloudwatch_log_group.this["{name}"]',
                    "aws_cloudwatch_log_group.this",
                ]
            },
        }
        for name, log_type in names.items()
    ]
    changes: list[dict[str, object]] = []
    for name in names:
        changes.append(
            {
                "address": f'module.opensearch.aws_cloudwatch_log_group.this["{name}"]',
                "type": "aws_cloudwatch_log_group",
                "change": {
                    "actions": ["create"],
                    "before": None,
                    "after": {},
                    "after_unknown": {"arn": True},
                    "after_sensitive": {},
                },
            }
        )
    changes.append(
        {
            "address": "module.opensearch.aws_opensearch_domain.this",
            "type": "aws_opensearch_domain",
            "change": {
                "actions": ["create"],
                "before": None,
                "after": {
                    "log_publishing_options": [
                        {"enabled": True, "log_type": log_type}
                        for log_type in sorted(names.values())
                    ]
                },
                "after_unknown": {
                    "log_publishing_options": [{"cloudwatch_log_group_arn": True} for _ in names]
                },
                "after_sensitive": {"log_publishing_options": [{} for _ in names]},
            },
        }
    )
    return {
        "format_version": "1.2",
        "terraform_version": "1.16.1",
        "variables": {"aws_region": {"value": "ap-southeast-1"}},
        "configuration": {
            "root_module": {
                "resources": [],
                "module_calls": {
                    "opensearch": {
                        "expressions": {},
                        "module": {
                            "resources": [
                                {
                                    "address": "aws_cloudwatch_log_group.this",
                                    "mode": "managed",
                                    "type": "aws_cloudwatch_log_group",
                                    "expressions": {},
                                },
                                {
                                    "address": "aws_opensearch_domain.this",
                                    "mode": "managed",
                                    "type": "aws_opensearch_domain",
                                    "expressions": {"log_publishing_options": configured_logs},
                                },
                            ]
                        },
                    }
                },
            }
        },
        "resource_changes": changes,
    }


def opensearch_omitted_password_plan() -> dict[str, object]:
    def reference(*values: str) -> dict[str, object]:
        return {"references": list(values)}

    domain_address = "module.opensearch.aws_opensearch_domain.this"
    role_address = "module.iam.aws_iam_role.opensearch_administrator"
    return {
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
                                    "expression": reference(
                                        "aws_iam_role.opensearch_administrator",
                                        "aws_iam_role.opensearch_administrator.arn",
                                    )
                                }
                            },
                        },
                    },
                    "opensearch": {
                        "expressions": {
                            "administrator_role_arn": reference(
                                "module.iam", "module.iam.opensearch_administrator_role_arn"
                            )
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
                                                        "master_user_arn": reference(
                                                            "var.administrator_role_arn"
                                                        )
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
                    "after_unknown": {"arn": True, "id": True},
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
                                        "master_user_name": None,
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


def opensearch_existing_role_omitted_password_plan() -> dict[str, object]:
    raw = opensearch_omitted_password_plan()
    changes = resource_changes(raw)
    role_body = change_body(changes[0])
    domain_body = change_body(changes[1])
    role_arn = "arn:aws:iam::526338061652:role/enterprise-ai-sandbox-opensearch-admin"
    trust_policy = '{"Statement":[],"Version":"2012-10-17"}'
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
    after = cast(dict[str, object], domain_body["after"])
    advanced = cast(list[dict[str, object]], after["advanced_security_options"])[0]
    master = cast(list[dict[str, object]], advanced["master_user_options"])[0]
    master["master_user_arn"] = role_arn
    unknown = cast(dict[str, object], domain_body["after_unknown"])
    unknown_advanced = cast(list[dict[str, object]], unknown["advanced_security_options"])[0]
    unknown_master = cast(list[dict[str, object]], unknown_advanced["master_user_options"])[0]
    unknown_master.clear()
    return raw


def test_sensitive_evidence_fields_are_rejected_without_echoing_values() -> None:
    with pytest.raises(ContractError, match="sensitive field"):
        canonical_json_bytes({"api_key": "-".join(("synthetic", "sensitive", "value"))})


def test_repository_and_escape_paths_are_rejected(tmp_path: Path) -> None:
    repository = Path(__file__).resolve().parents[2]
    with pytest.raises(ContractError, match="inside the repository"):
        ensure_external_path(repository / "report.json", repository, repository)
    with pytest.raises(ContractError, match="outside"):
        ensure_external_path(tmp_path.parent / "escape.json", tmp_path, repository)


def test_sensitive_and_policy_critical_unknown_plan_values_fail_closed() -> None:
    for change in (
        {"actions": ["create"], "after": {}, "after_sensitive": {"password": True}},
        {"actions": ["create"], "after": {}, "after_unknown": {"subnet_id": True}},
        {"actions": ["create"], "after": {"password": "".join(("syn", "thetic"))}},
    ):
        with pytest.raises(ContractError):
            normalize_plan(plan(change), evaluation_time="2026-09-08T00:00:00Z")


def test_exact_opensearch_omitted_password_marker_is_structurally_normalized() -> None:
    raw = opensearch_omitted_password_plan()
    original = deepcopy(raw)

    normalized = normalize_plan(raw, evaluation_time="2026-09-08T00:00:00Z")

    changes = cast(list[dict[str, object]], normalized["resource_changes"])
    domain = cast(dict[str, object], changes[1]["change"])
    assert domain["after_sensitive"] == {
        "advanced_security_options": [{"master_user_options": [{}]}]
    }
    after = cast(dict[str, object], domain["after"])
    advanced = cast(list[dict[str, object]], after["advanced_security_options"])[0]
    master = cast(list[dict[str, object]], advanced["master_user_options"])[0]
    assert "master_user_password" not in master
    context = cast(dict[str, object], normalized["evaluation_context"])
    assert context["provider_sensitive_nulls"] == [
        {
            "address": "module.opensearch.aws_opensearch_domain.this",
            "type": "aws_opensearch_domain",
            "field_path": (
                "advanced_security_options[].master_user_options[].master_user_password"
            ),
            "relationship": ("omitted-null-password-with-structurally-resolved-admin-role"),
            "source_address": "module.iam.aws_iam_role.opensearch_administrator",
        }
    ]
    assert raw == original


def test_existing_opensearch_role_omitted_password_marker_is_structurally_normalized() -> None:
    raw = opensearch_existing_role_omitted_password_plan()
    original = deepcopy(raw)

    normalized = normalize_plan(raw, evaluation_time="2026-09-08T00:00:00Z")

    context = cast(dict[str, object], normalized["evaluation_context"])
    assert context["provider_sensitive_nulls"] == [
        {
            "address": "module.opensearch.aws_opensearch_domain.this",
            "type": "aws_opensearch_domain",
            "field_path": (
                "advanced_security_options[].master_user_options[].master_user_password"
            ),
            "relationship": "omitted-null-password-with-existing-admin-role",
            "source_address": "module.iam.aws_iam_role.opensearch_administrator",
        }
    ]
    changes = cast(list[dict[str, object]], normalized["resource_changes"])
    domain = cast(dict[str, object], changes[1]["change"])
    assert domain["after_sensitive"] == {
        "advanced_security_options": [{"master_user_options": [{}]}]
    }
    assert raw == original


def test_existing_noop_opensearch_role_omitted_password_marker_is_normalized() -> None:
    raw = opensearch_existing_role_omitted_password_plan()
    role_body = change_body(resource_changes(raw)[0])
    after = deepcopy(role_body["after"])
    role_body.update({"actions": ["no-op"], "before": after, "after": after})

    normalized = normalize_plan(raw, evaluation_time="2026-09-08T00:00:00Z")

    context = cast(dict[str, object], normalized["evaluation_context"])
    binding = cast(list[dict[str, object]], context["provider_sensitive_nulls"])[0]
    assert binding["relationship"] == "omitted-null-password-with-existing-admin-role"


def test_existing_opensearch_empty_password_placeholder_is_normalized() -> None:
    raw = opensearch_existing_role_omitted_password_plan()
    domain_body = change_body(resource_changes(raw)[1])
    after = cast(dict[str, object], domain_body["after"])
    advanced = cast(list[dict[str, object]], after["advanced_security_options"])[0]
    master = cast(list[dict[str, object]], advanced["master_user_options"])[0]
    master["master_user_password"] = ""
    domain_body["actions"] = ["update"]
    domain_body["before"] = deepcopy(after)
    domain_body["before_sensitive"] = deepcopy(domain_body["after_sensitive"])

    normalized = normalize_plan(raw, evaluation_time="2026-09-08T00:00:00Z")

    changes = cast(list[dict[str, object]], normalized["resource_changes"])
    domain = cast(dict[str, object], changes[1]["change"])
    normalized_after = cast(dict[str, object], domain["after"])
    normalized_before = cast(dict[str, object], domain["before"])
    for value in (normalized_before, normalized_after):
        advanced = cast(list[dict[str, object]], value["advanced_security_options"])[0]
        master = cast(list[dict[str, object]], advanced["master_user_options"])[0]
        assert "master_user_password" not in master


def test_existing_opensearch_admin_trust_expiry_reconciliation_is_normalized() -> None:
    raw = opensearch_existing_role_omitted_password_plan()
    changes = resource_changes(raw)
    role_body = change_body(changes[0])
    domain_body = change_body(changes[1])
    before_role = cast(dict[str, object], role_body["before"])
    after_role = cast(dict[str, object], role_body["after"])
    previous_expiry = cast(dict[str, object], before_role["tags"])["ExpiresAt"]
    current_expiry = cast(dict[str, object], after_role["tags"])["ExpiresAt"]

    def trust(expiry: object) -> str:
        return json.dumps(
            {
                "Statement": [
                    {
                        "Action": "sts:AssumeRole",
                        "Condition": {"DateLessThan": {"aws:CurrentTime": expiry}},
                        "Effect": "Allow",
                        "Principal": {"AWS": "arn:aws:iam::123456789012:role/owner"},
                        "Sid": "TimeBoundExactSandboxAdministrator",
                    }
                ],
                "Version": "2012-10-17",
            }
        )

    before_role["assume_role_policy"] = trust(previous_expiry)
    trust_expiry = "2026-09-08T11:00:00Z"
    assert previous_expiry < trust_expiry < current_expiry
    after_role["assume_role_policy"] = trust(trust_expiry)
    after_domain = cast(dict[str, object], domain_body["after"])
    advanced = cast(list[dict[str, object]], after_domain["advanced_security_options"])[0]
    master = cast(list[dict[str, object]], advanced["master_user_options"])[0]
    master["master_user_name"] = ""
    master["master_user_password"] = ""
    domain_body["before"] = deepcopy(after_domain)
    domain_body["before_sensitive"] = deepcopy(domain_body["after_sensitive"])
    domain_body["actions"] = ["update"]

    normalized = normalize_plan(raw, evaluation_time="2026-09-08T00:00:00Z")

    context = cast(dict[str, object], normalized["evaluation_context"])
    assert len(cast(list[object], context["provider_sensitive_before_nulls"])) == 1
    assert len(cast(list[object], context["provider_sensitive_nulls"])) == 1


def test_existing_opensearch_admin_trust_and_resource_expiries_may_be_distinct() -> None:
    raw = opensearch_existing_role_omitted_password_plan()
    changes = resource_changes(raw)
    role_body = change_body(changes[0])
    before_role = cast(dict[str, object], role_body["before"])
    after_role = cast(dict[str, object], role_body["after"])

    def trust(expiry: str) -> str:
        return json.dumps(
            {
                "Statement": [
                    {
                        "Action": "sts:AssumeRole",
                        "Condition": {"DateLessThan": {"aws:CurrentTime": expiry}},
                        "Effect": "Allow",
                        "Principal": {"AWS": "arn:aws:iam::123456789012:role/owner"},
                        "Sid": "TimeBoundExactSandboxAdministrator",
                    }
                ],
                "Version": "2012-10-17",
            }
        )

    before_role["assume_role_policy"] = trust("2026-09-07T12:00:00Z")
    after_role["assume_role_policy"] = trust("2026-09-08T12:00:00Z")

    normalized = normalize_plan(raw, evaluation_time="2026-09-08T00:00:00Z")

    context = cast(dict[str, object], normalized["evaluation_context"])
    assert len(cast(list[object], context["provider_sensitive_nulls"])) == 1


@pytest.mark.parametrize(
    "mutation",
    (
        "arn_mismatch",
        "arn_unknown",
        "role_sensitive",
        "trust_policy_changed",
        "non_expiry_update",
        "non_expiry_tag_update",
    ),
)
def test_existing_opensearch_role_sensitivity_fails_closed_on_deviation(
    mutation: str,
) -> None:
    raw = opensearch_existing_role_omitted_password_plan()
    changes = resource_changes(raw)
    role_body = change_body(changes[0])
    domain_body = change_body(changes[1])

    if mutation == "arn_mismatch":
        after = cast(dict[str, object], domain_body["after"])
        advanced = cast(list[dict[str, object]], after["advanced_security_options"])[0]
        master = cast(list[dict[str, object]], advanced["master_user_options"])[0]
        master["master_user_arn"] = "arn:aws:iam::526338061652:role/unrelated"
    elif mutation == "arn_unknown":
        role_body["after_unknown"] = {"arn": True}
    elif mutation == "role_sensitive":
        role_body["after_sensitive"] = {"arn": True}
    elif mutation == "trust_policy_changed":
        after = cast(dict[str, object], role_body["after"])
        after["assume_role_policy"] = '{"Statement":[{}],"Version":"2012-10-17"}'
    elif mutation == "non_expiry_update":
        after = cast(dict[str, object], role_body["after"])
        after["name"] = "altered-role"
    else:
        after = cast(dict[str, object], role_body["after"])
        tags = cast(dict[str, object], after["tags"])
        tags["Environment"] = "other"

    with pytest.raises(ContractError, match="sensitive"):
        normalize_plan(raw, evaluation_time="2026-09-08T00:00:00Z")


def test_iam_module_does_not_defer_policy_data_sources_to_expiry_gate() -> None:
    sandbox = (
        Path(__file__).resolve().parents[2] / "infra" / "environments" / "sandbox" / "main.tf"
    ).read_text(encoding="utf-8")
    iam_start = sandbox.index('module "iam"')
    iam_end = sandbox.index('module "opensearch"', iam_start)
    iam_module = sandbox[iam_start:iam_end]

    assert "depends_on" not in iam_module
    assert 'expires_at                     = var.mandatory_tags["ExpiresAt"]' in iam_module
    assert "tags                           = var.mandatory_tags" in iam_module


@pytest.mark.parametrize(
    "mutation",
    (
        "non_null_password",
        "configured_password",
        "password_unknown",
        "internal_database",
        "configured_username",
        "missing_role",
        "missing_output",
        "unrelated_role",
        "multiple_role_sources",
        "external_parent_source",
        "missing_module_base_reference",
        "missing_role_base_reference",
        "extra_module_reference",
        "extra_role_reference",
        "constant_arn",
        "arn_not_unknown",
        "additional_sensitive",
        "before_password",
        "markerless_password",
        "wrong_resource",
    ),
)
def test_opensearch_omitted_password_normalization_fails_closed_on_deviation(
    mutation: str,
) -> None:
    raw = opensearch_omitted_password_plan()
    changes = resource_changes(raw)
    domain_body = change_body(changes[1])
    after = cast(dict[str, object], domain_body["after"])
    advanced = cast(list[dict[str, object]], after["advanced_security_options"])[0]
    master = cast(list[dict[str, object]], advanced["master_user_options"])[0]
    configuration = cast(dict[str, object], raw["configuration"])
    root = cast(dict[str, object], configuration["root_module"])
    calls = cast(dict[str, object], root["module_calls"])
    opensearch_call = cast(dict[str, object], calls["opensearch"])
    opensearch_module = cast(dict[str, object], opensearch_call["module"])
    domain_configuration = cast(
        dict[str, object], cast(list[dict[str, object]], opensearch_module["resources"])[0]
    )
    expressions = cast(dict[str, object], domain_configuration["expressions"])
    configured_advanced = cast(list[dict[str, object]], expressions["advanced_security_options"])[0]
    configured_master = cast(list[dict[str, object]], configured_advanced["master_user_options"])[0]

    if mutation == "non_null_password":
        master["master_user_password"] = "-".join(("synthetic", "non", "secret", "test", "value"))
    elif mutation == "configured_password":
        configured_master["master_user_password"] = {"constant_value": None}
    elif mutation == "password_unknown":
        unknown = cast(dict[str, object], domain_body["after_unknown"])
        unknown_advanced = cast(list[dict[str, object]], unknown["advanced_security_options"])[0]
        unknown_master = cast(list[dict[str, object]], unknown_advanced["master_user_options"])[0]
        unknown_master["master_user_password"] = True
    elif mutation == "internal_database":
        advanced["internal_user_database_enabled"] = True
    elif mutation == "configured_username":
        configured_master["master_user_name"] = {"constant_value": None}
    elif mutation == "missing_role":
        changes.pop(0)
    elif mutation == "missing_output":
        iam_call = cast(dict[str, object], calls["iam"])
        iam_module = cast(dict[str, object], iam_call["module"])
        outputs = cast(dict[str, object], iam_module["outputs"])
        outputs.clear()
    elif mutation in {"unrelated_role", "multiple_role_sources", "constant_arn"}:
        arn_expression = cast(dict[str, object], configured_master["master_user_arn"])
        if mutation == "unrelated_role":
            arn_expression["references"] = ["aws_iam_role.unrelated.arn"]
        elif mutation == "multiple_role_sources":
            arn_expression["references"] = [
                "var.administrator_role_arn",
                "aws_iam_role.unrelated.arn",
            ]
        else:
            arn_expression.clear()
            arn_expression["constant_value"] = "synthetic-arn"
    elif mutation == "external_parent_source":
        arguments = cast(dict[str, object], opensearch_call["expressions"])
        argument = cast(dict[str, object], arguments["administrator_role_arn"])
        argument["references"] = [
            "module.iam",
            "module.iam.opensearch_administrator_role_arn",
            "var.external_admin_arn",
        ]
    elif mutation in {
        "missing_module_base_reference",
        "extra_module_reference",
    }:
        arguments = cast(dict[str, object], opensearch_call["expressions"])
        argument = cast(dict[str, object], arguments["administrator_role_arn"])
        if mutation == "missing_module_base_reference":
            argument["references"] = ["module.iam.opensearch_administrator_role_arn"]
        else:
            argument["references"] = [
                "module.iam",
                "module.iam.opensearch_administrator_role_arn",
                "module.other",
            ]
    elif mutation in {
        "missing_role_base_reference",
        "extra_role_reference",
    }:
        iam_call = cast(dict[str, object], calls["iam"])
        iam_module = cast(dict[str, object], iam_call["module"])
        outputs = cast(dict[str, object], iam_module["outputs"])
        output = cast(dict[str, object], outputs["opensearch_administrator_role_arn"])
        expression = cast(dict[str, object], output["expression"])
        if mutation == "missing_role_base_reference":
            expression["references"] = ["aws_iam_role.opensearch_administrator.arn"]
        else:
            expression["references"] = [
                "aws_iam_role.opensearch_administrator",
                "aws_iam_role.opensearch_administrator.arn",
                "aws_iam_role.unrelated",
            ]
    elif mutation == "arn_not_unknown":
        unknown = cast(dict[str, object], domain_body["after_unknown"])
        unknown_advanced = cast(list[dict[str, object]], unknown["advanced_security_options"])[0]
        unknown_master = cast(list[dict[str, object]], unknown_advanced["master_user_options"])[0]
        unknown_master["master_user_arn"] = False
    elif mutation == "additional_sensitive":
        sensitive = cast(dict[str, object], domain_body["after_sensitive"])
        sensitive["tags"] = True
    elif mutation == "before_password":
        domain_body["before"] = {
            "advanced_security_options": [
                {"master_user_options": [{"master_user_password": "".join(("syn", "thetic"))}]}
            ]
        }
    elif mutation == "markerless_password":
        master["master_user_password"] = "".join(("syn", "thetic"))
        domain_body["after_sensitive"] = {}
    else:
        changes[1]["address"] = "module.other.aws_opensearch_domain.this"

    with pytest.raises(ContractError, match="sensitive"):
        normalize_plan(raw, evaluation_time="2026-09-08T00:00:00Z")


@pytest.mark.parametrize("unknown_key", sorted(POLICY_CRITICAL_UNKNOWN_KEYS))
def test_every_policy_critical_unknown_key_remains_fail_closed(unknown_key: str) -> None:
    change = {
        "actions": ["create"],
        "after": {},
        "after_unknown": {unknown_key: True},
    }
    with pytest.raises(ContractError, match="policy-critical unknown"):
        normalize_plan(plan(change), evaluation_time="2026-09-08T00:00:00Z")


def test_structurally_proven_provider_computed_s3_policy_is_normalized() -> None:
    raw = s3_provider_computed_policy_plan()
    original = deepcopy(raw)

    normalized = normalize_plan(raw, evaluation_time="2026-09-08T00:00:00Z")

    normalized_changes = cast(list[dict[str, object]], normalized["resource_changes"])
    bucket_change = change_body(normalized_changes[0])
    assert bucket_change["after_unknown"] == {"id": True}
    context = cast(dict[str, object], normalized["evaluation_context"])
    assert context["provider_computed_unknowns"] == [
        {
            "address": "aws_s3_bucket.terraform_state",
            "type": "aws_s3_bucket",
            "unknown_paths": ["policy"],
        }
    ]
    assert context["s3_bucket_policy_bindings"] == [
        {
            "bucket_address": "aws_s3_bucket.terraform_state",
            "policy_address": "aws_s3_bucket_policy.terraform_state_tls",
        }
    ]
    assert context["s3_kms_encryption_bindings"] == []
    assert raw == original


def test_structurally_proven_provider_computed_s3_kms_key_is_normalized() -> None:
    raw = s3_provider_computed_kms_plan()
    original = deepcopy(raw)

    normalized = normalize_plan(raw, evaluation_time="2026-09-08T00:00:00Z")

    normalized_changes = cast(list[dict[str, object]], normalized["resource_changes"])
    encryption_change = change_body(normalized_changes[0])
    assert encryption_change["after_unknown"] == {
        "bucket": True,
        "id": True,
        "rule": [
            {
                "apply_server_side_encryption_by_default": [{}],
                "blocked_encryption_types": True,
            }
        ],
    }
    context = cast(dict[str, object], normalized["evaluation_context"])
    assert context["provider_computed_unknowns"] == [
        {
            "address": ("aws_s3_bucket_server_side_encryption_configuration.terraform_state"),
            "type": "aws_s3_bucket_server_side_encryption_configuration",
            "unknown_paths": ["rule[].apply_server_side_encryption_by_default[].kms_master_key_id"],
        }
    ]
    assert context["s3_bucket_policy_bindings"] == []
    assert context["s3_kms_encryption_bindings"] == [
        {
            "bucket_address": "aws_s3_bucket.terraform_state",
            "encryption_address": (
                "aws_s3_bucket_server_side_encryption_configuration.terraform_state"
            ),
            "kms_key_address": "aws_kms_key.terraform_state",
            "field_path": ("rule[].apply_server_side_encryption_by_default[].kms_master_key_id"),
        }
    ]
    assert raw == original


def test_provider_computed_s3_kms_key_requires_exact_unique_relationship() -> None:
    cases = []

    missing = s3_provider_computed_kms_plan()
    configured_resources(missing).pop(1)
    resource_changes(missing).pop(2)
    cases.append(missing)

    unrelated = s3_provider_computed_kms_plan()
    encryption_configuration = configured_resources(unrelated)[2]
    expressions = cast(dict[str, object], encryption_configuration["expressions"])
    kms_expression = cast(
        dict[str, object],
        cast(
            list[dict[str, object]],
            cast(list[dict[str, object]], expressions["rule"])[0][
                "apply_server_side_encryption_by_default"
            ],
        )[0]["kms_master_key_id"],
    )
    kms_expression["references"] = ["aws_kms_key.other.arn"]
    cases.append(unrelated)

    ambiguous = s3_provider_computed_kms_plan()
    configured_resources(ambiguous).append(
        {
            "address": "aws_kms_key.other",
            "mode": "managed",
            "type": "aws_kms_key",
            "expressions": {"policy": {"constant_value": "{}"}},
        }
    )
    resource_changes(ambiguous).append(
        {
            "address": "aws_kms_key.other",
            "type": "aws_kms_key",
            "change": {
                "actions": ["create"],
                "after": {"policy": "{}"},
                "after_unknown": {},
                "after_sensitive": {},
            },
        }
    )
    ambiguous_configuration = configured_resources(ambiguous)[2]
    ambiguous_expressions = cast(dict[str, object], ambiguous_configuration["expressions"])
    ambiguous_defaults = cast(
        list[dict[str, object]],
        cast(list[dict[str, object]], ambiguous_expressions["rule"])[0][
            "apply_server_side_encryption_by_default"
        ],
    )[0]
    ambiguous_kms_expression = cast(dict[str, object], ambiguous_defaults["kms_master_key_id"])
    ambiguous_kms_expression["references"] = [
        "aws_kms_key.terraform_state.arn",
        "aws_kms_key.other.arn",
    ]
    cases.append(ambiguous)

    sensitive = s3_provider_computed_kms_plan()
    sensitive_kms_change = change_body(resource_changes(sensitive)[2])
    sensitive_kms_change["after_sensitive"] = {"policy": True}
    cases.append(sensitive)

    wrong_algorithm = s3_provider_computed_kms_plan()
    wrong_encryption_change = change_body(resource_changes(wrong_algorithm)[0])
    wrong_after = cast(dict[str, object], wrong_encryption_change["after"])
    wrong_rule = cast(list[dict[str, object]], wrong_after["rule"])[0]
    wrong_defaults = cast(
        list[dict[str, object]],
        wrong_rule["apply_server_side_encryption_by_default"],
    )[0]
    wrong_defaults["sse_algorithm"] = "AES256"
    cases.append(wrong_algorithm)

    for raw in cases:
        with pytest.raises(ContractError, match="policy-critical unknown"):
            normalize_plan(raw, evaluation_time="2026-09-08T00:00:00Z")


def test_provider_computed_s3_policy_requires_exact_known_companion() -> None:
    cases = []

    missing = s3_provider_computed_policy_plan()
    configured_resources(missing).pop()
    resource_changes(missing).pop()
    cases.append(missing)

    unrelated = s3_provider_computed_policy_plan()
    companion_configuration = configured_resources(unrelated)[1]
    expressions = cast(dict[str, object], companion_configuration["expressions"])
    bucket_expression = cast(dict[str, object], expressions["bucket"])
    bucket_expression["references"] = ["aws_s3_bucket.other.id"]
    cases.append(unrelated)

    unknown_companion = s3_provider_computed_policy_plan()
    unknown_companion_change = change_body(resource_changes(unknown_companion)[1])
    unknown_companion_after = cast(dict[str, object], unknown_companion_change["after"])
    unknown_companion_after["policy"] = None
    unknown_companion_change["after_unknown"] = {"policy": True}
    cases.append(unknown_companion)

    sensitive_companion = s3_provider_computed_policy_plan()
    sensitive_companion_change = change_body(resource_changes(sensitive_companion)[1])
    sensitive_companion_change["after_sensitive"] = {"policy": True}
    cases.append(sensitive_companion)

    for raw in cases:
        with pytest.raises(ContractError, match="policy-critical unknown"):
            normalize_plan(raw, evaluation_time="2026-09-08T00:00:00Z")


def test_inline_or_additional_policy_critical_unknowns_remain_rejected() -> None:
    inline = s3_provider_computed_policy_plan()
    inline_bucket_configuration = configured_resources(inline)[0]
    inline_expressions = cast(dict[str, object], inline_bucket_configuration["expressions"])
    inline_expressions["policy"] = {"references": ["data.aws_iam_policy_document.inline.json"]}

    additional = s3_provider_computed_policy_plan()
    additional_change = change_body(resource_changes(additional)[0])
    additional_unknowns = cast(dict[str, object], additional_change["after_unknown"])
    additional_unknowns["tags"] = True

    for raw in (inline, additional):
        with pytest.raises(ContractError, match="policy-critical unknown"):
            normalize_plan(raw, evaluation_time="2026-09-08T00:00:00Z")


def test_exact_ecr_kms_and_opensearch_log_references_are_normalized() -> None:
    for raw, relationship, expected_sources in (
        (
            ecr_kms_reference_plan(),
            "platform-ecr-kms-key-reference",
            ["module.kms.aws_kms_key.this"],
        ),
        (
            opensearch_log_reference_plan(),
            "opensearch-log-groups-reference",
            [
                'module.opensearch.aws_cloudwatch_log_group.this["application"]',
                'module.opensearch.aws_cloudwatch_log_group.this["audit"]',
                'module.opensearch.aws_cloudwatch_log_group.this["index_slow"]',
                'module.opensearch.aws_cloudwatch_log_group.this["search_slow"]',
            ],
        ),
    ):
        original = deepcopy(raw)
        normalized = normalize_plan(raw, evaluation_time="2026-09-08T00:00:00Z")
        context = cast(dict[str, object], normalized["evaluation_context"])
        records = cast(list[dict[str, object]], context["resource_reference_unknowns"])

        assert raw == original
        assert len(records) == 1
        assert records[0]["relationship"] == relationship
        assert records[0]["source_addresses"] == expected_sources


def test_ecr_kms_and_opensearch_log_reference_deviations_fail_closed() -> None:
    cases: list[dict[str, object]] = []

    wrong_kms = ecr_kms_reference_plan()
    wrong_configuration = cast(dict[str, object], wrong_kms["configuration"])
    wrong_root = cast(dict[str, object], wrong_configuration["root_module"])
    wrong_calls = cast(dict[str, object], wrong_root["module_calls"])
    wrong_ecr = cast(dict[str, object], wrong_calls["ecr"])
    wrong_ecr_expressions = cast(dict[str, object], wrong_ecr["expressions"])
    wrong_ecr_expressions["kms_key_arn"] = {"references": ["module.other.key_arn"]}
    cases.append(wrong_kms)

    sensitive_kms = ecr_kms_reference_plan()
    change_body(resource_changes(sensitive_kms)[0])["after_sensitive"] = {"arn": True}
    cases.append(sensitive_kms)

    missing_kms = ecr_kms_reference_plan()
    resource_changes(missing_kms).pop(0)
    cases.append(missing_kms)

    duplicate_kms = ecr_kms_reference_plan()
    resource_changes(duplicate_kms).append(deepcopy(resource_changes(duplicate_kms)[0]))
    cases.append(duplicate_kms)

    wrong_kms_type = ecr_kms_reference_plan()
    resource_changes(wrong_kms_type)[0]["type"] = "aws_kms_alias"
    cases.append(wrong_kms_type)

    wrong_kms_action = ecr_kms_reference_plan()
    change_body(resource_changes(wrong_kms_action)[0])["actions"] = ["no-op"]
    cases.append(wrong_kms_action)

    missing_kms_arn_unknown = ecr_kms_reference_plan()
    change_body(resource_changes(missing_kms_arn_unknown)[0])["after_unknown"] = {}
    cases.append(missing_kms_arn_unknown)

    known_kms_arn = ecr_kms_reference_plan()
    change_body(resource_changes(known_kms_arn)[0])["after"] = {"arn": "known"}
    cases.append(known_kms_arn)

    transformed_kms_expression = ecr_kms_reference_plan()
    transformed_kms_configuration = cast(
        dict[str, object], transformed_kms_expression["configuration"]
    )
    transformed_kms_root = cast(dict[str, object], transformed_kms_configuration["root_module"])
    transformed_kms_calls = cast(dict[str, object], transformed_kms_root["module_calls"])
    transformed_ecr_call = cast(dict[str, object], transformed_kms_calls["ecr"])
    transformed_ecr_expressions = cast(dict[str, object], transformed_ecr_call["expressions"])
    transformed_call_expression = cast(
        dict[str, object], transformed_ecr_expressions["kms_key_arn"]
    )
    transformed_call_expression["transformation"] = "replace"
    cases.append(transformed_kms_expression)

    duplicate_ecr_consumer = ecr_kms_reference_plan()
    resource_changes(duplicate_ecr_consumer).append(
        deepcopy(resource_changes(duplicate_ecr_consumer)[1])
    )
    cases.append(duplicate_ecr_consumer)

    extra_ecr_unknown = ecr_kms_reference_plan()
    ecr_body = change_body(resource_changes(extra_ecr_unknown)[1])
    ecr_unknowns = cast(dict[str, object], ecr_body["after_unknown"])
    ecr_unknowns["tags"] = True
    cases.append(extra_ecr_unknown)

    missing_log = opensearch_log_reference_plan()
    missing_configuration = cast(dict[str, object], missing_log["configuration"])
    missing_root = cast(dict[str, object], missing_configuration["root_module"])
    missing_calls = cast(dict[str, object], missing_root["module_calls"])
    missing_module_call = cast(dict[str, object], missing_calls["opensearch"])
    missing_module = cast(dict[str, object], missing_module_call["module"])
    missing_resources = cast(list[dict[str, object]], missing_module["resources"])
    domain_configuration = missing_resources[1]
    domain_expressions = cast(dict[str, object], domain_configuration["expressions"])
    configured_logs = cast(list[dict[str, object]], domain_expressions["log_publishing_options"])
    configured_logs.pop()
    cases.append(missing_log)

    duplicate_log = opensearch_log_reference_plan()
    duplicate_configuration = cast(dict[str, object], duplicate_log["configuration"])
    duplicate_root = cast(dict[str, object], duplicate_configuration["root_module"])
    duplicate_calls = cast(dict[str, object], duplicate_root["module_calls"])
    duplicate_module_call = cast(dict[str, object], duplicate_calls["opensearch"])
    duplicate_module = cast(dict[str, object], duplicate_module_call["module"])
    duplicate_resources = cast(list[dict[str, object]], duplicate_module["resources"])
    duplicate_domain = duplicate_resources[1]
    duplicate_expressions = cast(dict[str, object], duplicate_domain["expressions"])
    duplicate_logs = cast(list[dict[str, object]], duplicate_expressions["log_publishing_options"])
    duplicate_logs[1] = deepcopy(duplicate_logs[0])
    cases.append(duplicate_log)

    sensitive_log_source = opensearch_log_reference_plan()
    change_body(resource_changes(sensitive_log_source)[0])["after_sensitive"] = {"arn": True}
    cases.append(sensitive_log_source)

    missing_log_source = opensearch_log_reference_plan()
    resource_changes(missing_log_source).pop(0)
    cases.append(missing_log_source)

    duplicate_log_source = opensearch_log_reference_plan()
    resource_changes(duplicate_log_source).append(
        deepcopy(resource_changes(duplicate_log_source)[0])
    )
    cases.append(duplicate_log_source)

    wrong_log_source_action = opensearch_log_reference_plan()
    change_body(resource_changes(wrong_log_source_action)[0])["actions"] = ["no-op"]
    cases.append(wrong_log_source_action)

    missing_log_arn_unknown = opensearch_log_reference_plan()
    change_body(resource_changes(missing_log_arn_unknown)[0])["after_unknown"] = {}
    cases.append(missing_log_arn_unknown)

    known_log_arn = opensearch_log_reference_plan()
    change_body(resource_changes(known_log_arn)[0])["after"] = {"arn": "known"}
    cases.append(known_log_arn)

    rewired_log = opensearch_log_reference_plan()
    rewired_configuration = cast(dict[str, object], rewired_log["configuration"])
    rewired_root = cast(dict[str, object], rewired_configuration["root_module"])
    rewired_calls = cast(dict[str, object], rewired_root["module_calls"])
    rewired_call = cast(dict[str, object], rewired_calls["opensearch"])
    rewired_module = cast(dict[str, object], rewired_call["module"])
    rewired_resources = cast(list[dict[str, object]], rewired_module["resources"])
    rewired_domain = rewired_resources[1]
    rewired_expressions = cast(dict[str, object], rewired_domain["expressions"])
    rewired_options = cast(list[dict[str, object]], rewired_expressions["log_publishing_options"])
    rewired_options[0]["cloudwatch_log_group_arn"] = {
        "references": [
            "aws_cloudwatch_log_group.this",
            'aws_cloudwatch_log_group.this["audit"]',
            'aws_cloudwatch_log_group.this["audit"].arn',
        ]
    }
    cases.append(rewired_log)

    transformed_log_expression = opensearch_log_reference_plan()
    transformed_log_configuration = cast(
        dict[str, object], transformed_log_expression["configuration"]
    )
    transformed_log_root = cast(dict[str, object], transformed_log_configuration["root_module"])
    transformed_log_calls = cast(dict[str, object], transformed_log_root["module_calls"])
    transformed_log_call = cast(dict[str, object], transformed_log_calls["opensearch"])
    transformed_log_module = cast(dict[str, object], transformed_log_call["module"])
    transformed_log_resources = cast(list[dict[str, object]], transformed_log_module["resources"])
    transformed_domain = transformed_log_resources[1]
    transformed_domain_expressions = cast(dict[str, object], transformed_domain["expressions"])
    transformed_options = cast(
        list[dict[str, object]], transformed_domain_expressions["log_publishing_options"]
    )
    transformed_arn_expression = cast(
        dict[str, object], transformed_options[0]["cloudwatch_log_group_arn"]
    )
    transformed_arn_expression["transformation"] = "replace"
    cases.append(transformed_log_expression)

    duplicate_log_consumer = opensearch_log_reference_plan()
    resource_changes(duplicate_log_consumer).append(
        deepcopy(resource_changes(duplicate_log_consumer)[-1])
    )
    cases.append(duplicate_log_consumer)

    extra_log_unknown = opensearch_log_reference_plan()
    log_domain_body = change_body(resource_changes(extra_log_unknown)[-1])
    log_unknowns = cast(dict[str, object], log_domain_body["after_unknown"])
    log_unknowns["tags"] = True
    cases.append(extra_log_unknown)

    for raw in cases:
        with pytest.raises(
            ContractError,
            match="policy-critical unknown|sensitive values|addresses must be unique",
        ):
            normalize_plan(raw, evaluation_time="2026-09-08T00:00:00Z")


def test_complete_module_aware_platform_unknown_inventory_is_structurally_normalized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = module_aware_platform_unknown_plan()
    original = deepcopy(raw)
    patch_fixture_policy_expression_hashes(monkeypatch, raw)

    normalized = normalize_plan(raw, evaluation_time="2026-09-08T00:00:00Z")

    context = cast(dict[str, object], normalized["evaluation_context"])
    provider_records = cast(list[dict[str, object]], context["provider_computed_unknowns"])
    reference_records = cast(list[dict[str, object]], context["resource_reference_unknowns"])
    policy_records = cast(list[dict[str, object]], context["policy_document_bindings"])
    removed_pairs = {
        (cast(str, record["address"]), path)
        for record in [*provider_records, *reference_records]
        for path in cast(list[str], record["unknown_paths"])
    }
    removed_pairs.update(
        (cast(str, record["resource_address"]), cast(str, record["field_path"]))
        for record in policy_records
    )
    assert len(removed_pairs) == 67

    critical_removed_pairs = {
        (cast(str, record["address"]), path)
        for record in [*provider_records, *reference_records]
        for path in cast(list[str], record["unknown_paths"])
    }
    critical_removed_pairs.update(
        (cast(str, record["resource_address"]), cast(str, record["field_path"]))
        for record in policy_records
    )

    assert len(critical_removed_pairs) == 67
    assert len({address for address, _ in critical_removed_pairs}) == 33
    assert len(policy_records) == 10
    assert {
        (record["resource_address"], record["field_path"], record["policy_document_address"])
        for record in policy_records
        if record["field_path"] != "policy"
    } == {
        (
            "module.iam.aws_iam_role.runtime",
            "assume_role_policy",
            "module.iam.data.aws_iam_policy_document.runtime_trust",
        ),
        (
            "module.iam.aws_iam_role.ingestion",
            "assume_role_policy",
            "module.iam.data.aws_iam_policy_document.ingestion_trust",
        ),
        (
            "module.iam.aws_iam_role.opensearch_administrator",
            "assume_role_policy",
            "module.iam.data.aws_iam_policy_document.administrator_trust",
        ),
        (
            "module.iam.aws_iam_role.github_oidc",
            "assume_role_policy",
            "module.iam.data.aws_iam_policy_document.github_trust",
        ),
        (
            "module.opensearch.aws_opensearch_domain.this",
            "access_policies",
            "module.opensearch.data.aws_iam_policy_document.domain_access",
        ),
        (
            "module.opensearch.aws_cloudwatch_log_resource_policy.opensearch",
            "policy_document",
            "module.opensearch.data.aws_iam_policy_document.log_delivery",
        ),
    }
    assert context["provider_computed_unknowns"] == sorted(
        provider_records,
        key=lambda record: (
            cast(str, record["address"]),
            cast(str, record["type"]),
            ",".join(cast(list[str], record["unknown_paths"])),
        ),
    )
    assert context["resource_reference_unknowns"] == sorted(
        reference_records,
        key=lambda record: (
            cast(str, record["address"]),
            cast(str, record["relationship"]),
            ",".join(cast(list[str], record["unknown_paths"])),
            ",".join(cast(list[str], record["source_addresses"])),
        ),
    )
    assert raw == original


def test_module_aware_unknown_relationships_fail_closed_when_structural_proof_changes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    approved = module_aware_platform_unknown_plan()
    patch_fixture_policy_expression_hashes(monkeypatch, approved)
    cases: list[dict[str, object]] = []

    missing_source = module_aware_platform_unknown_plan()
    missing_configuration = cast(dict[str, object], missing_source["configuration"])
    missing_root = cast(dict[str, object], missing_configuration["root_module"])
    missing_calls = cast(dict[str, object], missing_root["module_calls"])
    missing_network_call = cast(dict[str, object], missing_calls["network"])
    missing_network = cast(dict[str, object], missing_network_call["module"])
    missing_network_resources = cast(list[dict[str, object]], missing_network["resources"])
    missing_network_resources[:] = [
        resource for resource in missing_network_resources if resource["address"] != "aws_vpc.this"
    ]
    cases.append(missing_source)

    cross_kms = module_aware_platform_unknown_plan()
    cross_configuration = cast(dict[str, object], cross_kms["configuration"])
    cross_root = cast(dict[str, object], cross_configuration["root_module"])
    cross_calls = cast(dict[str, object], cross_root["module_calls"])
    cross_storage_call = cast(dict[str, object], cross_calls["storage"])
    cross_storage_expressions = cast(dict[str, object], cross_storage_call["expressions"])
    cross_storage_expressions["kms_key_arn"] = {"references": ["module.other.key_arn"]}
    cases.append(cross_kms)

    inline_gateway_policy = module_aware_platform_unknown_plan()
    inline_configuration = cast(dict[str, object], inline_gateway_policy["configuration"])
    inline_root = cast(dict[str, object], inline_configuration["root_module"])
    inline_calls = cast(dict[str, object], inline_root["module_calls"])
    inline_network_call = cast(dict[str, object], inline_calls["network"])
    inline_network = cast(dict[str, object], inline_network_call["module"])
    inline_resources = cast(list[dict[str, object]], inline_network["resources"])
    gateway = next(
        resource
        for resource in inline_resources
        if resource["address"] == "aws_vpc_endpoint.gateway"
    )
    gateway_expressions = cast(dict[str, object], gateway["expressions"])
    gateway_expressions["policy"] = {"constant_value": "{}"}
    cases.append(inline_gateway_policy)

    altered_policy = module_aware_platform_unknown_plan()
    altered_configuration = cast(dict[str, object], altered_policy["configuration"])
    altered_root = cast(dict[str, object], altered_configuration["root_module"])
    altered_calls = cast(dict[str, object], altered_root["module_calls"])
    altered_iam_call = cast(dict[str, object], altered_calls["iam"])
    altered_iam = cast(dict[str, object], altered_iam_call["module"])
    altered_resources = cast(list[dict[str, object]], altered_iam["resources"])
    runtime_policy = next(
        resource
        for resource in altered_resources
        if resource["address"] == "data.aws_iam_policy_document.runtime"
    )
    runtime_expressions = cast(dict[str, object], runtime_policy["expressions"])
    runtime_statements = cast(list[dict[str, object]], runtime_expressions["statement"])
    runtime_statements.pop()
    cases.append(altered_policy)

    altered_trust = module_aware_platform_unknown_plan()
    altered_trust_configuration = cast(dict[str, object], altered_trust["configuration"])
    altered_trust_root = cast(dict[str, object], altered_trust_configuration["root_module"])
    altered_trust_calls = cast(dict[str, object], altered_trust_root["module_calls"])
    altered_trust_iam_call = cast(dict[str, object], altered_trust_calls["iam"])
    altered_trust_iam = cast(dict[str, object], altered_trust_iam_call["module"])
    altered_trust_resources = cast(list[dict[str, object]], altered_trust_iam["resources"])
    runtime_trust = next(
        resource
        for resource in altered_trust_resources
        if resource["address"] == "data.aws_iam_policy_document.runtime_trust"
    )
    runtime_trust_expressions = cast(dict[str, object], runtime_trust["expressions"])
    runtime_trust_statements = cast(list[dict[str, object]], runtime_trust_expressions["statement"])
    runtime_trust_statements[0]["sid"] = {"constant_value": "AlteredTrust"}
    cases.append(altered_trust)

    unrelated_trust = module_aware_platform_unknown_plan()
    unrelated_configuration = cast(dict[str, object], unrelated_trust["configuration"])
    unrelated_root = cast(dict[str, object], unrelated_configuration["root_module"])
    unrelated_calls = cast(dict[str, object], unrelated_root["module_calls"])
    unrelated_iam_call = cast(dict[str, object], unrelated_calls["iam"])
    unrelated_iam = cast(dict[str, object], unrelated_iam_call["module"])
    unrelated_resources = cast(list[dict[str, object]], unrelated_iam["resources"])
    runtime_role = next(
        resource
        for resource in unrelated_resources
        if resource["address"] == "aws_iam_role.runtime"
    )
    runtime_role_expressions = cast(dict[str, object], runtime_role["expressions"])
    runtime_role_expressions["assume_role_policy"] = {
        "references": ["data.aws_iam_policy_document.other.json"]
    }
    cases.append(unrelated_trust)

    extra_same_sid = module_aware_platform_unknown_plan()
    extra_configuration = cast(dict[str, object], extra_same_sid["configuration"])
    extra_root = cast(dict[str, object], extra_configuration["root_module"])
    extra_calls = cast(dict[str, object], extra_root["module_calls"])
    extra_iam_call = cast(dict[str, object], extra_calls["iam"])
    extra_iam = cast(dict[str, object], extra_iam_call["module"])
    extra_resources = cast(list[dict[str, object]], extra_iam["resources"])
    extra_runtime_trust = next(
        resource
        for resource in extra_resources
        if resource["address"] == "data.aws_iam_policy_document.runtime_trust"
    )
    extra_expressions = cast(dict[str, object], extra_runtime_trust["expressions"])
    extra_statements = cast(list[dict[str, object]], extra_expressions["statement"])
    extra_statements.append(deepcopy(extra_statements[0]))
    cases.append(extra_same_sid)

    wrong_action = module_aware_platform_unknown_plan()
    wrong_action_document = next(
        resource
        for resource in resource_changes(wrong_action)
        if resource["address"] == "module.iam.data.aws_iam_policy_document.runtime_trust"
    )
    change_body(wrong_action_document)["actions"] = ["create"]
    cases.append(wrong_action)

    sensitive_document = module_aware_platform_unknown_plan()
    sensitive_change = next(
        resource
        for resource in resource_changes(sensitive_document)
        if resource["address"] == "module.iam.data.aws_iam_policy_document.runtime_trust"
    )
    change_body(sensitive_change)["after_sensitive"] = {"json": True}
    cases.append(sensitive_document)

    duplicate_document = module_aware_platform_unknown_plan()
    duplicate_change = next(
        resource
        for resource in resource_changes(duplicate_document)
        if resource["address"] == "module.iam.data.aws_iam_policy_document.runtime_trust"
    )
    resource_changes(duplicate_document).append(deepcopy(duplicate_change))
    cases.append(duplicate_document)

    inconsistent_after = module_aware_platform_unknown_plan()
    inconsistent_role = next(
        resource
        for resource in resource_changes(inconsistent_after)
        if resource["address"] == "module.iam.aws_iam_role.runtime"
    )
    change_body(inconsistent_role)["after"] = {"assume_role_policy": "known-policy-text"}
    cases.append(inconsistent_after)

    altered_parent_input = module_aware_platform_unknown_plan()
    altered_parent_configuration = cast(dict[str, object], altered_parent_input["configuration"])
    altered_parent_root = cast(dict[str, object], altered_parent_configuration["root_module"])
    altered_parent_calls = cast(dict[str, object], altered_parent_root["module_calls"])
    altered_parent_iam = cast(dict[str, object], altered_parent_calls["iam"])
    altered_parent_expressions = cast(dict[str, object], altered_parent_iam["expressions"])
    altered_parent_expressions["runtime_service_account"] = {
        "constant_value": "attacker-selected-service-account"
    }
    cases.append(altered_parent_input)

    altered_resolved_input = module_aware_platform_unknown_plan()
    altered_runtime_trust = next(
        resource
        for resource in resource_changes(altered_resolved_input)
        if resource["address"] == "module.iam.data.aws_iam_policy_document.runtime_trust"
    )
    change_body(altered_runtime_trust)["after"] = {
        "statement": [{"condition": [{"values": ["attacker-selected-service-account"]}]}]
    }
    cases.append(altered_resolved_input)

    for raw in cases:
        with pytest.raises(ContractError):
            normalize_plan(raw, evaluation_time="2026-09-08T00:00:00Z")


def test_complete_native_inventory_rejects_partial_service_coverage() -> None:
    with pytest.raises(ContractError, match="every approved service"):
        CompleteNativeServiceLister({})


@pytest.mark.parametrize("method", ["delete_object", "abort_multipart_upload"])
def test_purge_low_level_method_requires_authority_before_any_client_call(method: str) -> None:
    from tools.platformctl.aws_live import S3PurgeAdapter

    calls: list[str] = []

    class IdentityProbe:
        def verify_identity(self) -> None:
            calls.append("identity")

    def forbidden_client(service: str, region: str) -> object:
        calls.append(service)
        raise AssertionError("No client may be constructed without authority")

    adapter = S3PurgeAdapter(IdentityProbe(), forbidden_client)
    with pytest.raises(ContractError, match="PURGE_LOW_LEVEL_AUTHORITY_REQUIRED"):
        adapter._call(method, {})
    assert calls == []


def test_process_adapter_never_enables_a_command_shell() -> None:
    source = (
        Path(__file__).resolve().parents[2] / "tools/platformctl/process_runner.py"
    ).read_text(encoding="utf-8")
    assert "shell=False" in source
    assert "shell=True" not in source


def test_external_report_collision_never_overwrites(tmp_path: Path) -> None:
    repository = Path(__file__).resolve().parents[2]
    from tools.platformctl.lifecycle_io import reserve_operation_directory

    private_root = tmp_path / "reports"
    reserve_operation_directory(private_root, private_root, repository)
    target = tmp_path / "reports" / "plan.json"
    first_hash = write_canonical_json_atomic(
        target,
        {"status": "PASS"},
        allowed_root=tmp_path,
        repository_root=repository,
    )
    original = target.read_bytes()
    with pytest.raises(ContractError, match="already exists"):
        write_canonical_json_atomic(
            target,
            {"status": "FAIL"},
            allowed_root=tmp_path,
            repository_root=repository,
        )
    assert target.read_bytes() == original
    assert len(first_hash) == 64


def test_infracost_error_output_and_normalized_policy_input_fail_closed() -> None:
    with pytest.raises(ContractError, match="estimation error"):
        parse_infracost_output(
            {
                "currency": "USD",
                "totalMonthlyCost": "0",
                "summary": {
                    "totalDetectedResources": 0,
                    "totalSupportedResources": 0,
                    "totalUnsupportedResources": 0,
                    "totalUsageBasedResources": 0,
                    "totalNoPriceResources": 0,
                },
                "projects": [
                    {
                        "metadata": {"type": "error", "errors": [{"code": 106}]},
                        "summary": {
                            "totalDetectedResources": 0,
                            "totalSupportedResources": 0,
                            "totalUnsupportedResources": 0,
                            "totalUsageBasedResources": 0,
                            "totalNoPriceResources": 0,
                        },
                        "breakdown": {"resources": [], "totalMonthlyCost": "0"},
                    }
                ],
            }
        )

    with pytest.raises(ContractError, match="Terraform show JSON"):
        validate_terraform_plan_json(
            canonical_json_bytes(
                {
                    "evaluation_context": {},
                    "format_version": "1.2",
                    "resource_changes": [],
                    "terraform_version": "1.16.1",
                }
            )
        )


@pytest.mark.parametrize(
    "override",
    [
        {"TF_CLI_CONFIG_FILE": "unapproved.rc"},
        {"CHECKPOINT_DISABLE": "0"},
        {"INFRACOST_DISABLE_ENVFILE": "false"},
        {"INFRACOST_ENABLE_CLOUD_UPLOAD": "true"},
        {"INFRACOST_PRICING_API_ENDPOINT": "https://example.invalid"},
        {"HTTPS_PROXY": "https://example.invalid"},
        {"PATH": "first", "path": "second"},
    ],
)
def test_tool_launch_rejects_owner_setting_overrides_before_dispatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, override: dict[str, str]
) -> None:
    from tools.platformctl.terraform_runner import SubprocessCommandRunner

    calls: list[object] = []

    def forbidden(*args: object, **kwargs: object) -> None:
        calls.append(args)
        pytest.fail("process must not start")

    monkeypatch.setattr(SubprocessCommandRunner, "_capture", staticmethod(forbidden))
    runner = SubprocessCommandRunner()
    for tool, verb in (("terraform", "version"), ("infracost", "--version")):
        with pytest.raises(ContractError, match="CHILD_ENVIRONMENT_NOT_APPROVED"):
            runner.run(
                (str(tmp_path / f"{tool}.exe"), verb),
                cwd=tmp_path,
                environment=override,
                timeout_seconds=10,
            )
    assert calls == []


def test_tool_launch_requires_explicit_isolation_roots(tmp_path: Path) -> None:
    from tools.platformctl.terraform_runner import SubprocessCommandRunner

    with pytest.raises(ContractError, match="TOOL_ISOLATION_ROOTS_REQUIRED"):
        SubprocessCommandRunner().run(
            (str(tmp_path / "infracost.exe"), "--version"),
            cwd=tmp_path,
            environment={},
            timeout_seconds=10,
        )


def test_isolation_retains_unexpected_residue_and_blocks_reuse(tmp_path: Path) -> None:
    from tools.platformctl.lifecycle_io import private_tool_directory

    repository = tmp_path / "repository"
    repository.mkdir()
    external = tmp_path / "external"
    external.mkdir()
    with pytest.raises(ContractError, match="TOOL_ISOLATION_UNEXPECTED_RESIDUE"):
        with private_tool_directory(external, repository) as home:
            unexpected = home / "unexpected.synthetic"
            unexpected.write_bytes(b"synthetic tool residue")
    assert unexpected.read_bytes() == b"synthetic tool residue"
    with pytest.raises(ContractError, match="TOOL_ISOLATION_LEFTOVER_REQUIRES_REVIEW"):
        with private_tool_directory(external, repository):
            pytest.fail("retained launch directory must block another launch")
    assert unexpected.exists()


def test_isolation_rejects_repository_root_before_creating_files(tmp_path: Path) -> None:
    from tools.platformctl.lifecycle_io import private_tool_directory

    with pytest.raises(ContractError, match="inside the repository"):
        with private_tool_directory(tmp_path, tmp_path):
            pytest.fail("repository is not a tool home")
    assert not list(tmp_path.iterdir())


def test_infracost_version_rejects_extra_command_arguments(tmp_path: Path) -> None:
    from tools.platformctl.terraform_runner import SubprocessCommandRunner

    with pytest.raises(ContractError, match="INFRACOST_COMMAND_NOT_EXACT"):
        SubprocessCommandRunner().run(
            (str(tmp_path / "infracost.exe"), "--version", "--config-file", "unapproved.yml"),
            cwd=tmp_path,
            environment={},
            timeout_seconds=10,
        )


def test_private_pricing_output_collision_never_invokes_producer(tmp_path: Path) -> None:
    from tools.platformctl.lifecycle_io import (
        capture_private_tool_json,
        reserve_operation_directory,
    )

    repository = tmp_path / "repository"
    repository.mkdir()
    external = tmp_path / "external"
    reserve_operation_directory(external, external, repository)
    target = external / "existing.json"
    target.write_bytes(b"owner evidence")

    def forbidden(path: Path) -> None:
        pytest.fail("existing output must not reach a tool")

    with pytest.raises(ContractError, match="already exists"):
        capture_private_tool_json(
            target, forbidden, allowed_root=external, repository_root=repository
        )
    assert target.read_bytes() == b"owner evidence"


def test_private_pricing_output_replacement_is_not_read_or_deleted(tmp_path: Path) -> None:
    from tools.platformctl.lifecycle_io import (
        capture_private_tool_json,
        reserve_operation_directory,
    )

    repository = tmp_path / "repository"
    repository.mkdir()
    external = tmp_path / "external"
    reserve_operation_directory(external, external, repository)
    target = external / "output.json"
    displaced = external / "displaced.json"

    def replace_output(path: Path) -> None:
        path.rename(displaced)
        path.write_bytes(b"replacement must be preserved")

    with pytest.raises(ContractError, match="OWNERSHIP_CHANGED"):
        capture_private_tool_json(
            target, replace_output, allowed_root=external, repository_root=repository
        )
    assert target.read_bytes() == b"replacement must be preserved"
    assert displaced.read_bytes() == b""


def test_native_policy_comparison_preserves_semantics_and_input() -> None:
    from copy import deepcopy

    from tools.platformctl.aws_live import diagnostic_policy_digest, native_policy_digest
    from tools.platformctl.lifecycle_io import canonical_json_bytes, sha256_bytes
    from tools.platformctl.policy_runner import policy_semantic_value

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "Exact",
                "Effect": "Allow",
                "Action": ["service:B", "service:A"],
                "Resource": ["exact-b", "exact-a"],
                "Principal": {"AWS": "exact-principal"},
                "Condition": {"StringEquals": {"exact-key": "exact-value"}},
            }
        ],
    }
    original = deepcopy(policy)
    equivalent = deepcopy(policy)
    equivalent["Statement"][0]["Action"].reverse()
    equivalent["Statement"][0]["Resource"].reverse()
    equivalent["Statement"][0]["Principal"]["AWS"] = ["exact-principal"]
    equivalent["Statement"][0]["Condition"]["StringEquals"]["exact-key"] = ["exact-value"]
    assert diagnostic_policy_digest(policy) == diagnostic_policy_digest(equivalent)
    assert native_policy_digest(policy) == sha256_bytes(
        canonical_json_bytes(policy_semantic_value(canonical_json_bytes(policy).decode()))
    )
    assert policy == original
    altered = deepcopy(policy)
    altered["Statement"][0]["Resource"].append("*")
    assert diagnostic_policy_digest(policy) != diagnostic_policy_digest(altered)
    duplicated = deepcopy(policy)
    duplicated["Statement"].append(deepcopy(duplicated["Statement"][0]))
    with pytest.raises(ContractError):
        diagnostic_policy_digest(duplicated)


@pytest.mark.parametrize("change", ["resource", "scan", "rule", "ownership", "group"])
def test_diagnostic_profile_tampering_is_rejected(change: str) -> None:
    import json
    from dataclasses import replace

    from tools.platformctl.aws_inventory import (
        diagnostic_discovery_profile,
        diagnostic_resource_profile,
    )
    from tools.platformctl.lifecycle_io import canonical_json_bytes
    from tools.platformctl.lifecycle_models import (
        DIAGNOSTIC_SCHEMA_VERSION,
        DiagnosticRuntimeConfiguration,
    )
    from tools.platformctl.plan import diagnostic_rules, validate_diagnostic_profiles

    targets = diagnostic_resource_profile("platform")
    scans = diagnostic_discovery_profile()
    configuration = DiagnosticRuntimeConfiguration(
        DIAGNOSTIC_SCHEMA_VERSION,
        (),
        (),
        (),
        (),
        (),
        "",
        "",
        "",
        canonical_json_bytes(targets).decode(),
        canonical_json_bytes(diagnostic_resource_profile("bootstrap")).decode(),
        canonical_json_bytes(scans).decode(),
        diagnostic_rules("platform"),
        diagnostic_rules("bootstrap"),
        None,
        None,
        (),
        None,
    )
    validate_diagnostic_profiles(configuration)
    if change == "scan":
        configuration = replace(
            configuration,
            native_scans_json=canonical_json_bytes(replace(scans, scans=scans.scans[:-1])).decode(),
        )
    elif change == "rule":
        configuration = replace(configuration, platform_rules=configuration.platform_rules[:-1])
    else:
        rows = list(targets.targets)
        if change == "resource":
            rows[0] = replace(rows[0], address="module.other.aws_kms_key.this")
        elif change == "ownership":
            index = next(
                i
                for i, row in enumerate(rows)
                if any(assertion.category == "SOURCE_OWNERSHIP" for assertion in row.assertions)
            )
            rows[index] = replace(rows[index], assertions=rows[index].assertions[1:])
        else:
            index = next(
                i for i, row in enumerate(rows) if "aws_vpc_endpoint.interface" in row.address
            )
            assertion = rows[index].assertions[1]
            fields = json.loads(assertion.expected_fields_json)
            fields["Groups.@unordered"].append({"GroupId": "unapproved-group"})
            rows[index] = replace(
                rows[index],
                assertions=(
                    rows[index].assertions[0],
                    replace(assertion, expected_fields_json=canonical_json_bytes(fields).decode()),
                ),
            )
        configuration = replace(
            configuration,
            native_targets_json=canonical_json_bytes(
                replace(targets, targets=tuple(rows))
            ).decode(),
        )
    with pytest.raises(ContractError, match="DIAGNOSTIC_REVIEWED_"):
        validate_diagnostic_profiles(configuration)


def test_native_kms_identity_formats_do_not_relax_account_boundary() -> None:
    from tools.platformctl.aws_live import _native_field

    arn = "arn:aws:kms:ap-southeast-1:526338061652:key/exact-key"
    assert _native_field({"key": arn}, "key.@kms_identity") == "exact-key"
    assert _native_field({"key": "exact-key"}, "key.@kms_identity") == "exact-key"
    with pytest.raises(ContractError):
        _native_field(
            {"key": "arn:aws:kms:ap-southeast-1:000000000000:key/exact-key"}, "key.@kms_identity"
        )


def test_native_nested_boolean_never_matches_an_integer() -> None:
    import json
    from types import SimpleNamespace
    from typing import cast

    from tools.platformctl.aws_inventory import NativeReadSpec
    from tools.platformctl.aws_live import Boto3AwsInventoryProvider, BoundedNativeReader
    from tools.platformctl.lifecycle_models import Outcome

    provider = cast(Boto3AwsInventoryProvider, SimpleNamespace(verify_identity=lambda: None))
    client = SimpleNamespace(get_bucket_encryption=lambda **_kwargs: {"Rules": [{"Enabled": True}]})
    reader = BoundedNativeReader(provider, lambda _service, _region: client)
    probe = NativeReadSpec(
        "exact",
        "aws_s3_bucket_server_side_encryption_configuration",
        "s3",
        "get_bucket_encryption",
        json.dumps({"Bucket": "exact-bucket", "ExpectedBucketOwner": "526338061652"}),
        "",
        None,
        None,
        1,
        10,
        "exact-bucket",
        "",
    )
    assert (
        reader.inspect(probe, expected_fields={"Rules": [{"Enabled": 1}]}).configuration
        is Outcome.FAIL
    )


@pytest.fixture
def diagnostic_profile_factory(monkeypatch: pytest.MonkeyPatch):
    import os
    from types import SimpleNamespace

    from tools.platformctl import aws_live

    for key in tuple(os.environ):
        if key.upper().startswith("AWS_"):
            monkeypatch.delenv(key)
    original_import = aws_live.importlib.import_module
    session_calls = []
    client_calls = []

    def build(scoped, **overrides):
        def client(*args, **kwargs):
            client_calls.append((args, kwargs))
            raise AssertionError("Profile validation must never create an AWS client")

        def session(**kwargs):
            session_calls.append(kwargs)
            return SimpleNamespace(
                _session=SimpleNamespace(get_scoped_config=lambda: scoped),
                client=client,
            )

        def import_module(name, package=None):
            if name == "boto3":
                return SimpleNamespace(Session=session)
            return original_import(name, package)

        monkeypatch.setattr(aws_live.importlib, "import_module", import_module)
        arguments = {
            "native_lister": None,
            "profile": "default",
            "region": "ap-southeast-1",
            "account_id": "526338061652",
            "caller_arn": "arn:aws:iam::526338061652:user/finopsinfra",
            "diagnostic_only": True,
        }
        arguments.update(overrides)
        return aws_live.Boto3AwsInventoryProvider.from_profile(**arguments)

    return build, session_calls, client_calls


def static_diagnostic_profile() -> dict[str, object]:
    return {
        "aws_access_key_id": "-".join(("synthetic", "access")),
        "aws_secret_access_key": "-".join(("synthetic", "secret")),
        "region": "ap-southeast-1",
    }


@pytest.mark.parametrize("output", [None, "json", "text", "table", "yaml", "yaml-stream"])
def test_diagnostic_profile_accepts_only_display_metadata(
    diagnostic_profile_factory, output
) -> None:
    from copy import deepcopy

    build, session_calls, client_calls = diagnostic_profile_factory
    scoped = static_diagnostic_profile()
    if output is not None:
        scoped["output"] = output
    before = deepcopy(scoped)
    build(scoped)
    assert scoped == before
    assert session_calls == [{"profile_name": "default", "region_name": "ap-southeast-1"}]
    assert client_calls == []


@pytest.mark.parametrize("output", ["", "JSON", "json-stream", "json\n", None, 1, [], {}])
def test_diagnostic_profile_rejects_invalid_display_metadata(
    diagnostic_profile_factory, output
) -> None:
    build, _, client_calls = diagnostic_profile_factory
    scoped = static_diagnostic_profile()
    scoped["output"] = output
    with pytest.raises(ContractError, match="DIAGNOSTIC_STATIC_OWNER_PROFILE_REQUIRED"):
        build(scoped)
    assert client_calls == []


@pytest.mark.parametrize(
    "key",
    [
        "endpoint_url",
        "services",
        "credential_process",
        "role_arn",
        "source_profile",
        "credential_source",
        "web_identity_token_file",
        "sso_session",
        "sso_start_url",
    ],
)
def test_display_metadata_does_not_allow_profile_overrides(
    diagnostic_profile_factory, key: str
) -> None:
    build, _, client_calls = diagnostic_profile_factory
    scoped = static_diagnostic_profile()
    scoped.update(output="json")
    scoped[key] = "not-executed"
    with pytest.raises(ContractError, match="DIAGNOSTIC_STATIC_OWNER_PROFILE_REQUIRED"):
        build(scoped)
    assert client_calls == []


@pytest.mark.parametrize("key", ["aws_access_key_id", "aws_secret_access_key"])
def test_display_metadata_does_not_allow_missing_static_credentials(
    diagnostic_profile_factory, key: str
) -> None:
    build, _, client_calls = diagnostic_profile_factory
    scoped = static_diagnostic_profile()
    scoped["output"] = "json"
    del scoped[key]
    with pytest.raises(ContractError, match="DIAGNOSTIC_STATIC_OWNER_PROFILE_REQUIRED"):
        build(scoped)
    assert client_calls == []


@pytest.mark.parametrize(
    "overrides",
    [
        {"profile": "other"},
        {"region": "us-east-1"},
        {"account_id": "000000000000"},
        {"caller_arn": "arn:aws:iam::526338061652:user/other"},
    ],
)
def test_display_metadata_preserves_profile_identity_boundary(
    diagnostic_profile_factory, overrides
) -> None:
    build, _, client_calls = diagnostic_profile_factory
    scoped = static_diagnostic_profile()
    scoped["output"] = "json"
    with pytest.raises(ContractError):
        build(scoped, **overrides)
    assert client_calls == []


@pytest.mark.parametrize(
    "code,reason",
    [
        ("AccessDeniedException", "NATIVE_ACCESS_DENIED"),
        ("ThrottlingException", "NATIVE_THROTTLED"),
        ("SDK_PARAMETER_VALIDATION_FAILED", "NATIVE_SDK_PARAMETER_VALIDATION_FAILED"),
        ("SDK_TRANSPORT_FAILED", "NATIVE_TRANSPORT_FAILED"),
        ("unreviewed private response", "NATIVE_READ_UNAVAILABLE"),
    ],
)
def test_dynamodb_ownership_failure_is_sanitized_and_does_not_latch(code: str, reason: str) -> None:
    from tools.platformctl.aws_inventory import diagnostic_resource_profile
    from tools.platformctl.aws_live import (
        DiagnosticAwsSession,
        DiagnosticReadError,
        diagnose_native_target,
    )

    from tests.fakes.platform_lifecycle import DiagnosticAwsFixture

    target = next(
        item
        for item in diagnostic_resource_profile("bootstrap").targets
        if item.address == "aws_dynamodb_table.terraform_lock"
    )
    fixture = DiagnosticAwsFixture()
    fixture.responses[("dynamodb", "describe_table")] = [
        {"Table": {"TableName": "enterprise-ai-platform-sandbox-tflock"}}
    ]
    fixture.responses[("dynamodb", "list_tags_of_resource")] = [DiagnosticReadError(code)]
    session = cast(DiagnosticAwsSession, fixture.session())
    result, details = diagnose_native_target(
        session,
        target,
        operation_id="diagnostic-fixture",
        observed_at="2026-09-12T00:00:00Z",
        valid_until="2026-09-12T00:15:00Z",
    )
    assert result is None
    owner = next(row for row in details if row["check"] == "OWNERSHIP")
    assert owner["reason_code"] == reason
    assert owner["service"] == "dynamodb"
    assert owner["method"] == "list_tags_of_resource"
    assert owner["status"] == "INDETERMINATE"
    assert all(
        row["status"] == "BLOCKED_DEPENDENCY" for row in details if row["check"] == "CONFIGURATION"
    )
    assert session.fatal_reason is None
    assert b"unreviewed private response" not in canonical_json_bytes(details)
    session.verify_identity()


def test_native_fatal_routing_failure_is_preserved_and_latched(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from types import SimpleNamespace

    from tools.platformctl.aws_inventory import diagnostic_resource_profile
    from tools.platformctl.aws_live import (
        DiagnosticAwsSession,
        DiagnosticFatalError,
        diagnose_native_target,
    )

    from tests.fakes.platform_lifecycle import DiagnosticAwsFixture

    fixture = DiagnosticAwsFixture()
    session = cast(DiagnosticAwsSession, fixture.session())
    original = session._source._client_factory

    def client(service: str, region: str) -> object:
        result = original(service, region)
        if service == "dynamodb":
            cast(SimpleNamespace, result).meta.endpoint_url = "https://unapproved.invalid"
        return result

    monkeypatch.setattr(session._source, "_client_factory", client)
    target = next(
        item
        for item in diagnostic_resource_profile("bootstrap").targets
        if item.address == "aws_dynamodb_table.terraform_lock"
    )
    result, details = diagnose_native_target(
        session,
        target,
        operation_id="diagnostic-fixture",
        observed_at="2026-09-12T00:00:00Z",
        valid_until="2026-09-12T00:15:00Z",
    )
    assert result is None
    assert details[0]["reason_code"] == "DIAGNOSTIC_ENDPOINT_NOT_APPROVED"
    assert session.fatal_reason == "DIAGNOSTIC_ENDPOINT_NOT_APPROVED"
    calls = len(fixture.calls)
    with pytest.raises(DiagnosticFatalError):
        session.call("ce", "list_cost_allocation_tags", {"TagKeys": ["Project"]})
    assert len(fixture.calls) == calls
    assert b"unapproved.invalid" not in canonical_json_bytes(details)


@pytest.mark.parametrize(
    "actual,expected,path,classification",
    [
        ([{"Status": "Disabled"}], [{"Status": "Enabled"}], "Rules[0].Status", "VALUE_MISMATCH"),
        ([{}], [{"Filter": {}}], "Rules[0].Filter", "MISSING_FIELD"),
        (
            [{"Filter": {"Prefix": "private prefix"}}],
            [{"Filter": {}}],
            "Rules[0].Filter.Prefix",
            "UNEXPECTED_FIELD",
        ),
        (
            [{"AbortIncompleteMultipartUpload": {"DaysAfterInitiation": True}}],
            [{"AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 7}}],
            "Rules[0].AbortIncompleteMultipartUpload.DaysAfterInitiation",
            "TYPE_MISMATCH",
        ),
        (
            [{"private-field-name": "private value"}],
            [{}],
            "Rules[0].<unrecognized-field>",
            "UNEXPECTED_FIELD",
        ),
        (None, [], "Rules", "TYPE_MISMATCH"),
        ([{}, {}], [{}], "Rules", "ITEM_COUNT_MISMATCH"),
    ],
)
def test_lifecycle_mismatch_details_are_paths_not_values(
    actual: object, expected: object, path: str, classification: str
) -> None:
    from tools.platformctl.aws_live import _lifecycle_mismatch_paths

    before = deepcopy((actual, expected))
    result = _lifecycle_mismatch_paths(actual, expected)
    assert (path, classification) in result
    assert b"private" not in canonical_json_bytes(result)
    assert (actual, expected) == before


def test_lifecycle_mismatch_details_bound_depth_size_and_preserve_duplicates() -> None:
    from tools.platformctl.aws_live import _lifecycle_mismatch_paths

    rule = {"ID": "synthetic rule", "Status": "Enabled"}
    assert _lifecycle_mismatch_paths([rule], [rule]) == ()
    assert _lifecycle_mismatch_paths([rule, {}], [{}, rule]) == ()
    assert ("Rules", "ITEM_COUNT_MISMATCH") in _lifecycle_mismatch_paths([rule, rule], [rule])
    result = _lifecycle_mismatch_paths([{"Status": "Disabled"}] * 100, [rule] * 100)
    assert len(result) <= 65
    assert ("Rules", "MISMATCH_DETAIL_LIMIT") in result


def test_lifecycle_native_failure_reports_fields_without_accepting_drift() -> None:
    from dataclasses import replace

    from tools.platformctl.aws_inventory import diagnostic_resource_profile
    from tools.platformctl.aws_live import DiagnosticAwsSession, diagnose_native_target

    from tests.fakes.platform_lifecycle import DiagnosticAwsFixture

    target = next(
        item
        for item in diagnostic_resource_profile("bootstrap").targets
        if item.resource_type == "aws_s3_bucket_lifecycle_configuration"
    )
    target = replace(
        target,
        assertions=(
            replace(target.assertions[0], expected_fields_json='{"TagSet":{"Project":"test"}}'),
            target.assertions[1],
        ),
    )
    rules = [
        {
            "ID": "abort-incomplete-multipart-uploads",
            "Status": "Enabled",
            "Filter": {},
            "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 9},
        }
    ]
    fixture = DiagnosticAwsFixture()
    fixture.responses[("s3", "get_bucket_lifecycle_configuration")] = [
        {"Rules": deepcopy(rules)},
        {"Rules": deepcopy(rules)},
    ]
    fixture.responses[("s3", "get_bucket_tagging")] = [
        {"TagSet": [{"Key": "Project", "Value": "test"}]}
    ]
    session = cast(DiagnosticAwsSession, fixture.session())
    result, details = diagnose_native_target(
        session,
        target,
        operation_id="diagnostic-fixture",
        observed_at="2026-09-12T00:00:00Z",
        valid_until="2026-09-12T00:15:00Z",
    )
    assert result is None
    configuration = next(item for item in details if item["check"] == "CONFIGURATION")
    assert configuration["status"] == "FAIL"
    assert configuration["reason_code"] == "NATIVE_CONFIGURATION_MISMATCH"
    assert configuration["mismatches"] == [
        {
            "path": "Rules[0].AbortIncompleteMultipartUpload.DaysAfterInitiation",
            "classification": "VALUE_MISMATCH",
        }
    ]
    assert b"abort-incomplete-multipart-uploads" not in canonical_json_bytes(details)
    assert session.fatal_reason is None


def test_query_limits_do_not_disable_independent_reads_but_global_limits_do() -> None:
    from tools.platformctl.aws_live import (
        DIAGNOSTIC_LIMITS,
        DiagnosticAwsSession,
        DiagnosticCollectionError,
        DiagnosticFatalError,
    )

    from tests.fakes.platform_lifecycle import DiagnosticAwsFixture

    fixture = DiagnosticAwsFixture()
    fixture.responses[("dynamodb", "list_tables")] = [
        {"TableNames": ["synthetic"] * (DIAGNOSTIC_LIMITS.items_per_query + 1)}
    ]
    session = cast(DiagnosticAwsSession, fixture.session())
    with pytest.raises(DiagnosticCollectionError, match="QUERY_ITEM_LIMIT"):
        session.call("dynamodb", "list_tables", {})
    assert session.fatal_reason is None
    assert session.discovery_items == DIAGNOSTIC_LIMITS.items_per_query + 1
    session.verify_identity()
    with pytest.raises(DiagnosticCollectionError, match="RESPONSE_SIZE_LIMIT"):
        session._response_size({"large": "x" * DIAGNOSTIC_LIMITS.response_bytes})
    assert session.fatal_reason is None
    session.verify_identity()
    session.requests = DIAGNOSTIC_LIMITS.requests
    calls = len(fixture.calls)
    with pytest.raises(DiagnosticFatalError, match="REQUEST_LIMIT"):
        session.verify_identity()
    assert len(fixture.calls) == calls


def test_diagnostic_sdk_validation_error_never_exposes_parameters() -> None:
    from tools.platformctl.aws_live import (
        DiagnosticAwsSession,
        DiagnosticReadError,
        diagnostic_failure_reason,
    )

    from tests.fakes.platform_lifecycle import DiagnosticAwsFixture

    class ParamValidationError(Exception):
        pass

    fixture = DiagnosticAwsFixture()
    fixture.responses[("dynamodb", "list_tables")] = [
        ParamValidationError("private parameter value and service response")
    ]
    session = cast(DiagnosticAwsSession, fixture.session())
    with pytest.raises(DiagnosticReadError) as caught:
        session.call("dynamodb", "list_tables", {})
    assert diagnostic_failure_reason(caught.value) == "NATIVE_SDK_PARAMETER_VALIDATION_FAILED"
    assert "private" not in str(caught.value)
    assert session.fatal_reason is None


@pytest.mark.parametrize(
    "service,method",
    [
        ("sts", "get_caller_identity"),
        ("s3", "head_object"),
        ("s3", "get_object"),
        ("s3", "list_buckets"),
        ("s3", "get_bucket_tagging"),
        ("ec2", "describe_vpc_endpoints"),
        ("ec2", "describe_vpcs"),
        ("ec2", "describe_subnets"),
        ("ec2", "describe_route_tables"),
        ("ec2", "describe_security_groups"),
        ("ec2", "describe_network_interfaces"),
        ("iam", "list_roles"),
        ("iam", "get_role"),
        ("iam", "list_policies"),
        ("iam", "list_policy_tags"),
        ("iam", "list_entities_for_policy"),
        ("kms", "list_keys"),
        ("kms", "describe_key"),
        ("kms", "list_aliases"),
        ("kms", "list_resource_tags"),
        ("cloudtrail", "lookup_events"),
        ("ce", "get_cost_and_usage"),
    ],
)
def test_resolution_production_sdk_request_preparation(offline_dynamodb_sdk, service, method):
    from datetime import UTC, datetime

    run = offline_dynamodb_sdk(intercept_only=True, resolution_only=True)
    arguments = (
        sdk_diagnostic_arguments(service, method)
        if method != "list_entities_for_policy"
        else {"PolicyArn": "arn:aws:iam::526338061652:policy/synthetic"}
    )
    if method == "describe_vpc_endpoints":
        run.session.resolution_endpoints = frozenset(f"vpce-{index:017x}" for index in range(8))
        arguments = {"VpcEndpointIds": sorted(run.session.resolution_endpoints)}
    if method == "list_buckets":
        arguments = {"BucketRegion": "ap-southeast-1"}
    for key in ("RoleName", "PolicyArn", "KeyId", "Bucket"):
        if key in arguments:
            run.session.resolution_candidates[key].add(arguments[key])
    if service == "cloudtrail":
        arguments = {
            "LookupAttributes": [{"AttributeKey": "EventName", "AttributeValue": "CreateLogGroup"}],
            "StartTime": datetime(2026, 9, 10, 7, 42, tzinfo=UTC),
            "EndTime": datetime(2026, 9, 10, 7, 43, tzinfo=UTC),
        }
    if service == "ce":
        arguments["TimePeriod"] = {"Start": "2026-09-08", "End": "2026-09-13"}
    with pytest.raises(OfflineTransportIntercepted):
        run.session.call(service, method, arguments)
    assert run.prepared == run.transported
    assert len(run.transported) == 1
    assert run.session.requests == 1


@pytest.mark.parametrize(
    "case", ["total", "billing", "pages", "time", "resource", "dates", "api", "redirect"]
)
def test_resolution_guards_stop_before_unauthorized_transport(offline_dynamodb_sdk, case):
    from tools.platformctl.aws_live import DiagnosticCollectionError, DiagnosticFatalError

    run = offline_dynamodb_sdk(
        intercept_only=True,
        resolution_only=True,
        destination="https://unapproved.invalid/" if case == "redirect" else None,
    )
    service, method, args = "ec2", "describe_vpcs", {}
    if case == "total":
        run.session.requests = 200
    elif case == "billing":
        run.session.billing_requests = 3
        service, method = "ce", "get_cost_and_usage"
        args = {
            "TimePeriod": {"Start": "2026-09-08", "End": "2026-09-13"},
            "Granularity": "DAILY",
            "Metrics": ["UnblendedCost"],
            "GroupBy": [],
            "Filter": {"Dimensions": {"Key": "LINKED_ACCOUNT", "Values": ["526338061652"]}},
        }
    elif case == "pages":
        for index in range(3):
            with pytest.raises(OfflineTransportIntercepted):
                run.session.call(service, method, {"NextToken": str(index)})
        args = {"NextToken": "four"}
    elif case == "time":
        run.session._monotonic = lambda: 901.0
    elif case == "resource":
        method, args = "describe_vpc_endpoints", {"VpcEndpointIds": ["vpce-unbound"]}
    elif case == "dates":
        service, method = "ce", "get_cost_and_usage"
        args = {"TimePeriod": {"Start": "2026-09-08", "End": "2026-09-14"}}
    elif case == "api":
        service, method = "dynamodb", "list_tables"
    before = len(run.transported)
    with pytest.raises((ContractError, DiagnosticCollectionError, DiagnosticFatalError)):
        run.session.call(service, method, args)
    assert len(run.transported) == before


def test_resolution_policy_comparison_preserves_semantic_differences():
    from copy import deepcopy

    from tools.platformctl.aws_live import resolution_policy_differences

    policy = {
        "Version": "2008-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "*"}
        ],
    }
    representation = deepcopy(policy)
    representation["Statement"][0].update(Sid="display-only", Action=["s3:GetObject"])
    assert (
        resolution_policy_differences(policy, representation)["classification"] == "SEMANTIC_MATCH"
    )
    changed = deepcopy(representation)
    changed["Statement"][0]["Action"] = ["s3:DeleteObject"]
    before = deepcopy(changed)
    result = resolution_policy_differences(policy, changed)
    assert result["classification"] == "SEMANTIC_DIFFERENCE"
    assert any("Action" in row["path"] for row in result["differences"])
    assert "s3:DeleteObject" not in str(result)
    assert changed == before


def test_resolution_limits_retain_specific_safe_reasons_and_partial_results():
    from tools.platformctl.aws_live import (
        DiagnosticCollectionError,
        DiagnosticFatalError,
        diagnostic_failure_reason,
    )

    from tests.fakes.platform_lifecycle import DiagnosticAwsFixture

    fixture = DiagnosticAwsFixture()
    fixture.responses[("ec2", "describe_vpcs")] = [
        {"Vpcs": [{"VpcId": f"vpc-synthetic-{index}", "Tags": []}], "NextToken": str(index)}
        for index in range(3)
    ]
    result = fixture.session(resolution_only=True).resolution_discovery("EC2_NETWORK", frozenset())
    assert result["enumeration_complete"] is False
    assert result["collection_failure"] == "RESOLUTION_ENUMERATION_PAGE_LIMIT"
    assert len(result["resources"]) == 3
    for reason in (
        "RESOLUTION_ENUMERATION_PAGE_LIMIT",
        "RESOLUTION_PRESERVATION_CAPACITY_RESERVED",
    ):
        assert diagnostic_failure_reason(DiagnosticCollectionError(reason)) == reason
    assert (
        diagnostic_failure_reason(DiagnosticFatalError("RESOLUTION_ROLE_IDENTITY"))
        == "RESOLUTION_ROLE_IDENTITY"
    )
    assert "private value" not in diagnostic_failure_reason(DiagnosticFatalError("private value"))


@pytest.mark.parametrize(
    "shape", ["complete", "empty", "missing_day", "paged", "wrong_day", "duplicate"]
)
def test_resolution_billing_preserves_coverage_uncertainty(shape):
    from tests.fakes.platform_lifecycle import DiagnosticAwsFixture

    days = [
        {
            "TimePeriod": {"Start": f"2026-09-{day:02d}", "End": f"2026-09-{day + 1:02d}"},
            "Estimated": True,
            "Total": {"UnblendedCost": {"Amount": "1.00", "Unit": "USD"}},
        }
        for day in range(8, 13)
    ]
    if shape == "empty":
        days = []
    elif shape == "missing_day":
        days.pop()
    elif shape == "wrong_day":
        days[0]["TimePeriod"] = {"Start": "2026-09-13", "End": "2026-09-14"}
    elif shape == "duplicate":
        days.append(days[0])
    response = {"ResultsByTime": days}
    if shape == "paged":
        response["NextPageToken"] = "synthetic-more"
    fixture = DiagnosticAwsFixture()
    fixture.responses[("ce", "get_cost_and_usage")] = [response]
    session = fixture.session(resolution_only=True)
    if shape in {"wrong_day", "duplicate"}:
        with pytest.raises(ContractError, match="BILLING_INTERVAL_INVALID"):
            session.resolution_billing("account")
    else:
        result = session.resolution_billing("account")
        assert result["complete"] is (shape == "complete")
        assert result["w5_incurred_usd"] is None and result["headroom_usd"] is None
    assert session.billing_requests == 1


@pytest.mark.parametrize("tagged", [False, True])
def test_resolution_individual_discovery_unknown_is_not_orphan(tagged):
    from tools.platformctl.contracts import stable_cleanup_tags

    from tests.fakes.platform_lifecycle import DiagnosticAwsFixture

    fixture = DiagnosticAwsFixture()
    tags = [{"Key": key, "Value": value} for key, value in stable_cleanup_tags("sandbox").items()]
    fixture.responses[("ec2", "describe_vpcs")] = [
        {"Vpcs": [{"VpcId": "vpc-synthetic", "Tags": tags if tagged else []}]}
    ]
    result = fixture.session(resolution_only=True).resolution_discovery("EC2_NETWORK", frozenset())
    assert result["enumeration_complete"] is True
    assert result["resources"][0]["classification"] == (
        "PROJECT_OWNED_RESIDUAL" if tagged else "INSUFFICIENT_OWNERSHIP_EVIDENCE"
    )
    assert result["unknown_is_orphan"] is False


def test_correction_identity_refresh_cannot_spend_preservation_reserve(offline_dynamodb_sdk):
    from tools.platformctl.aws_live import DiagnosticCollectionError

    wire = (
        b'<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">'
        b"<GetCallerIdentityResult><Account>526338061652</Account><UserId>synthetic</UserId>"
        b"<Arn>arn:aws:iam::526338061652:user/finopsinfra</Arn></GetCallerIdentityResult>"
        b"</GetCallerIdentityResponse>"
    )
    run = offline_dynamodb_sdk(
        resolution_only=True,
        prerequisite=True,
        prerequisite_correction=True,
        wire_response=lambda *_: wire,
    )
    run.session.requests = 31
    run.session._last_identity = None
    with pytest.raises(DiagnosticCollectionError, match="RESERVED"):
        run.session.call("iam", "get_user", {"UserName": "finopsinfra"})
    assert run.session.requests == 32
    assert len(run.transported) == 1


def test_followup_protected_identity_producer_matches_current_governance():
    from hashlib import sha256
    from pathlib import Path

    from tools.platformctl.plan import DIAGNOSTIC_PROTECTED_IDENTITIES

    repository = Path(__file__).resolve().parents[2]
    for name, expected in DIAGNOSTIC_PROTECTED_IDENTITIES:
        assert sha256((repository / name).read_bytes()).hexdigest() == expected, name


class OfflineTransportIntercepted(BaseException):
    """Stop after real serialization/signing/routing and the production destination guard."""


def test_resolution_cli_dispatch_uses_production_sdk_and_bound_input_producer(
    offline_dynamodb_sdk,
    monkeypatch,
    tmp_path,
):
    from types import SimpleNamespace

    from tools.platformctl import cli
    from tools.platformctl import plan as plan_module
    from tools.platformctl.aws_inventory import RESOLUTION_EVIDENCE_SHA256

    run = offline_dynamodb_sdk(intercept_only=True, resolution_only=True)
    observed = []

    def inputs(repository, external, source, *, resolution_only=False, followup=False):
        assert resolution_only is True
        assert followup is False
        assert source == "a" * 64
        observed.append("verified-local-inputs")
        return SimpleNamespace(), {"synthetic": True}, None

    def dispatch(self, command, payload):
        assert command == "aws-verify" and payload == b'{"synthetic":true}\n'
        assert self.runtime_identity is None and self.session.resolution_only is True
        observed.append("coordinator-dispatch")
        self.session.call("sts", "get_caller_identity", {})
        raise AssertionError("Transport must have been intercepted")

    monkeypatch.setattr(plan_module, "_build_owner_diagnostic_inputs", inputs)
    monkeypatch.setattr(plan_module.RepositoryDiagnosticCoordinator, "execute_request", dispatch)
    monkeypatch.setattr(
        cli,
        "load_lifecycle_config",
        lambda _path: {"external_paths": {"temporary_root": str(tmp_path)}},
    )
    with pytest.raises(OfflineTransportIntercepted):
        cli.main(
            [
                "aws-verify",
                "--environment",
                "sandbox",
                "--target",
                "platform",
                "--diagnostic",
                "--resolution",
                "--execute",
                "--source-sha256",
                "a" * 64,
                "--evidence-sha256",
                RESOLUTION_EVIDENCE_SHA256,
            ]
        )
    assert observed == ["verified-local-inputs", "coordinator-dispatch"]
    assert run.prepared == run.transported and len(run.transported) == 1


@pytest.fixture
def offline_dynamodb_sdk(monkeypatch: pytest.MonkeyPatch):
    """Use installed SDK serialization/signing/routing; intercept only HTTP transport."""
    import os
    import socket
    from types import SimpleNamespace

    import boto3
    import botocore.configloader
    import botocore.credentials
    import botocore.httpsession
    import botocore.session
    from botocore.awsrequest import AWSResponse
    from tools.platformctl.aws_live import Boto3AwsInventoryProvider, DiagnosticAwsSession

    def forbidden(*_args, **_kwargs):
        raise AssertionError(
            "Offline SDK reproduction must not discover credentials or use network"
        )

    for key in tuple(os.environ):
        if key.upper().startswith("AWS_"):
            monkeypatch.delenv(key)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(botocore.httpsession.URLLib3Session, "send", forbidden)
    monkeypatch.setattr(botocore.configloader, "load_config", forbidden)
    monkeypatch.setattr(botocore.configloader, "raw_config_parse", forbidden)
    monkeypatch.setattr(botocore.credentials.CredentialResolver, "load_credentials", forbidden)

    def build(
        *,
        diagnostic_only=True,
        destination=None,
        http_status=200,
        credential_account="526338061652",
        intercept_only=False,
        resolution_only=False,
        resolution_followup=False,
        prerequisite=False,
        prerequisite_correction=False,
        wire_response=None,
    ):
        core = botocore.session.Session()
        scoped = static_diagnostic_profile()
        core._config = {"profiles": {"default": scoped}, "sso_sessions": {}, "services": {}}
        core.set_config_variable("region", "ap-southeast-1")
        core.set_credentials(
            scoped["aws_access_key_id"],
            scoped["aws_secret_access_key"],
            account_id=credential_account,
        )
        sdk_session = boto3.session.Session(botocore_session=core)
        original_client = sdk_session.client
        clients = {}
        prepared = []
        transported = []

        def client(service, **kwargs):
            if service in clients:
                return clients[service]
            result = original_client(service, **kwargs)
            clients[service] = result

            def observe(request, **_kwargs):
                if destination is not None:
                    request.url = destination
                prepared.append(request.url)

            def send(request):
                # Reached only after the production before-send guard has inspected the URL.
                transported.append(request.url)
                if intercept_only:
                    raise OfflineTransportIntercepted
                headers = {"content-type": "application/x-amz-json-1.0"}
                if http_status == 307:
                    headers["location"] = "https://unapproved.invalid/"
                response = AWSResponse(request.url, http_status, headers, None)
                response._content = (
                    wire_response(service, request) if wire_response else b'{"Tags":[]}'
                )
                return response

            result.meta.events.register_first("before-send.*.*", observe)
            monkeypatch.setattr(result._endpoint.http_session, "send", send)
            return result

        monkeypatch.setattr(sdk_session, "client", client)
        monkeypatch.setattr(boto3, "Session", lambda **_kwargs: sdk_session)
        provider = Boto3AwsInventoryProvider.from_profile(
            native_lister=None,
            profile="default",
            region="ap-southeast-1",
            account_id="526338061652",
            caller_arn="arn:aws:iam::526338061652:user/finopsinfra",
            diagnostic_only=diagnostic_only,
        )
        session = DiagnosticAwsSession(
            provider,
            monotonic=lambda: 0.0,
            resolution_only=resolution_only,
            resolution_followup=resolution_followup,
            prerequisite=prerequisite,
            prerequisite_correction=prerequisite_correction,
        )
        # Isolate the actual tag operation: identity is synthetic, never obtained from STS.
        session._last_identity = 0.0
        return SimpleNamespace(
            provider=provider,
            session=session,
            clients=clients,
            prepared=prepared,
            transported=transported,
        )

    return build


def iam_simulation_xml(action, arns, *, change="none"):
    from xml.sax.saxutils import escape

    children = []
    for index, arn in enumerate(arns):
        if change == "missing" and index == 3:
            continue
        decision = "explicitDeny" if change == "mixed" and index == 2 else "allowed"
        missing = (
            "<MissingContextValues><member>aws:RequestTag/ExpiresAt</member></MissingContextValues>"
            if change == "context"
            else ""
        )
        children.append(
            f"<member><EvalResourceName>{escape(arn)}</EvalResourceName><EvalResourceDecision>{decision}</EvalResourceDecision>{missing}</member>"
        )
    if change == "duplicate":
        children.append(children[0])
    aggregate = "explicitDeny" if change == "mixed" else "allowed"
    return (
        f'<SimulatePrincipalPolicyResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">'
        f"<SimulatePrincipalPolicyResult><EvaluationResults><member><EvalActionName>{action}</EvalActionName>"
        f"<EvalResourceName>*</EvalResourceName><EvalDecision>{aggregate}</EvalDecision>"
        f"<ResourceSpecificResults>{''.join(children)}</ResourceSpecificResults></member></EvaluationResults>"
        "<IsTruncated>false</IsTruncated></SimulatePrincipalPolicyResult>"
        "<ResponseMetadata><RequestId>synthetic</RequestId></ResponseMetadata></SimulatePrincipalPolicyResponse>"
    ).encode()


@pytest.mark.parametrize(
    "change",
    ["none", "mixed", "context", "missing", "duplicate", "unexpected", "malformed", "incomplete"],
)
def test_correction_sdk_xml_survives_production_transport_and_normalizer(
    offline_dynamodb_sdk, change
):
    from tools.platformctl.aws_inventory import PREREQUISITE_LOG_NAMES
    from tools.platformctl.aws_live import normalize_simulation_results

    action = "logs:CreateLogGroup"
    arns = [
        "arn:aws:logs:ap-southeast-1:526338061652:log-group:" + name + ":*"
        for name in PREREQUISITE_LOG_NAMES
    ]
    run = offline_dynamodb_sdk(
        resolution_only=True,
        prerequisite=True,
        prerequisite_correction=True,
        wire_response=lambda _s, _r: iam_simulation_xml(action, arns, change=change),
    )
    rows, complete = run.session.prerequisite_enumerate(
        "iam",
        "simulate_principal_policy",
        {
            "PolicySourceArn": "arn:aws:iam::526338061652:user/finopsinfra",
            "ActionNames": [action],
            "ResourceArns": arns,
            "MaxItems": 100,
        },
        "EvaluationResults",
    )
    assert len(rows) == 1 and rows[0]["EvalResourceName"] == "*"
    if change == "unexpected":
        rows[0]["ResourceSpecificResults"][0]["EvalResourceName"] = "unexpected"
    elif change == "malformed":
        rows[0]["EvalDecision"] = {"not_reportable": "synthetic-private-value"}
    result = normalize_simulation_results(
        rows, action, arns, complete=complete and change != "incomplete"
    )
    assert len(result["findings"]) == 4
    assert "synthetic-private-value" not in str(result)
    assert result["assessment"] == (
        "ALLOWED" if change == "none" else "DENIED" if change == "mixed" else "INDETERMINATE"
    )
    assert result["live_authorization_guarantee"] is False
    assert len(run.transported) == 1
    if change == "mixed":
        assert [row["decision"] for row in result["findings"]] == [
            "allowed",
            "allowed",
            "explicitDeny",
            "allowed",
        ]
    if change == "context":
        assert result["missing_context"] == ["aws:RequestTag/ExpiresAt"]


def test_correction_sdk_attachment_arrays_survive(offline_dynamodb_sdk):
    xml = (
        b'<ListEntitiesForPolicyResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">'
        b"<ListEntitiesForPolicyResult><PolicyRoles><member><RoleName>example-role</RoleName>"
        b"</member></PolicyRoles><PolicyUsers><member><UserName>example-user</UserName>"
        b"</member></PolicyUsers><PolicyGroups><member><GroupName>example-group</GroupName>"
        b"</member></PolicyGroups><IsTruncated>false</IsTruncated>"
        b"</ListEntitiesForPolicyResult></ListEntitiesForPolicyResponse>"
    )
    run = offline_dynamodb_sdk(
        resolution_only=True,
        prerequisite=True,
        prerequisite_correction=True,
        wire_response=lambda *_: xml,
    )
    rows, complete = run.session.prerequisite_policy_entities("PermissionsPolicy")
    assert complete
    assert rows == [
        {"entity_type": "Role", "name": "example-role"},
        {"entity_type": "User", "name": "example-user"},
        {"entity_type": "Group", "name": "example-group"},
    ]
    assert len(run.transported) == 1


@pytest.mark.parametrize("condition", ["requests", "time", "total", "billing", "unapproved"])
def test_correction_exact_request_limits_before_transport(offline_dynamodb_sdk, condition):
    from tools.platformctl.aws_live import DiagnosticCollectionError, DiagnosticFatalError

    run = offline_dynamodb_sdk(
        resolution_only=True, prerequisite=True, prerequisite_correction=True, intercept_only=True
    )
    assert run.session.limits.requests == 40
    assert run.session.limits.billing_requests == 0
    assert run.session.limits.pages == 3
    assert run.session.limits.elapsed_seconds == 600
    service, method = "sts", "get_caller_identity"
    if condition == "requests":
        run.session.requests = 32
    elif condition == "time":
        run.session._monotonic = lambda: 480
    elif condition == "total":
        run.session.preservation_phase = True
        run.session.requests = 40
    elif condition == "billing":
        service, method = "ce", "get_cost_and_usage"
    else:
        service, method = "iam", "get_role"
    with pytest.raises((DiagnosticCollectionError, DiagnosticFatalError)):
        run.session.call(service, method, {})
    assert run.transported == []


@pytest.mark.parametrize(
    "change", ["equal", "different", "missing", "malformed", "wrong_key", "deposed"]
)
def test_private_kms_accessor_and_comparison(change):
    import json
    from hashlib import sha256

    from tools.platformctl.plan import expected_platform_kms_policy, private_policy_comparison

    key = "arn:aws:kms:ap-southeast-1:526338061652:key/synthetic"
    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "kms:Encrypt", "Resource": "*"}],
    }
    instance = {"attributes": {"arn": key, "policy": json.dumps(policy)}}
    if change == "missing":
        instance["attributes"].pop("policy")
    if change == "malformed":
        instance["attributes"]["policy"] = "{"
    if change == "wrong_key":
        instance["attributes"]["arn"] = "different"
    if change == "deposed":
        instance["deposed"] = "synthetic"
    raw = json.dumps(
        {
            "resources": [
                {
                    "module": "module.kms",
                    "mode": "managed",
                    "type": "aws_kms_key",
                    "name": "this",
                    "instances": [instance],
                }
            ]
        }
    ).encode()
    if change not in {"equal", "different"}:
        with pytest.raises(ContractError):
            expected_platform_kms_policy(raw, sha256(raw).hexdigest(), key)
        return
    expected = expected_platform_kms_policy(raw, sha256(raw).hexdigest(), key)
    native = json.loads(json.dumps(policy))
    if change == "different":
        native["Statement"][0]["Action"] = "kms:Decrypt"
    result = private_policy_comparison(expected, native)
    assert result["equal"] is (change == "equal")
    assert "kms:Decrypt" not in json.dumps(result)


def test_exact_opensearch_log_kms_statement_rejects_the_failed_via_service_shape() -> None:
    from tools.platformctl.aws_inventory import diagnostic_policy_templates
    from tools.platformctl.plan import _has_exact_opensearch_log_kms_statement

    policy = cast(dict[str, object], diagnostic_policy_templates("platform")["kms"])
    assert _has_exact_opensearch_log_kms_statement(policy)
    overconstrained = deepcopy(policy)
    statements = cast(list[dict[str, object]], overconstrained["Statement"])
    statement = next(row for row in statements if row["Sid"] == "AllowExactOpenSearchLogEncryption")
    condition = cast(dict[str, object], statement["Condition"])
    condition["StringEquals"] = {"kms:ViaService": "logs.ap-southeast-1.amazonaws.com"}
    assert not _has_exact_opensearch_log_kms_statement(overconstrained)


@pytest.mark.parametrize("credential_account", [None, "000000000000"])
def test_offline_sdk_tag_query_reproduces_initial_account_host_rejection(
    offline_dynamodb_sdk, credential_account: str | None
) -> None:
    from tools.platformctl.aws_live import DiagnosticFatalError

    run = offline_dynamodb_sdk(diagnostic_only=False, credential_account=credential_account)
    with pytest.raises(DiagnosticFatalError, match="DIAGNOSTIC_INITIAL_HOST_NOT_APPROVED"):
        run.session.call(
            "dynamodb",
            "list_tags_of_resource",
            {"ResourceArn": "arn:aws:dynamodb:ap-southeast-1:526338061652:table/synthetic"},
        )
    assert run.prepared == ["https://526338061652.ddb.ap-southeast-1.amazonaws.com/"]
    assert run.transported == []  # No response existed: this cannot be an HTTP redirect.
    assert run.clients["dynamodb"].meta.config.account_id_endpoint_mode == "preferred"
    assert run.session.fatal_reason == "DIAGNOSTIC_INITIAL_HOST_NOT_APPROVED"


def prerequisite_sdk_cases():
    from tools.platformctl.aws_inventory import (
        PREREQUISITE_LOG_ACTIONS,
        PREREQUISITE_LOG_NAMES,
        PREREQUISITE_POLICY,
        PREREQUISITE_ROLES,
        PREREQUISITE_ROUTES,
    )

    owner = "526338061652"
    caller = "arn:aws:iam::526338061652:user/finopsinfra"
    bucket = "enterprise-ai-platform-sbx-tfstate-526338061652-ap-southeast-1"
    state = {"Bucket": bucket, "Key": "sandbox/platform.tfstate", "ExpectedBucketOwner": owner}
    cases = [
        ("sts", "get_caller_identity", {}),
        ("s3", "head_object", state),
        ("s3", "get_object", {**state, "IfMatch": "synthetic"}),
        (
            "s3",
            "list_object_versions",
            {"Bucket": bucket, "ExpectedBucketOwner": owner, "MaxKeys": 1000},
        ),
        (
            "s3",
            "list_multipart_uploads",
            {"Bucket": bucket, "ExpectedBucketOwner": owner, "MaxUploads": 1000},
        ),
        (
            "s3",
            "list_parts",
            {
                "Bucket": bucket,
                "ExpectedBucketOwner": owner,
                "Key": "fixture",
                "UploadId": "fixture",
                "MaxParts": 1000,
            },
        ),
        ("ec2", "describe_route_tables", {"RouteTableIds": list(PREREQUISITE_ROUTES)}),
        ("iam", "get_role", {"RoleName": PREREQUISITE_ROLES[0]}),
        (
            "iam",
            "list_entities_for_policy",
            {
                "PolicyArn": PREREQUISITE_POLICY,
                "PolicyUsageFilter": "PermissionsPolicy",
                "MaxItems": 100,
            },
        ),
        (
            "iam",
            "list_entities_for_policy",
            {
                "PolicyArn": PREREQUISITE_POLICY,
                "PolicyUsageFilter": "PermissionsBoundary",
                "MaxItems": 100,
            },
        ),
        ("iam", "get_user", {"UserName": "finopsinfra"}),
        ("iam", "get_context_keys_for_principal_policy", {"PolicySourceArn": caller}),
        ("kms", "describe_key", {"KeyId": "arn:aws:kms:ap-southeast-1:526338061652:key/synthetic"}),
        (
            "kms",
            "get_key_policy",
            {
                "KeyId": "arn:aws:kms:ap-southeast-1:526338061652:key/synthetic",
                "PolicyName": "default",
            },
        ),
        ("dynamodb", "describe_table", {"TableName": "synthetic"}),
        (
            "ecr",
            "describe_images",
            {"registryId": owner, "repositoryName": "synthetic", "maxResults": 1000},
        ),
        (
            "ce",
            "get_cost_and_usage",
            {
                "TimePeriod": {"Start": "2026-09-08", "End": "2026-09-13"},
                "Granularity": "DAILY",
                "Metrics": ["UnblendedCost"],
                "Filter": {"Dimensions": {"Key": "LINKED_ACCOUNT", "Values": [owner]}},
                "GroupBy": [
                    {"Type": "DIMENSION", "Key": "SERVICE"},
                    {"Type": "DIMENSION", "Key": "RECORD_TYPE"},
                ],
            },
        ),
    ]
    for action in PREREQUISITE_LOG_ACTIONS:
        cases.append(
            (
                "iam",
                "simulate_principal_policy",
                {
                    "PolicySourceArn": caller,
                    "ActionNames": [action],
                    "ResourceArns": [
                        "arn:aws:logs:ap-southeast-1:526338061652:log-group:"
                        + name
                        + ("" if action == "logs:TagResource" else ":*")
                        for name in PREREQUISITE_LOG_NAMES
                    ],
                    "MaxItems": 100,
                },
            )
        )
    return cases


def seed_prerequisite_session(run):
    bucket = "enterprise-ai-platform-sbx-tfstate-526338061652-ap-southeast-1"
    run.session.prerequisite_targets = {
        "bootstrap_bucket": bucket,
        "platform_bucket": "synthetic-platform-bucket",
        "ecr": "synthetic",
        "dynamodb": "synthetic",
        "kms": "arn:aws:kms:ap-southeast-1:526338061652:key/synthetic",
    }
    run.session.prerequisite_state_conditions = {"IfMatch": "synthetic"}
    run.session.prerequisite_uploads.add((bucket, "fixture", "fixture"))


@pytest.mark.parametrize(("service", "method", "arguments"), prerequisite_sdk_cases())
def test_prerequisite_production_sdk_request_path(offline_dynamodb_sdk, service, method, arguments):
    from urllib.parse import urlsplit

    from tools.platformctl.aws_live import _DIAGNOSTIC_ENDPOINTS

    run = offline_dynamodb_sdk(resolution_only=True, prerequisite=True, intercept_only=True)
    seed_prerequisite_session(run)
    with pytest.raises(OfflineTransportIntercepted):
        run.session.call(service, method, deepcopy(arguments))
    assert len(run.transported) == 1
    assert run.transported == run.prepared
    approved = {_DIAGNOSTIC_ENDPOINTS[service][1]}
    if service == "s3":
        approved.add(arguments["Bucket"] + ".s3.ap-southeast-1.amazonaws.com")
    assert urlsplit(run.transported[0]).hostname in approved


@pytest.mark.parametrize(("service", "method", "arguments"), prerequisite_sdk_cases())
def test_prerequisite_rejects_extra_arguments_before_transport(
    offline_dynamodb_sdk, service, method, arguments
):
    from tools.platformctl.aws_live import DiagnosticFatalError

    run = offline_dynamodb_sdk(resolution_only=True, prerequisite=True, intercept_only=True)
    seed_prerequisite_session(run)
    with pytest.raises(DiagnosticFatalError, match="EXACT_ARGUMENTS"):
        run.session.call(service, method, {**arguments, "unapproved": True})
    assert run.transported == []


@pytest.mark.parametrize("method", ["list_roles", "create_role", "lookup_events", "put_object"])
def test_prerequisite_rejects_unapproved_methods(offline_dynamodb_sdk, method):
    from tools.platformctl.aws_live import DiagnosticFatalError

    run = offline_dynamodb_sdk(resolution_only=True, prerequisite=True)
    with pytest.raises(DiagnosticFatalError, match="API_NOT_APPROVED"):
        run.session.call("iam", method, {})
    assert run.transported == []


def test_prerequisite_enforces_reserved_capacity_and_deadline(offline_dynamodb_sdk):
    from tools.platformctl.aws_live import DiagnosticCollectionError, DiagnosticFatalError

    run = offline_dynamodb_sdk(resolution_only=True, prerequisite=True)
    assert run.session.limits.requests == 80
    assert run.session.limits.billing_requests == 3
    assert run.session.limits.pages == 3
    assert run.session.limits.elapsed_seconds == 600
    run.session.requests = 72
    with pytest.raises(DiagnosticCollectionError, match="RESERVED"):
        run.session.call("sts", "get_caller_identity", {})
    run.session.preservation_phase = True
    run.session.requests = 80
    with pytest.raises(DiagnosticFatalError, match="REQUEST_LIMIT"):
        run.session.call("sts", "get_caller_identity", {})
    run = offline_dynamodb_sdk(resolution_only=True, prerequisite=True)
    run.session._monotonic = lambda: 480
    with pytest.raises(DiagnosticCollectionError, match="RESERVED"):
        run.session.call("sts", "get_caller_identity", {})
    run.session.preservation_phase = True
    run.session._monotonic = lambda: 600
    with pytest.raises(DiagnosticFatalError, match="TIME_LIMIT"):
        run.session.call("sts", "get_caller_identity", {})


def test_prerequisite_rejects_unissued_pagination(offline_dynamodb_sdk):
    from tools.platformctl.aws_live import DiagnosticFatalError

    run = offline_dynamodb_sdk(resolution_only=True, prerequisite=True)
    seed_prerequisite_session(run)
    with pytest.raises(DiagnosticFatalError, match="PAGINATION_NOT_ISSUED"):
        run.session.call(
            "ecr",
            "describe_images",
            {
                "registryId": "526338061652",
                "repositoryName": "synthetic",
                "maxResults": 1000,
                "nextToken": "fabricated",
            },
        )
    assert run.transported == []


def test_offline_sdk_diagnostic_tag_query_uses_exact_regional_endpoint(
    offline_dynamodb_sdk,
) -> None:
    run = offline_dynamodb_sdk()
    result = run.session.call(
        "dynamodb",
        "list_tags_of_resource",
        {"ResourceArn": "arn:aws:dynamodb:ap-southeast-1:526338061652:table/synthetic"},
    )
    assert result["Tags"] == []
    assert run.prepared == run.transported == ["https://dynamodb.ap-southeast-1.amazonaws.com/"]
    assert run.clients["dynamodb"].meta.config.account_id_endpoint_mode == "disabled"
    assert run.clients["dynamodb"].meta.config.retries["total_max_attempts"] == 1
    assert run.session.fatal_reason is None
    other = run.provider._client_factory("logs", "ap-southeast-1")
    assert other.meta.config.account_id_endpoint_mode == "preferred"


@pytest.mark.parametrize(
    "destination",
    [
        "https://unapproved.invalid/",
        "http://dynamodb.ap-southeast-1.amazonaws.com/",
        "https://dynamodb.us-west-2.amazonaws.com/",
        "https://dynamodb.ap-southeast-1.amazonaws.com.unapproved.invalid/",
        "https://526338061652.ddb.ap-southeast-1.amazonaws.com/",
    ],
)
def test_offline_sdk_diagnostic_guard_rejects_prepared_unauthorized_destination(
    offline_dynamodb_sdk, destination: str
) -> None:
    from tools.platformctl.aws_live import DiagnosticFatalError

    run = offline_dynamodb_sdk(destination=destination)
    with pytest.raises(DiagnosticFatalError, match="DIAGNOSTIC_INITIAL_HOST_NOT_APPROVED"):
        run.session.call(
            "dynamodb",
            "list_tags_of_resource",
            {"ResourceArn": "arn:aws:dynamodb:ap-southeast-1:526338061652:table/synthetic"},
        )
    assert run.prepared == [destination]
    assert run.transported == []
    with pytest.raises(DiagnosticFatalError, match="DIAGNOSTIC_INITIAL_HOST_NOT_APPROVED"):
        run.session.checkpoint()


def test_offline_sdk_http_redirect_is_not_initial_host_rejection(offline_dynamodb_sdk) -> None:
    from tools.platformctl.aws_live import DiagnosticFatalError

    run = offline_dynamodb_sdk(http_status=307)
    with pytest.raises(DiagnosticFatalError, match="DIAGNOSTIC_HTTP_REDIRECT_NOT_APPROVED"):
        run.session.call(
            "dynamodb",
            "list_tags_of_resource",
            {"ResourceArn": "arn:aws:dynamodb:ap-southeast-1:526338061652:table/synthetic"},
        )
    assert run.prepared == run.transported == ["https://dynamodb.ap-southeast-1.amazonaws.com/"]
    assert run.session.fatal_reason == "DIAGNOSTIC_HTTP_REDIRECT_NOT_APPROVED"


@pytest.mark.parametrize(
    ("change", "accepted"),
    [
        ({}, True),
        ({"Filter": {}}, True),
        ({"Filter": {"Prefix": "private/"}}, False),
        ({"Filter": {"Prefix": None}}, False),
        ({"Filter": {"Prefix": 0}}, False),
        ({"Filter": {"Prefix": []}}, False),
        ({"Filter": {"Prefix": "", "Tag": {"Key": "x", "Value": "y"}}}, False),
        ({"Filter": {"Prefix": "", "ObjectSizeGreaterThan": 0}}, False),
        ({"Filter": {"And": {"Prefix": ""}}}, False),
        ({"Filter": None}, False),
        ({"ID": "different-rule"}, False),
        ({"Status": "Disabled"}, False),
        ({"AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 8}}, False),
        ({"AbortIncompleteMultipartUpload": {"DaysAfterInitiation": True}}, False),
        ({"Expiration": {"Days": 7}}, False),
        ({"Prefix": ""}, False),
    ],
)
def test_lifecycle_empty_prefix_semantics_preserve_all_other_controls(change, accepted) -> None:
    import json
    from types import SimpleNamespace

    from tools.platformctl.aws_inventory import diagnostic_resource_profile
    from tools.platformctl.aws_live import Boto3AwsInventoryProvider, BoundedNativeReader
    from tools.platformctl.lifecycle_models import Outcome

    target = next(
        row
        for row in diagnostic_resource_profile("bootstrap").targets
        if row.resource_type == "aws_s3_bucket_lifecycle_configuration"
    )
    assertion = target.assertions[1]
    expected = json.loads(assertion.expected_fields_json)
    rule = {**deepcopy(expected["Rules.@unordered"][0]), "Filter": {"Prefix": ""}, **change}
    response = {"Rules": [rule]}
    before = deepcopy(response)
    provider = cast(Boto3AwsInventoryProvider, SimpleNamespace(verify_identity=lambda: None))
    client = SimpleNamespace(get_bucket_lifecycle_configuration=lambda **_kwargs: response)
    reader = BoundedNativeReader(provider, lambda *_args: client, diagnostic_details=True)
    result = reader.inspect(assertion.probe, expected_fields=expected)
    assert result.configuration is (Outcome.PASS if accepted else Outcome.FAIL)
    assert bool(result.mismatches) is not accepted
    assert response == before
    if not change:
        strict = BoundedNativeReader(provider, lambda *_args: client)
        assert (
            strict.inspect(assertion.probe, expected_fields=expected).configuration is Outcome.FAIL
        )


@pytest.mark.parametrize("alteration", ["address", "type", "expected", "duplicate", "missing"])
def test_lifecycle_empty_prefix_normalization_is_exactly_bounded(alteration: str) -> None:
    import json
    from dataclasses import replace

    from tools.platformctl.aws_inventory import diagnostic_resource_profile
    from tools.platformctl.aws_live import _diagnostic_lifecycle_comparison_item

    target = next(
        row
        for row in diagnostic_resource_profile("bootstrap").targets
        if row.resource_type == "aws_s3_bucket_lifecycle_configuration"
    )
    assertion = target.assertions[1]
    spec = assertion.probe
    expected = json.loads(assertion.expected_fields_json)
    rule = {**deepcopy(expected["Rules.@unordered"][0]), "Filter": {"Prefix": ""}}
    item = {"Rules": [rule]}
    if alteration == "address":
        spec = replace(spec, address="module.storage.aws_s3_bucket_lifecycle_configuration.this")
    elif alteration == "type":
        spec = replace(spec, resource_type="aws_s3_bucket")
    elif alteration == "expected":
        expected["Rules.@unordered"][0]["AbortIncompleteMultipartUpload"]["DaysAfterInitiation"] = 8
    elif alteration == "duplicate":
        item["Rules"].append(deepcopy(rule))
    else:
        del rule["Filter"]
    before = deepcopy(item)
    assert _diagnostic_lifecycle_comparison_item(spec, item, expected) is item
    assert item == before


# Independent, exhaustive diagnostic operation inventory. A new production permission
# must fail this coverage assertion until its actual SDK preparation is also reviewed.
@pytest.mark.parametrize("service", ["s3", "dynamodb"])
def test_offline_sdk_http_redirect_stops_before_sdk_followup(offline_dynamodb_sdk, service):
    from tools.platformctl.aws_live import DiagnosticFatalError

    run = offline_dynamodb_sdk(http_status=307)
    method = "get_bucket_tagging" if service == "s3" else "list_tags_of_resource"
    with pytest.raises(DiagnosticFatalError, match="DIAGNOSTIC_HTTP_REDIRECT_NOT_APPROVED"):
        run.session.call(service, method, sdk_diagnostic_arguments(service, method))
    assert len(run.transported) == 1
    assert run.session.fatal_reason == "DIAGNOSTIC_HTTP_REDIRECT_NOT_APPROVED"


@pytest.mark.parametrize("version", ["2008-10-17", "2012-10-17"])
@pytest.mark.parametrize("principal", ["*", {"AWS": "*"}, {"AWS": ["*"]}])
def test_diagnostic_default_endpoint_policy_equivalence_is_exact(version, principal):
    import json
    from copy import deepcopy

    from tools.platformctl.aws_live import (
        _diagnostic_endpoint_comparison_item,
        diagnostic_policy_digest,
    )

    policy = {
        "Version": "2008-10-17",
        "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "*", "Resource": "*"}],
    }
    expected = {"PolicyDocument.@diagnostic_policy_sha256": diagnostic_policy_digest(policy)}
    actual = deepcopy(policy)
    actual["Version"] = version
    actual["Statement"][0]["Principal"] = principal
    actual["Statement"][0]["Action"] = ["*"]
    item = {"PolicyDocument": json.dumps(actual)}
    original = deepcopy(item)
    compared = _diagnostic_endpoint_comparison_item(item, expected)
    assert diagnostic_policy_digest(compared["PolicyDocument"]) == next(iter(expected.values()))
    assert item == original


@pytest.mark.parametrize(
    "change",
    [
        {"Effect": "Deny"},
        {"Principal": {"AWS": "arn:aws:iam::526338061652:root"}},
        {"Principal": {"Service": "ec2.amazonaws.com"}},
        {"Action": "s3:GetObject"},
        {"Resource": "arn:aws:s3:::synthetic/*"},
        {"Condition": {"Bool": {"aws:SecureTransport": "true"}}},
        {"Sid": "PreservedIdentifier"},
        {"NotAction": "s3:DeleteObject"},
    ],
)
def test_diagnostic_endpoint_equivalence_does_not_hide_policy_changes(change):
    import json
    from copy import deepcopy

    from tools.platformctl.aws_live import (
        _diagnostic_endpoint_comparison_item,
        diagnostic_policy_digest,
    )

    policy = {
        "Version": "2008-10-17",
        "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "*", "Resource": "*"}],
    }
    expected = {"PolicyDocument.@diagnostic_policy_sha256": diagnostic_policy_digest(policy)}
    actual = deepcopy(policy)
    actual["Statement"][0].update(change)
    item = {"PolicyDocument": json.dumps(actual)}
    assert _diagnostic_endpoint_comparison_item(item, expected) is item


@pytest.mark.parametrize("region", [None, "eu-west-1", "ap-southeast-1", 1])
def test_diagnostic_s3_discovery_never_reads_an_unverified_regional_bucket(region):
    from dataclasses import replace

    from tools.platformctl.aws_inventory import diagnostic_discovery_profile
    from tools.platformctl.aws_live import discover_diagnostic_scan

    from tests.fakes.platform_lifecycle import DiagnosticAwsFixture

    fixture = DiagnosticAwsFixture()
    bucket = {"Name": "synthetic-unattributed-bucket"}
    if region is not None:
        bucket["BucketRegion"] = region
    fixture.responses[("s3", "list_buckets")] = [{"Buckets": [bucket]}]
    fixture.responses[("s3", "get_bucket_tagging")] = [{"TagSet": []}]
    session = fixture.session()
    profile = diagnostic_discovery_profile()
    bundle = replace(profile, scans=tuple(scan for scan in profile.scans if scan.coverage == "S3"))
    if region == "eu-west-1":
        assert discover_diagnostic_scan(session.provider, session.client, bundle) == ()
    else:
        reason = (
            "BUCKET_REGION_UNVERIFIED"
            if region is None
            else "UNTAGGED_RESOURCE_OWNERSHIP_UNCLASSIFIED"
            if region == "ap-southeast-1"
            else "BUCKET_REGION_MALFORMED"
        )
        with pytest.raises(ContractError, match=reason):
            discover_diagnostic_scan(session.provider, session.client, bundle)
    tag_calls = [call for call in fixture.calls if call[1] == "get_bucket_tagging"]
    assert len(tag_calls) == (1 if region == "ap-southeast-1" else 0)
    assert session.fatal_reason is None


def test_diagnostic_s3_discovery_preserves_fatal_redirect_and_blocks_remote_checks():
    from dataclasses import replace

    from tools.platformctl.aws_inventory import diagnostic_discovery_profile
    from tools.platformctl.aws_live import DiagnosticFatalError, discover_diagnostic_scan
    from tools.platformctl.lifecycle_models import DiagnosticStatus
    from tools.platformctl.plan import DiagnosticChecks

    from tests.fakes.platform_lifecycle import DiagnosticAwsFixture, FrozenClock

    fixture = DiagnosticAwsFixture()
    fixture.responses[("s3", "list_buckets")] = [
        {"Buckets": [{"Name": "synthetic-bucket", "BucketRegion": "ap-southeast-1"}]}
    ]
    fixture.responses[("s3", "get_bucket_tagging")] = [
        DiagnosticFatalError("DIAGNOSTIC_HTTP_REDIRECT_NOT_APPROVED")
    ]
    session = fixture.session()
    profile = diagnostic_discovery_profile()
    bundle = replace(profile, scans=tuple(scan for scan in profile.scans if scan.coverage == "S3"))
    checks = DiagnosticChecks(FrozenClock(), session)

    def collect():
        discover_diagnostic_scan(session.provider, session.client, bundle)
        raise AssertionError("Fatal routing error was swallowed")

    checks.run("s3", collect, remote=True)
    checks.run("billing", collect, remote=True)
    assert checks.checks[0].status is DiagnosticStatus.FAIL
    assert checks.checks[0].reason_code == "DIAGNOSTIC_HTTP_REDIRECT_NOT_APPROVED"
    assert checks.checks[1].status is DiagnosticStatus.BLOCKED


@pytest.mark.parametrize(
    ("coverage", "method", "result", "identity"),
    [
        ("EC2_NETWORK", "describe_vpcs", "Vpcs", {"VpcId": "vpc-synthetic"}),
        ("EC2_SUBNETS", "describe_subnets", "Subnets", {"SubnetId": "subnet-synthetic"}),
        (
            "EC2_SECURITY_GROUPS",
            "describe_security_groups",
            "SecurityGroups",
            {"GroupId": "sg-synthetic"},
        ),
    ],
)
def test_diagnostic_discovery_missing_tags_is_specific_and_nonfatal(
    coverage, method, result, identity
):
    from dataclasses import replace

    from tools.platformctl.aws_inventory import diagnostic_discovery_profile
    from tools.platformctl.aws_live import discover_diagnostic_scan

    from tests.fakes.platform_lifecycle import DiagnosticAwsFixture

    fixture = DiagnosticAwsFixture()
    fixture.responses[("ec2", method)] = [{result: [identity]}]
    session = fixture.session()
    profile = diagnostic_discovery_profile()
    bundle = replace(profile, scans=tuple(s for s in profile.scans if s.coverage == coverage))
    with pytest.raises(ContractError, match="NATIVE_DISCOVERY_OWNERSHIP_TAGS_UNAVAILABLE"):
        discover_diagnostic_scan(session.provider, session.client, bundle)
    assert session.fatal_reason is None
    session.verify_identity()


def test_diagnostic_discovery_foreign_identity_stops_all_remote_collection():
    from dataclasses import replace

    from tools.platformctl.aws_inventory import diagnostic_discovery_profile
    from tools.platformctl.aws_live import DiagnosticFatalError, discover_diagnostic_scan

    from tests.fakes.platform_lifecycle import DiagnosticAwsFixture

    fixture = DiagnosticAwsFixture()
    fixture.responses[("iam", "list_roles")] = [{"Roles": [{"RoleName": "synthetic"}]}]
    fixture.responses[("iam", "get_role")] = [
        {"Role": {"Arn": "arn:aws:iam::000000000000:role/synthetic", "Tags": []}}
    ]
    session = fixture.session()
    profile = diagnostic_discovery_profile()
    bundle = replace(profile, scans=tuple(s for s in profile.scans if s.coverage == "IAM_ROLES"))
    with pytest.raises(DiagnosticFatalError, match="DIAGNOSTIC_NATIVE_IDENTITY_OR_ROUTING"):
        discover_diagnostic_scan(session.provider, session.client, bundle)
    count = len(fixture.calls)
    with pytest.raises(DiagnosticFatalError):
        session.verify_identity()
    assert len(fixture.calls) == count


SDK_DIAGNOSTIC_OPERATIONS = {
    "ec2": "describe_vpcs describe_subnets describe_route_tables describe_security_groups "
    "describe_vpc_endpoints describe_network_interfaces describe_volumes describe_addresses",
    "logs": "describe_log_groups describe_resource_policies list_tags_for_resource",
    "cloudwatch": "describe_alarms list_tags_for_resource",
    "opensearch": "describe_domain list_domain_names list_tags",
    "kms": "describe_key list_keys list_aliases list_resource_tags get_key_rotation_status "
    "get_key_policy",
    "iam": "get_role get_role_policy get_policy get_policy_version list_roles list_policies "
    "list_role_tags list_policy_tags list_attached_role_policies list_role_policies get_user "
    "list_attached_user_policies list_user_policies get_user_policy list_groups_for_user "
    "list_attached_group_policies list_group_policies get_group_policy simulate_principal_policy",
    "ecr": "describe_repositories list_tags_for_resource get_lifecycle_policy",
    "s3": "head_bucket list_buckets get_bucket_location get_bucket_tagging get_public_access_block "
    "get_bucket_encryption get_bucket_versioning get_bucket_policy_status get_bucket_policy "
    "get_bucket_ownership_controls get_bucket_lifecycle_configuration head_object get_object",
    "dynamodb": "describe_table list_tables describe_continuous_backups list_tags_of_resource",
    "secretsmanager": "describe_secret list_secrets",  # pragma: allowlist secret
    "eks": "describe_cluster list_clusters list_nodegroups describe_nodegroup",
    "elbv2": "describe_load_balancers describe_target_groups describe_tags",
    "resourcegroupstaggingapi": "get_resources",
    "lambda": "list_functions list_tags",
    "glue": "get_jobs get_tags",
    "stepfunctions": "list_state_machines list_tags_for_resource",
    "events": "list_rules list_tags_for_resource",
    "ce": "get_cost_and_usage list_cost_allocation_tags",
    "cloudtrail": "lookup_events",
    "sts": "get_caller_identity",
}
SDK_DIAGNOSTIC_HOSTS = {
    "ec2": "ec2.ap-southeast-1.amazonaws.com",
    "logs": "logs.ap-southeast-1.amazonaws.com",
    "cloudwatch": "monitoring.ap-southeast-1.amazonaws.com",
    "opensearch": "es.ap-southeast-1.amazonaws.com",
    "kms": "kms.ap-southeast-1.amazonaws.com",
    "iam": "iam.amazonaws.com",
    "ecr": "api.ecr.ap-southeast-1.amazonaws.com",
    "s3": "s3.ap-southeast-1.amazonaws.com",
    "dynamodb": "dynamodb.ap-southeast-1.amazonaws.com",
    "secretsmanager": "secretsmanager.ap-southeast-1.amazonaws.com",  # pragma: allowlist secret
    "eks": "eks.ap-southeast-1.amazonaws.com",
    "elbv2": "elasticloadbalancing.ap-southeast-1.amazonaws.com",
    "resourcegroupstaggingapi": "tagging.ap-southeast-1.amazonaws.com",
    "lambda": "lambda.ap-southeast-1.amazonaws.com",
    "glue": "glue.ap-southeast-1.amazonaws.com",
    "stepfunctions": "states.ap-southeast-1.amazonaws.com",
    "events": "events.ap-southeast-1.amazonaws.com",
    "ce": "ce.us-east-1.amazonaws.com",
    "cloudtrail": "cloudtrail.ap-southeast-1.amazonaws.com",
    "sts": "sts.ap-southeast-1.amazonaws.com",
}


def sdk_diagnostic_arguments(service: str, method: str) -> dict[str, object]:
    """Synthetic inputs for each permitted operation, including routing-sensitive IDs."""
    from datetime import UTC, datetime

    account, region = "526338061652", "ap-southeast-1"
    arn = f"arn:aws:{service}:{region}:{account}:synthetic"
    if service == "s3" and method != "list_buckets":
        values = {
            "Bucket": "enterprise-ai-platform-sbx-tfstate-526338061652-ap-southeast-1",
            "ExpectedBucketOwner": account,
        }
        if method in {"head_object", "get_object"}:
            values["Key"] = "sandbox/platform.tfstate"
        return values
    if service == "kms" and method not in {"list_keys", "list_aliases"}:
        return {"KeyId": f"arn:aws:kms:{region}:{account}:key/synthetic"}
    if service == "dynamodb":
        if method == "list_tags_of_resource":
            return {"ResourceArn": f"arn:aws:dynamodb:{region}:{account}:table/synthetic"}
        if method != "list_tables":
            return {"TableName": "synthetic"}
    if service == "ecr":
        if method == "list_tags_for_resource":
            return {"resourceArn": f"arn:aws:ecr:{region}:{account}:repository/synthetic"}
        return {
            "registryId": account,
            "repositoryName" if method == "get_lifecycle_policy" else "repositoryNames": (
                "synthetic" if method == "get_lifecycle_policy" else ["synthetic"]
            ),
        }
    if service == "iam":
        if method == "simulate_principal_policy":
            return {
                "PolicySourceArn": f"arn:aws:iam::{account}:user/finopsinfra",
                "ActionNames": ["logs:TagResource"],
                "ResourceArns": [f"arn:aws:logs:{region}:{account}:log-group:synthetic"],
            }
        if method == "list_policies":
            return {"Scope": "Local"}
        if method in {"get_policy", "get_policy_version", "list_policy_tags"}:
            values = {"PolicyArn": f"arn:aws:iam::{account}:policy/synthetic"}
            if method == "get_policy_version":
                values["VersionId"] = "v1"
            return values
        if method == "list_roles":
            return {}
        field = (
            "GroupName"
            if "group" in method and method != "list_groups_for_user"
            else ("RoleName" if "role" in method else "UserName")
        )
        values = {field: "finopsinfra" if field == "UserName" else "synthetic"}
        if method in {"get_role_policy", "get_user_policy", "get_group_policy"}:
            values["PolicyName"] = "synthetic"
        return values
    if service == "opensearch":
        if method == "describe_domain":
            return {"DomainName": "synthetic"}
        if method == "list_tags":
            return {"ARN": f"arn:aws:es:{region}:{account}:domain/synthetic"}
    tag_fields = {
        "logs": "resourceArn",
        "cloudwatch": "ResourceARN",
        "lambda": "Resource",
        "glue": "ResourceArn",
        "stepfunctions": "resourceArn",
        "events": "ResourceARN",
    }
    if method in {"list_tags_for_resource", "list_tags", "get_tags"} and service in tag_fields:
        return {tag_fields[service]: arn}
    if service == "secretsmanager" and method == "describe_secret":
        return {"SecretId": arn}
    if service == "eks" and method != "list_clusters":
        values = {"name" if method == "describe_cluster" else "clusterName": "synthetic"}
        if method == "describe_nodegroup":
            values["nodegroupName"] = "synthetic"
        return values
    if service == "elbv2" and method == "describe_tags":
        return {"ResourceArns": [f"arn:aws:elasticloadbalancing:{region}:{account}:synthetic"]}
    if service == "cloudtrail":
        return {
            "LookupAttributes": [{"AttributeKey": "EventName", "AttributeValue": "CreateGrant"}],
            "StartTime": datetime(2026, 9, 10, 7, 40, tzinfo=UTC),
            "EndTime": datetime(2026, 9, 10, 8, 40, tzinfo=UTC),
        }
    if service == "ce":
        if method == "list_cost_allocation_tags":
            return {"TagKeys": ["Project"]}
        return {
            "Filter": {"Dimensions": {"Key": "LINKED_ACCOUNT", "Values": [account]}},
            "TimePeriod": {"Start": "2026-09-08", "End": "2026-09-12"},
            "Granularity": "DAILY",
            "Metrics": ["UnblendedCost"],
            "GroupBy": [{"Type": "DIMENSION", "Key": "SERVICE"}],
        }
    return {}


def test_offline_sdk_matrix_covers_entire_permitted_inventory() -> None:
    from tools.platformctl.aws_live import _DIAGNOSTIC_ENDPOINTS, _DIAGNOSTIC_METHODS

    matrix = {
        service: frozenset(methods.split())
        for service, methods in SDK_DIAGNOSTIC_OPERATIONS.items()
    }
    assert matrix == _DIAGNOSTIC_METHODS
    assert set(matrix) == set(SDK_DIAGNOSTIC_HOSTS) == set(_DIAGNOSTIC_ENDPOINTS)
    assert len(matrix) == 20
    assert sum(map(len, matrix.values())) == 83


@pytest.mark.parametrize(
    ("service", "method"),
    [
        (service, method)
        for service, methods in SDK_DIAGNOSTIC_OPERATIONS.items()
        for method in methods.split()
    ],
)
def test_offline_sdk_every_diagnostic_operation_prepares_approved_destination(
    offline_dynamodb_sdk, service: str, method: str
) -> None:
    from urllib.parse import urlsplit

    run = offline_dynamodb_sdk(intercept_only=True)
    run.session._caller_groups.add("synthetic")
    run.session._billing_end = "2026-09-12"
    arguments = sdk_diagnostic_arguments(service, method)
    if method == "simulate_principal_policy":
        run.session._simulation_targets["logs:TagResource"] = tuple(arguments["ResourceArns"])
    with pytest.raises(OfflineTransportIntercepted):
        run.session.call(service, method, arguments)
    host = SDK_DIAGNOSTIC_HOSTS[service]
    # Botocore forces path-style addressing specifically for GetBucketLocation.
    if service == "s3" and "Bucket" in arguments and method != "get_bucket_location":
        host = str(arguments["Bucket"]) + "." + host
    assert len(run.transported) == 1
    assert run.prepared == run.transported
    prepared_url = urlsplit(run.transported[0])
    assert prepared_url.hostname == host
    if service == "s3" and method == "get_bucket_location":
        assert prepared_url.path == f"/{arguments['Bucket']}"
        assert prepared_url.query == "location"
    assert run.session.fatal_reason is None


@pytest.mark.parametrize("service", list(SDK_DIAGNOSTIC_OPERATIONS))
def test_offline_sdk_each_service_blocks_unapproved_prepared_destination(
    offline_dynamodb_sdk, service: str
) -> None:
    from tools.platformctl.aws_live import DiagnosticFatalError

    run = offline_dynamodb_sdk(intercept_only=True, destination="https://unapproved.invalid/")
    method = SDK_DIAGNOSTIC_OPERATIONS[service].split()[0]
    run.session._billing_end = "2026-09-12"
    with pytest.raises(DiagnosticFatalError, match="DIAGNOSTIC_INITIAL_HOST_NOT_APPROVED"):
        run.session.call(service, method, sdk_diagnostic_arguments(service, method))
    assert not run.transported
    assert run.session.fatal_reason == "DIAGNOSTIC_INITIAL_HOST_NOT_APPROVED"


@pytest.mark.parametrize("bucket", ["synthetic-bucket", "synthetic.bucket"])
def test_offline_sdk_s3_bucket_routing_is_exact_not_suffix_based(
    offline_dynamodb_sdk, bucket
) -> None:
    from urllib.parse import urlsplit

    run = offline_dynamodb_sdk(intercept_only=True)
    with pytest.raises(OfflineTransportIntercepted):
        run.session.call(
            "s3", "head_bucket", {"Bucket": bucket, "ExpectedBucketOwner": "526338061652"}
        )
    host = "s3.ap-southeast-1.amazonaws.com"
    assert urlsplit(run.transported[0]).hostname == (host if "." in bucket else bucket + "." + host)


@pytest.mark.parametrize("scope", ["bootstrap", "platform"])
@pytest.mark.parametrize(
    "change", ["empty", "nonempty", "malformed", "missing", "action", "predicate", "duplicate"]
)
def test_offline_both_lifecycle_consumers_preserve_exact_rule_semantics(scope, change) -> None:
    import json
    from types import SimpleNamespace

    from tools.platformctl.aws_inventory import diagnostic_resource_profile
    from tools.platformctl.aws_live import BoundedNativeReader, native_unordered_value
    from tools.platformctl.lifecycle_models import Outcome

    target = next(
        row
        for row in diagnostic_resource_profile(scope).targets
        if row.resource_type == "aws_s3_bucket_lifecycle_configuration"
    )
    assertion = next(row for row in target.assertions if row.category == "CONFIGURATION")
    expected = json.loads(assertion.expected_fields_json)
    rules = deepcopy(expected["Rules.@unordered"])
    first = rules[0]
    first["Filter"] = {"Prefix": ""}
    if change == "nonempty":
        first["Filter"] = {"Prefix": "do-not-record-this/"}
    elif change == "malformed":
        first["Filter"] = {"Prefix": 17}
    elif change == "missing":
        del first["Filter"]
    elif change == "action":
        first["AbortIncompleteMultipartUpload"]["DaysAfterInitiation"] = 8
    elif change == "predicate":
        first["Filter"]["ObjectSizeGreaterThan"] = 1
    elif change == "duplicate":
        rules.append(deepcopy(first))
    response = {"Rules": rules}
    before = deepcopy(response)
    expected["Rules.@unordered"] = native_unordered_value(expected["Rules.@unordered"])
    provider = SimpleNamespace(verify_identity=lambda: None)
    client = SimpleNamespace(get_bucket_lifecycle_configuration=lambda **_kwargs: response)
    result = BoundedNativeReader(provider, lambda *_args: client, diagnostic_details=True).inspect(
        assertion.probe, expected_fields=expected
    )
    assert result.configuration is (Outcome.PASS if change == "empty" else Outcome.FAIL)
    assert response == before
    assert "do-not-record-this" not in repr(result)
    assert result.comparison_notes
    if scope == "platform":
        assert rules[1]["Filter"] == {"Prefix": "tmp/"}
        assert rules[2]["Filter"] == {"Prefix": "test/"}


@pytest.mark.parametrize(
    "endpoint",
    [
        "Bedrock Runtime",
        "CloudWatch Logs",
        "ECR API",
        "ECR DKR",
        "EKS",
        "KMS",
        "STS",
        "Secrets Manager",
    ],
)
@pytest.mark.parametrize(
    "change",
    [
        "none",
        "order",
        "missing",
        "type",
        "subnet",
        "group",
        "group_missing",
        "dns",
        "policy",
        "owner",
    ],
)
def test_all_eight_interface_endpoint_comparisons_are_sanitized(endpoint, change) -> None:
    import json
    from types import SimpleNamespace

    from tools.platformctl.aws_inventory import diagnostic_resource_profile
    from tools.platformctl.aws_live import (
        BoundedNativeReader,
        diagnostic_policy_digest,
        native_unordered_value,
    )
    from tools.platformctl.lifecycle_models import Outcome

    target = next(
        row
        for row in diagnostic_resource_profile("platform").targets
        if row.address == f'module.network.aws_vpc_endpoint.interface["{endpoint}"]'
    )
    assertion = next(row for row in target.assertions if row.category == "CONFIGURATION")
    expected = json.loads(assertion.expected_fields_json)
    item = {path.split(".")[0]: deepcopy(value) for path, value in expected.items()}
    item["VpcEndpointId"] = assertion.probe.expected_native_identity
    for path, value in expected.items():
        if path.endswith(".@diagnostic_policy_sha256"):
            expected[path] = diagnostic_policy_digest(value)
        elif path.endswith(".@unordered"):
            expected[path] = native_unordered_value(value)
    if change == "order":
        item["SubnetIds"] = list(reversed(expected["SubnetIds.@unordered"]))
    elif change == "missing":
        del item["PrivateDnsEnabled"]
    elif change == "type":
        item["PrivateDnsEnabled"] = 1
    elif change == "subnet":
        item["SubnetIds"][0] = "private-native-value-never-report"
    elif change == "group":
        item["Groups"][0]["GroupId"] = "private-native-value-never-report"
    elif change == "group_missing":
        del item["Groups"][0]["GroupName"]
    elif change == "dns":
        item["PrivateDnsEnabled"] = False
    elif change == "policy":
        item["PolicyDocument"]["Statement"][0]["Action"] = "s3:GetObject"
    elif change == "owner":
        item["VpcId"] = "different-vpc"
    before = deepcopy(item)
    provider = SimpleNamespace(verify_identity=lambda: None)
    client = SimpleNamespace(describe_vpc_endpoints=lambda **_kwargs: {"VpcEndpoints": [item]})
    result = BoundedNativeReader(provider, lambda *_args: client, diagnostic_details=True).inspect(
        assertion.probe, expected_fields=expected
    )
    assert result.configuration is (Outcome.PASS if change in {"none", "order"} else Outcome.FAIL)
    assert bool(result.mismatches) is (change not in {"none", "order"})
    if change == "order":
        assert ("SubnetIds", "ORDERING_DIFFERENCE_EQUIVALENT") in result.comparison_notes
    if change == "missing":
        assert ("PrivateDnsEnabled", "MISSING_FIELD") in result.mismatches
    if change == "type":
        assert ("PrivateDnsEnabled", "TYPE_MISMATCH") in result.mismatches
    if change == "group_missing":
        assert ("Groups[0].GroupName", "MISSING_FIELD") in result.mismatches
    assert "private-native-value-never-report" not in repr(result)
    assert item == before


@pytest.mark.parametrize(
    ("service", "method", "arguments"),
    [
        ("ecr", "describe_repositories", {"registryId": "000000000000"}),
        ("kms", "describe_key", {"KeyId": "arn:aws:kms:us-west-2:526338061652:key/synthetic"}),
        (
            "dynamodb",
            "list_tags_of_resource",
            {"ResourceArn": "arn:aws:dynamodb:ap-southeast-1:000000000000:table/synthetic"},
        ),
        ("s3", "head_bucket", {"Bucket": "synthetic", "ExpectedBucketOwner": "000000000000"}),
    ],
)
def test_offline_sdk_account_and_region_overrides_stop_before_transport(
    offline_dynamodb_sdk, service, method, arguments
) -> None:
    from tools.platformctl.aws_live import DiagnosticFatalError

    run = offline_dynamodb_sdk(intercept_only=True)
    with pytest.raises(DiagnosticFatalError):
        run.session.call(service, method, arguments)
    assert run.prepared == run.transported == []


@pytest.mark.parametrize("index", [1, 2])
@pytest.mark.parametrize("change", ["prefix", "action", "status", "identity"])
def test_platform_scoped_lifecycle_rules_are_not_generalized(index, change) -> None:
    import json

    from tools.platformctl.aws_inventory import diagnostic_resource_profile
    from tools.platformctl.aws_live import (
        _diagnostic_lifecycle_comparison_item,
        _lifecycle_mismatch_paths,
        native_unordered_value,
    )

    target = next(
        row
        for row in diagnostic_resource_profile("platform").targets
        if row.resource_type == "aws_s3_bucket_lifecycle_configuration"
    )
    assertion = next(row for row in target.assertions if row.category == "CONFIGURATION")
    expected = json.loads(assertion.expected_fields_json)
    item = {"Rules": deepcopy(expected["Rules.@unordered"])}
    item["Rules"][0]["Filter"] = {"Prefix": ""}
    rule = item["Rules"][index]
    if change == "prefix":
        rule["Filter"] = {"Prefix": ""}
    elif change == "action":
        rule["Expiration"]["Days"] = 31
    elif change == "status":
        rule["Status"] = "Disabled"
    else:
        rule["ID"] = "different"
    before = deepcopy(item)
    normalized = _diagnostic_lifecycle_comparison_item(assertion.probe, item, expected)
    assert _lifecycle_mismatch_paths(normalized["Rules"], expected["Rules.@unordered"])
    assert native_unordered_value(normalized["Rules"]) != native_unordered_value(
        expected["Rules.@unordered"]
    )
    assert item == before


def followup_retained_fixture(monkeypatch):
    """Synthetic evidence identities; no retained live report or credentials are needed."""
    from hashlib import sha256

    from tools.platformctl import aws_live, plan
    from tools.platformctl.lifecycle_io import canonical_json_bytes

    specs = {
        "EC2_NETWORK": ("vpc", 2),
        "EC2_SECURITY_GROUPS": ("sg", 3),
        "EC2_SUBNETS": ("subnet", 5),
        "EC2_ROUTES": ("rtb", 3),
        "ENI": ("eni", 16),
    }
    categories = {
        name: [
            {
                "resource": f"{prefix}-{index:017x}",
                "classification": "INSUFFICIENT_OWNERSHIP_EVIDENCE",
                "evidence": "SYNTHETIC",
            }
            for index in range(count)
        ]
        for name, (prefix, count) in specs.items()
    }
    categories["IAM_ROLES"] = [
        {"resource": f"synthetic-role-{index}", "classification": "INSUFFICIENT_OWNERSHIP_EVIDENCE"}
        for index in range(32)
    ]
    categories["IAM_POLICIES"] = [
        {
            "resource": (
                "arn:aws:iam::526338061652:policy/service-role/"
                "AWSLambdaBasicExecutionRole-b48d6859-d98d-40eb-b786-c933f136e828"
            ),
            "classification": "INSUFFICIENT_OWNERSHIP_EVIDENCE",
        }
    ]
    categories["KMS"] = [{"resource": "synthetic-key", "classification": "AWS_MANAGED"}]
    categories["S3"] = [
        {"resource": "synthetic-bucket", "classification": "GOVERNED_STATE_MANAGED"}
    ]
    report = canonical_json_bytes(
        {
            "operation_id": "w5-004-resolution-evidence-001",
            "account_id": "526338061652",
            "region": "ap-southeast-1",
            "checks": [
                {
                    "check_id": "discovery/" + category,
                    "details": [
                        ["enumeration_complete", "true"],
                        ["resources", canonical_json_bytes(rows).decode()],
                    ],
                }
                for category, rows in categories.items()
            ],
        }
    )
    identity = canonical_json_bytes({"report_sha256": sha256(report).hexdigest()})
    for module in (aws_live, plan):
        monkeypatch.setattr(
            module, "RESOLUTION_FOLLOWUP_EVIDENCE_SHA256", sha256(report).hexdigest()
        )
        monkeypatch.setattr(
            module, "RESOLUTION_FOLLOWUP_IDENTITY_SHA256", sha256(identity).hexdigest()
        )
    return report, identity


def followup_arguments(session, service, method):
    from datetime import UTC, datetime

    from tools.platformctl.aws_live import FOLLOWUP_NETWORK

    if service == "ec2":
        if method == "describe_vpc_endpoints":
            session.resolution_endpoints = frozenset(f"vpce-{i:017x}" for i in range(8))
            return {"VpcEndpointIds": sorted(session.resolution_endpoints)}
        spec = next(value for value in FOLLOWUP_NETWORK.values() if value[0] == method)
        return {spec[1]: session.followup_targets[method]}
    if method == "list_entities_for_policy":
        return {
            "PolicyArn": next(iter(session.resolution_candidates["PolicyArn"])),
            "PolicyUsageFilter": "PermissionsPolicy",
            "MaxItems": 100,
        }
    if method == "get_role":
        return {"RoleName": "synthetic-role-0"}
    if service == "cloudtrail":
        return {
            "LookupAttributes": [{"AttributeKey": "EventName", "AttributeValue": "CreateLogGroup"}],
            "StartTime": datetime(2026, 9, 10, 7, 42, tzinfo=UTC),
            "EndTime": datetime(2026, 9, 10, 7, 43, tzinfo=UTC),
            "MaxResults": 50,
        }
    if service == "ce":
        return {
            "TimePeriod": {"Start": "2026-09-08", "End": "2026-09-13"},
            "Granularity": "DAILY",
            "Metrics": ["UnblendedCost"],
            "Filter": {"Dimensions": {"Key": "LINKED_ACCOUNT", "Values": ["526338061652"]}},
            "GroupBy": [
                {"Type": "DIMENSION", "Key": "SERVICE"},
                {"Type": "DIMENSION", "Key": "USAGE_TYPE"},
            ],
        }
    return sdk_diagnostic_arguments(service, method) if service == "s3" else {}


@pytest.mark.parametrize(
    ("service", "method"),
    [
        ("sts", "get_caller_identity"),
        ("s3", "head_object"),
        ("s3", "get_object"),
        ("ec2", "describe_vpc_endpoints"),
        ("ec2", "describe_vpcs"),
        ("ec2", "describe_subnets"),
        ("ec2", "describe_route_tables"),
        ("ec2", "describe_security_groups"),
        ("ec2", "describe_network_interfaces"),
        ("iam", "get_role"),
        ("iam", "list_entities_for_policy"),
        ("cloudtrail", "lookup_events"),
        ("ce", "get_cost_and_usage"),
    ],
)
@pytest.mark.parametrize("unauthorized", [False, True])
def test_followup_all_sdk_routes_are_production_prepared(
    offline_dynamodb_sdk, monkeypatch, service, method, unauthorized
):
    from urllib.parse import urlsplit

    from tools.platformctl.aws_live import DiagnosticFatalError

    run = offline_dynamodb_sdk(
        resolution_only=True,
        resolution_followup=True,
        intercept_only=True,
        destination="https://unapproved.invalid/" if unauthorized else None,
    )
    run.session.bind_followup_evidence(*followup_retained_fixture(monkeypatch))
    arguments = followup_arguments(run.session, service, method)
    with pytest.raises(DiagnosticFatalError if unauthorized else OfflineTransportIntercepted):
        run.session.call(service, method, arguments)
    if unauthorized:
        assert not run.transported
    else:
        assert run.prepared == run.transported and len(run.transported) == 1
        host = SDK_DIAGNOSTIC_HOSTS[service]
        if service == "s3":
            host = arguments["Bucket"] + "." + host
        assert urlsplit(run.transported[0]).hostname == host


@pytest.mark.parametrize(
    "change", ["date", "account", "grouping", "token", "limit", "target", "unapproved_api"]
)
def test_followup_argument_rejections_precede_transport(offline_dynamodb_sdk, monkeypatch, change):
    from tools.platformctl.aws_live import DiagnosticFatalError

    run = offline_dynamodb_sdk(resolution_only=True, resolution_followup=True, intercept_only=True)
    run.session.bind_followup_evidence(*followup_retained_fixture(monkeypatch))
    service, method = "ce", "get_cost_and_usage"
    args = followup_arguments(run.session, service, method)
    if change == "date":
        args["TimePeriod"]["End"] = "2026-09-14"
    elif change == "account":
        args["Filter"]["Dimensions"]["Values"] = ["000000000000"]
    elif change == "grouping":
        args["GroupBy"] = []
    elif change == "token":
        args["NextPageToken"] = "unissued"
    elif change == "limit":
        args["MaxResults"] = 100
    elif change == "target":
        service, method, args = "ec2", "describe_vpcs", {"VpcIds": ["vpc-unapproved"]}
    else:
        service, method, args = "iam", "create_service_linked_role", {}
    with pytest.raises(DiagnosticFatalError):
        run.session.call(service, method, args)
    assert not run.prepared and not run.transported


@pytest.mark.parametrize(
    "changed",
    ["none", "condition", "effect", "principal", "action", "resource", "extra", "version"],
)
def test_followup_default_endpoint_omission_both_comparison_paths(changed):
    from copy import deepcopy

    from tools.platformctl.aws_live import (
        _diagnostic_endpoint_comparison_item,
        diagnostic_policy_digest,
        resolution_policy_differences,
    )

    expected = {
        "Version": "2008-10-17",
        "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "*", "Resource": "*"}],
    }
    actual = deepcopy(expected)
    actual.pop("Version")
    statement = actual["Statement"][0]
    if changed == "condition":
        statement["Condition"] = {"Bool": {"aws:SecureTransport": "true"}}
    elif changed in {"effect", "principal", "action", "resource"}:
        statement[changed.title()] = {
            "effect": "Deny",
            "principal": "other",
            "action": "s3:GetObject",
            "resource": "other",
        }[changed]
    elif changed == "extra":
        actual["Statement"].append(deepcopy(statement))
    elif changed == "version":
        actual["Version"] = None
    fields = {"PolicyDocument.@diagnostic_policy_sha256": diagnostic_policy_digest(expected)}
    normalized = _diagnostic_endpoint_comparison_item({"PolicyDocument": actual}, fields)
    if changed == "version":
        with pytest.raises(ContractError):
            resolution_policy_differences(expected, actual, approved_default_endpoint=True)
    else:
        result = resolution_policy_differences(expected, actual, approved_default_endpoint=True)
        assert (result["classification"] == "SEMANTIC_MATCH") == (changed == "none")
    assert (isinstance(normalized["PolicyDocument"], str)) == (changed == "none")
    if changed == "none":
        assert resolution_policy_differences(expected, actual)["classification"] != "SEMANTIC_MATCH"


@pytest.mark.parametrize(
    ("message", "actions", "established"),
    [
        ("KMS access mentioned, cause unclear", [], False),
        (
            "Not authorized to perform: logs:TagResource because "
            "no identity-based policy allows it",
            ["logs:tagresource"],
            True,
        ),
        (
            "Not authorized to perform: logs:CreateLogGroup with an explicit deny",
            ["logs:createloggroup"],
            True,
        ),
        ("logs:TagResource exists but the request failed", [], False),
    ],
)
def test_followup_denial_messages_are_not_persisted(message, actions, established):
    from tools.platformctl.aws_live import DiagnosticAwsSession
    from tools.platformctl.lifecycle_io import canonical_json_bytes

    result = DiagnosticAwsSession.followup_denial_details({"errorMessage": message})
    assert result["explicit_denied_actions"] == actions
    assert result["authorization_cause_established"] is established
    assert message not in canonical_json_bytes(result).decode()
    assert result["permission_grant_recommended"] is False


@pytest.mark.parametrize(
    "limit", ["total", "reserve_requests", "reserve_time", "elapsed", "billing", "pages"]
)
def test_followup_limits_block_before_transport(offline_dynamodb_sdk, monkeypatch, limit):
    from tools.platformctl.aws_live import DiagnosticCollectionError, DiagnosticFatalError

    run = offline_dynamodb_sdk(resolution_only=True, resolution_followup=True, intercept_only=True)
    run.session.bind_followup_evidence(*followup_retained_fixture(monkeypatch))
    service, method = "ce", "get_cost_and_usage"
    arguments = followup_arguments(run.session, service, method)
    if limit == "total":
        run.session.requests = 200
    elif limit == "reserve_requests":
        run.session.requests = 192
    elif limit == "reserve_time":
        run.session._monotonic = lambda: 780.0
    elif limit == "elapsed":
        run.session._monotonic = lambda: 900.0
    elif limit == "billing":
        run.session.billing_requests = 3
    else:
        from tools.platformctl.lifecycle_io import canonical_json_bytes

        identity = service + "/" + method + canonical_json_bytes(arguments).decode()
        run.session.enumeration_pages[identity] = 3
    with pytest.raises((DiagnosticFatalError, DiagnosticCollectionError, ContractError)):
        run.session.call(service, method, arguments)
    assert not run.transported


def test_followup_unbound_source_rejected_without_a_call(offline_dynamodb_sdk, monkeypatch):
    run = offline_dynamodb_sdk(resolution_only=True, resolution_followup=True, intercept_only=True)
    raw, identity = followup_retained_fixture(monkeypatch)
    with pytest.raises(ContractError):
        run.session.bind_followup_evidence(raw + b" ", identity)
    assert run.session.requests == 0
    with pytest.raises(ContractError):
        run.session.call("sts", "get_caller_identity", {})
    assert not run.transported


def test_followup_discovery_insufficient_evidence_is_not_unrelated(
    offline_dynamodb_sdk, monkeypatch
):
    run = offline_dynamodb_sdk(resolution_only=True, resolution_followup=True)
    run.session.bind_followup_evidence(*followup_retained_fixture(monkeypatch))
    run.session.followup_vpc = "vpc-" + "0" * 17
    targets = run.session.followup_targets["describe_subnets"]
    monkeypatch.setattr(
        run.session,
        "pages",
        lambda *_a, **_k: [
            {"SubnetId": value, "Tags": [], "VpcId": "vpc-" + "1" * 17} for value in targets
        ],
    )
    result = run.session.resolution_discovery("EC2_SUBNETS", frozenset())
    assert all(row["relationship"] == "INSUFFICIENT_EVIDENCE" for row in result["resources"])
    assert result["unknown_is_orphan"] is False


def test_plan_owner_envelope_has_no_external_execution_path() -> None:
    import ast
    import inspect
    import textwrap

    from tools.platformctl.plan_artifact_producer import prepare_owner_envelope

    tree = ast.parse(textwrap.dedent(inspect.getsource(prepare_owner_envelope)))
    forbidden_roots = {
        "boto3",
        "botocore",
        "git",
        "requests",
        "socket",
        "subprocess",
        "terraform",
        "urllib",
    }
    imported_roots = {
        alias.name.partition(".")[0].casefold()
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imported_roots.update(
        node.module.partition(".")[0].casefold()
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    )
    called_roots: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        callable_node = node.func
        while isinstance(callable_node, ast.Attribute):
            callable_node = callable_node.value
        if isinstance(callable_node, ast.Name):
            called_roots.add(callable_node.id.casefold())
    assert imported_roots.isdisjoint(forbidden_roots)
    assert called_roots.isdisjoint(forbidden_roots)


def test_plan_owner_envelope_rejects_same_named_noncanonical_example(tmp_path: Path) -> None:
    from tools.platformctl.plan_artifact_producer import _repository_example

    repository = tmp_path / "repository"
    expected = repository / "infra/environments/sandbox/terraform.tfvars.example"
    expected.parent.mkdir(parents=True)
    expected.write_text('aws_account_id = "526338061652"\n', encoding="utf-8")
    alias = tmp_path / "terraform.tfvars.example"
    alias.write_bytes(expected.read_bytes())
    with pytest.raises(ContractError, match="EXAMPLE_PATH_MISMATCH"):
        _repository_example(
            alias,
            Path("infra/environments/sandbox/terraform.tfvars.example"),
            sha256(expected.read_bytes()).hexdigest(),
            repository,
        )


def test_w12_residue_unknown_never_classifies_clean() -> None:
    from tools.platformctl.aws_inventory import (
        W12_001_RESIDUAL_SURFACES,
        classify_w12_residuals,
    )

    observed = {name: [] for name in W12_001_RESIDUAL_SURFACES}
    observed["hcp-workspaces-runs-and-state-versions"] = None
    assert classify_w12_residuals(observed) == "INDETERMINATE"


def _synthetic_w12_purge(delete: bool):
    from tools.platformctl.lifecycle_models import PurgeInventoryV3, PurgeItem

    from tests.unit.test_platformctl import _w12_coverage_binding

    binding = _w12_coverage_binding()
    versions = tuple(
        PurgeItem("OBJECT_VERSION", item.key, item.version_id) for item in binding.protected_objects
    )
    return (
        PurgeInventoryV3(
            schema_version="platformctl.purge-inventory.v3",
            operation_id="synthetic",
            account_id="123456789012",
            region="ap-southeast-1",
            environment="sandbox",
            bucket=binding.verified_record_object.bucket,
            ownership="PROJECT_MANAGED",
            items=versions if delete else (),
            retained=() if delete else versions,
            pagination_evidence=None,
            observed_at="2026-01-01T00:00:00Z",
            valid_until="2026-01-02T00:00:00Z",
            w12_retention_bindings=(binding,),
        ),
        binding,
    )


def test_publication_selector_not_serialized() -> None:
    from tools.platformctl.aws_inventory import canonical_purge_inventory_v3

    inventory, _ = _synthetic_w12_purge(False)
    encoded = canonical_purge_inventory_v3(inventory)
    assert b"publication-selector.json" not in encoded
    assert b"proof_root" not in encoded


def test_publication_selector_is_untrusted() -> None:
    from tools.capstone_release import validate_publication_proof

    source = __import__("inspect").getsource(validate_publication_proof)
    assert "_read_selected_object" in source
    assert "validate_publication_selector" in source
    assert "_s3_read_exact" in source


def test_local_retention_paths_not_serialized() -> None:
    from tools.platformctl.aws_inventory import canonical_purge_inventory_v3

    inventory, _ = _synthetic_w12_purge(False)
    encoded = canonical_purge_inventory_v3(inventory)
    assert b"w12-retention-proof-root" not in encoded
    assert b"publication-selector.json" not in encoded


def test_purge_rejects_unexpired_w12_version() -> None:
    from tools.platformctl.contracts import ContractError
    from tools.platformctl.destroy import _validate_w12_purge_scope

    inventory, binding = _synthetic_w12_purge(True)
    with pytest.raises(ContractError, match="PURGE_W12_EVIDENCE_RETAINED_BY_POLICY"):
        _validate_w12_purge_scope(
            inventory,
            (binding,),
            datetime(2026, 1, 2, tzinfo=UTC),
        )


def test_storage_module_remains_single_lifecycle_owner() -> None:
    root = Path(__file__).resolve().parents[2]
    storage = (root / "infra/modules/storage/main.tf").read_text()
    sandbox = (root / "infra/environments/sandbox/main.tf").read_text()
    assert 'resource "aws_s3_bucket_lifecycle_configuration"' in storage
    assert 'resource "aws_s3_bucket_lifecycle_configuration"' not in sandbox


def test_w12_evidence_not_expired_before_180_days() -> None:
    root = Path(__file__).resolve().parents[2]
    storage = (root / "infra/modules/storage/main.tf").read_text()
    sandbox = (root / "infra/environments/sandbox/main.tf").read_text()
    assert "noncurrent_days = var.noncurrent_version_retention_days" in storage
    assert "noncurrent_version_retention_days = 180" in sandbox


def test_live_delete_revalidates_w12_version() -> None:
    source = (Path(__file__).resolve().parents[2] / "tools/platformctl/destroy.py").read_text()
    purge = source.split("def purge_approved_inventory(", 1)[1].split(
        "def verify_purge_execution(", 1
    )[0]
    assert "_validate_w12_purge_scope(inventory, bindings, now)" in purge
    assert "adapter.inventory(inventory)" in purge
    assert "context.revalidate(" in purge


def test_platform_destroy_requires_w12_dependency_proof() -> None:
    root = Path(__file__).resolve().parents[2]
    plan = (root / "tools/platformctl/plan.py").read_text()
    destroy = (root / "tools/platformctl/destroy.py").read_text()
    assert "w12_bucket_residue_present" in plan
    assert "W12_SOURCE_BUCKET" in plan
    assert "W12" in destroy
