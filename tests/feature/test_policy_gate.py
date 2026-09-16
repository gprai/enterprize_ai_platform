"""Feature tests for the combined offline W5-003 OPA and Checkov gate."""

from __future__ import annotations

import json
import os
import re
import subprocess
from collections.abc import Callable
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
from tools.platformctl.policy_runner import normalize_plan

from tests.security.test_w5_004_lifecycle_security import (
    ecr_kms_reference_plan,
    opensearch_log_reference_plan,
)

ROOT = Path(__file__).resolve().parents[2]
POLICY_DIRECTORY = ROOT / "policies/opa"
CHECKOV_CONFIG = ROOT / ".checkov.yml"
OPA = Path(r"E:\AI\.tools\opa\1.20.0\opa.exe")
CHECKOV_PYTHON = Path(r"E:\AI\.venvs\enterprise-ai-platform-checkov-3.3.16\Scripts\python.exe")
CHECKOV_CLI = Path(r"E:\AI\.venvs\enterprise-ai-platform-checkov-3.3.16\Scripts\checkov")
POLICY_IDS = [
    "W5-PLAN-001",
    "W5-REG-001",
    "W5-TAG-001",
    "W5-TAG-002",
    "W5-PLAN-002",
    "W5-S3-001",
    "W5-S3-002",
    "W5-S3-003",
    "W5-S3-004",
    "W5-KMS-001",
    "W5-IAM-001",
    "W5-IAM-002",
    "W5-NET-001",
    "W5-NET-002",
    "W5-OS-001",
    "W5-OS-002",
    "W5-ECR-001",
    "W5-ECR-002",
    "W5-SEC-001",
    "W5-EXC-001",
]

PLATFORM_RECOVERY_CREATE_RESOURCES = {
    'module.opensearch.aws_cloudwatch_log_group.this["application"]': ("aws_cloudwatch_log_group"),
    'module.opensearch.aws_cloudwatch_log_group.this["audit"]': "aws_cloudwatch_log_group",
    'module.opensearch.aws_cloudwatch_log_group.this["index_slow"]': ("aws_cloudwatch_log_group"),
    'module.opensearch.aws_cloudwatch_log_group.this["search_slow"]': ("aws_cloudwatch_log_group"),
    "module.opensearch.aws_opensearch_domain.this": "aws_opensearch_domain",
}

PLATFORM_RECOVERY_UPDATE_RESOURCES = {
    "module.ecr.aws_ecr_repository.this": "aws_ecr_repository",
    "module.iam.aws_iam_role.github_oidc": "aws_iam_role",
    "module.iam.aws_iam_role.ingestion": "aws_iam_role",
    "module.iam.aws_iam_role.opensearch_administrator": "aws_iam_role",
    "module.iam.aws_iam_role.runtime": "aws_iam_role",
    "module.iam.aws_iam_role_policy.runtime": "aws_iam_role_policy",
    "module.kms.aws_kms_key.this": "aws_kms_key",
    "module.network.aws_default_security_group.restricted": "aws_default_security_group",
    "module.network.aws_route_table.private": "aws_route_table",
    "module.network.aws_security_group.endpoints": "aws_security_group",
    "module.network.aws_subnet.private[0]": "aws_subnet",
    "module.network.aws_subnet.private[1]": "aws_subnet",
    "module.network.aws_vpc.this": "aws_vpc",
    'module.network.aws_vpc_endpoint.gateway["DynamoDB"]': "aws_vpc_endpoint",
    'module.network.aws_vpc_endpoint.gateway["S3"]': "aws_vpc_endpoint",
    'module.network.aws_vpc_endpoint.interface["Bedrock Runtime"]': "aws_vpc_endpoint",
    'module.network.aws_vpc_endpoint.interface["CloudWatch Logs"]': "aws_vpc_endpoint",
    'module.network.aws_vpc_endpoint.interface["ECR API"]': "aws_vpc_endpoint",
    'module.network.aws_vpc_endpoint.interface["ECR DKR"]': "aws_vpc_endpoint",
    'module.network.aws_vpc_endpoint.interface["EKS"]': "aws_vpc_endpoint",
    'module.network.aws_vpc_endpoint.interface["KMS"]': "aws_vpc_endpoint",
    'module.network.aws_vpc_endpoint.interface["STS"]': "aws_vpc_endpoint",
    'module.network.aws_vpc_endpoint.interface["Secrets Manager"]': "aws_vpc_endpoint",
    "module.storage.aws_s3_bucket.this": "aws_s3_bucket",
    "terraform_data.owner_expiry_gate": "terraform_data",
}


def _base_plan() -> dict[str, Any]:
    return {
        "format_version": "1.2",
        "terraform_version": "1.14.0",
        "variables": {"aws_region": {"value": "ap-southeast-1"}},
        "evaluation_context": {
            "evaluation_time": "2026-09-04T00:00:00Z",
            "policy_ids": POLICY_IDS,
        },
        "resource_changes": [
            {
                "address": "aws_route_table_association.private[0]",
                "type": "aws_route_table_association",
                "change": {
                    "actions": ["create"],
                    "after": {
                        "route_table_id": "rtb-synthetic",
                        "subnet_id": "subnet-synthetic",
                    },
                },
            }
        ],
    }


def _owner_expiry_gate() -> dict[str, Any]:
    return {
        "address": "terraform_data.owner_expiry_gate",
        "type": "terraform_data",
        "change": {
            "actions": ["create"],
            "before": None,
            "after": {
                "input": "2026-09-04T01:00:00Z",
                "store": None,
                "triggers_replace": None,
            },
            "after_unknown": {"id": True, "output": True},
            "after_sensitive": {},
        },
    }


def _normalized_bootstrap_s3_plan() -> dict[str, Any]:
    plan = _base_plan()
    bucket_address = "aws_s3_bucket.terraform_state"
    encryption_address = "aws_s3_bucket_server_side_encryption_configuration.terraform_state"
    policy_address = "aws_s3_bucket_policy.terraform_state_tls"
    kms_address = "aws_kms_key.terraform_state"
    plan["evaluation_context"] = {
        **plan["evaluation_context"],
        "provider_computed_unknowns": [
            {
                "address": encryption_address,
                "type": "aws_s3_bucket_server_side_encryption_configuration",
                "unknown_paths": [
                    "rule[].apply_server_side_encryption_by_default[].kms_master_key_id"
                ],
            }
        ],
        "s3_bucket_policy_bindings": [
            {
                "bucket_address": bucket_address,
                "policy_address": policy_address,
            }
        ],
        "s3_kms_encryption_bindings": [
            {
                "bucket_address": bucket_address,
                "encryption_address": encryption_address,
                "kms_key_address": kms_address,
                "field_path": (
                    "rule[].apply_server_side_encryption_by_default[].kms_master_key_id"
                ),
            }
        ],
    }
    plan["resource_changes"] = [
        {
            "address": bucket_address,
            "type": "aws_s3_bucket",
            "change": {
                "actions": ["create"],
                "after": {"bucket": "approved-bucket", "tags_all": _approved_tags()},
            },
        },
        {
            "address": "aws_s3_bucket_public_access_block.terraform_state",
            "type": "aws_s3_bucket_public_access_block",
            "change": {
                "actions": ["create"],
                "after": {
                    "block_public_acls": True,
                    "block_public_policy": True,
                    "ignore_public_acls": True,
                    "restrict_public_buckets": True,
                },
            },
        },
        {
            "address": encryption_address,
            "type": "aws_s3_bucket_server_side_encryption_configuration",
            "change": {
                "actions": ["create"],
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
                "after_unknown": {"rule": [{"apply_server_side_encryption_by_default": [{}]}]},
            },
        },
        {
            "address": "aws_s3_bucket_versioning.terraform_state",
            "type": "aws_s3_bucket_versioning",
            "change": {
                "actions": ["create"],
                "after": {"versioning_configuration": [{"status": "Enabled"}]},
            },
        },
        {
            "address": "aws_s3_bucket_lifecycle_configuration.terraform_state",
            "type": "aws_s3_bucket_lifecycle_configuration",
            "change": {
                "actions": ["create"],
                "after": {
                    "rule": [{"abort_incomplete_multipart_upload": [{"days_after_initiation": 7}]}]
                },
            },
        },
        {
            "address": policy_address,
            "type": "aws_s3_bucket_policy",
            "change": {
                "actions": ["create"],
                "after": {
                    "policy": (
                        '{"Statement":[{"Effect":"Deny",'
                        '"Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}'
                    )
                },
            },
        },
        {
            "address": kms_address,
            "type": "aws_kms_key",
            "change": {
                "actions": ["create"],
                "after": {
                    "enable_key_rotation": True,
                    "deletion_window_in_days": 7,
                    "tags_all": _approved_tags(),
                },
            },
        },
        _owner_expiry_gate(),
    ]
    return plan


def _normalized_opensearch_sensitive_metadata_plan() -> dict[str, Any]:
    plan = _base_plan()
    role_address = "module.iam.aws_iam_role.opensearch_administrator"
    domain_address = "module.opensearch.aws_opensearch_domain.this"
    plan["evaluation_context"] = {
        **plan["evaluation_context"],
        "provider_sensitive_nulls": [
            {
                "address": domain_address,
                "type": "aws_opensearch_domain",
                "field_path": (
                    "advanced_security_options[].master_user_options[].master_user_password"
                ),
                "relationship": ("omitted-null-password-with-structurally-resolved-admin-role"),
                "source_address": role_address,
            }
        ],
    }
    plan["resource_changes"] = [
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
                                    "master_user_name": None,
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
                "after_sensitive": {"advanced_security_options": [{"master_user_options": [{}]}]},
            },
        },
    ]
    return plan


def _normalized_opensearch_existing_sensitive_metadata_plan() -> dict[str, Any]:
    plan = _normalized_opensearch_sensitive_metadata_plan()
    role = plan["resource_changes"][0]
    domain = plan["resource_changes"][1]
    role_arn = "arn:aws:iam::526338061652:role/enterprise-ai-sandbox-opensearch-admin"
    trust_policy = '{"Statement":[],"Version":"2012-10-17"}'
    previous_tags = {**_approved_tags(), "ExpiresAt": "2026-09-03T23:00:00Z"}
    current_tags = _approved_tags()
    role["change"] = {
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
    advanced = domain["change"]["after"]["advanced_security_options"][0]
    advanced["master_user_options"][0]["master_user_arn"] = role_arn
    unknown_master = domain["change"]["after_unknown"]["advanced_security_options"][0][
        "master_user_options"
    ][0]
    unknown_master.clear()
    plan["evaluation_context"]["provider_sensitive_nulls"][0]["relationship"] = (
        "omitted-null-password-with-existing-admin-role"
    )
    plan["resource_changes"].append(
        {
            "address": "terraform_data.owner_expiry_gate",
            "type": "terraform_data",
            "change": {
                "actions": ["update"],
                "before": {
                    "id": "owner-expiry-gate-id",
                    "input": previous_tags["ExpiresAt"],
                    "output": previous_tags["ExpiresAt"],
                    "store": None,
                    "triggers_replace": None,
                },
                "after": {
                    "id": "owner-expiry-gate-id",
                    "input": current_tags["ExpiresAt"],
                    "store": None,
                    "triggers_replace": None,
                },
                "after_unknown": {"output": True},
                "after_sensitive": {},
            },
        }
    )
    return plan


def _partial_bootstrap_recovery_plan() -> dict[str, Any]:
    plan = _base_plan()
    previous_tags = {**_approved_tags(), "ExpiresAt": "2026-09-03T23:00:00Z"}
    kms_address = "aws_kms_key.terraform_state"
    bucket_address = "aws_s3_bucket.terraform_state"
    policy_address = "aws_s3_bucket_policy.terraform_state_tls"
    encryption_address = "aws_s3_bucket_server_side_encryption_configuration.terraform_state"
    kms_arn = "arn:aws:kms:ap-southeast-1:526338061652:key/11111111-2222-3333-4444-555555555555"
    grant_statement = {
        "Sid": "AllowExactAccountDynamoDBStateGrant",
        "Effect": "Allow",
        "Principal": {"AWS": "arn:aws:iam::526338061652:root"},
        "Action": "kms:CreateGrant",
        "Resource": "*",
        "Condition": {
            "StringEquals": {"kms:CallerAccount": "526338061652"},
            "StringLike": {"kms:ViaService": "dynamodb.*.amazonaws.com"},
        },
    }
    base_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowExactAccountStateCryptography",
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::526338061652:root"},
                "Action": ["kms:Decrypt", "kms:DescribeKey", "kms:Encrypt"],
                "Resource": "*",
            }
        ],
    }
    updated_policy = {
        **base_policy,
        "Statement": [*base_policy["Statement"], grant_statement],
    }

    def normalized_change(
        address: str,
        resource_type: str,
        actions: list[str],
        before: dict[str, Any] | None,
        after: dict[str, Any] | None,
    ) -> dict[str, Any]:
        return {
            "address": address,
            "type": resource_type,
            "change": {
                "actions": actions,
                "before": before,
                "after": after,
                "after_unknown": {},
                "after_sensitive": {},
            },
        }

    kms_before = {
        "description": "W5 sandbox Terraform state encryption",
        "enable_key_rotation": True,
        "deletion_window_in_days": 7,
        "policy": json.dumps(base_policy, separators=(",", ":")),
        "tags": previous_tags,
        "tags_all": previous_tags,
    }
    kms_after = {
        **kms_before,
        "policy": json.dumps(updated_policy, separators=(",", ":")),
        "tags": _approved_tags(),
        "tags_all": _approved_tags(),
    }
    bucket_before = {
        "bucket": "enterprise-ai-platform-sandbox-tfstate-526338061652-ap-southeast-1",
        "force_destroy": False,
        "policy": "",
        "tags": previous_tags,
        "tags_all": previous_tags,
    }
    bucket_after = {
        **bucket_before,
        "tags": _approved_tags(),
        "tags_all": _approved_tags(),
    }
    expiry_change = {
        "address": "terraform_data.owner_expiry_gate",
        "type": "terraform_data",
        "change": {
            "actions": ["update"],
            "before": {
                "id": "owner-expiry-gate-id",
                "input": previous_tags["ExpiresAt"],
                "output": previous_tags["ExpiresAt"],
                "store": None,
                "triggers_replace": None,
            },
            "after": {
                "id": "owner-expiry-gate-id",
                "input": _approved_tags()["ExpiresAt"],
                "store": None,
                "triggers_replace": None,
            },
            "after_unknown": {"output": True},
            "after_sensitive": {},
        },
    }
    table_values = {
        "attribute": [{"name": "LockID", "type": "S"}],
        "billing_mode": "PAY_PER_REQUEST",
        "hash_key": "LockID",
        "point_in_time_recovery": [{"enabled": True}],
        "server_side_encryption": [{"enabled": True, "kms_key_arn": kms_arn}],
        "tags": _approved_tags(),
        "tags_all": _approved_tags(),
    }
    table_change = normalized_change(
        "aws_dynamodb_table.terraform_lock",
        "aws_dynamodb_table",
        ["create"],
        None,
        table_values,
    )
    public_access = {
        "block_public_acls": True,
        "block_public_policy": True,
        "ignore_public_acls": True,
        "restrict_public_buckets": True,
    }
    encryption = {
        "rule": [
            {
                "apply_server_side_encryption_by_default": [
                    {"kms_master_key_id": kms_arn, "sse_algorithm": "aws:kms"}
                ],
                "bucket_key_enabled": True,
            }
        ]
    }
    versioning = {"versioning_configuration": [{"status": "Enabled"}]}
    lifecycle = {"rule": [{"abort_incomplete_multipart_upload": [{"days_after_initiation": 7}]}]}
    tls_policy = {
        "policy": (
            '{"Statement":[{"Effect":"Deny","Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}'
        )
    }
    plan["evaluation_context"] = {
        **plan["evaluation_context"],
        "s3_bucket_policy_bindings": [
            {"bucket_address": bucket_address, "policy_address": policy_address}
        ],
        "s3_kms_encryption_bindings": [],
    }
    plan["resource_changes"] = [
        table_change,
        normalized_change(kms_address, "aws_kms_key", ["update"], kms_before, kms_after),
        normalized_change(bucket_address, "aws_s3_bucket", ["update"], bucket_before, bucket_after),
        expiry_change,
        normalized_change(
            "aws_s3_bucket_public_access_block.terraform_state",
            "aws_s3_bucket_public_access_block",
            ["no-op"],
            public_access,
            public_access,
        ),
        normalized_change(
            encryption_address,
            "aws_s3_bucket_server_side_encryption_configuration",
            ["no-op"],
            encryption,
            encryption,
        ),
        normalized_change(
            "aws_s3_bucket_versioning.terraform_state",
            "aws_s3_bucket_versioning",
            ["no-op"],
            versioning,
            versioning,
        ),
        normalized_change(
            "aws_s3_bucket_lifecycle_configuration.terraform_state",
            "aws_s3_bucket_lifecycle_configuration",
            ["no-op"],
            lifecycle,
            lifecycle,
        ),
        normalized_change(
            policy_address,
            "aws_s3_bucket_policy",
            ["no-op"],
            tls_policy,
            tls_policy,
        ),
    ]
    return plan


def _partial_platform_recovery_plan() -> dict[str, Any]:
    plan = _base_plan()
    current_tags = _approved_tags()
    previous_tags = {**current_tags, "ExpiresAt": "2026-09-03T23:00:00Z"}

    def normalized_change(
        address: str,
        resource_type: str,
        actions: list[str],
        before: dict[str, Any] | None,
        after: dict[str, Any] | None,
    ) -> dict[str, Any]:
        return {
            "address": address,
            "type": resource_type,
            "change": {
                "actions": actions,
                "before": before,
                "after": after,
                "after_unknown": {},
                "after_sensitive": {},
            },
        }

    changes = [
        normalized_change(address, resource_type, ["create"], None, {})
        for address, resource_type in PLATFORM_RECOVERY_CREATE_RESOURCES.items()
    ]
    changes.extend(
        normalized_change(
            address,
            resource_type,
            ["update"],
            {"tags": previous_tags, "tags_all": previous_tags},
            {"tags": current_tags, "tags_all": current_tags},
        )
        for address, resource_type in PLATFORM_RECOVERY_UPDATE_RESOURCES.items()
        if address
        not in {
            "module.iam.aws_iam_role_policy.runtime",
            "terraform_data.owner_expiry_gate",
        }
    )
    runtime_policy_before = _runtime_policy(previous_tags["ExpiresAt"])
    runtime_policy_after = _runtime_policy(current_tags["ExpiresAt"])
    changes.append(
        normalized_change(
            "module.iam.aws_iam_role_policy.runtime",
            "aws_iam_role_policy",
            ["update"],
            {
                "name": "enterprise-ai-sandbox-runtime",
                "policy": runtime_policy_before,
                "role": "enterprise-ai-sandbox-runtime",
            },
            {
                "name": "enterprise-ai-sandbox-runtime",
                "policy": runtime_policy_after,
                "role": "enterprise-ai-sandbox-runtime",
            },
        )
    )
    changes.append(
        {
            "address": "terraform_data.owner_expiry_gate",
            "type": "terraform_data",
            "change": {
                "actions": ["update"],
                "before": {
                    "id": "owner-expiry-gate-id",
                    "input": previous_tags["ExpiresAt"],
                    "output": previous_tags["ExpiresAt"],
                    "store": None,
                    "triggers_replace": None,
                },
                "after": {
                    "id": "owner-expiry-gate-id",
                    "input": current_tags["ExpiresAt"],
                    "store": None,
                    "triggers_replace": None,
                },
                "after_unknown": {"output": True},
                "after_sensitive": {},
            },
        }
    )
    plan["resource_changes"] = changes
    return plan


def _runtime_policy(expires_at: str) -> str:
    runtime_role_arn = "".join(
        (
            "arn:aws:iam::526338061652:role/",
            "enterprise-ai-sandbox-runtime",
        )
    )
    inference_profile_arn = "".join(
        (
            "arn:aws:bedrock:ap-southeast-1:526338061652:",
            "inference-profile/approved",
        )
    )
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "InvokeExactApprovedInferenceProfile",
                    "Effect": "Allow",
                    "Action": "bedrock:InvokeModel",
                    "Resource": inference_profile_arn,
                    "Condition": {
                        "ArnEquals": {"aws:PrincipalArn": runtime_role_arn},
                        "DateLessThan": {"aws:CurrentTime": expires_at},
                        "StringEquals": {
                            "aws:PrincipalAccount": "526338061652",
                            "aws:RequestedRegion": "ap-southeast-1",
                            "bedrock:InferenceProfileArn": inference_profile_arn,
                        },
                    },
                },
                {
                    "Sid": "RuntimeReadPlatformObjects",
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::enterprise-ai-platform-sandbox/*",
                },
            ],
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def _approved_tags() -> dict[str, str]:
    return {
        "Project": "enterprise-ai-platform",
        "Environment": "sandbox",
        "Owner": "Gyan-Prakash-Rai",
        "ManagedBy": "terraform",
        "CostCenter": "Personal-Learning",
        "Feature": "MVP-001",
        "ExpiresAt": "2026-09-04T01:00:00Z",
        "Repository": "enterprise-ai-platform",
    }


def _local_environment() -> dict[str, str]:
    environment = os.environ.copy()
    for name in (
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "BC_API_KEY",
        "PRISMA_API_URL",
    ):
        environment.pop(name, None)
    return environment


def _opa_findings(tmp_path: Path, plan: dict[str, Any]) -> list[dict[str, str]]:
    if not OPA.is_file():
        pytest.skip(f"owner-controlled OPA executable is absent: {OPA}")
    input_path = tmp_path / "terraform-plan-shaped-input.json"
    input_path.write_text(json.dumps(plan), encoding="utf-8", newline="\n")
    completed = subprocess.run(  # noqa: S603 - fixed owner-controlled OPA executable
        [
            str(OPA),
            "eval",
            "--format=json",
            "--data",
            str(POLICY_DIRECTORY),
            "--input",
            str(input_path),
            "data.enterprise_ai.terraform.plan.findings",
        ],
        cwd=ROOT,
        env=_local_environment(),
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout)
    assert len(payload.get("result", [])) == 1, "OPA policy result is missing or unevaluated"
    expressions = payload["result"][0].get("expressions", [])
    assert len(expressions) == 1 and isinstance(expressions[0].get("value"), list)
    return expressions[0]["value"]


def _checkov(directory: Path) -> subprocess.CompletedProcess[str]:
    if not CHECKOV_PYTHON.is_file() or not CHECKOV_CLI.is_file():
        pytest.skip("owner-controlled Checkov 3.3.16 environment is absent")
    return subprocess.run(  # noqa: S603 - fixed owner-controlled Checkov interpreter
        [
            str(CHECKOV_PYTHON),
            str(CHECKOV_CLI),
            "--config-file",
            str(CHECKOV_CONFIG),
            "-d",
            str(directory),
        ],
        cwd=ROOT,
        env=_local_environment(),
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )


def _eligibility(
    opa_findings: list[dict[str, str]] | None,
    *,
    checkov_completed: bool,
    checkov_failed: int,
    checkov_skipped: int,
) -> str:
    if opa_findings is None or not checkov_completed:
        return "FAIL"
    if opa_findings or checkov_failed != 0 or checkov_skipped != 20:
        return "FAIL"
    return "PASS"


def test_secure_synthetic_plan_is_evaluated_and_passes(tmp_path: Path) -> None:
    assert _opa_findings(tmp_path, _base_plan()) == []


def test_bootstrap_plan_with_exact_owner_expiry_gate_passes(tmp_path: Path) -> None:
    plan = _base_plan()
    plan["resource_changes"].append(_owner_expiry_gate())

    assert _opa_findings(tmp_path, plan) == []


def test_realistic_normalized_bootstrap_s3_plan_passes(tmp_path: Path) -> None:
    assert _opa_findings(tmp_path, _normalized_bootstrap_s3_plan()) == []


def test_exact_partial_bootstrap_recovery_plan_passes(tmp_path: Path) -> None:
    assert _opa_findings(tmp_path, _partial_bootstrap_recovery_plan()) == []


@pytest.mark.parametrize(
    "mutation",
    (
        "broader_grant",
        "missing_via_service",
        "wrong_account",
        "altered_kms",
        "altered_bucket",
        "unexpected_update",
        "replacement",
        "deletion",
        "sensitive",
        "critical_unknown",
    ),
)
def test_partial_bootstrap_recovery_deviations_fail_closed(tmp_path: Path, mutation: str) -> None:
    plan = _partial_bootstrap_recovery_plan()
    changes = plan["resource_changes"]
    table = changes[0]
    kms = changes[1]
    bucket = changes[2]

    if mutation in {"broader_grant", "missing_via_service", "wrong_account"}:
        policy = json.loads(kms["change"]["after"]["policy"])
        grant = policy["Statement"][-1]
        if mutation == "broader_grant":
            grant["Action"] = ["kms:CreateGrant", "kms:RetireGrant"]
        elif mutation == "missing_via_service":
            del grant["Condition"]["StringLike"]
        else:
            grant["Principal"]["AWS"] = "arn:aws:iam::000000000000:root"
        kms["change"]["after"]["policy"] = json.dumps(policy, separators=(",", ":"))
    elif mutation == "altered_kms":
        kms["change"]["after"]["description"] = "unapproved change"
    elif mutation == "altered_bucket":
        bucket["change"]["after"]["force_destroy"] = True
    elif mutation == "unexpected_update":
        unexpected = deepcopy(changes[-1])
        unexpected["address"] = "aws_s3_bucket_policy.unexpected"
        unexpected["change"]["actions"] = ["update"]
        changes.append(unexpected)
    elif mutation == "replacement":
        table["change"]["actions"] = ["delete", "create"]
        table["change"]["before"] = deepcopy(table["change"]["after"])
    elif mutation == "deletion":
        changes.append(
            {
                "address": "aws_kms_alias.terraform_state",
                "type": "aws_kms_alias",
                "change": {
                    "actions": ["delete"],
                    "before": {"name": "alias/enterprise-ai-platform-sandbox-tfstate"},
                    "after": None,
                    "after_unknown": {},
                    "after_sensitive": {},
                },
            }
        )
    elif mutation == "sensitive":
        table["change"]["after_sensitive"] = {"server_side_encryption": True}
    else:
        table["change"]["after_unknown"] = {"tags": True}

    findings = _opa_findings(tmp_path, plan)

    assert findings
    assert {finding["policy_id"] for finding in findings} & {
        "W5-PLAN-001",
        "W5-PLAN-002",
        "W5-SEC-001",
    }


def test_exact_partial_platform_recovery_shape_requires_no_update_exception(
    tmp_path: Path,
) -> None:
    findings = _opa_findings(tmp_path, _partial_platform_recovery_plan())

    assert "W5-PLAN-002" not in {finding["policy_id"] for finding in findings}


def test_partial_platform_recovery_accepts_known_passive_change(tmp_path: Path) -> None:
    plan = _partial_platform_recovery_plan()
    plan["resource_changes"].append(
        {
            "address": "module.ecr.aws_ecr_lifecycle_policy.retain_exact_count",
            "type": "aws_ecr_lifecycle_policy",
            "change": {
                "actions": ["no-op"],
                "before": {"policy": "synthetic"},
                "after": {"policy": "synthetic"},
                "after_unknown": {},
                "after_sensitive": {},
            },
        }
    )

    findings = _opa_findings(tmp_path, plan)

    assert "W5-PLAN-002" not in {finding["policy_id"] for finding in findings}


def test_partial_platform_recovery_accepts_false_only_sensitivity_shape(tmp_path: Path) -> None:
    plan = _partial_platform_recovery_plan()
    role = next(
        change
        for change in plan["resource_changes"]
        if change["address"] == "module.iam.aws_iam_role.opensearch_administrator"
    )
    role["change"]["after_sensitive"] = {
        "inline_policy": [],
        "managed_policy_arns": [],
        "tags": {"ExpiresAt": False},
        "tags_all": {"ExpiresAt": False},
    }

    findings = _opa_findings(tmp_path, plan)
    finding_ids = {finding["policy_id"] for finding in findings}

    assert "W5-PLAN-001" not in finding_ids
    assert "W5-PLAN-002" not in finding_ids
    assert "W5-SEC-001" not in finding_ids


@pytest.mark.parametrize(
    "mutation",
    (
        "wrong_expiry",
        "additional_policy_change",
        "unknown_policy",
        "sensitive_policy",
    ),
)
def test_runtime_policy_recovery_deviations_fail_closed(
    tmp_path: Path,
    mutation: str,
) -> None:
    plan = _partial_platform_recovery_plan()
    runtime_policy = next(
        change
        for change in plan["resource_changes"]
        if change["address"] == "module.iam.aws_iam_role_policy.runtime"
    )

    if mutation == "wrong_expiry":
        runtime_policy["change"]["after"]["policy"] = _runtime_policy("2026-09-04T00:30:00Z")
    elif mutation == "additional_policy_change":
        document = json.loads(runtime_policy["change"]["after"]["policy"])
        document["Statement"][1]["Action"] = "s3:DeleteObject"
        runtime_policy["change"]["after"]["policy"] = json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
        )
    elif mutation == "unknown_policy":
        runtime_policy["change"]["after_unknown"] = {"policy": True}
    else:
        runtime_policy["change"]["after_sensitive"] = {"policy": True}

    findings = _opa_findings(tmp_path, plan)
    finding_ids = {finding["policy_id"] for finding in findings}

    assert finding_ids & {"W5-PLAN-001", "W5-PLAN-002", "W5-SEC-001"}


@pytest.mark.parametrize(
    "mutation",
    (
        "missing_create",
        "additional_create",
        "wrong_address",
        "wrong_type",
        "missing_update",
        "non_expiry_update",
        "security_change",
        "replacement",
        "deletion",
        "sensitive",
        "malformed_sensitive",
        "malformed_sensitive_leaf",
        "critical_unknown",
        "mismatched_resource_expiry",
        "mismatched_tags_all_expiry",
        "excessive_expiry",
    ),
)
def test_partial_platform_recovery_deviations_fail_closed(
    tmp_path: Path,
    mutation: str,
) -> None:
    plan = _partial_platform_recovery_plan()
    changes = plan["resource_changes"]
    create_address = 'module.opensearch.aws_cloudwatch_log_group.this["application"]'
    domain_address = "module.opensearch.aws_opensearch_domain.this"
    update_address = "module.ecr.aws_ecr_repository.this"
    expiry_address = "terraform_data.owner_expiry_gate"

    create = next(change for change in changes if change["address"] == create_address)
    domain = next(change for change in changes if change["address"] == domain_address)
    update = next(change for change in changes if change["address"] == update_address)
    expiry = next(change for change in changes if change["address"] == expiry_address)

    if mutation == "missing_create":
        changes.remove(create)
    elif mutation == "additional_create":
        changes.append(
            {
                "address": "module.opensearch.aws_cloudwatch_log_group.unexpected",
                "type": "aws_cloudwatch_log_group",
                "change": {
                    "actions": ["create"],
                    "before": None,
                    "after": {},
                    "after_unknown": {},
                    "after_sensitive": {},
                },
            }
        )
    elif mutation == "wrong_address":
        create["address"] = 'module.opensearch.aws_cloudwatch_log_group.this["other"]'
    elif mutation == "wrong_type":
        domain["type"] = "aws_cloudwatch_log_group"
    elif mutation == "missing_update":
        changes.remove(update)
    elif mutation in {"non_expiry_update", "security_change"}:
        update["change"]["before"]["image_tag_mutability"] = "IMMUTABLE"
        update["change"]["after"]["image_tag_mutability"] = (
            "MUTABLE" if mutation == "security_change" else "IMMUTABLE_WITH_EXCLUSION"
        )
    elif mutation == "replacement":
        domain["change"]["actions"] = ["delete", "create"]
        domain["change"]["before"] = {}
    elif mutation == "deletion":
        changes.append(
            {
                "address": "module.kms.aws_kms_alias.this",
                "type": "aws_kms_alias",
                "change": {
                    "actions": ["delete"],
                    "before": {"name": "alias/enterprise-ai-platform-sandbox"},
                    "after": None,
                    "after_unknown": {},
                    "after_sensitive": {},
                },
            }
        )
    elif mutation == "sensitive":
        create["change"]["after_sensitive"] = {"kms_key_id": True}
    elif mutation == "malformed_sensitive":
        update["change"]["after_sensitive"] = []
    elif mutation == "malformed_sensitive_leaf":
        update["change"]["after_sensitive"] = {"tags": {"ExpiresAt": "false"}}
    elif mutation == "critical_unknown":
        create["change"]["after_unknown"] = {"tags": True}
    elif mutation == "mismatched_resource_expiry":
        update["change"]["after"]["tags"]["ExpiresAt"] = "2026-09-04T00:30:00Z"
    elif mutation == "mismatched_tags_all_expiry":
        update["change"]["after"]["tags_all"]["ExpiresAt"] = "2026-09-04T00:30:00Z"
    else:
        expiry["change"]["after"]["input"] = "2026-09-06T00:00:00Z"

    findings = _opa_findings(tmp_path, plan)
    finding_ids = {finding["policy_id"] for finding in findings}

    assert finding_ids & {"W5-PLAN-001", "W5-PLAN-002", "W5-SEC-001"}


@pytest.mark.parametrize("binding_name", ("policy", "kms"))
def test_malformed_structural_s3_binding_fails_closed(tmp_path: Path, binding_name: str) -> None:
    plan = _normalized_bootstrap_s3_plan()
    context = plan["evaluation_context"]
    if binding_name == "policy":
        context["s3_bucket_policy_bindings"][0]["policy_address"] = "aws_s3_bucket_policy.unrelated"
    else:
        context["s3_kms_encryption_bindings"][0]["field_path"] = "kms_master_key_id"

    findings = _opa_findings(tmp_path, plan)

    assert "W5-PLAN-001" in {finding["policy_id"] for finding in findings}


def test_module_resource_reference_context_is_evaluated_fail_closed(tmp_path: Path) -> None:
    plan = _base_plan()
    vpc_address = "module.network.aws_vpc.this"
    consumer_address = "module.network.aws_default_security_group.restricted"
    plan["resource_changes"] = [
        {
            "address": vpc_address,
            "type": "aws_vpc",
            "change": {
                "actions": ["create"],
                "after": {
                    "enable_dns_support": True,
                    "enable_dns_hostnames": True,
                    "tags_all": _approved_tags(),
                },
            },
        },
        {
            "address": consumer_address,
            "type": "aws_default_security_group",
            "change": {
                "actions": ["create"],
                "after": {"ingress": [], "egress": [], "tags_all": _approved_tags()},
            },
        },
    ]
    binding = {
        "address": consumer_address,
        "type": "aws_default_security_group",
        "unknown_paths": ["vpc_id"],
        "source_addresses": [vpc_address],
        "relationship": "network-vpc-reference",
    }
    plan["evaluation_context"] = {
        **plan["evaluation_context"],
        "resource_reference_unknowns": [binding],
    }

    assert "W5-PLAN-001" not in {finding["policy_id"] for finding in _opa_findings(tmp_path, plan)}

    binding["source_addresses"] = ["module.network.aws_vpc.unrelated"]
    assert "W5-PLAN-001" in {finding["policy_id"] for finding in _opa_findings(tmp_path, plan)}


@pytest.mark.parametrize(
    ("factory", "policy_id"),
    (
        (ecr_kms_reference_plan, "W5-ECR-001"),
        (opensearch_log_reference_plan, "W5-OS-002"),
    ),
)
def test_exact_platform_reference_unknown_metadata_is_accepted_by_opa(
    tmp_path: Path,
    factory: Callable[[], dict[str, object]],
    policy_id: str,
) -> None:
    normalized = normalize_plan(factory(), evaluation_time="2026-09-08T00:00:00Z")
    if policy_id == "W5-ECR-001":
        normalized["resource_changes"][1]["change"]["after"].update(
            {
                "image_scanning_configuration": [{"scan_on_push": True}],
                "image_tag_mutability": "IMMUTABLE",
            }
        )
    else:
        changes = normalized["resource_changes"]
        for change in changes[:-1]:
            change["change"]["after"].update(
                {"kms_key_id": "kms-approved", "retention_in_days": 30}
            )
        domain = changes[-1]
        domain["change"]["after"].update(
            {
                "access_policies": '{"Statement":[{"Principal":{"AWS":"526338061652"}}]}',
                "domain_endpoint_options": [
                    {
                        "enforce_https": True,
                        "tls_security_policy": "Policy-Min-TLS-1-2-2019-07",
                    }
                ],
                "encrypt_at_rest": [{"enabled": True, "kms_key_id": "kms-approved"}],
                "node_to_node_encryption": [{"enabled": True}],
                "vpc_options": [{"subnet_ids": ["subnet-approved"]}],
            }
        )
        changes.append(
            {
                "address": "module.opensearch.aws_cloudwatch_log_resource_policy.opensearch",
                "type": "aws_cloudwatch_log_resource_policy",
                "change": {
                    "actions": ["create"],
                    "after": {
                        "policy_document": (
                            '{"Statement":[{"Principal":{"Service":"es.amazonaws.com"},'
                            '"Action":["logs:CreateLogStream","logs:PutLogEvents"],'
                            '"Resource":"arn:aws:logs:ap-southeast-1:526338061652:'
                            "log-group:/aws/OpenSearchService/domains/"
                            'enterprise-ai-sandbox/application-logs:*",'
                            '"Condition":{"StringEquals":{"aws:SourceAccount":'
                            '"526338061652"},"ArnLike":{"aws:SourceArn":'
                            '"arn:aws:es:ap-southeast-1:526338061652:'
                            'domain/enterprise-ai-sandbox"}}}]} '
                        )
                    },
                    "after_unknown": {},
                    "after_sensitive": {},
                },
            }
        )
    findings = _opa_findings(tmp_path, normalized)
    finding_ids = {finding["policy_id"] for finding in findings}

    assert "W5-PLAN-001" not in finding_ids
    assert policy_id not in finding_ids

    without_binding = deepcopy(normalized)
    without_binding["evaluation_context"]["resource_reference_unknowns"] = []
    assert policy_id in {
        finding["policy_id"] for finding in _opa_findings(tmp_path, without_binding)
    }

    forged = deepcopy(normalized)
    source_address = forged["evaluation_context"]["resource_reference_unknowns"][0][
        "source_addresses"
    ][0]
    source = next(
        change for change in forged["resource_changes"] if change["address"] == source_address
    )
    source["change"]["actions"] = ["no-op"]
    assert "W5-PLAN-001" in {finding["policy_id"] for finding in _opa_findings(tmp_path, forged)}

    duplicate_consumer = deepcopy(normalized)
    consumer_address = duplicate_consumer["evaluation_context"]["resource_reference_unknowns"][0][
        "address"
    ]
    duplicate_consumer["resource_changes"].append(
        deepcopy(
            next(
                change
                for change in duplicate_consumer["resource_changes"]
                if change["address"] == consumer_address
            )
        )
    )
    assert "W5-PLAN-001" in {
        finding["policy_id"] for finding in _opa_findings(tmp_path, duplicate_consumer)
    }


def test_exact_opensearch_sensitive_metadata_is_accepted_by_opa(tmp_path: Path) -> None:
    findings = _opa_findings(tmp_path, _normalized_opensearch_sensitive_metadata_plan())

    assert "W5-PLAN-001" not in {finding["policy_id"] for finding in findings}
    assert "W5-SEC-001" not in {finding["policy_id"] for finding in findings}


def test_exact_existing_opensearch_role_sensitive_metadata_is_accepted_by_opa(
    tmp_path: Path,
) -> None:
    findings = _opa_findings(
        tmp_path,
        _normalized_opensearch_existing_sensitive_metadata_plan(),
    )

    assert "W5-PLAN-001" not in {finding["policy_id"] for finding in findings}
    assert "W5-SEC-001" not in {finding["policy_id"] for finding in findings}


def test_exact_existing_noop_opensearch_role_sensitive_metadata_is_accepted_by_opa(
    tmp_path: Path,
) -> None:
    plan = _normalized_opensearch_existing_sensitive_metadata_plan()
    role = plan["resource_changes"][0]
    after = deepcopy(role["change"]["after"])
    role["change"].update({"actions": ["no-op"], "before": after, "after": after})

    findings = _opa_findings(tmp_path, plan)

    assert "W5-PLAN-001" not in {finding["policy_id"] for finding in findings}


@pytest.mark.parametrize(
    "mutation",
    ("trust_policy_changed", "role_unknown", "role_sensitive", "arn_mismatch", "non_expiry"),
)
def test_existing_opensearch_role_sensitive_metadata_fails_closed(
    tmp_path: Path,
    mutation: str,
) -> None:
    plan = _normalized_opensearch_existing_sensitive_metadata_plan()
    role = plan["resource_changes"][0]
    domain = plan["resource_changes"][1]

    if mutation == "trust_policy_changed":
        role["change"]["after"]["assume_role_policy"] = '{"Statement":[{}],"Version":"2012-10-17"}'
    elif mutation == "role_unknown":
        role["change"]["after_unknown"] = {"arn": True}
    elif mutation == "role_sensitive":
        role["change"]["after_sensitive"] = {"arn": True}
    elif mutation == "arn_mismatch":
        domain["change"]["after"]["advanced_security_options"][0]["master_user_options"][0][
            "master_user_arn"
        ] = "arn:aws:iam::526338061652:role/unrelated"
    else:
        role["change"]["after"]["name"] = "altered-role"

    assert "W5-PLAN-001" in {finding["policy_id"] for finding in _opa_findings(tmp_path, plan)}


@pytest.mark.parametrize(
    "mutation",
    (
        "wrong_path",
        "wrong_source",
        "extra_key",
        "duplicate_binding",
        "missing_metadata",
        "missing_metadata_and_role_with_password",
        "role_not_created",
        "arn_not_unknown",
        "internal_database",
        "password_value",
    ),
)
def test_forged_opensearch_sensitive_metadata_fails_closed(
    tmp_path: Path,
    mutation: str,
) -> None:
    plan = _normalized_opensearch_sensitive_metadata_plan()
    context = plan["evaluation_context"]
    binding = context["provider_sensitive_nulls"][0]
    role = plan["resource_changes"][0]
    domain = plan["resource_changes"][1]
    advanced = domain["change"]["after"]["advanced_security_options"][0]

    if mutation == "wrong_path":
        binding["field_path"] = "advanced_security_options[].master_user_options[].other"
    elif mutation == "wrong_source":
        binding["source_address"] = "module.iam.aws_iam_role.unrelated"
    elif mutation == "extra_key":
        binding["unexpected"] = True
    elif mutation == "duplicate_binding":
        context["provider_sensitive_nulls"].append(deepcopy(binding))
    elif mutation == "missing_metadata":
        context["provider_sensitive_nulls"] = []
    elif mutation == "missing_metadata_and_role_with_password":
        context["provider_sensitive_nulls"] = []
        plan["resource_changes"].pop(0)
        advanced["master_user_options"][0]["master_user_password"] = "".join(("syn", "thetic"))
    elif mutation == "role_not_created":
        role["change"]["actions"] = ["no-op"]
    elif mutation == "arn_not_unknown":
        domain["change"]["after_unknown"]["advanced_security_options"][0]["master_user_options"][0][
            "master_user_arn"
        ] = False
    elif mutation == "internal_database":
        advanced["internal_user_database_enabled"] = True
    else:
        advanced["master_user_options"][0]["master_user_password"] = "".join(("syn", "thetic"))

    findings = _opa_findings(tmp_path, plan)

    assert "W5-PLAN-001" in {finding["policy_id"] for finding in findings}


def test_policy_document_binding_requires_exact_bound_data_change(tmp_path: Path) -> None:
    plan = _base_plan()
    policy_address = "module.iam.aws_iam_role_policy.runtime"
    document_address = "module.iam.data.aws_iam_policy_document.runtime"
    plan["resource_changes"] = [
        {
            "address": policy_address,
            "type": "aws_iam_role_policy",
            "change": {"actions": ["create"], "after": {"policy": None}},
        },
        {
            "address": document_address,
            "type": "aws_iam_policy_document",
            "change": {
                "actions": ["read"],
                "before": None,
                "after": {},
                "after_unknown": {"json": True},
                "after_sensitive": {},
            },
        },
    ]
    binding = {
        "resource_address": policy_address,
        "resource_type": "aws_iam_role_policy",
        "field_path": "policy",
        "policy_document_address": document_address,
        "relationship": "exact-policy-document",
    }
    plan["evaluation_context"] = {
        **plan["evaluation_context"],
        "policy_document_bindings": [binding],
    }

    assert "W5-PLAN-001" not in {finding["policy_id"] for finding in _opa_findings(tmp_path, plan)}

    binding["policy_document_address"] = "module.iam.data.aws_iam_policy_document.other"
    assert "W5-PLAN-001" in {finding["policy_id"] for finding in _opa_findings(tmp_path, plan)}


@pytest.mark.parametrize(
    ("resource_address", "resource_type", "field_path", "document_address"),
    (
        (
            "module.iam.aws_iam_role.runtime",
            "aws_iam_role",
            "assume_role_policy",
            "module.iam.data.aws_iam_policy_document.runtime_trust",
        ),
        (
            "module.iam.aws_iam_role.ingestion",
            "aws_iam_role",
            "assume_role_policy",
            "module.iam.data.aws_iam_policy_document.ingestion_trust",
        ),
        (
            "module.iam.aws_iam_role.opensearch_administrator",
            "aws_iam_role",
            "assume_role_policy",
            "module.iam.data.aws_iam_policy_document.administrator_trust",
        ),
        (
            "module.iam.aws_iam_role.github_oidc",
            "aws_iam_role",
            "assume_role_policy",
            "module.iam.data.aws_iam_policy_document.github_trust",
        ),
        (
            "module.opensearch.aws_opensearch_domain.this",
            "aws_opensearch_domain",
            "access_policies",
            "module.opensearch.data.aws_iam_policy_document.domain_access",
        ),
        (
            "module.opensearch.aws_cloudwatch_log_resource_policy.opensearch",
            "aws_cloudwatch_log_resource_policy",
            "policy_document",
            "module.opensearch.data.aws_iam_policy_document.log_delivery",
        ),
    ),
)
def test_exact_real_plan_policy_document_relationship_satisfies_input_contract(
    tmp_path: Path,
    resource_address: str,
    resource_type: str,
    field_path: str,
    document_address: str,
) -> None:
    plan = _base_plan()
    consumer = {
        "address": resource_address,
        "type": resource_type,
        "change": {
            "actions": ["create"],
            "before": None,
            "after": {field_path: None},
            "after_unknown": {},
            "after_sensitive": {},
        },
    }
    document = {
        "address": document_address,
        "type": "aws_iam_policy_document",
        "change": {
            "actions": ["read"],
            "before": None,
            "after": {},
            "after_unknown": {"json": True},
            "after_sensitive": {},
        },
    }
    binding = {
        "resource_address": resource_address,
        "resource_type": resource_type,
        "field_path": field_path,
        "policy_document_address": document_address,
        "relationship": "exact-policy-document",
    }
    plan["resource_changes"] = [consumer, document]
    plan["evaluation_context"] = {
        **plan["evaluation_context"],
        "policy_document_bindings": [binding],
    }

    findings = _opa_findings(tmp_path, plan)

    assert "W5-PLAN-001" not in {finding["policy_id"] for finding in findings}

    binding["field_path"] = "policy"
    findings = _opa_findings(tmp_path, plan)
    assert "W5-PLAN-001" in {finding["policy_id"] for finding in findings}


@pytest.mark.parametrize(
    "endpoint_name",
    ("Bedrock Runtime", "CloudWatch Logs", "ECR API", "ECR DKR", "Secrets Manager"),
)
def test_allowlisted_interface_endpoint_addresses_with_spaces_are_valid_plan_input(
    tmp_path: Path,
    endpoint_name: str,
) -> None:
    plan = _base_plan()
    endpoint = {
        "address": f'module.network.aws_vpc_endpoint.interface["{endpoint_name}"]',
        "type": "aws_vpc_endpoint",
        "change": {
            "actions": ["create"],
            "before": None,
            "after": {"vpc_endpoint_type": "Interface"},
            "after_unknown": {},
            "after_sensitive": {},
        },
    }
    plan["resource_changes"] = [endpoint]

    findings = _opa_findings(tmp_path, plan)

    assert "W5-PLAN-001" not in {finding["policy_id"] for finding in findings}


@pytest.mark.parametrize(
    "endpoint_name",
    ("Unapproved Service", "ECR API ", "ECR  API", " Secrets Manager"),
)
def test_unlisted_interface_endpoint_address_with_spaces_fails_closed(
    tmp_path: Path,
    endpoint_name: str,
) -> None:
    plan = _base_plan()
    plan["resource_changes"] = [
        {
            "address": f'module.network.aws_vpc_endpoint.interface["{endpoint_name}"]',
            "type": "aws_vpc_endpoint",
            "change": {
                "actions": ["create"],
                "before": None,
                "after": {"vpc_endpoint_type": "Interface"},
                "after_unknown": {},
                "after_sensitive": {},
            },
        }
    ]

    findings = _opa_findings(tmp_path, plan)

    assert "W5-PLAN-001" in {finding["policy_id"] for finding in findings}


@pytest.mark.parametrize(
    ("resource_type", "field_path"),
    (
        ("aws_iam_role", "assume_role_policy"),
        ("aws_opensearch_domain", "access_policies"),
        ("aws_cloudwatch_log_resource_policy", "policy_document"),
    ),
)
def test_unbound_policy_document_unknowns_fail_closed(
    tmp_path: Path,
    resource_type: str,
    field_path: str,
) -> None:
    plan = _base_plan()
    plan["resource_changes"] = [
        {
            "address": f"{resource_type}.unapproved",
            "type": resource_type,
            "change": {
                "actions": ["create"],
                "before": None,
                "after": {field_path: None},
                "after_unknown": {field_path: True},
                "after_sensitive": {},
            },
        }
    ]

    findings = _opa_findings(tmp_path, plan)

    assert "W5-PLAN-001" in {finding["policy_id"] for finding in findings}


@pytest.mark.parametrize(
    "mutation",
    (
        "wrong_address",
        "wrong_type",
        "wrong_action",
        "expired",
        "excessive",
        "unexpected_after",
        "unexpected_unknown",
        "sensitive",
    ),
)
def test_invalid_owner_expiry_gate_fails_closed(tmp_path: Path, mutation: str) -> None:
    plan = _base_plan()
    gate = _owner_expiry_gate()
    change = gate["change"]
    after = change["after"]

    if mutation == "wrong_address":
        gate["address"] = "terraform_data.unapproved"
    elif mutation == "wrong_type":
        gate["type"] = "aws_route_table_association"
    elif mutation == "wrong_action":
        change["actions"] = ["update"]
    elif mutation == "expired":
        after["input"] = "2026-09-03T23:59:59Z"
    elif mutation == "excessive":
        after["input"] = "2026-09-05T00:00:01Z"
    elif mutation == "unexpected_after":
        after["unexpected"] = True
    elif mutation == "unexpected_unknown":
        change["after_unknown"]["tags"] = True
    else:
        change["after_sensitive"]["input"] = True

    plan["resource_changes"].append(gate)
    findings = _opa_findings(tmp_path, plan)

    assert "W5-PLAN-001" in {finding["policy_id"] for finding in findings}


def test_runtime_finding_uses_only_safe_bounded_allowlisted_fields(tmp_path: Path) -> None:
    plan = _base_plan()
    plan["variables"] = {"aws_region": {"value": "us-east-1"}}

    findings = _opa_findings(tmp_path, plan)

    assert len(findings) == 1
    finding = findings[0]
    assert set(finding) == {
        "schema_version",
        "policy_id",
        "severity",
        "resource_address",
        "category",
        "remediation_code",
        "exception_status",
    }
    assert finding == {
        "schema_version": "w5-003.policy-finding.v1",
        "policy_id": "W5-REG-001",
        "severity": "CRITICAL",
        "resource_address": "policy.region",
        "category": "REGION",
        "remediation_code": "USE_APPROVED_REGION",
        "exception_status": "NONE",
    }
    assert all(isinstance(value, str) and len(value) <= 240 for value in finding.values())


@pytest.mark.parametrize(
    ("mutation", "expected_policy"),
    [
        ("wrong_region", "W5-REG-001"),
        ("unsupported_aws", "W5-PLAN-001"),
        ("secret_material", "W5-SEC-001"),
        ("destructive_change", "W5-PLAN-002"),
    ],
)
def test_insecure_synthetic_plan_fails_for_intended_rule(
    tmp_path: Path, mutation: str, expected_policy: str
) -> None:
    plan = _base_plan()
    if mutation == "wrong_region":
        plan["variables"] = {"aws_region": {"value": "us-east-1"}}
    elif mutation == "unsupported_aws":
        plan["resource_changes"] = [
            {
                "address": "aws_lambda_function.unapproved",
                "type": "aws_lambda_function",
                "change": {"actions": ["create"], "after": {}},
            }
        ]
    elif mutation == "secret_material":
        plan["api_key"] = "".join(("runtime", "-", "only"))
    else:
        plan["resource_changes"][0]["change"] = {"actions": ["delete"], "after": None}

    findings = _opa_findings(tmp_path, plan)
    assert expected_policy in {finding["policy_id"] for finding in findings}


def test_empty_missing_or_partially_evaluated_policy_cannot_pass() -> None:
    assert (
        _eligibility(None, checkov_completed=True, checkov_failed=0, checkov_skipped=20) == "FAIL"
    )
    assert _eligibility([], checkov_completed=False, checkov_failed=0, checkov_skipped=20) == "FAIL"


def test_opa_and_checkov_disagreement_is_fail() -> None:
    assert _eligibility([], checkov_completed=True, checkov_failed=0, checkov_skipped=20) == "PASS"
    assert _eligibility([], checkov_completed=True, checkov_failed=1, checkov_skipped=20) == "FAIL"
    assert (
        _eligibility(
            [{"policy_id": "W5-REG-001"}],
            checkov_completed=True,
            checkov_failed=0,
            checkov_skipped=20,
        )
        == "FAIL"
    )
    assert _eligibility([], checkov_completed=True, checkov_failed=0, checkov_skipped=19) == "FAIL"


def test_checkov_secure_and_insecure_hcl_stays_under_pytest_tmp_path(tmp_path: Path) -> None:
    secure = tmp_path / "secure"
    insecure = tmp_path / "insecure"
    secure.mkdir()
    insecure.mkdir()
    (secure / "main.tf").write_text(
        'variable "synthetic_region" {\n  type = string\n}\n',
        encoding="utf-8",
        newline="\n",
    )
    (insecure / "main.tf").write_text(
        'resource "aws_s3_bucket" "public" {\n'
        '  bucket = "w5-003-insecure-example"\n'
        '  acl    = "public-read"\n'
        "}\n",
        encoding="utf-8",
        newline="\n",
    )

    secure_result = _checkov(secure)
    insecure_result = _checkov(insecure)

    assert secure_result.returncode == 0, secure_result.stdout + secure_result.stderr
    assert insecure_result.returncode != 0
    assert secure.is_relative_to(tmp_path) and insecure.is_relative_to(tmp_path)


def test_current_terraform_checkov_baseline_is_exact() -> None:
    completed = _checkov(ROOT / "infra")
    combined = completed.stdout + completed.stderr
    counts = re.search(
        r"Passed checks:\s*(\d+),\s*Failed checks:\s*(\d+),\s*Skipped checks:\s*(\d+)",
        combined,
    )

    assert completed.returncode == 0, combined
    assert counts is not None, "Checkov did not emit the required complete scan counts"
    assert tuple(map(int, counts.groups())) == (226, 0, 20)


def test_production_decision_requires_one_defined_consistent_value() -> None:
    from tools.platformctl.policy_runner import parse_production_decision

    value = {"schema_version": "w5-004.policy-decision.v2", "allow": True, "findings": []}
    payload = {"result": [{"expressions": [{"value": value}]}]}
    assert parse_production_decision(json.dumps(payload).encode()) == value
    for malformed in ({}, {"errors": []}, {"result": []}, {"result": [{"expressions": []}]}):
        with pytest.raises(ValueError):
            parse_production_decision(json.dumps(malformed).encode())


def test_statement_reordering_does_not_permit_policy_broadening() -> None:
    from tools.platformctl.policy_runner import policy_semantic_value

    first = {"Sid": "First", "Action": ["example:Read"], "Resource": "one"}
    second = {"Sid": "Second", "Action": ["example:List"], "Resource": "two"}
    assert policy_semantic_value(
        json.dumps({"Statement": [first, second]})
    ) == policy_semantic_value(json.dumps({"Statement": [second, first]}))
    with pytest.raises(ValueError):
        policy_semantic_value(json.dumps({"Statement": [first, first]}))
