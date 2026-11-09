"""Owner-executed setup of independent HCP bootstrap refresh identities.

Default: read-only setup plan. --apply: exact typed approval, AWS IAM setup and
HCP environment-variable binding only. Never creates a Terraform run.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import boto3  # type: ignore[import-untyped]
from botocore.exceptions import ClientError  # type: ignore[import-untyped]

from provision.hcp import active_runs, canonical
from provision.iam_handoff import output
from provision.services import ServiceError, Services
from provision.setup import source_identity

WORKSPACE = "ws-LjfZ8rLyoFSmfE3P"
ACCOUNT = "526338061652"
REGION = "ap-southeast-1"
ROOT = Path(r"E:\AI\enterprise_ai_platform")
EVIDENCE = Path(r"E:\AI\evidence\enterprise_ai_platform\W12")
POLICY_NAME = "BootstrapRefreshExactExistingObjects"


def documents(
    root: Path,
    bucket: str,
    table: str,
    key: str,
    *,
    purpose: str = "refresh",
    aliases: list[str] | None = None,
) -> dict[str, Any]:
    """Existing-object refresh only; no resource create/delete or self-administration."""
    if (
        not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", bucket)
        or not re.fullmatch(r"[A-Za-z0-9_.-]{3,255}", table)
        or not re.fullmatch(rf"arn:aws:kms:{REGION}:{ACCOUNT}:key/[a-f0-9-]{{36}}", key)
    ):
        raise ServiceError("BOOTSTRAP_STORAGE_IDENTITY_INVALID")
    imports = (root / "infra/bootstrap/platform_iam_imports.tf").read_text(encoding="utf-8")
    ids = re.findall(r'^\s*id\s*=\s*"([^"\n]+)"', imports, re.MULTILINE)
    roles = sorted(
        {f"arn:aws:iam::{ACCOUNT}:role/{i}" for i in ids if "/" not in i and ":" not in i}
    )
    manifest = json.loads(
        (root / "infra/bootstrap/platform-iam-config/hcp-resources.json").read_bytes()
    )
    policies = sorted(p["arn"] for p in manifest["policies"].values())
    if len(roles) != 17 or len(policies) != 13:
        raise ServiceError("BOOTSTRAP_AUTHORITY_INVENTORY_MISMATCH")
    if purpose not in {"refresh", "teardown"} or any(
        not re.fullmatch(rf"arn:aws:kms:{REGION}:{ACCOUNT}:alias/[\w/-]+", alias)
        for alias in (aliases or [])
    ):
        raise ServiceError("BOOTSTRAP_AUTHORITY_PURPOSE_OR_ALIAS_INVALID")
    statements: list[dict[str, Any]] = []

    def allow(actions: list[str], resources: list[str]) -> None:
        statements.append({"Effect": "Allow", "Action": actions, "Resource": resources})

    allow(
        [
            "iam:GetRole",
            "iam:ListRolePolicies",
            "iam:GetRolePolicy",
            "iam:ListAttachedRolePolicies",
            "iam:ListRoleTags",
        ],
        roles,
    )
    allow(["iam:GetPolicy", "iam:GetPolicyVersion", "iam:ListPolicyVersions"], policies)
    managed = sorted(set(re.findall(r"arn:aws:iam::aws:policy/[A-Za-z0-9_/+=,.@-]+", imports)))
    if managed:
        allow(["iam:GetPolicy", "iam:GetPolicyVersion"], managed)
    allow(
        ["iam:GetOpenIDConnectProvider"],
        [
            f"arn:aws:iam::{ACCOUNT}:oidc-provider/{host}"
            for host in ("app.terraform.io", "token.actions.githubusercontent.com")
        ],
    )
    allow(
        [
            "s3:ListBucket",
            "s3:GetBucketAcl",
            "s3:GetBucketLocation",
            "s3:GetBucketPolicy",
            "s3:GetBucketPolicyStatus",
            "s3:GetBucketTagging",
            "s3:GetBucketVersioning",
            "s3:GetBucketPublicAccessBlock",
            "s3:GetEncryptionConfiguration",
            "s3:GetLifecycleConfiguration",
            "s3:GetBucketOwnershipControls",
            "s3:GetBucketLogging",
            "s3:GetBucketObjectLockConfiguration",
            "s3:GetBucketWebsite",
            "s3:GetReplicationConfiguration",
            "s3:GetBucketCORS",
            "s3:GetAccelerateConfiguration",
            "s3:GetBucketRequestPayment",
        ],
        [f"arn:aws:s3:::{bucket}"],
    )
    allow(
        [
            "dynamodb:DescribeTable",
            "dynamodb:DescribeContinuousBackups",
            "dynamodb:DescribeTimeToLive",
            "dynamodb:ListTagsOfResource",
            "dynamodb:GetResourcePolicy",
            "dynamodb:DescribeContributorInsights",
        ],
        [f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/{table}"],
    )
    allow(
        ["kms:DescribeKey", "kms:GetKeyPolicy", "kms:GetKeyRotationStatus", "kms:ListResourceTags"],
        [key],
    )
    # ListAliases has no resource-level authorization. No cryptography is granted.
    statements.append(
        {
            "Effect": "Allow",
            "Action": ["kms:ListAliases"],
            "Resource": ["*"],
            "Condition": {"StringEquals": {"aws:RequestedRegion": REGION}},
        }
    )
    result = {}
    for phase in ("plan", "apply"):
        grants = list(statements)
        if phase == "apply":
            grants += [
                {
                    "Effect": "Allow",
                    "Action": [
                        "iam:UpdateAssumeRolePolicy",
                        "iam:TagRole",
                        "iam:UntagRole",
                        "iam:PutRolePolicy",
                    ],
                    "Resource": roles,
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "iam:CreatePolicyVersion",
                        "iam:DeletePolicyVersion",
                        "iam:SetDefaultPolicyVersion",
                    ],
                    "Resource": policies,
                },
                {
                    "Effect": "Allow",
                    "Action": ["s3:PutBucketTagging"],
                    "Resource": [f"arn:aws:s3:::{bucket}"],
                },
                {
                    "Effect": "Allow",
                    "Action": ["dynamodb:TagResource", "dynamodb:UntagResource"],
                    "Resource": [f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/{table}"],
                },
                {
                    "Effect": "Allow",
                    "Action": ["kms:TagResource", "kms:UntagResource"],
                    "Resource": [key],
                },
            ]
            if purpose == "teardown":
                grants += [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "iam:DeleteRole",
                            "iam:DeleteRolePolicy",
                            "iam:DetachRolePolicy",
                            "iam:ListInstanceProfilesForRole",
                        ],
                        "Resource": roles,
                    },
                    {"Effect": "Allow", "Action": ["iam:DeletePolicy"], "Resource": policies},
                    {
                        "Effect": "Allow",
                        "Action": [
                            "s3:DeleteBucket",
                            "s3:DeleteBucketPolicy",
                            "s3:PutBucketPublicAccessBlock",
                            "s3:PutBucketOwnershipControls",
                            "s3:PutEncryptionConfiguration",
                            "s3:PutLifecycleConfiguration",
                            "s3:PutBucketVersioning",
                        ],
                        "Resource": [f"arn:aws:s3:::{bucket}"],
                    },
                    {
                        "Effect": "Allow",
                        "Action": ["dynamodb:DeleteTable"],
                        "Resource": [f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/{table}"],
                    },
                    {"Effect": "Allow", "Action": ["kms:ScheduleKeyDeletion"], "Resource": [key]},
                ]
                if aliases:
                    grants.append(
                        {
                            "Effect": "Allow",
                            "Action": ["kms:DeleteAlias"],
                            "Resource": [key, *aliases],
                        }
                    )
        name = f"enterprise-ai-bootstrap-{purpose}-{phase}"
        subject = (
            "organization:Enterprise_AI_AWS_Arch:project:enterprise-ai-capstone:"
            f"workspace:enterprise-ai-bootstrap:run_phase:{phase}"
        )
        # Combine only statements with identical scope/conditions. This preserves
        # least privilege while staying within the role's aggregate inline limit.
        compact: dict[bytes, dict[str, Any]] = {}
        for grant in grants:
            scope = canonical({k: v for k, v in grant.items() if k != "Action"})
            if scope not in compact:
                compact[scope] = dict(grant, Action=[])
            compact[scope]["Action"] = sorted(set(compact[scope]["Action"]) | set(grant["Action"]))
        result[phase] = {
            "name": name,
            "arn": f"arn:aws:iam::{ACCOUNT}:role/{name}",
            "trust": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "sts:AssumeRoleWithWebIdentity",
                        "Principal": {
                            "Federated": f"arn:aws:iam::{ACCOUNT}:oidc-provider/app.terraform.io"
                        },
                        "Condition": {
                            "StringEquals": {
                                "app.terraform.io:aud": "aws.workload.identity",
                                "app.terraform.io:sub": subject,
                            }
                        },
                    }
                ],
            },
            "policy": {"Version": "2012-10-17", "Statement": list(compact.values())},
        }
        if len(canonical(result[phase]["policy"])) > 10240:
            raise ServiceError("BOOTSTRAP_INLINE_POLICY_TOO_LARGE")
    return result


def variable_snapshot(services: Services) -> dict[str, Any]:
    keys = {"TFC_AWS_PROVIDER_AUTH", "TFC_AWS_PLAN_ROLE_ARN", "TFC_AWS_APPLY_ROLE_ARN"}
    result = {}
    for row in services.hcp_pages(f"/workspaces/{WORKSPACE}/vars"):
        attrs = row["attributes"]
        if attrs.get("key") not in keys:
            continue
        if attrs["key"] in result or attrs.get("category") != "env" or attrs.get("sensitive"):
            raise ServiceError("BOOTSTRAP_VARIABLE_AMBIGUOUS_OR_UNREADABLE")
        result[attrs["key"]] = {
            "id": row["id"],
            "value": attrs.get("value"),
            "hcl": attrs.get("hcl", False),
        }
    return result


def check_role(iam: Any, spec: dict[str, Any]) -> bool:
    try:
        role = iam.get_role(RoleName=spec["name"])["Role"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchEntity":
            return False
        raise
    if (
        role["Arn"] != spec["arn"]
        or role["AssumeRolePolicyDocument"] != spec["trust"]
        or role.get("PermissionsBoundary")
    ):
        raise ServiceError("EXISTING_BOOTSTRAP_ROLE_CONFLICT")
    if iam.list_attached_role_policies(RoleName=spec["name"])["AttachedPolicies"]:
        raise ServiceError("EXISTING_BOOTSTRAP_ROLE_EXTRA_AUTHORITY")
    names = iam.list_role_policies(RoleName=spec["name"])["PolicyNames"]
    if set(names) - {POLICY_NAME}:
        raise ServiceError("EXISTING_BOOTSTRAP_ROLE_EXTRA_AUTHORITY")
    if (
        names
        and iam.get_role_policy(RoleName=spec["name"], PolicyName=POLICY_NAME)["PolicyDocument"]
        != spec["policy"]
    ):
        raise ServiceError("EXISTING_BOOTSTRAP_POLICY_CONFLICT")
    return True


def run(args: argparse.Namespace) -> None:
    destination = args.plan.resolve()
    if not destination.is_relative_to(EVIDENCE.resolve()):
        raise ServiceError("SETUP_PLAN_MUST_USE_EXTERNAL_EVIDENCE_ROOT")
    services = Services(ROOT, args.profile)
    source = source_identity(services)
    session = boto3.Session(profile_name=args.profile, region_name=REGION)
    if session.client("sts").get_caller_identity()["Account"] != ACCOUNT:
        raise ServiceError("AWS_ACCOUNT_MISMATCH")
    ws = services.hcp(f"/workspaces/{WORKSPACE}")["data"]["attributes"]
    if (
        ws.get("name") != "enterprise-ai-bootstrap"
        or ws.get("execution-mode") != "remote"
        or ws.get("auto-apply") is not False
        or active_runs(services, WORKSPACE)
    ):
        raise ServiceError("BOOTSTRAP_WORKSPACE_NOT_IDLE_REMOTE_MANUAL")
    state = services.current_state(WORKSPACE)
    bucket, table, key = (
        output(services, state, k)
        for k in ("state_bucket_name", "lock_table_name", "state_kms_key_arn")
    )
    aliases: list[str] = []
    if args.purpose == "teardown":
        for page in session.client("kms").get_paginator("list_aliases").paginate(KeyId=key):
            aliases.extend(
                a["AliasArn"]
                for a in page["Aliases"]
                if a.get("TargetKeyId") == key.rsplit("/", 1)[-1]
            )
    specs = documents(ROOT, bucket, table, key, purpose=args.purpose, aliases=sorted(aliases))
    plan = {
        "source": source,
        "state": state,
        "purpose": args.purpose,
        "variables_before": variable_snapshot(services),
        "roles": specs,
    }
    sha = hashlib.sha256(canonical(plan)).hexdigest()
    iam = session.client("iam")
    for spec in specs.values():
        check_role(iam, spec)
        analyzer = session.client("accessanalyzer")
        page_token: dict[str, str] = {}
        for _ in range(100):
            page = analyzer.validate_policy(
                policyDocument=json.dumps(spec["policy"]),
                policyType="IDENTITY_POLICY",
                **page_token,
            )
            if any(f["findingType"] in {"ERROR", "SECURITY_WARNING"} for f in page["findings"]):
                raise ServiceError("BOOTSTRAP_SETUP_POLICY_VALIDATION_FAILED")
            if not page.get("nextToken"):
                break
            page_token = {"nextToken": page["nextToken"]}
        else:
            raise ServiceError("BOOTSTRAP_SETUP_VALIDATION_INCOMPLETE")
    if not args.apply:
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("x", encoding="utf-8") as stream:
            json.dump(
                {
                    "plan": plan,
                    "sha256": sha,
                    "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
                },
                stream,
                indent=2,
            )
        print(
            json.dumps(
                {
                    "Result": "BOOTSTRAP_AUTHORITY_PLAN_READY",
                    "Plan": str(destination),
                    "SHA256": sha,
                    "CloudMutation": False,
                }
            )
        )
        return
    saved = json.loads(destination.read_bytes())
    if (
        saved["sha256"] != sha
        or saved["plan"] != plan
        or datetime.now(UTC) >= datetime.fromisoformat(saved["expires_at"])
    ):
        raise ServiceError("SETUP_PLAN_CHANGED_OR_EXPIRED_PREPARE_FRESH_PLAN")
    if (
        input(f"Type SETUP BOOTSTRAP AUTHORITY {sha}: ").strip()
        != f"SETUP BOOTSTRAP AUTHORITY {sha}"
    ):
        raise ServiceError("OWNER_SETUP_NOT_APPROVED")
    # Readback after approval; no mutation until source/workspace/state still match.
    if (
        source_identity(services) != source
        or services.current_state(WORKSPACE) != state
        or variable_snapshot(services) != plan["variables_before"]
        or active_runs(services, WORKSPACE)
    ):
        raise ServiceError("SETUP_BINDINGS_CHANGED_DURING_APPROVAL")
    journal = destination.with_suffix(".events.jsonl")

    def event(operation: str, status: str) -> None:
        with journal.open("a", encoding="utf-8") as stream:
            stream.write(
                json.dumps(
                    {"operation": operation, "status": status, "at": datetime.now(UTC).isoformat()}
                )
                + "\n"
            )

    for phase, spec in specs.items():
        if not check_role(iam, spec):
            event("create-role-" + phase, "ATTEMPTED")
            iam.create_role(
                RoleName=spec["name"],
                AssumeRolePolicyDocument=json.dumps(spec["trust"]),
                Description="Independent owner-managed HCP bootstrap refresh authority",
            )
            event("create-role-" + phase, "RETURNED")
        if POLICY_NAME not in iam.list_role_policies(RoleName=spec["name"])["PolicyNames"]:
            event("put-policy-" + phase, "ATTEMPTED")
            iam.put_role_policy(
                RoleName=spec["name"],
                PolicyName=POLICY_NAME,
                PolicyDocument=json.dumps(spec["policy"]),
            )
            event("put-policy-" + phase, "RETURNED")
        check_role(iam, spec)
        if POLICY_NAME not in iam.list_role_policies(RoleName=spec["name"])["PolicyNames"]:
            raise ServiceError("BOOTSTRAP_ROLE_POLICY_READBACK_MISSING")
    wanted = {
        "TFC_AWS_PROVIDER_AUTH": "true",
        **{f"TFC_AWS_{phase.upper()}_ROLE_ARN": spec["arn"] for phase, spec in specs.items()},
    }
    for key, value in wanted.items():
        old = plan["variables_before"].get(key)
        if variable_snapshot(services).get(key) != old:
            raise ServiceError("SETUP_VARIABLE_CHANGED_BEFORE_WRITE")
        if old and old["value"] == value and old["hcl"] is False:
            continue
        attrs = {"key": key, "value": value, "category": "env", "hcl": False, "sensitive": False}
        event(key, "ATTEMPTED")
        services.hcp(
            f"/workspaces/{WORKSPACE}/vars" + (f"/{old['id']}" if old else ""),
            "PATCH" if old else "POST",
            {"data": {"type": "vars", "attributes": attrs}},
        )
        event(key, "RETURNED")
    final = variable_snapshot(services)
    if any(final.get(k, {}).get("value") != v for k, v in wanted.items()):
        raise ServiceError("BOOTSTRAP_SETUP_READBACK_FAILED")
    result = {
        "Result": "PASS_BOOTSTRAP_REFRESH_AUTHORITY_BOUND",
        "PlanSHA256": sha,
        "BootstrapExecutionInputs": {
            phase + "_role_arn": spec["arn"] for phase, spec in specs.items()
        },
        "TerraformRunCreated": False,
        "ApplyRequested": False,
        "TokenPrinted": False,
    }
    destination.with_suffix(".result.json").write_text(
        json.dumps(result, indent=2), encoding="utf-8"
    )
    print(json.dumps(result, indent=2))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--profile", default="enterprise-ai-platform-w6-004")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--purpose", choices=("refresh", "teardown"), default="refresh")
    args = parser.parse_args()
    try:
        run(args)
    except Exception as exc:
        # Never emit SDK exceptions, headers, tokens or policy bodies.
        print(
            json.dumps(
                {
                    "Result": "BOOTSTRAP_SETUP_STOPPED",
                    "ErrorCode": exc.code
                    if isinstance(exc, ServiceError)
                    else "SERVICE_FAILURE_INSPECT_JOURNAL_BEFORE_RETRY",
                    "TerraformRunCreated": False,
                    "TokenPrinted": False,
                }
            )
        )
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
