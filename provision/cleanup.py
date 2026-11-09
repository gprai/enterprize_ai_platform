"""Bounded cleanup around HCP destroy. No local Terraform state or apply commands."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import boto3  # type: ignore[import-untyped]

from provision.services import ServiceError, Services


def retained(kind: str) -> bool:
    # Conservative default retains the entire evidence-storage/key lifecycle,
    # including policies/encryption, rather than leaving an unreadable bucket.
    return kind.startswith(("aws_iam_", "aws_s3_", "aws_kms_"))


def destroy_inventory(services: Services, workspace: str, *, bootstrap: bool) -> dict[str, Any]:
    resources = services.resources(workspace)
    inventory = [
        {"address": r["attributes"]["address"], "type": r["attributes"]["provider-type"]}
        for r in resources
        if not r["attributes"]["address"].startswith("data.")
        and ".data." not in r["attributes"]["address"]
    ]
    if len({r["address"] for r in inventory}) != len(inventory):
        raise ServiceError("DUPLICATE_RESOURCE_INVENTORY")
    targets = sorted(r["address"] for r in inventory if bootstrap or not retained(r["type"]))
    if not targets:
        raise ServiceError("NO_DESTROY_TARGETS_RECONCILE_RETAINED_STATE")
    return {
        "inventory": inventory,
        "targets": targets,
        "retained": sorted(r["address"] for r in inventory if r["address"] not in targets),
    }


def validate_destroy(plan: dict[str, Any], step: dict[str, Any]) -> None:
    targets = set(step["targets"])
    observed: set[str] = set()
    cleanup: list[dict[str, str]] = []
    native: list[dict[str, str]] = []
    for change in plan.get("resource_changes", []):
        if change.get("mode") != "managed" or change["change"]["actions"] == ["no-op"]:
            continue
        address, kind = change["address"], change["type"]
        if (
            address not in targets
            or change["change"]["actions"] != ["delete"]
            or (step["target"] == "sandbox" and retained(kind))
        ):
            raise ServiceError("DESTROY_OUTSIDE_EXACT_RETAINED_BOUNDARY")
        observed.add(address)
        before = change["change"]["before"]
        identity = before.get("id")
        if not isinstance(identity, str) or not identity:
            raise ServiceError("DESTROY_NATIVE_IDENTITY_MISSING")
        native.append({"address": address, "type": kind, "id": identity})
        if kind == "aws_ecr_repository":
            name = before.get("name", "")
            arn = before.get("arn", "")
            if (
                not name.startswith("enterprise-ai/sandbox/")
                or arn != f"arn:aws:ecr:ap-southeast-1:526338061652:repository/{name}"
            ):
                raise ServiceError("ECR_PURGE_REPOSITORY_BINDING_MISMATCH")
            cleanup.append({"name": name, "arn": arn})
    if not observed:
        raise ServiceError("NO_DELETIONS_IN_DESTROY_PLAN")
    step["cleanup_repositories"] = cleanup
    step["native_targets"] = native


def purge_bootstrap_buckets(
    client: Any, step: dict[str, Any], check_current: Callable[[], None]
) -> dict[str, int]:
    """Only bootstrap buckets in the separately approved exact destroy plan."""
    counts = {}
    for target in step["native_targets"]:
        if target["type"] != "aws_s3_bucket":
            continue
        bucket = target["id"]
        removed = 0
        for _ in range(20):
            check_current()
            batches = client.get_paginator("list_object_versions").paginate(
                Bucket=bucket, ExpectedBucketOwner="526338061652"
            )
            found = False
            for page in batches:
                objects = [
                    {"Key": v["Key"], "VersionId": v["VersionId"]}
                    for v in page.get("Versions", []) + page.get("DeleteMarkers", [])
                ]
                if not objects:
                    continue
                found = True
                check_current()
                response = client.delete_objects(
                    Bucket=bucket,
                    ExpectedBucketOwner="526338061652",
                    Delete={"Objects": objects, "Quiet": True},
                )
                if response.get("Errors"):
                    raise ServiceError("BOOTSTRAP_BUCKET_PURGE_FAILED")
                removed += len(objects)
            for page in client.get_paginator("list_multipart_uploads").paginate(
                Bucket=bucket, ExpectedBucketOwner="526338061652"
            ):
                for upload in page.get("Uploads", []):
                    found = True
                    check_current()
                    client.abort_multipart_upload(
                        Bucket=bucket,
                        Key=upload["Key"],
                        UploadId=upload["UploadId"],
                        ExpectedBucketOwner="526338061652",
                    )
            if not found:
                counts[bucket] = removed
                break
        else:
            raise ServiceError("BOOTSTRAP_BUCKET_PURGE_NOT_CONVERGED", "INDETERMINATE")
    return counts


def purge_ecr(
    client: Any, repositories: list[dict[str, str]], check_current: Callable[[], None]
) -> dict[str, int]:
    """Delete OCI indexes first, then children; relist until empty, bounded to 20 passes."""
    result: dict[str, int] = {}
    for repository in repositories:
        name = repository["name"]
        deleted: set[str] = set()
        for _ in range(20):
            check_current()
            entries = [
                entry
                for page in client.get_paginator("describe_images").paginate(
                    registryId="526338061652", repositoryName=name
                )
                for entry in page["imageDetails"]
            ]
            if not entries:
                result[name] = len(deleted)
                break
            parents = [
                e
                for e in entries
                if e.get("imageManifestMediaType")
                in {
                    "application/vnd.docker.distribution.manifest.list.v2+json",
                    "application/vnd.oci.image.index.v1+json",
                }
            ]
            ids = sorted({e["imageDigest"] for e in (parents or entries)})
            for offset in range(0, len(ids), 100):
                check_current()
                batch = ids[offset : offset + 100]
                response = client.batch_delete_image(
                    registryId="526338061652",
                    repositoryName=name,
                    imageIds=[{"imageDigest": item} for item in batch],
                )
                failures = response.get("failures", [])
                if any(
                    f.get("failureCode") not in {"ImageNotFound", "ImageReferencedByManifestList"}
                    for f in failures
                ):
                    raise ServiceError("ECR_PURGE_FAILED")
                deleted.update(i["imageDigest"] for i in response.get("imageIds", []))
        else:
            raise ServiceError("ECR_PURGE_NOT_CONVERGED", "INDETERMINATE")
    return result


def session(services: Services) -> Any:
    return boto3.Session(profile_name=services.profile, region_name="ap-southeast-1")


def reconcile(services: Services, step: dict[str, Any], workspace: str) -> dict[str, Any]:
    remaining = {
        r["attributes"]["address"]
        for r in services.resources(workspace)
        if not r["attributes"]["address"].startswith("data.")
        and ".data." not in r["attributes"]["address"]
    }
    if remaining - set(step["retained"]):
        raise ServiceError("UNEXPECTED_MANAGED_STATE_REMAINS")
    sdk = session(services)
    checks: list[dict[str, str]] = []
    # Exact native identities taken from the reviewed destroy plan, never a name wildcard.
    operations = {
        "aws_eks_cluster": ("eks", "describe_cluster", "name", {"ResourceNotFoundException"}),
        "aws_ecr_repository": (
            "ecr",
            "describe_repositories",
            "repositoryNames",
            {"RepositoryNotFoundException"},
        ),
        "aws_opensearch_domain": (
            "opensearch",
            "describe_domain",
            "DomainName",
            {"ResourceNotFoundException"},
        ),
        "aws_codebuild_project": ("codebuild", "batch_get_projects", "names", set()),
        "aws_vpc": ("ec2", "describe_vpcs", "VpcIds", {"InvalidVpcID.NotFound"}),
    }
    from botocore.exceptions import ClientError  # type: ignore[import-untyped]

    for item in step["native_targets"]:
        if item["type"] not in operations:
            continue
        service, method, parameter, missing_codes = operations[item["type"]]
        value: Any = (
            [item["id"]] if parameter in {"names", "VpcIds", "repositoryNames"} else item["id"]
        )
        try:
            response = getattr(sdk.client(service), method)(**{parameter: value})
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in missing_codes:
                raise ServiceError("NATIVE_ABSENCE_INDETERMINATE", "INDETERMINATE") from None
            absent = True
        else:
            absent = service == "codebuild" and response.get("projectsNotFound") == [item["id"]]
        checks.append({"address": item["address"], "status": "ABSENT" if absent else "PRESENT"})
    if any(c["status"] != "ABSENT" for c in checks):
        raise ServiceError("NATIVE_RESOURCES_STILL_PRESENT", "INDETERMINATE")
    return {
        "hcp_remaining_retained_addresses": sorted(remaining),
        "native_primary_resources": checks,
        "native_residue_scope": "PRIMARY_RESOURCES_ONLY_UNTAGGED_ORPHANS_NOT_PROVEN_ABSENT",
        "cost_reconciliation": "OPEN_DELAYED_ESTIMATED_BILLING_REQUIRES_LATER_CHECK",
        "classification": "HCP_DESTROY_COMPLETE_RECONCILIATION_OPEN",
    }
