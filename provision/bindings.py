"""Owner-approved immutable image and EKS bindings between HCP stages."""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

from tools import capstone_release as release

from provision.cleanup import session
from provision.hcp import digest
from provision.services import ServiceError, Services

WORKFLOW = "w12-prerequisite-images.yml"  # Existing tracked workflow; no new week-named script.
REGISTRY = "526338061652.dkr.ecr.ap-southeast-1.amazonaws.com"


def release_storage(
    services: Services, context: dict[str, Any], approve: Callable[[str], None]
) -> None:
    """Rebind recreated storage identities from the current HCP state, with owner review."""
    workspace = context["bindings"]["workspaces"]["sandbox"]
    state = services.current_state(workspace)
    metadata = services.hcp(f"/state-versions/{state['id']}")["data"]
    if metadata.get("attributes", {}).get("resources-processed") is not True:
        raise ServiceError("PUBLICATION_OUTPUTS_STILL_PROCESSING", "INDETERMINATE")
    outputs = services.hcp_pages(f"/state-versions/{state['id']}/outputs")
    matches = [
        o["attributes"]
        for o in outputs
        if o.get("attributes", {}).get("name") == "capstone_release_source_bucket_name"
    ]
    if len(matches) != 1 or matches[0].get("sensitive") is not False:
        raise ServiceError("APPLIED_PUBLICATION_BUCKET_OUTPUT_REQUIRED")
    bucket = matches[0]["value"]
    if not isinstance(bucket, str) or not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", bucket):
        raise ServiceError("PUBLICATION_BUCKET_IDENTITY_INVALID")
    sdk = session(services)
    encryption = sdk.client("s3").get_bucket_encryption(
        Bucket=bucket, ExpectedBucketOwner="526338061652"
    )["ServerSideEncryptionConfiguration"]["Rules"]
    if (
        len(encryption) != 1
        or encryption[0]["ApplyServerSideEncryptionByDefault"].get("SSEAlgorithm") != "aws:kms"
    ):
        raise ServiceError("PUBLICATION_KMS_ENCRYPTION_REQUIRED")
    key = sdk.client("kms").describe_key(
        KeyId=encryption[0]["ApplyServerSideEncryptionByDefault"]["KMSMasterKeyID"]
    )["KeyMetadata"]
    if key.get("KeyState") != "Enabled" or not key.get("Arn", "").startswith(
        "arn:aws:kms:ap-southeast-1:526338061652:key/"
    ):
        raise ServiceError("PUBLICATION_KMS_IDENTITY_INVALID")
    if services.current_state(workspace) != state:
        raise ServiceError("PUBLICATION_STATE_CHANGED")
    github_binding(services, "W12_SOURCE_BUCKET", bucket, approve)
    github_binding(services, "W12_RELEASE_KMS_KEY_ARN", key["Arn"], approve)
    context["bindings"]["publication"] = {
        "state": state,
        "bucket": bucket,
        "kms_key_arn": key["Arn"],
    }


def github_binding(
    services: Services, name: str, value: str, approve: Callable[[str], None]
) -> None:
    existing = [
        v for v in services.github_pages("/actions/variables", "variables") if v["name"] == name
    ]
    if len(existing) > 1:
        raise ServiceError("DUPLICATE_GITHUB_BINDING")
    if existing and existing[0]["value"] == value:
        return
    approve(f"BIND GITHUB {name} {value}")
    path = f"/actions/variables/{name}" if existing else "/actions/variables"
    services.github(path, "PATCH" if existing else "POST", {"name": name, "value": value})
    actual = services.github(f"/actions/variables/{name}")
    if actual.get("value") != value:
        raise ServiceError("GITHUB_BINDING_READBACK_FAILED")


def images(
    services: Services,
    context: dict[str, Any],
    save: Callable[[], None],
    approve: Callable[[str], None],
    run_id: int | None = None,
) -> dict[str, Any]:
    step: dict[str, Any] = context["results"].setdefault("images", {})
    commit = context["source"]["commit"]
    if run_id:
        if step.get("run_id") not in (None, run_id):
            raise ServiceError("PUBLICATION_RUN_CHANGED")
        step["run_id"] = run_id
        save()
    if not step.get("run_id"):
        if step.get("dispatch_attempted"):
            raise ServiceError(
                "PUBLICATION_DISPATCH_UNCERTAIN_SUPPLY_EXISTING_RUN_ID", "INDETERMINATE"
            )
        approve("DISPATCH PREREQUISITE PUBLICATION " + commit)
        step["dispatch_attempted"] = True
        save()
        response = services.github(
            f"/actions/workflows/{WORKFLOW}/dispatches", "POST", {"ref": "main"}
        )
        identity = response.get("workflow_run_id") if isinstance(response, dict) else None
        if type(identity) is not int or identity <= 0:
            raise ServiceError(
                "PUBLICATION_DISPATCH_UNCERTAIN_SUPPLY_EXISTING_RUN_ID", "INDETERMINATE"
            )
        step["run_id"] = identity
        save()
    run = services.github(f"/actions/runs/{step['run_id']}")
    if (
        run.get("head_sha") != commit
        or run.get("head_branch") != "main"
        or run.get("event") != "workflow_dispatch"
        or run.get("path") != f".github/workflows/{WORKFLOW}"
    ):
        raise ServiceError("PREREQUISITE_PUBLICATION_IDENTITY_MISMATCH")
    if run.get("status") != "completed":
        return {
            "classification": "IN_PROGRESS",
            "run_id": step["run_id"],
            "url": run["html_url"],
            "approval": "OWNER_APPROVES_PROTECTED_SANDBOX_IN_GITHUB",
        }
    if run.get("conclusion") != "success":
        raise ServiceError("PREREQUISITE_PUBLICATION_FAILED")
    tag = f"source-{commit}-{step['run_id']}-{run['run_attempt']}"
    client = session(services).client("ecr")
    digests = {}
    for kind in ("toolchain", "codebuild"):
        repository = "enterprise-ai/sandbox/w12-" + kind
        details = client.describe_images(
            registryId="526338061652", repositoryName=repository, imageIds=[{"imageTag": tag}]
        )["imageDetails"]
        if len(details) != 1 or not re.fullmatch(r"sha256:[0-9a-f]{64}", details[0]["imageDigest"]):
            raise ServiceError("PUBLISHED_IMMUTABLE_DIGEST_MISSING")
        digests[kind] = f"{REGISTRY}/{repository}@{details[0]['imageDigest']}"
    github_binding(services, "W12_BUILD_TOOLCHAIN_DIGEST", digests["toolchain"], approve)
    context["bindings"].setdefault("runtime_variables", {})["w12_codebuild_image_digest"] = digests[
        "codebuild"
    ]
    step.update(complete=True, classification="PASS", digests=digests)
    save()
    return step


def eks(
    services: Services,
    context: dict[str, Any],
    save: Callable[[], None],
    approve: Callable[[str], None],
) -> dict[str, Any]:
    cluster = (
        session(services).client("eks").describe_cluster(name="enterprise-ai-sandbox")["cluster"]
    )
    if cluster.get("status") != "ACTIVE" or cluster.get("arn") != (
        "arn:aws:eks:ap-southeast-1:526338061652:cluster/enterprise-ai-sandbox"
    ):
        raise ServiceError("EXACT_ACTIVE_EKS_CLUSTER_REQUIRED")
    issuer = cluster["identity"]["oidc"]["issuer"]
    if not re.fullmatch(r"https://oidc\.eks\.ap-southeast-1\.amazonaws\.com/id/[A-F0-9]+", issuer):
        raise ServiceError("EKS_ISSUER_INVALID")
    codebuild = context["bindings"].get("runtime_variables", {}).get("w12_codebuild_image_digest")
    if not codebuild:
        raise ServiceError("PUBLISHED_CODEBUILD_IMAGE_REQUIRED")
    review = context["results"]["hcp"]["foundation"]["review"]
    plan_raw = release._hcp_plan_json_bytes(review["plan_id"], services.hcp_token)
    if digest(plan_raw) != review["plan_sha256"]:
        raise ServiceError("FOUNDATION_PLAN_CHANGED")
    import json

    emails = (
        json.loads(plan_raw).get("variables", {}).get("alert_email_endpoints", {}).get("value", [])
    )
    if not isinstance(emails, list) or len(emails) != 2 or len(set(emails)) != 2:
        raise ServiceError("FOUNDATION_ALERT_BINDINGS_INVALID")
    topic = "arn:aws:sns:ap-southeast-1:526338061652:enterprise-ai-sandbox-alerts"
    subscriptions = []
    for page in (
        session(services)
        .client("sns")
        .get_paginator("list_subscriptions_by_topic")
        .paginate(TopicArn=topic)
    ):
        subscriptions.extend(page.get("Subscriptions", []))
    confirmed = [
        s["Endpoint"]
        for s in subscriptions
        if s.get("Protocol") == "email" and s.get("SubscriptionArn", "").startswith(topic + ":")
    ]
    if sorted(confirmed) != sorted(emails):
        raise ServiceError("OWNER_SNS_EMAIL_CONFIRMATIONS_REQUIRED")
    approve(f"BIND EKS ISSUER {issuer} AND REUSE REVIEWED CODEBUILD IMAGE FOR PROBE {codebuild}")
    context["bindings"]["runtime_variables"].update(
        w12_owner_approved_eks_issuer=issuer, w12_probe_image_digest=codebuild
    )
    save()
    return {
        "classification": "PASS",
        "cluster_arn": cluster["arn"],
        "issuer": issuer,
        "probe_image": codebuild,
        "confirmed_sns_endpoints": 2,
    }
