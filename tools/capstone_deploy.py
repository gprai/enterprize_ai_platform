"""Bounded CodeBuild deployment of a hashed W6-derived TLS package."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

from tools.capstone_release import (
    CONTROL_KEY,
    SOURCE_KEY,
    ReleaseError,
    _canonical_bytes,
    _canonical_document,
    _fields,
    _file_inventory,
    _make_zip,
    _zip_files,
    application_image_from_ready,
    encode_s3v_locator,
    load_prior_rollback_lineage,
    validate_primary_source_bundle,
    validate_record,
    validate_render_inputs,
    validate_rendered_release,
)
from tools.w6_001_k8s import TEMPLATE_FILES, W12RenderBindings, render_w12_release

ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = ROOT / "deploy/k8s"
OVERLAY = ROOT / "deploy/capstone/api-overlay.yaml"
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
IMAGE_DIGEST = re.compile(
    r"[a-z0-9][a-z0-9.-]*(?::[0-9]{1,5})?/[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}\Z"
)
NAMESPACE = "enterprise-ai-sandbox"
SERVICE = "enterprise-ai-api"


def _hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _kubectl(*args: str, timeout: int = 20, input_text: str | None = None) -> str:
    executable = shutil.which("kubectl")
    if executable is None or not Path(executable).is_absolute():
        raise ReleaseError("KUBECTL_EXECUTABLE_UNAVAILABLE")
    result = subprocess.run(  # noqa: S603 -- fixed executable, no shell, bounded arguments
        [executable, "--request-timeout=15s", *args],
        input=input_text,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        raise ReleaseError("KUBERNETES_COMMAND_FAILED")
    if len(result.stdout) > 262_144:
        raise ReleaseError("KUBERNETES_OUTPUT_OVERSIZE")
    return result.stdout


def _required_env(name: str) -> str:
    value = os.environ.get(name, "")
    if not value or any(c.isspace() for c in value):
        raise ReleaseError("MISSING_OR_INVALID_" + name)
    return value


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _pair(root: Path, stem: str) -> tuple[bytes, bytes]:
    return (root / (stem + ".json")).read_bytes(), (root / (stem + ".sha256")).read_bytes()


def _tree_files(root: Path) -> dict[str, bytes]:
    if root.is_symlink() or not root.is_dir():
        raise ReleaseError("EXTRACTED_SOURCE_ROOT_INVALID")
    result: dict[str, bytes] = {}
    for path in root.rglob("*"):
        if path.is_symlink() or (not path.is_file() and not path.is_dir()):
            raise ReleaseError("EXTRACTED_SOURCE_UNSAFE_ENTRY")
        if path.is_file():
            name = path.relative_to(root).as_posix()
            if name.casefold() in {item.casefold() for item in result}:
                raise ReleaseError("EXTRACTED_SOURCE_ALIAS")
            result[name] = path.read_bytes()
    return result


def _s3_version(bucket: str, key: str, version: str, digest: str) -> bytes:
    if not version or version == "null" or not HEX64.fullmatch(digest):
        raise ReleaseError("S3_VERSION_OR_DIGEST_REQUIRED")
    import boto3  # type: ignore[import-untyped]

    response = boto3.client("s3").get_object(
        Bucket=bucket, Key=key, VersionId=version, ChecksumMode="ENABLED"
    )
    if response.get("VersionId") != version or response.get("ServerSideEncryption") != "aws:kms":
        raise ReleaseError("S3_VERSION_OR_ENCRYPTION_MISMATCH")
    raw = response["Body"].read(1_073_741_825)
    if not isinstance(raw, bytes):
        raise ReleaseError("S3_OBJECT_BODY_TYPE")
    if len(raw) > 1_073_741_824 or _sha(raw) != digest:
        raise ReleaseError("S3_OBJECT_DIGEST_MISMATCH")
    checksum = response.get("ChecksumSHA256")
    if not checksum or base64.b64decode(checksum, validate=True).hex() != digest:
        raise ReleaseError("S3_FULL_CHECKSUM_MISMATCH")
    return raw


def _record_chain(root: Path) -> tuple[list[dict[str, Any]], list[bytes]]:
    raws: list[bytes] = []
    records: list[dict[str, Any]] = []
    for revision, status in enumerate(
        ("REQUESTED", "READY_FOR_OWNER", "APPROVED", "APPLIED"), start=1
    ):
        folder = root / f"records/r{revision}" if revision < 4 else root
        raw, sidecar = _pair(folder, "release-record")
        record = validate_record(raw, sidecar, previous=raws[-1] if raws else None)
        if record["revision"] != revision or record["status"] != status:
            raise ReleaseError("CONTROL_RECORD_CHAIN_ORDER")
        raws.append(raw)
        records.append(record)
    if _sha(raws[-1]) != _required_env("W12_RECORD_SHA256"):
        raise ReleaseError("APPLIED_RECORD_DIGEST_MISMATCH")
    first = records[0]
    for record in records[1:]:
        if (
            record["source"]["repository"] != first["source"]["repository"]
            or record["source"]["commit"] != first["source"]["commit"]
            or record["source"]["tree"] != first["source"]["tree"]
            or record["operation"] != first["operation"]
        ):
            raise ReleaseError("CONTROL_RECORD_IDENTITY_DRIFT")
    if (
        first["source"]["commit"] != _required_env("W12_GIT_COMMIT")
        or records[-1]["terraform"]["run_id"] != _required_env("W12_HCP_RUN_ID")
        or records[-1]["operation"] != _required_env("W12_OPERATION")
    ):
        raise ReleaseError("CONTROL_ENVIRONMENT_BINDING")
    return records, raws


def _source(
    args: argparse.Namespace,
) -> tuple[dict[str, Any], dict[str, bytes], dict[str, Any], list[dict[str, Any]], list[bytes]]:
    primary = Path(_required_env("CODEBUILD_SRC_DIR")).resolve(strict=True)
    control = Path(_required_env("CODEBUILD_SRC_DIR_W12_CONTROL")).resolve(strict=True)
    source_version = _required_env("W12_SOURCE_VERSION_ID")
    control_version = _required_env("W12_CONTROL_VERSION_ID")
    if (
        os.environ.get("CODEBUILD_SOURCE_VERSION") != source_version
        or os.environ.get("CODEBUILD_SOURCE_VERSION_W12_CONTROL") != control_version
    ):
        raise ReleaseError("CODEBUILD_SOURCE_VERSION_MISMATCH", "INDETERMINATE")
    records, raws = _record_chain(control)
    requested, ready, approved, applied = records
    transition_fields = {
        2: [
            "schema_version",
            "record_id",
            "from_revision",
            "to_revision",
            "parent_record_sha256",
            "source_manifest_sha256",
            "w6_release_hashes_sha256",
            "source_archive_sha256",
            "source_version_id",
            "opa_receipt_sha256",
            "infracost_result_id",
            "observed_at_utc",
        ],
        3: [
            "schema_version",
            "transition",
            "record_id",
            "from_revision",
            "to_revision",
            "parent_record_sha256",
            "github_approval",
            "hcp_authenticated_resource",
            "hcp_apply",
            "observed_at_utc",
        ],
        4: [
            "schema_version",
            "record_id",
            "from_revision",
            "to_revision",
            "parent_record_sha256",
            "hcp_run_id",
            "hcp_plan_id",
            "hcp_apply_id",
            "input_state_version_id",
            "output_state_version_id",
            "output_state_lineage",
            "output_state_serial",
            "render_inputs_sha256",
            "observed_at_utc",
        ],
    }
    for revision in (2, 3, 4):
        evidence_raw, evidence_sidecar = _pair(
            control / f"records/r{revision}", "transition-evidence"
        )
        evidence = _canonical_document(
            evidence_raw, fields=transition_fields[revision], code="CONTROL_TRANSITION"
        )
        if (
            evidence_sidecar != (_sha(evidence_raw) + "\n").encode("ascii")
            or evidence["record_id"] != applied["record_id"]
            or evidence["from_revision"] != revision - 1
            or evidence["to_revision"] != revision
            or evidence["parent_record_sha256"] != _sha(raws[revision - 2])
        ):
            raise ReleaseError("CONTROL_TRANSITION_CHAIN")
    if (
        applied["source"]["s3_key"] != SOURCE_KEY
        or applied["source"]["s3_version_id"] != source_version
        or applied["source"]["archive_sha256"] != _required_env("W12_SOURCE_ARCHIVE_SHA256")
    ):
        raise ReleaseError("PRIMARY_SOURCE_BINDING")
    if any(record["source"] != ready["source"] for record in records[2:]):
        raise ReleaseError("SOURCE_IDENTITY_CHANGED_AFTER_READY")
    bucket = applied["source"]["s3_bucket"]
    source_raw = _s3_version(
        bucket, SOURCE_KEY, source_version, applied["source"]["archive_sha256"]
    )
    import boto3

    source_head = boto3.client("s3", region_name=applied["deployment"]["region"]).head_object(
        Bucket=bucket,
        Key=SOURCE_KEY,
        VersionId=source_version,
    )
    observed_kms = source_head.get("SSEKMSKeyId")
    if (
        source_head.get("VersionId") != source_version
        or source_head.get("ServerSideEncryption") != "aws:kms"
        or observed_kms != _required_env("W12_RELEASE_KMS_KEY_ARN")
        or not isinstance(observed_kms, str)
        or not observed_kms.startswith(
            f"arn:aws:kms:{applied['deployment']['region']}:{applied['deployment']['account_id']}:key/"
        )
    ):
        raise ReleaseError("RESULT_KMS_KEY_NOT_SOURCE_BOUND")
    os.environ["W12_RESULT_KMS_KEY_ARN"] = observed_kms
    source_evidence = {item["kind"]: item["sha256"] for item in ready["evidence"]}
    manifest_sha = _required_env("W12_SOURCE_MANIFEST_SHA256")
    if source_evidence.get("w12_source_manifest") != manifest_sha:
        raise ReleaseError("SOURCE_MANIFEST_RECORD_BINDING")
    w6_sha = ready["deployment"]["w6_release_hashes_sha256"]
    if source_evidence.get("w6_release_hashes") != w6_sha:
        raise ReleaseError("W6_INVENTORY_RECORD_BINDING")
    source_files = validate_primary_source_bundle(
        source_raw,
        archive_sha256=applied["source"]["archive_sha256"],
        manifest_sha256=manifest_sha,
        w6_sha256=w6_sha,
        commit=requested["source"]["commit"],
        tree=requested["source"]["tree"],
    )
    if source_files != _tree_files(primary):
        raise ReleaseError("PRIMARY_EXTRACTED_BYTES_MISMATCH")
    for module_name, relative in (
        ("tools.capstone_release", "tools/capstone_release.py"),
        ("__main__", "tools/capstone_deploy.py"),
        ("tools.w6_001_k8s", "tools/w6_001_k8s.py"),
    ):
        loaded = sys.modules.get(module_name)
        location = getattr(loaded, "__file__", None)
        if (
            module_name == "__main__"
            and getattr(getattr(loaded, "__spec__", None), "name", None) != "tools.capstone_deploy"
        ):
            raise ReleaseError("CODEBUILD_EXECUTABLE_MODULE_NAME")
        if not isinstance(location, str):
            raise ReleaseError("CODEBUILD_EXECUTABLE_MODULE_IDENTITY")
        module_path = Path(location)
        if (
            module_path.is_symlink()
            or module_path.resolve() != (primary / relative).resolve()
            or module_path.read_bytes() != source_files.get(relative)
        ):
            raise ReleaseError("CODEBUILD_EXECUTABLE_BLOB_SUBSTITUTION")
    control_digest = _required_env("W12_CONTROL_ARCHIVE_SHA256")
    control_raw = _s3_version(bucket, CONTROL_KEY, control_version, control_digest)
    control_head = boto3.client("s3", region_name=applied["deployment"]["region"]).head_object(
        Bucket=bucket,
        Key=CONTROL_KEY,
        VersionId=control_version,
        ChecksumMode="ENABLED",
    )
    if (
        control_head.get("VersionId") != control_version
        or control_head.get("ServerSideEncryption") != "aws:kms"
        or control_head.get("SSEKMSKeyId") != observed_kms
        or control_head.get("ChecksumSHA256")
        != base64.b64encode(hashlib.sha256(control_raw).digest()).decode("ascii")
    ):
        raise ReleaseError("CONTROL_KMS_OR_VERSION_CHANGED", "INDETERMINATE")
    control_files = _zip_files(control_raw)
    if control_files != _tree_files(control):
        raise ReleaseError("CONTROL_EXTRACTED_BYTES_MISMATCH")
    expected_control = {
        "release-record.json",
        "release-record.sha256",
        "records/r1/release-record.json",
        "records/r1/release-record.sha256",
        "records/r2/release-record.json",
        "records/r2/release-record.sha256",
        "records/r2/transition-evidence.json",
        "records/r2/transition-evidence.sha256",
        "records/r3/release-record.json",
        "records/r3/release-record.sha256",
        "records/r3/transition-evidence.json",
        "records/r3/transition-evidence.sha256",
        "records/r4/transition-evidence.json",
        "records/r4/transition-evidence.sha256",
        "codebuild-handoff.json",
        "codebuild-handoff.sha256",
        "w12-render-inputs.json",
        "w12-render-inputs.sha256",
    }
    if applied["operation"] == "rollback":
        expected_control.update(
            {
                "rollback/rollback-lineage-manifest.json",
                "rollback/rollback-lineage-manifest.sha256",
                "rollback/verified/release-record.json",
                "rollback/verified/release-record.sha256",
                "rollback/parent/release-record.json",
                "rollback/parent/release-record.sha256",
            }
        )
    if set(control_files) != expected_control:
        raise ReleaseError("CONTROL_ARCHIVE_FILE_SET")
    handoff_raw, handoff_sidecar = _pair(control, "codebuild-handoff")
    if handoff_sidecar != (_sha(handoff_raw) + "\n").encode("ascii") or _sha(
        handoff_raw
    ) != _required_env("W12_CODEBUILD_HANDOFF_SHA256"):
        raise ReleaseError("CONTROL_HANDOFF_DIGEST")
    handoff = _canonical_document(
        handoff_raw,
        fields=[
            "schema_version",
            "record_id",
            "operation",
            "workflow_run_id",
            "primary_source",
            "records",
            "w6_release",
            "artifacts",
            "terraform",
            "created_at_utc",
            "files",
        ],
        code="CODEBUILD_HANDOFF",
    )
    if (
        handoff["schema_version"] != "w12-001.codebuild-handoff.v2"
        or handoff["record_id"] != applied["record_id"]
        or handoff["operation"] != applied["operation"]
    ):
        raise ReleaseError("CONTROL_HANDOFF_IDENTITY")
    payload = {
        name: raw
        for name, raw in control_files.items()
        if name not in ("codebuild-handoff.json", "codebuild-handoff.sha256")
    }
    listed = handoff["files"]
    if len(payload) != (
        22 if applied["operation"] == "rollback" else 16
    ) or listed != _file_inventory(payload):
        raise ReleaseError("CONTROL_HANDOFF_FILE_COVERAGE")
    _fields(
        handoff["primary_source"],
        ["bucket", "key", "version_id", "object_sha256", "manifest_sha256", "commit", "tree"],
        "HANDOFF_PRIMARY_SOURCE",
    )
    _fields(handoff["w6_release"], ["release_hashes_sha256"], "HANDOFF_W6_RELEASE")
    _fields(handoff["artifacts"], ["image_digest"], "HANDOFF_ARTIFACTS")
    _fields(
        handoff["terraform"],
        [
            "organization",
            "workspace",
            "run_id",
            "plan_id",
            "input_state_version_id",
            "input_state_lineage",
            "input_state_serial",
            "output_state_version_id",
            "output_state_lineage",
            "output_state_serial",
        ],
        "HANDOFF_TERRAFORM",
    )
    if handoff["primary_source"] != {
        "bucket": bucket,
        "key": SOURCE_KEY,
        "version_id": source_version,
        "object_sha256": applied["source"]["archive_sha256"],
        "manifest_sha256": manifest_sha,
        "commit": requested["source"]["commit"],
        "tree": requested["source"]["tree"],
    } or handoff["w6_release"] != {"release_hashes_sha256": w6_sha}:
        raise ReleaseError("CONTROL_HANDOFF_SOURCE")
    if handoff["artifacts"] != {"image_digest": application_image_from_ready(ready)}:
        raise ReleaseError("CONTROL_HANDOFF_IMAGE")
    if len(handoff["records"]) != 4 or [
        (item["revision"], item["status"], item["record_sha256"]) for item in handoff["records"]
    ] != [
        (index, item["status"], _sha(raws[index - 1]))
        for index, item in enumerate(records, start=1)
    ]:
        raise ReleaseError("CONTROL_HANDOFF_CHAIN")
    for item in handoff["records"]:
        _fields(
            item,
            ["revision", "status", "record_sha256", "artifact_id", "artifact_digest"],
            "HANDOFF_RECORD_ITEM",
        )
        if (
            type(item["artifact_id"]) is not int
            or item["artifact_id"] <= 0
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", item["artifact_digest"])
        ):
            raise ReleaseError("HANDOFF_ARTIFACT_IDENTITY")
    terraform = handoff["terraform"]
    if (
        terraform["organization"],
        terraform["workspace"],
        terraform["run_id"],
        terraform["plan_id"],
        terraform["input_state_version_id"],
        terraform["input_state_lineage"],
        terraform["input_state_serial"],
    ) != (
        applied["terraform"]["organization"],
        applied["terraform"]["workspace"],
        applied["terraform"]["run_id"],
        applied["terraform"]["plan_id"],
        applied["terraform"]["input_state_version_id"],
        applied["terraform"]["state_lineage"],
        applied["terraform"]["input_state_serial"],
    ):
        raise ReleaseError("HANDOFF_TERRAFORM_INPUT_CHANGED")
    render_raw, render_sidecar = _pair(control, "w12-render-inputs")
    render = validate_render_inputs(
        render_raw,
        render_sidecar,
        ready=ready,
        ready_sha256=_sha(raws[1]),
        approved=approved,
        approved_sha256=_sha(raws[2]),
        applied=applied,
    )
    if (
        terraform["output_state_version_id"],
        terraform["output_state_lineage"],
        terraform["output_state_serial"],
    ) != (render["applied_state_version_id"], render["state_lineage"], render["state_serial"]):
        raise ReleaseError("HANDOFF_TERRAFORM_OUTPUT_CHANGED")
    if (
        render["application_image"] != application_image_from_ready(ready)
        or render["otel_collector_image"] != ready["artifacts"]["otel_collector_image"]
    ):
        raise ReleaseError("IMAGE_ROLE_SUBSTITUTION")
    if (
        render["application_image"] == render["otel_collector_image"]
        or render["application_image"].rsplit("@", 1)[1]
        == render["otel_collector_image"].rsplit("@", 1)[1]
    ):
        raise ReleaseError("IMAGE_ROLE_CONFUSION")
    if applied["operation"] == "rollback":
        prior_files, prior_records, _, prior_render = load_prior_rollback_lineage(
            requested,
            client=boto3.client("s3", region_name=applied["deployment"]["region"]),
            kms_key_arn=observed_kms,
        )
        if any(control_files[name] != contents for name, contents in prior_files.items()):
            raise ReleaseError("ROLLBACK_CONTROL_LINEAGE_SUBSTITUTION")
        if (
            prior_render["bedrock_inference_profile_arn"] != render["bedrock_inference_profile_arn"]
            or application_image_from_ready(prior_records[1]) != application_image_from_ready(ready)
            or prior_records[1]["artifacts"]["otel_collector_image"]
            != ready["artifacts"]["otel_collector_image"]
            or prior_records[4]["deployment"]["root_fingerprint_sha256"]
            != applied["deployment"]["root_fingerprint_sha256"]
            or prior_records[4]["deployment"]["trust_bundle_sha256"]
            != applied["deployment"]["trust_bundle_sha256"]
        ):
            raise ReleaseError("ROLLBACK_PRE_KUBERNETES_IDENTITY_CHANGED", "INDETERMINATE")
    return applied, source_files, render, records, raws


def _record(args: argparse.Namespace) -> dict[str, Any]:
    applied, _, _, _, _ = _source(args)
    return applied


def _by_identity(documents: list[dict[str, Any]]) -> dict[tuple[str, str], dict[str, Any]]:
    result: dict[tuple[str, str], dict[str, Any]] = {}
    for item in documents:
        kind = item.get("kind")
        metadata = item.get("metadata")
        name = metadata.get("name") if isinstance(metadata, dict) else None
        if not isinstance(kind, str) or not isinstance(name, str):
            raise ReleaseError("MANIFEST_DUPLICATE_OR_MISSING_IDENTITY")
        key = (kind, name)
        if key in result:
            raise ReleaseError("MANIFEST_DUPLICATE_OR_MISSING_IDENTITY")
        result[key] = item
    return result


def _observed_render_identities(record: dict[str, Any], render: dict[str, Any]) -> str:
    """Read exact AWS identities using the short-lived CodeBuild role."""
    import boto3

    account = record["deployment"]["account_id"]
    region = record["deployment"]["region"]
    if (
        not re.fullmatch(r"[0-9]{12}", account)
        or render["aws_account_id"] != account
        or render["aws_region"] != region
    ):
        raise ReleaseError("AWS_TARGET_IDENTITY_MISMATCH")
    if boto3.client("sts").get_caller_identity().get("Account") != account:
        raise ReleaseError("AWS_CALLER_ACCOUNT_MISMATCH")
    domain_arn = render["opensearch_domain_arn"]
    if not domain_arn.startswith(f"arn:aws:es:{region}:{account}:domain/"):
        raise ReleaseError("OPENSEARCH_ACCOUNT_OR_REGION_MISMATCH")
    domain = domain_arn.rsplit("/", 1)[1]
    observed = boto3.client("opensearch", region_name=region).describe_domain(DomainName=domain)[
        "DomainStatus"
    ]
    observed_endpoint = observed.get("Endpoint") or observed.get("Endpoints", {}).get("vpc")
    if (
        observed.get("ARN") != domain_arn
        or "https://" + str(observed_endpoint) != render["opensearch_https_endpoint"]
    ):
        raise ReleaseError("OPENSEARCH_OBSERVED_IDENTITY_MISMATCH")
    profile = boto3.client("bedrock", region_name=region).get_inference_profile(
        inferenceProfileIdentifier=render["bedrock_inference_profile_arn"]
    )
    if (
        profile.get("inferenceProfileArn") != render["bedrock_inference_profile_arn"]
        or profile.get("status") != "ACTIVE"
    ):
        raise ReleaseError("BEDROCK_OBSERVED_PROFILE_MISMATCH")
    cluster = boto3.client("eks", region_name=region).describe_cluster(
        name="enterprise-ai-sandbox"
    )["cluster"]
    issuer = cluster.get("identity", {}).get("oidc", {}).get("issuer")
    if (
        not isinstance(issuer, str)
        or issuer != _required_env("W12_OWNER_APPROVED_EKS_ISSUER")
        or not issuer.startswith("https://")
    ):
        raise ReleaseError("EKS_ISSUER_NOT_OWNER_APPROVED")
    return issuer


def _overlay(files: dict[str, bytes], record: dict[str, Any], issuer: str) -> dict[str, bytes]:
    """Apply the fixed W12 TLS overlay to already rendered W6 objects."""
    result = dict(files)
    overlay = _by_identity(
        [
            item
            for item in yaml.safe_load_all(OVERLAY.read_text(encoding="utf-8"))
            if isinstance(item, dict)
        ]
    )
    if set(overlay) != {("Deployment", SERVICE), ("Service", SERVICE)}:
        raise ReleaseError("W12_OVERLAY_IDENTITY")
    for name in ("deployment.yaml", "service.yaml", "configmap.yaml", "networkpolicy.yaml"):
        documents = [item for item in yaml.safe_load_all(result[name]) if isinstance(item, dict)]
        objects = _by_identity(documents)
        if name == "deployment.yaml":
            deployment = objects[("Deployment", SERVICE)]
            pod = deployment["spec"]["template"]["spec"]
            api = next(item for item in pod["containers"] if item["name"] == "api")
            patch = overlay[("Deployment", SERVICE)]
            patch_api = patch["spec"]["template"]["spec"]["containers"][0]
            for field in (
                "args",
                "ports",
                "lifecycle",
                "startupProbe",
                "livenessProbe",
                "readinessProbe",
            ):
                api[field] = patch_api[field]
            inherited_env = {item["name"]: item for item in api.get("env", [])}
            for item in patch_api["env"]:
                entry = dict(item)
                if entry["name"] == "ENTERPRISE_AI_WORKLOAD_PROBE_ISSUER":
                    entry["value"] = issuer
                elif entry["name"] == "ENTERPRISE_AI_CAPSTONE_TLS_ROOT_FINGERPRINT_SHA256":
                    entry["value"] = record["deployment"]["root_fingerprint_sha256"]
                inherited_env[entry["name"]] = entry
            api["env"] = list(inherited_env.values())
            mounts = {item["name"]: item for item in api.get("volumeMounts", [])}
            mounts.update({item["name"]: item for item in patch_api["volumeMounts"]})
            api["volumeMounts"] = list(mounts.values())
            volumes = {item["name"]: item for item in pod.get("volumes", [])}
            volumes.update(
                {item["name"]: item for item in patch["spec"]["template"]["spec"]["volumes"]}
            )
            pod["volumes"] = list(volumes.values())
            deployment["metadata"].setdefault("labels", {}).update(patch["metadata"]["labels"])
        elif name == "service.yaml":
            service = objects[("Service", SERVICE)]
            service["spec"]["ports"] = overlay[("Service", SERVICE)]["spec"]["ports"]
            if any(
                item.get("port") != 443 or item.get("name") != "https"
                for item in service["spec"]["ports"]
            ):
                raise ReleaseError("PLAINTEXT_SERVICE_RETAINED")
        elif name == "configmap.yaml":
            config = objects[("ConfigMap", "enterprise-ai-runtime")]
            config["data"].update(
                {
                    "ENTERPRISE_AI_WORKLOAD_PROBE_AUTH_ENABLED": "true",
                    "ENTERPRISE_AI_CAPSTONE_TLS_ENABLED": "true",
                }
            )
        else:
            policy = objects[("NetworkPolicy", "enterprise-ai-api-ingress")]
            policy["spec"]["ingress"][0]["ports"] = [{"protocol": "TCP", "port": 8000}]
        result[name] = (
            yaml.safe_dump_all(documents, sort_keys=True, allow_unicode=True).rstrip("\n") + "\n"
        ).encode("utf-8")
    for name in ("pki.yaml", "trust-bundle.yaml", "tokenreview-rbac.yaml"):
        raw = (ROOT / "deploy/capstone" / name).read_bytes()
        if b"kind: Secret" in raw or b"OWNER_BINDING_REQUIRED" in raw:
            raise ReleaseError("W12_EXTRA_MANIFEST_UNSAFE")
        result["capstone/" + name] = raw
    return result


def _render_bundle(
    applied: dict[str, Any],
    source_files: dict[str, bytes],
    render: dict[str, Any],
    records: list[dict[str, Any]],
    raws: list[bytes],
) -> tuple[dict[str, bytes], bytes, bytes, str]:
    ready = records[1]
    # The adapter, not a caller of the pure renderer, authenticates both image roles.
    application = application_image_from_ready(ready)
    collector = ready["artifacts"]["otel_collector_image"]
    if (
        render["application_image"] != application
        or render["otel_collector_image"] != collector
        or application == collector
        or application.rsplit("@", 1)[1] == collector.rsplit("@", 1)[1]
    ):
        raise ReleaseError("IMAGE_ROLE_SUBSTITUTION")
    issuer = _observed_render_identities(applied, render)
    with tempfile.TemporaryDirectory(prefix="w12-render-") as temporary:
        source_root = Path(temporary) / "k8s-source"
        source_root.mkdir(mode=0o700)
        source_names = [name for name in source_files if name.startswith("deploy/k8s/")]
        if set(source_names) != {"deploy/k8s/" + name for name in TEMPLATE_FILES}:
            raise ReleaseError("W6_TEMPLATE_SET_CHANGED")
        for name in source_names:
            (source_root / Path(name).name).write_bytes(source_files[name])
        bindings = W12RenderBindings(
            application_image=application,
            otel_collector_image=collector,
            opensearch_https_endpoint=render["opensearch_https_endpoint"],
            bedrock_inference_profile_arn=render["bedrock_inference_profile_arn"],
            release_record_sha256=_sha(raws[2]),
            render_inputs_sha256=applied["deployment"]["render_inputs_sha256"],
            w6_release_hashes_sha256=ready["deployment"]["w6_release_hashes_sha256"],
        )
        files = _overlay(
            render_w12_release(source_root=source_root, bindings=bindings), applied, issuer
        )
    renderer_sha = _sha(source_files["tools/w6_001_k8s.py"])
    inventory = {
        "schema_version": "w12-001.rendered-release.v1",
        "ready_record_sha256": _sha(raws[1]),
        "approved_record_sha256": _sha(raws[2]),
        "applied_record_sha256": _sha(raws[3]),
        "source_archive_sha256": applied["source"]["archive_sha256"],
        "w6_release_hashes_sha256": ready["deployment"]["w6_release_hashes_sha256"],
        "render_inputs_sha256": applied["deployment"]["render_inputs_sha256"],
        "renderer_path": "tools/w6_001_k8s.py",
        "renderer_sha256": renderer_sha,
        "created_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "files": _file_inventory(files),
    }
    inventory_raw = _canonical_bytes(inventory)
    inventory_sidecar = (_sha(inventory_raw) + "\n").encode("ascii")
    validate_rendered_release(
        inventory_raw,
        inventory_sidecar,
        archive_files=files,
        ready_sha256=_sha(raws[1]),
        approved_sha256=_sha(raws[2]),
        applied_sha256=_sha(raws[3]),
        source_sha256=applied["source"]["archive_sha256"],
        w6_sha256=ready["deployment"]["w6_release_hashes_sha256"],
        render_inputs_sha256=applied["deployment"]["render_inputs_sha256"],
        renderer_sha256=renderer_sha,
    )
    return files, inventory_raw, inventory_sidecar, _sha(inventory_raw)


def _pki_ready(record: dict[str, Any]) -> None:
    # The regular role never reads Kubernetes Secrets. Certificate Ready plus
    # both TLS Pods Ready proves the mounted leaf exists and is usable.
    for args in (
        ("get", "clusterissuer", "enterprise-ai-capstone-ca", "-o", "json"),
        ("get", "certificate", "enterprise-ai-api-tls", "-n", NAMESPACE, "-o", "json"),
        ("get", "bundle", "enterprise-ai-capstone-root", "-o", "json"),
    ):
        data = json.loads(_kubectl(*args))
        conditions = data.get("status", {}).get("conditions", [])
        if not any(
            item.get("type") in ("Ready", "Synced") and item.get("status") == "True"
            for item in conditions
        ):
            raise ReleaseError("PKI_RESOURCE_NOT_READY")
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes

    bundle = json.loads(
        _kubectl("get", "configmap", "enterprise-ai-capstone-root", "-n", NAMESPACE, "-o", "json")
    )
    pem = bundle.get("data", {}).get("ca.crt")
    if (
        not isinstance(pem, str)
        or _sha(pem.encode("utf-8")) != record["deployment"]["trust_bundle_sha256"]
    ):
        raise ReleaseError("TRUST_BUNDLE_DIGEST_CHANGED")
    try:
        root = x509.load_pem_x509_certificate(pem.encode("utf-8"))
    except ValueError as exc:
        raise ReleaseError("TRUST_ROOT_INVALID") from exc
    if root.fingerprint(hashes.SHA256()).hex() != record["deployment"]["root_fingerprint_sha256"]:
        raise ReleaseError("TRUST_ROOT_FINGERPRINT_CHANGED")


def _tls_pods_ready(record: dict[str, Any]) -> None:
    _kubectl(
        "rollout", "status", "deployment/" + SERVICE, "-n", NAMESPACE, "--timeout=600s", timeout=610
    )
    pods = json.loads(
        _kubectl(
            "get", "pods", "-n", NAMESPACE, "-l", "app.kubernetes.io/name=" + SERVICE, "-o", "json"
        )
    )
    expected_app = (
        record["artifacts"]["container_repository"] + "@" + record["artifacts"]["image_digest"]
    )
    expected_collector = record["artifacts"]["otel_collector_image"]
    ready = []
    for item in pods.get("items", []):
        conditions = item.get("status", {}).get("conditions", [])
        annotations = item.get("metadata", {}).get("annotations", {})
        images = {
            entry.get("name"): entry.get("image")
            for entry in item.get("spec", {}).get("containers", [])
        }
        if (
            any(c.get("type") == "Ready" and c.get("status") == "True" for c in conditions)
            and annotations.get("enterprise.ai/release-record-sha256")
            == record["previous_record_sha256"]
            and annotations.get("enterprise.ai/render-inputs-sha256")
            == record["deployment"]["render_inputs_sha256"]
            and images.get("api") == expected_app
            and images.get("otel-collector") == expected_collector
        ):
            ready.append(item)
    if len(ready) < 2:
        raise ReleaseError("TWO_TLS_PODS_NOT_READY")


def _build_uuid() -> str:
    build_id = _required_env("CODEBUILD_BUILD_ID")
    if not re.fullmatch(r"enterprise-ai-capstone-deploy:[0-9a-f-]{36}", build_id):
        raise ReleaseError("CODEBUILD_BUILD_ID_INVALID")
    return build_id.split(":", 1)[1]


def _archive_identity_path() -> Path:
    return Path("out/w12-001/rendered-archive.json")


def _publish_archive(
    applied: dict[str, Any], files: dict[str, bytes], inventory_raw: bytes, inventory_sidecar: bytes
) -> dict[str, str]:
    import boto3

    archive_files = dict(files)
    archive_files["w12-rendered-release.json"] = inventory_raw
    archive_files["w12-rendered-release.sha256"] = inventory_sidecar
    archive = _make_zip(archive_files)
    digest = _sha(archive)
    key = f"w12-001/results/{applied['record_id']}/r4/{_build_uuid()}/w12-rendered-release.zip"
    bucket = applied["source"]["s3_bucket"]
    kms_key = _required_env("W12_RESULT_KMS_KEY_ARN")
    s3 = boto3.client("s3", region_name=applied["deployment"]["region"])
    try:
        response = s3.put_object(
            Bucket=bucket,
            Key=key,
            Body=archive,
            ContentType="application/zip",
            ServerSideEncryption="aws:kms",
            SSEKMSKeyId=kms_key,
            ChecksumSHA256=base64.b64encode(hashlib.sha256(archive).digest()).decode("ascii"),
            IfNoneMatch="*",
            Metadata={
                "record-id": applied["record_id"],
                "record-revision": "4",
                "build-uuid": _build_uuid(),
                "record-sha256": _required_env("W12_RECORD_SHA256"),
                "archive-sha256": digest,
            },
        )
    except Exception as exc:
        raise ReleaseError("RENDERED_ARCHIVE_UPLOAD_AMBIGUOUS", "INDETERMINATE") from exc
    version = response.get("VersionId")
    if (
        not isinstance(version, str)
        or not version
        or version == "null"
        or not response.get("ChecksumSHA256")
        or base64.b64decode(response["ChecksumSHA256"], validate=True).hex() != digest
    ):
        raise ReleaseError("RENDERED_ARCHIVE_UPLOAD_IDENTITY", "INDETERMINATE")
    reread = _s3_version(bucket, key, version, digest)
    extracted = _zip_files(reread)
    if extracted != archive_files:
        raise ReleaseError("RENDERED_ARCHIVE_READBACK_MISMATCH")
    return {
        "bucket": bucket,
        "key": key,
        "version_id": version,
        "sha256": digest,
        "inventory_sha256": _sha(inventory_raw),
    }


def _read_verified_archive(
    applied: dict[str, Any],
    records: list[dict[str, Any]],
    raws: list[bytes],
    source_files: dict[str, bytes],
) -> tuple[dict[str, bytes], dict[str, str]]:
    identity = json.loads(_archive_identity_path().read_text(encoding="utf-8"))
    if (
        list(identity) != ["bucket", "key", "version_id", "sha256", "inventory_sha256"]
        or identity["bucket"] != applied["source"]["s3_bucket"]
        or identity["key"]
        != f"w12-001/results/{applied['record_id']}/r4/{_build_uuid()}/w12-rendered-release.zip"
    ):
        raise ReleaseError("RENDERED_ARCHIVE_IDENTITY_MISMATCH")
    archive = _s3_version(
        identity["bucket"], identity["key"], identity["version_id"], identity["sha256"]
    )
    files = _zip_files(archive)
    inventory_raw = files.pop("w12-rendered-release.json")
    inventory_sidecar = files.pop("w12-rendered-release.sha256")
    validate_rendered_release(
        inventory_raw,
        inventory_sidecar,
        archive_files=files,
        ready_sha256=_sha(raws[1]),
        approved_sha256=_sha(raws[2]),
        applied_sha256=_sha(raws[3]),
        source_sha256=applied["source"]["archive_sha256"],
        w6_sha256=records[1]["deployment"]["w6_release_hashes_sha256"],
        render_inputs_sha256=applied["deployment"]["render_inputs_sha256"],
        renderer_sha256=_sha(source_files["tools/w6_001_k8s.py"]),
    )
    if _sha(inventory_raw) != identity["inventory_sha256"]:
        raise ReleaseError("RENDERED_INVENTORY_DIGEST_MISMATCH")
    return files, identity


def preflight(args: argparse.Namespace) -> dict[str, Any]:
    applied, source_files, render, records, raws = _source(args)
    if os.environ.get("W12_IMAGE_DIGEST") != records[1]["artifacts"]["image_digest"]:
        raise ReleaseError("IMAGE_INPUT_MISMATCH")
    files, inventory_raw, inventory_sidecar, inventory_sha = _render_bundle(
        applied, source_files, render, records, raws
    )
    identity = _publish_archive(applied, files, inventory_raw, inventory_sidecar)
    if identity["inventory_sha256"] != inventory_sha:
        raise ReleaseError("RENDERED_INVENTORY_CHANGED")
    path = _archive_identity_path()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with path.open("x", encoding="utf-8") as output:
        os.chmod(path, 0o600)
        output.write(json.dumps(identity, separators=(",", ":")) + "\n")
    return {
        "classification": "PREFLIGHT_VALID",
        "rendered_inventory_sha256": inventory_sha,
        "rendered_archive_sha256": identity["sha256"],
        "rendered_archive_version_id": identity["version_id"],
    }


def _bootstrap_ready(files: dict[str, bytes], record: dict[str, Any]) -> None:
    """Require the exact owner-created identity and PKI resources before writes."""
    for name in (
        "namespace.yaml",
        "serviceaccount.yaml",
        "capstone/tokenreview-rbac.yaml",
        "capstone/pki.yaml",
        "capstone/trust-bundle.yaml",
    ):
        for desired in yaml.safe_load_all(files[name]):
            if not isinstance(desired, dict) or not isinstance(desired.get("metadata"), dict):
                raise ReleaseError("BOOTSTRAP_MANIFEST_MALFORMED")
            kind = desired.get("kind")
            resource_name = desired["metadata"].get("name")
            namespace = desired["metadata"].get("namespace")
            if not isinstance(kind, str) or not isinstance(resource_name, str):
                raise ReleaseError("BOOTSTRAP_RESOURCE_IDENTITY")
            args = (
                "get",
                kind,
                resource_name,
                *(("-n", namespace) if namespace else ()),
                "-o",
                "json",
            )
            observed = json.loads(_kubectl(*args))
            if (
                observed.get("kind") != kind
                or observed.get("metadata", {}).get("name") != resource_name
                or (namespace and observed.get("metadata", {}).get("namespace") != namespace)
            ):
                raise ReleaseError("BOOTSTRAP_RESOURCE_NOT_OBSERVED")
            if kind in ("ClusterRole", "Role") and observed.get("rules") != desired.get("rules"):
                raise ReleaseError("BOOTSTRAP_RBAC_RULES_CHANGED")
            if kind in ("ClusterRoleBinding", "RoleBinding") and (
                observed.get("roleRef") != desired.get("roleRef")
                or observed.get("subjects") != desired.get("subjects")
            ):
                raise ReleaseError("BOOTSTRAP_RBAC_BINDING_CHANGED")
            if kind == "ServiceAccount" and observed.get(
                "automountServiceAccountToken"
            ) != desired.get("automountServiceAccountToken"):
                raise ReleaseError("BOOTSTRAP_SERVICE_ACCOUNT_CHANGED")
    _pki_ready(record)
    service = json.loads(_kubectl("get", "service", SERVICE, "-n", NAMESPACE, "-o", "json"))
    ports = service.get("spec", {}).get("ports", [])
    if (
        service.get("metadata", {}).get("name") != SERVICE
        or len(ports) != 1
        or ports[0].get("port") != 443
        or ports[0].get("name") != "https"
    ):
        raise ReleaseError("PREEXISTING_PLAINTEXT_SERVICE")


def _apply_documents(files: dict[str, bytes], record: dict[str, Any]) -> None:
    if "service.yaml" not in files or "deployment.yaml" not in files:
        raise ReleaseError("RENDERED_DEPLOYMENT_FILES_MISSING")
    order = [
        "namespace.yaml",
        "serviceaccount.yaml",
        "capstone/tokenreview-rbac.yaml",
        "configmap.yaml",
        "otel-collector-configmap.yaml",
        "capstone/pki.yaml",
        "capstone/trust-bundle.yaml",
        "networkpolicy.yaml",
        "deployment.yaml",
        "hpa.yaml",
        "pdb.yaml",
    ]
    if set(files) != set(order) | {"service.yaml"}:
        raise ReleaseError("UNAPPROVED_RENDERED_FILE_SET")
    _bootstrap_ready(files, record)
    withdraw_service()
    withdrawn = json.loads(_kubectl("get", "service", SERVICE, "-n", NAMESPACE, "-o", "json"))
    if withdrawn.get("spec", {}).get("selector") != {
        "enterprise-ai.vayunetrix.com/withdrawn": "true"
    }:
        raise ReleaseError("SERVICE_WITHDRAWAL_NOT_OBSERVED")
    # Cluster scope and identity resources are owner-bootstrapped. The regular
    # CodeBuild principal can inspect them but cannot create RBAC or PKI roots.
    bootstrap = {
        "namespace.yaml",
        "serviceaccount.yaml",
        "capstone/tokenreview-rbac.yaml",
        "capstone/pki.yaml",
        "capstone/trust-bundle.yaml",
    }
    for name in order:
        if name in bootstrap:
            continue
        if not (name.endswith(".yaml") and (name.startswith("capstone/") or "/" not in name)):
            raise ReleaseError("UNAPPROVED_RENDERED_FILE")
        for item in yaml.safe_load_all(files[name]):
            if not isinstance(item, dict) or item.get("kind") == "Secret":
                raise ReleaseError("UNSAFE_KUBERNETES_MANIFEST")
            _kubectl("apply", "-f", "-", input_text=yaml.safe_dump(item), timeout=60)
    _pki_ready(record)
    _tls_pods_ready(record)
    service = list(yaml.safe_load_all(files["service.yaml"]))
    if (
        len(service) != 1
        or service[0].get("kind") != "Service"
        or service[0].get("metadata", {}).get("name") != SERVICE
    ):
        raise ReleaseError("TLS_SERVICE_IDENTITY")
    ports = service[0].get("spec", {}).get("ports", [])
    if len(ports) != 1 or ports[0].get("port") != 443 or ports[0].get("name") != "https":
        raise ReleaseError("TLS_SERVICE_REQUIRED")
    _kubectl("apply", "-f", "-", input_text=yaml.safe_dump(service[0]), timeout=60)
    _pki_ready(record)


def deploy(args: argparse.Namespace) -> dict[str, Any]:
    applied, source_files, _, records, raws = _source(args)
    if applied["operation"] != args.operation:
        raise ReleaseError("OPERATION_MISMATCH")
    files, identity = _read_verified_archive(applied, records, raws, source_files)
    if args.operation == "rollback":
        predecessor_sha = applied["recovery"]["previous_good_record_sha256"]
        if not predecessor_sha:
            withdraw_service()
            return {"classification": "WITHDRAWN", "reason": "NO_VERIFIED_TLS_PREDECESSOR"}
        # _source re-read the exact inbound lineage and prior control ZIP,
        # then compared the prior image, model, and trust identities before
        # any Kubernetes mutation. Do not accept a separate predecessor path.
    _apply_documents(files, applied)
    return {
        "classification": "APPLIED_TLS",
        "derivative_sha256": identity["inventory_sha256"],
        "rendered_archive_sha256": identity["sha256"],
        "rendered_archive_version_id": identity["version_id"],
        "image_digest": applied["artifacts"]["image_digest"],
    }


def withdraw_service() -> None:
    _kubectl(
        "patch",
        "service",
        SERVICE,
        "-n",
        NAMESPACE,
        "--type=merge",
        "-p",
        '{"spec":{"selector":{"enterprise-ai.vayunetrix.com/withdrawn":"true"}}}',
    )


def probe(args: argparse.Namespace) -> dict[str, Any]:
    record = _record(args)
    manifest = Path(args.job_manifest).read_text(encoding="utf-8")
    job = yaml.safe_load(manifest)
    if job.get("metadata", {}).get("name") != "enterprise-ai-capstone-probe":
        raise ReleaseError("PROBE_JOB_IDENTITY")
    image = os.environ.get("W12_PROBE_IMAGE", "")
    if not IMAGE_DIGEST.fullmatch(image):
        raise ReleaseError("PROBE_IMAGE_DIGEST_REQUIRED")
    job["spec"]["template"]["spec"]["containers"][0]["image"] = image
    _pki_ready(record)
    _tls_pods_ready(record)
    try:
        _kubectl("create", "-f", "-", input_text=yaml.safe_dump(job), timeout=60)
        _kubectl(
            "wait",
            "-n",
            NAMESPACE,
            "--for=condition=complete",
            "job/enterprise-ai-capstone-probe",
            "--timeout=120s",
            timeout=130,
        )
        logs = _kubectl("logs", "-n", NAMESPACE, "job/enterprise-ai-capstone-probe", timeout=30)
        result = json.loads(logs)
        if not isinstance(result, dict):
            raise ReleaseError("PROBE_RESULT_OBJECT_REQUIRED")
        if (
            result.get("classification") != "PROBE_OBSERVED"
            or result.get("invalid_token_status") != 401
            or result.get("wrong_tenant_status") != 422
        ):
            raise ReleaseError("PROBE_SECURITY_CHECK_FAILED")
        return result
    except Exception:
        withdraw_service()
        raise
    finally:
        try:
            _kubectl(
                "delete",
                "job",
                "enterprise-ai-capstone-probe",
                "-n",
                NAMESPACE,
                "--ignore-not-found=true",
                timeout=30,
            )
            _kubectl(
                "wait",
                "-n",
                NAMESPACE,
                "--for=delete",
                "job/enterprise-ai-capstone-probe",
                "--timeout=60s",
                timeout=65,
            )
            pods = json.loads(
                _kubectl(
                    "get",
                    "pods",
                    "-n",
                    NAMESPACE,
                    "-l",
                    "job-name=enterprise-ai-capstone-probe",
                    "-o",
                    "json",
                )
            )
            if pods.get("items"):
                raise ReleaseError("PROBE_POD_RESIDUE")
        except Exception:
            withdraw_service()
            raise


def inventory(args: argparse.Namespace) -> dict[str, Any]:
    record = _record(args)
    kinds = ("deployments", "services", "jobs", "configmaps", "certificates", "pods")
    counts: dict[str, int] = {}
    for kind in kinds:
        data = json.loads(_kubectl("get", kind, "-n", NAMESPACE, "-o", "json"))
        counts[kind] = len(data.get("items", []))
    return {
        "classification": "INVENTORY_ONLY",
        "record_id": record["record_id"],
        "resource_counts": counts,
        "cleanliness": "NOT_VERIFIED",
    }


def publish_result(args: argparse.Namespace) -> dict[str, Any]:
    """Publish only the canonical, redacted, versioned CodeBuild result."""
    import boto3

    applied, _, _, _, raws = _source(args)
    deployment = json.loads(
        Path("/tmp/w12-deploy-result.json").read_text(encoding="utf-8")  # noqa: S108
    )
    probe_result = json.loads(
        Path("/tmp/w12-probe-result.json").read_text(encoding="utf-8")  # noqa: S108
    )
    inventory = json.loads(
        Path("/tmp/w12-inventory-result.json").read_text(encoding="utf-8")  # noqa: S108
    )
    archive = json.loads(_archive_identity_path().read_text(encoding="utf-8"))
    if (
        deployment.get("classification") != "APPLIED_TLS"
        or probe_result.get("classification") != "PROBE_OBSERVED"
        or inventory.get("classification") != "INVENTORY_ONLY"
        or deployment.get("derivative_sha256") != archive["inventory_sha256"]
    ):
        raise ReleaseError("CODEBUILD_RESULT_PREREQUISITE_FAILED")
    build_id = _required_env("CODEBUILD_BUILD_ID")
    build_arn = _required_env("CODEBUILD_BUILD_ARN")
    build_number = _required_env("CODEBUILD_BUILD_NUMBER")
    if (
        not build_number.isdecimal()
        or int(build_number) <= 0
        or not build_arn.endswith(":build/" + build_id)
    ):
        raise ReleaseError("CODEBUILD_BUILD_IDENTITY")
    result = {
        "schema_version": "w12-001.codebuild-result.v1",
        "record_id": applied["record_id"],
        "record_revision": 4,
        "operation": applied["operation"],
        "observed_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "build": {
            "project_name": "enterprise-ai-capstone-deploy",
            "build_id": build_id,
            "build_arn": build_arn,
            "build_number": int(build_number),
        },
        "inputs": {
            "primary_source_version_id": _required_env("W12_SOURCE_VERSION_ID"),
            "control_source_version_id": _required_env("W12_CONTROL_VERSION_ID"),
            "source_archive_sha256": applied["source"]["archive_sha256"],
            "control_archive_sha256": _required_env("W12_CONTROL_ARCHIVE_SHA256"),
            "applied_record_sha256": _sha(raws[3]),
            "source_manifest_sha256": _required_env("W12_SOURCE_MANIFEST_SHA256"),
            "codebuild_handoff_sha256": _required_env("W12_CODEBUILD_HANDOFF_SHA256"),
            "image_digest": deployment["image_digest"],
            "hcp_run_id": applied["terraform"]["run_id"],
        },
        "deployment": {
            "namespace": NAMESPACE,
            "workload": SERVICE,
            "derivative_manifest_sha256": deployment["derivative_sha256"],
            "rollout_status": "PASS",
        },
        "probe": {
            "job_name": "enterprise-ai-capstone-probe",
            "status": "PASS",
            "evidence_sha256": _sha(_canonical_bytes(probe_result)),
        },
        "cleanup": {"job_deleted": True, "pod_absent": True},
        "status": "PASS",
    }
    raw = _canonical_bytes(result)
    _canonical_document(
        raw,
        fields=[
            "schema_version",
            "record_id",
            "record_revision",
            "operation",
            "observed_at_utc",
            "build",
            "inputs",
            "deployment",
            "probe",
            "cleanup",
            "status",
        ],
        code="CODEBUILD_RESULT",
    )
    if any(
        term in raw.lower()
        for term in (
            b"private key",
            b"password",
            b"bearer ",
            b"prompt",
            b"response",
            b"terraform state",
        )
    ):
        raise ReleaseError("CODEBUILD_RESULT_CONFIDENTIAL_CONTENT")
    key = f"w12-001/results/{applied['record_id']}/r4/{_build_uuid()}/codebuild-result.json"
    bucket = applied["source"]["s3_bucket"]
    digest = _sha(raw)
    try:
        response = boto3.client("s3", region_name=applied["deployment"]["region"]).put_object(
            Bucket=bucket,
            Key=key,
            Body=raw,
            ContentType="application/json",
            ServerSideEncryption="aws:kms",
            SSEKMSKeyId=_required_env("W12_RESULT_KMS_KEY_ARN"),
            ChecksumSHA256=base64.b64encode(hashlib.sha256(raw).digest()).decode("ascii"),
            IfNoneMatch="*",
            Metadata={
                "record-id": applied["record_id"],
                "record-revision": "4",
                "build-uuid": _build_uuid(),
                "record-sha256": _sha(raws[3]),
                "result-sha256": digest,
            },
        )
    except Exception as exc:
        raise ReleaseError("CODEBUILD_RESULT_UPLOAD_AMBIGUOUS", "INDETERMINATE") from exc
    version = response.get("VersionId")
    if (
        not isinstance(version, str)
        or not version
        or version == "null"
        or not response.get("ChecksumSHA256")
        or base64.b64decode(response["ChecksumSHA256"], validate=True).hex() != digest
    ):
        raise ReleaseError("CODEBUILD_RESULT_VERSION_OR_CHECKSUM", "INDETERMINATE")
    if _s3_version(bucket, key, version, digest) != raw:
        raise ReleaseError("CODEBUILD_RESULT_READBACK_MISMATCH")
    target = Path("out/w12-001/codebuild-result.json")
    with target.open("x", encoding="utf-8") as output:
        os.chmod(target, 0o600)
        output.write(raw.decode("utf-8"))
    return {
        "classification": "RESULT_PUBLISHED",
        "result_sha256": digest,
        "result_version_id": version,
        "result_locator": encode_s3v_locator(bucket, key, version),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("preflight", "deploy", "probe", "inventory", "publish-result"):
        command = commands.add_parser(name)
        if name == "deploy":
            command.add_argument("--operation", choices=("deploy", "rollback"), required=True)
        if name == "probe":
            command.set_defaults(job_manifest=str(ROOT / "deploy/codebuild/capstone-probe.yaml"))
    args = parser.parse_args(argv)
    try:
        result = {
            "preflight": preflight,
            "deploy": deploy,
            "probe": probe,
            "inventory": inventory,
            "publish-result": publish_result,
        }[args.command](args)
    except (ReleaseError, OSError, ValueError, subprocess.TimeoutExpired):
        print('{"code":"CAPSTONE_DEPLOY_STOPPED","classification":"FAIL"}', file=sys.stderr)
        return 4
    print(json.dumps(result, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
