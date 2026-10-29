"""Owner-controlled W12 release record and remote-run gate.

Importing this module has no network or filesystem side effects. Live subcommands
require an owner-supplied, separately approved execution context.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import io
import json
import os
import posixpath
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, TypedDict, cast

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs/ci/capstone-release.json"
GITHUB_REPOSITORY = "gprai/enterprize_ai_platform"
GITHUB_WORKFLOW = "capstone-release.yml"
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
B64URL = re.compile(r"[A-Za-z0-9_-]*\Z")
SOURCE_KEY = "w12-001/source/source.zip"
CONTROL_KEY = "w12-001/control/control.zip"
BOOTSTRAP_JSON = "w12-source-manifest.json"
BOOTSTRAP_SHA = "w12-source-manifest.sha256"
W6_HASHES_JSON = "w6-release/release-hashes.json"
W6_HASHES_SHA = "w6-release/release-hashes.sha256"
W12_RENDERED_FILE_NAMES = frozenset(
    {
        "namespace.yaml",
        "serviceaccount.yaml",
        "configmap.yaml",
        "otel-collector-configmap.yaml",
        "deployment.yaml",
        "service.yaml",
        "networkpolicy.yaml",
        "hpa.yaml",
        "pdb.yaml",
        "capstone/pki.yaml",
        "capstone/trust-bundle.yaml",
        "capstone/tokenreview-rbac.yaml",
    }
)
ZIP_EPOCH = (1980, 1, 1, 0, 0, 0)
UTC_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
SENSITIVE = re.compile(
    r"-----BEGIN (?:.*PRIVATE KEY|CERTIFICATE)-----|Bearer\s+\S+|"
    r"\b(?:ghp_|gho_|ghu_|ghs_|github_pat_|AKIA|ASIA)[A-Za-z0-9_/-]+|"
    r"\b(?:token|password|private_key|credential)\s*[:=]",
    re.IGNORECASE,
)


class ReleaseError(ValueError):
    def __init__(self, code: str, classification: str = "FAIL") -> None:
        super().__init__(code)
        self.code = code
        self.classification = classification


def _config() -> dict[str, Any]:
    value = json.loads(CONFIG.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ReleaseError("CONFIG_OBJECT_REQUIRED")
    return value


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReleaseError("DUPLICATE_FIELD")
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise ReleaseError("NON_JSON_NUMBER")


def _fields(value: Any, names: list[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or list(value) != names:
        raise ReleaseError(code)
    return value


def _hex(value: Any, *, required: bool = False) -> bool:
    return (value is None and not required) or (
        isinstance(value, str) and HEX64.fullmatch(value) is not None
    )


def _text(value: Any, *, nullable: bool = False) -> bool:
    return (value is None and nullable) or (
        isinstance(value, str) and bool(value) and value == unicodedata.normalize("NFC", value)
    )


def _empty_input_state(state_id: Any, lineage: Any, serial: Any) -> bool:
    """An initial workspace has no input state identity at all."""
    values = (state_id, lineage, serial)
    if all(value is None for value in values):
        return True
    if any(value is None for value in values):
        raise ReleaseError("HCP_INPUT_STATE_IDENTITY_PARTIAL")
    if not _text(state_id) or not _text(lineage) or type(serial) is not int or serial < 0:
        raise ReleaseError("HCP_INPUT_STATE_IDENTITY_INVALID")
    return False


def _utc(value: Any) -> datetime:
    if not isinstance(value, str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value
    ):
        raise ReleaseError("TIMESTAMP_FORMAT")
    try:
        parsed = datetime.strptime(value, UTC_FORMAT).replace(tzinfo=UTC)
    except ValueError as exc:
        raise ReleaseError("TIMESTAMP_FORMAT") from exc
    if parsed.strftime(UTC_FORMAT) != value:
        raise ReleaseError("TIMESTAMP_FORMAT")
    return parsed


def _safe_string(value: str) -> None:
    if SENSITIVE.search(value) or any(ord(ch) < 32 for ch in value):
        raise ReleaseError("PROHIBITED_RECORD_CONTENT")
    if "://" in value:
        parts = urllib.parse.urlsplit(value)
        if parts.username or parts.password or parts.query or parts.fragment:
            raise ReleaseError("PROHIBITED_RECORD_URI")


def _walk(value: Any) -> None:
    if isinstance(value, str):
        if unicodedata.normalize("NFC", value) != value:
            raise ReleaseError("NON_NFC_STRING")
        _safe_string(value)
    elif isinstance(value, list):
        for item in value:
            _walk(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            _walk(key)
            _walk(item)
    elif value is not None and type(value) not in (int, bool):
        raise ReleaseError("NON_CANONICAL_VALUE")


def validate_record(
    raw: bytes, sidecar: bytes, *, previous: bytes | None = None, requested: bool = False
) -> dict[str, Any]:
    """Validate the entire canonical record and, when supplied, its predecessor."""
    cfg = _config()
    if (
        not raw
        or len(raw) > cfg["record_max_bytes"]
        or not raw.endswith(b"\n")
        or raw.endswith(b"\n\n")
    ):
        raise ReleaseError("RECORD_BYTES_OR_LF")
    if raw.startswith(b"\xef\xbb\xbf"):
        raise ReleaseError("UTF8_BOM")
    try:
        decoded = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ReleaseError("UTF8_INVALID") from exc
    try:
        record = json.loads(
            decoded[:-1], object_pairs_hook=_unique_pairs, parse_constant=_reject_constant
        )
    except json.JSONDecodeError as exc:
        raise ReleaseError("RECORD_JSON_INVALID") from exc
    record = _fields(record, cfg["record_fields"], "RECORD_FIELD_ORDER")
    for field, names in (
        ("source", cfg["source_fields"]),
        ("artifacts", cfg["artifact_fields"]),
        ("terraform", cfg["terraform_fields"]),
        ("gates", cfg["gate_fields"]),
        ("deployment", cfg["deployment_fields"]),
        ("recovery", cfg["recovery_fields"]),
    ):
        _fields(record[field], names, field.upper() + "_FIELD_ORDER")
    if not isinstance(record["evidence"], list):
        raise ReleaseError("EVIDENCE_TYPE")
    for item in record["evidence"]:
        _fields(item, cfg["evidence_fields"], "EVIDENCE_FIELD_ORDER")
    if record["evidence"] != sorted(
        record["evidence"], key=lambda item: (item["kind"], item["uri"])
    ):
        raise ReleaseError("EVIDENCE_ORDER")
    _walk(record)
    if (
        json.dumps(record, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()
        + b"\n"
        != raw
    ):
        raise ReleaseError("RECORD_NOT_CANONICAL")
    digest = hashlib.sha256(raw).hexdigest()
    if sidecar != (digest + "\n").encode("ascii"):
        raise ReleaseError("RECORD_SHA256_MISMATCH")
    if record["schema_version"] != cfg["schema_version"]:
        raise ReleaseError("RECORD_SCHEMA_VERSION")
    try:
        identity = uuid.UUID(record["record_id"])
    except (ValueError, TypeError, AttributeError) as exc:
        raise ReleaseError("RECORD_ID") from exc
    if identity.version != 4 or str(identity) != record["record_id"]:
        raise ReleaseError("RECORD_ID")
    rev = record["revision"]
    if type(rev) is not int or rev < 1:
        raise ReleaseError("RECORD_REVISION")
    prior = record["previous_record_sha256"]
    if rev == 1:
        if prior is not None or previous is not None:
            raise ReleaseError("RECORD_CHAIN_GENESIS")
    elif not _hex(prior, required=True) or previous is None:
        raise ReleaseError("PREVIOUS_RECORD_REQUIRED")
    else:
        previous_object = json.loads(previous)
        if (
            hashlib.sha256(previous).hexdigest() != prior
            or previous_object.get("record_id") != record["record_id"]
            or previous_object.get("revision") != rev - 1
            or record["status"]
            not in cfg["status_transitions"].get(previous_object.get("status"), [])
        ):
            raise ReleaseError("RECORD_CHAIN_MISMATCH")
    if record["status"] not in cfg["status_values"] or record["operation"] not in (
        "deploy",
        "rollback",
    ):
        raise ReleaseError("RECORD_STATUS_OR_OPERATION")
    if requested and (record["status"] != "REQUESTED" or rev != 1):
        raise ReleaseError("REQUESTED_RECORD_REQUIRED")
    created = _utc(record["created_at_utc"])
    expires = _utc(record["expires_at_utc"])
    if not created < expires <= created + timedelta(seconds=cfg["record_expiry_seconds"]):
        raise ReleaseError("RECORD_EXPIRY")
    if requested and not created <= datetime.now(UTC) < expires:
        raise ReleaseError("RECORD_NOT_CURRENT")
    source = record["source"]
    if (
        source["repository"] != GITHUB_REPOSITORY
        or not isinstance(source["commit"], str)
        or not HEX40.fullmatch(source["commit"])
        or not isinstance(source["tree"], str)
        or not HEX40.fullmatch(source["tree"])
    ):
        raise ReleaseError("SOURCE_IDENTITY")
    if any(not _hex(source[name]) for name in ("archive_sha256",)):
        raise ReleaseError("SOURCE_DIGEST")
    for name in ("s3_bucket", "s3_key", "s3_version_id"):
        if not _text(source[name], nullable=True):
            raise ReleaseError("SOURCE_FIELD")
    artifacts = record["artifacts"]
    for name in (
        "container_repository",
        "otel_collector_image",
        "model_package_arn",
        "signature_ref",
    ):
        if not _text(artifacts[name], nullable=True):
            raise ReleaseError("ARTIFACT_FIELD")
    image = artifacts["image_digest"]
    if image is not None and (
        not isinstance(image, str)
        or not image.startswith("sha256:")
        or not _hex(image[7:], required=True)
    ):
        raise ReleaseError("IMAGE_DIGEST")
    repository = artifacts["container_repository"]
    if repository is not None and not re.fullmatch(
        r"[a-z0-9][a-z0-9.-]*(?::[0-9]{1,5})?/[a-z0-9][a-z0-9._/-]*", repository
    ):
        raise ReleaseError("IMAGE_REPOSITORY_MUTABLE_OR_INVALID")
    collector = artifacts["otel_collector_image"]
    if collector is not None and not re.fullmatch(
        r"[a-z0-9][a-z0-9.-]*(?::[0-9]{1,5})?/[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}", collector
    ):
        raise ReleaseError("COLLECTOR_IMAGE_MUTABLE_OR_INVALID")
    for name in ("sbom_sha256", "provenance_sha256"):
        if not _hex(artifacts[name]):
            raise ReleaseError("ARTIFACT_DIGEST")
    tf = record["terraform"]
    if (tf["organization"], tf["project"], tf["workspace"]) != (
        cfg["hcp_organization"],
        cfg["hcp_project"],
        cfg["hcp_sandbox_workspace"],
    ):
        raise ReleaseError("HCP_WORKSPACE")
    for name in (
        "configuration_version_id",
        "run_id",
        "plan_id",
        "input_state_version_id",
        "state_lineage",
    ):
        if not _text(tf[name], nullable=True):
            raise ReleaseError("HCP_IDENTITY")
    empty_input_state = _empty_input_state(
        tf["input_state_version_id"], tf["state_lineage"], tf["input_state_serial"]
    )
    if empty_input_state and record["operation"] != "deploy":
        raise ReleaseError("ROLLBACK_INPUT_STATE_REQUIRED")
    if not _hex(tf["configuration_sha256"]):
        raise ReleaseError("TERRAFORM_CONFIG_DIGEST")
    gates = record["gates"]
    for name in (
        "opa_status",
        "run_task_status",
        "scan_status",
        "github_approval_status",
        "hcp_approval_status",
    ):
        if gates[name] not in cfg["gate_values"]:
            raise ReleaseError("GATE_STATUS")
    if not _hex(gates["opa_evidence_sha256"]):
        raise ReleaseError("OPA_DIGEST")
    if not _text(gates["run_task_result_id"], nullable=True):
        raise ReleaseError("RUN_TASK_ID")
    for name in ("github_run_id", "github_environment_id"):
        if gates[name] is not None and (type(gates[name]) is not int or gates[name] <= 0):
            raise ReleaseError("GITHUB_ID")
    deployment = record["deployment"]
    if (
        deployment["region"] != cfg["aws_region"]
        or deployment["environment"] != cfg["deployment_environment"]
    ):
        raise ReleaseError("DEPLOYMENT_REGION")
    account = deployment["account_id"]
    if account is not None and (
        not isinstance(account, str) or not re.fullmatch(r"\d{12}", account)
    ):
        raise ReleaseError("ACCOUNT_ID")
    if deployment["render_contract"] not in (None, "w12-001.render.v1"):
        raise ReleaseError("RENDER_CONTRACT")
    for name in (
        "render_inputs_sha256",
        "w6_release_hashes_sha256",
        "derivative_manifest_sha256",
        "root_fingerprint_sha256",
        "trust_bundle_sha256",
    ):
        if not _hex(deployment[name]):
            raise ReleaseError("DEPLOYMENT_DIGEST")
    for name in ("previous_good_record_sha256",):
        if not _hex(record["recovery"][name]):
            raise ReleaseError("RECOVERY_DIGEST")
    for name in ("rollback_ref", "teardown_ref"):
        if not _text(record["recovery"][name], nullable=True):
            raise ReleaseError("RECOVERY_REF")
    for item in record["evidence"]:
        if not _text(item["kind"]) or not _text(item["uri"]) or not _hex(item["sha256"]):
            raise ReleaseError("EVIDENCE_ITEM")
        if not item["uri"].startswith("w12-s3v:") and (
            item["kind"] != "build_artifact"
            or re.fullmatch(r"urn:github-artifact:[1-9][0-9]*", item["uri"]) is None
        ):
            raise ReleaseError("EVIDENCE_KIND_OR_URI")
        if item["uri"].startswith("w12-s3v:"):
            locator = decode_s3v_locator(item["uri"])
            if (
                source["s3_bucket"] is not None and locator["bucket"] != source["s3_bucket"]
            ) or locator["version_id"] is None:
                raise ReleaseError("EVIDENCE_BUCKET_OR_VERSION")
            if item["kind"] == "w12_source_manifest":
                if locator["key"] != source["s3_key"] or locator["entry"] != BOOTSTRAP_JSON:
                    raise ReleaseError("SOURCE_MANIFEST_LOCATOR")
            elif item["kind"] == "source_bundle":
                if (
                    locator["key"] != SOURCE_KEY
                    or locator["entry"] is not None
                    or item["sha256"] != source["archive_sha256"]
                ):
                    raise ReleaseError("SOURCE_BUNDLE_LOCATOR")
            elif item["kind"] == "w6_release_hashes":
                if locator["key"] != source["s3_key"] or locator["entry"] != W6_HASHES_JSON:
                    raise ReleaseError("W6_HASHES_LOCATOR")
            elif item["kind"] == "codebuild_result":
                expected = (
                    rf"w12-001/results/{record['record_id']}/r4/"
                    r"[0-9a-f-]{36}/codebuild-result\.json"
                )
                if locator["entry"] is not None or not re.fullmatch(expected, locator["key"]):
                    raise ReleaseError("CODEBUILD_RESULT_LOCATOR")
            elif item["kind"] == "rendered_release_archive":
                expected = (
                    rf"w12-001/results/{record['record_id']}/r4/"
                    r"[0-9a-f-]{36}/w12-rendered-release\.zip"
                )
                if locator["entry"] is not None or not re.fullmatch(expected, locator["key"]):
                    raise ReleaseError("RENDERED_ARCHIVE_LOCATOR")
            elif item["kind"] == "codebuild-control-bundle":
                if locator["entry"] != "codebuild-handoff.json" or locator["key"] != CONTROL_KEY:
                    raise ReleaseError("CONTROL_BUNDLE_LOCATOR")
            elif item["kind"] in {
                "verified_transition",
                "verified_transition_sidecar",
                "opa_receipt",
                "opa_receipt_sidecar",
            }:
                if locator["entry"] is not None or locator["key"] != _release_publication_key(
                    record["record_id"], item["kind"]
                ):
                    raise ReleaseError("CANONICAL_OBJECT_LOCATOR")
            elif item["kind"] in {
                "rollback-lineage-archive",
                "rollback-lineage-manifest",
                "rollback-verified-record",
                "rollback-parent-record",
            }:
                expected_entry = {
                    "rollback-lineage-archive": "rollback/rollback-lineage-manifest.json",
                    "rollback-lineage-manifest": "rollback/rollback-lineage-manifest.json",
                    "rollback-verified-record": "rollback/verified/release-record.json",
                    "rollback-parent-record": "rollback/parent/release-record.json",
                }[item["kind"]]
                if record["operation"] != "rollback" or locator["entry"] != expected_entry:
                    raise ReleaseError("ROLLBACK_LINEAGE_SELECTOR")
            else:
                raise ReleaseError("UNAPPROVED_S3V_EVIDENCE_KIND")
            if (
                item["kind"] in ("source_bundle", "w12_source_manifest", "w6_release_hashes")
                and locator["version_id"] != source["s3_version_id"]
            ):
                raise ReleaseError("SOURCE_VERSION_LOCATOR")
    status = record["status"]
    lifecycle = {"REQUESTED": 1, "READY_FOR_OWNER": 2, "APPROVED": 3, "APPLIED": 4, "VERIFIED": 5}
    if status in lifecycle and rev != lifecycle[status]:
        raise ReleaseError("RECORD_LIFECYCLE_REVISION")
    if status == "REQUESTED" and (
        deployment["render_contract"] is not None
        or deployment["render_inputs_sha256"] is not None
        or deployment["w6_release_hashes_sha256"] is not None
        or deployment["derivative_manifest_sha256"] is not None
    ):
        raise ReleaseError("REQUESTED_RENDER_FIELDS")
    rollback_kinds = {
        "rollback-lineage-archive",
        "rollback-lineage-manifest",
        "rollback-verified-record",
        "rollback-parent-record",
    }
    present_rollback = {
        item["kind"]: item for item in record["evidence"] if item["kind"] in rollback_kinds
    }
    if record["operation"] == "rollback":
        ref = record["recovery"]["rollback_ref"]
        if not _hex(record["recovery"]["previous_good_record_sha256"], required=True) or not ref:
            raise ReleaseError("ROLLBACK_RECOVERY_IDENTITY")
        coordinate = decode_s3v_locator(ref)
        prior_key = re.fullmatch(
            r"w12-001/releases/([0-9a-f-]{36})/lineage/verified-lineage\.zip",
            coordinate["key"],
        )
        if (
            coordinate["entry"] != "rollback/rollback-lineage-manifest.json"
            or prior_key is None
            or coordinate["key"] != _release_publication_key(prior_key[1], "future_lineage")
            or (status != "REQUESTED" and coordinate["bucket"] != source["s3_bucket"])
        ):
            raise ReleaseError("ROLLBACK_RECOVERY_LOCATOR")
        required_rollback = (
            rollback_kinds
            if rev >= 2
            else {"rollback-lineage-archive", "rollback-lineage-manifest"}
        )
        if (
            set(present_rollback) != required_rollback
            or any(
                decode_s3v_locator(item["uri"])["bucket"] != coordinate["bucket"]
                or decode_s3v_locator(item["uri"])["key"] != coordinate["key"]
                or decode_s3v_locator(item["uri"])["version_id"] != coordinate["version_id"]
                for item in present_rollback.values()
            )
            or present_rollback["rollback-lineage-archive"]["uri"] != ref
            or present_rollback["rollback-lineage-manifest"]["uri"] != ref
        ):
            raise ReleaseError("ROLLBACK_EVIDENCE_CARRIAGE")
        if (
            rev >= 2
            and present_rollback["rollback-verified-record"]["sha256"]
            != record["recovery"]["previous_good_record_sha256"]
        ):
            raise ReleaseError("ROLLBACK_TARGET_DIGEST")
    elif record["recovery"]["rollback_ref"] is not None or present_rollback:
        raise ReleaseError("DEPLOY_ROLLBACK_LINEAGE_PROHIBITED")
    if record["status"] in ("READY_FOR_OWNER", "APPROVED", "APPLIED", "VERIFIED"):
        required = (
            source["archive_sha256"],
            source["s3_bucket"],
            source["s3_key"],
            source["s3_version_id"],
            artifacts["container_repository"],
            image,
            collector,
            artifacts["sbom_sha256"],
            artifacts["provenance_sha256"],
            artifacts["signature_ref"],
            tf["configuration_version_id"],
            tf["run_id"],
            tf["plan_id"],
            tf["configuration_sha256"],
            gates["opa_evidence_sha256"],
            gates["run_task_result_id"],
            deployment["account_id"],
            deployment["w6_release_hashes_sha256"],
            deployment["root_fingerprint_sha256"],
            deployment["trust_bundle_sha256"],
        )
        if (
            deployment["render_contract"] != "w12-001.render.v1"
            or any(item is None for item in required)
            or any(
                gates[name] != "PASS" for name in ("opa_status", "run_task_status", "scan_status")
            )
        ):
            raise ReleaseError("RELEASE_NOT_READY")
    if status in ("READY_FOR_OWNER", "APPROVED") and (
        deployment["render_inputs_sha256"] is not None
        or deployment["derivative_manifest_sha256"] is not None
    ):
        raise ReleaseError("RENDER_DIGEST_PREMATURE")
    if status in ("APPLIED", "VERIFIED") and not _hex(
        deployment["render_inputs_sha256"], required=True
    ):
        raise ReleaseError("RENDER_INPUT_DIGEST_REQUIRED")
    if status == "APPLIED" and deployment["derivative_manifest_sha256"] is not None:
        raise ReleaseError("RENDERED_DIGEST_PREMATURE")
    if status == "VERIFIED" and not _hex(deployment["derivative_manifest_sha256"], required=True):
        raise ReleaseError("RENDERED_DIGEST_REQUIRED")
    if status == "VERIFIED":
        required_kinds = {
            "source_bundle",
            "codebuild-control-bundle",
            "codebuild_result",
            "rendered_release_archive",
            "verified_transition",
            "verified_transition_sidecar",
            "opa_receipt",
            "opa_receipt_sidecar",
        }
        found = [item["kind"] for item in record["evidence"] if item["kind"] in required_kinds]
        if set(found) != required_kinds or len(found) != len(required_kinds):
            raise ReleaseError("VERIFIED_CANONICAL_OBJECT_COVERAGE")
    return record


def decode_record_b64url(encoded: str, expected_sha256: str) -> bytes:
    cfg = _config()
    if (
        not isinstance(encoded, str)
        or len(encoded) > cfg["record_max_b64url_chars"]
        or not B64URL.fullmatch(encoded)
        or len(encoded) % 4 == 1
    ):
        raise ReleaseError("B64URL_FORMAT")
    if not isinstance(expected_sha256, str) or not HEX64.fullmatch(expected_sha256):
        raise ReleaseError("RECORD_SHA256_FORMAT")
    try:
        raw = base64.b64decode(encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ReleaseError("B64URL_DECODE") from exc
    if (
        len(raw) > cfg["record_max_bytes"]
        or base64.urlsafe_b64encode(raw).decode().rstrip("=") != encoded
    ):
        raise ReleaseError("B64URL_NOT_CANONICAL")
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ReleaseError("RECORD_SHA256_MISMATCH")
    return raw


def _canonical_bytes(value: dict[str, Any]) -> bytes:
    _walk(value)
    return (
        json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode(
            "utf-8"
        )
        + b"\n"
    )


def _strict_transport(encoded: str, digest: str, *, receipt: bool) -> bytes:
    cfg = _config()
    maximum = cfg["opa_receipt_max_b64url_chars"] if receipt else cfg["record_max_b64url_chars"]
    if (
        not isinstance(encoded, str)
        or not encoded
        or len(encoded) > maximum
        or not B64URL.fullmatch(encoded)
        or len(encoded) % 4 == 1
    ):
        raise ReleaseError("TRANSPORT_FORMAT")
    if not isinstance(digest, str) or not HEX64.fullmatch(digest):
        raise ReleaseError("TRANSPORT_DIGEST_FORMAT")
    try:
        raw = base64.b64decode(encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ReleaseError("TRANSPORT_DECODE") from exc
    byte_limit = cfg["opa_receipt_max_bytes"] if receipt else cfg["record_max_bytes"]
    if (
        len(raw) > byte_limit
        or base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != encoded
    ):
        raise ReleaseError("TRANSPORT_NONCANONICAL")
    if hashlib.sha256(raw).hexdigest() != digest:
        raise ReleaseError("TRANSPORT_DIGEST_MISMATCH")
    return raw


def _strict_b64url(value: str) -> bytes:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 43_691
        or not B64URL.fullmatch(value)
        or len(value) % 4 == 1
    ):
        raise ReleaseError("LOCATOR_BASE64URL")
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ReleaseError("LOCATOR_BASE64URL") from exc
    if base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != value:
        raise ReleaseError("LOCATOR_BASE64URL")
    return decoded


def encode_s3v_locator(bucket: str, key: str, version_id: str, *, entry: str | None = None) -> str:
    """Construct the only approved query-free versioned S3 evidence coordinate."""
    if not isinstance(bucket, str) or not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", bucket):
        raise ReleaseError("LOCATOR_BUCKET")
    if not isinstance(key, str) or not key or not isinstance(version_id, str) or not version_id:
        raise ReleaseError("LOCATOR_OBJECT_IDENTITY")
    if entry is not None:
        _safe_bundle_path(entry)
        if entry == BOOTSTRAP_SHA:
            raise ReleaseError("BOOTSTRAP_SIDECAR_LOCATOR")
    components = [key, version_id]
    for value in components:
        if unicodedata.normalize("NFC", value) != value or any(ord(char) < 33 for char in value):
            raise ReleaseError("LOCATOR_COMPONENT")
    encoded = [
        base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii").rstrip("=")
        for value in components
    ]
    selector = (
        "object"
        if entry is None
        else "entry/" + base64.urlsafe_b64encode(entry.encode("utf-8")).decode("ascii").rstrip("=")
    )
    return f"w12-s3v://{bucket}/{encoded[0]}/{encoded[1]}/{selector}"


class S3vLocator(TypedDict):
    bucket: str
    key: str
    version_id: str
    entry: str | None


def decode_s3v_locator(uri: str) -> S3vLocator:
    if (
        not isinstance(uri, str)
        or len(uri) > 32_768
        or not uri.startswith("w12-s3v://")
        or any(char in uri for char in ("?", "#", "@", "%", " ", "\t", "\r", "\n"))
    ):
        raise ReleaseError("LOCATOR_SYNTAX")
    parts = uri[len("w12-s3v://") :].split("/")
    if len(parts) not in (4, 5) or not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", parts[0]):
        raise ReleaseError("LOCATOR_SYNTAX")
    if (len(parts) == 4 and parts[3] != "object") or (len(parts) == 5 and parts[3] != "entry"):
        raise ReleaseError("LOCATOR_SELECTOR")
    try:
        key = _strict_b64url(parts[1]).decode("utf-8", "strict")
        version = _strict_b64url(parts[2]).decode("utf-8", "strict")
        entry = _strict_b64url(parts[4]).decode("utf-8", "strict") if len(parts) == 5 else None
    except UnicodeDecodeError as exc:
        raise ReleaseError("LOCATOR_UTF8") from exc
    if not key or not version or any(ord(char) < 33 for char in key + version):
        raise ReleaseError("LOCATOR_OBJECT_IDENTITY")
    if entry is not None:
        _safe_bundle_path(entry)
        if entry == BOOTSTRAP_SHA:
            raise ReleaseError("BOOTSTRAP_SIDECAR_LOCATOR")
    if encode_s3v_locator(parts[0], key, version, entry=entry) != uri:
        raise ReleaseError("LOCATOR_NONCANONICAL")
    return {"bucket": parts[0], "key": key, "version_id": version, "entry": entry}


def _safe_bundle_path(path: str) -> str:
    if (
        not isinstance(path, str)
        or not path
        or path.startswith("/")
        or "\\" in path
        or "%" in path
        or re.match(r"^[A-Za-z]:", path) is not None
        or unicodedata.normalize("NFC", path) != path
        or any(ord(char) < 32 for char in path)
        or any(part in ("", ".", "..") for part in path.split("/"))
    ):
        raise ReleaseError("BUNDLE_PATH_UNSAFE")
    return path


def _canonical_document(raw: bytes, *, fields: list[str], code: str) -> dict[str, Any]:
    if (
        not raw
        or raw.startswith(b"\xef\xbb\xbf")
        or not raw.endswith(b"\n")
        or raw.endswith(b"\n\n")
    ):
        raise ReleaseError(code + "_BYTES")
    try:
        value = json.loads(
            raw[:-1].decode("utf-8", "strict"),
            object_pairs_hook=_unique_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ReleaseError(code + "_JSON") from exc
    value = _fields(value, fields, code + "_FIELDS")
    if _canonical_bytes(value) != raw:
        raise ReleaseError(code + "_NONCANONICAL")
    return value


def _manifest_files(items: Any, *, code: str) -> dict[str, tuple[int, str]]:
    if not isinstance(items, list) or not items:
        raise ReleaseError(code + "_EMPTY")
    found: dict[str, tuple[int, str]] = {}
    for item in items:
        _fields(item, ["path", "size", "sha256"], code + "_ITEM")
        name = _safe_bundle_path(item["path"])
        if (
            name in found
            or type(item["size"]) is not int
            or item["size"] < 0
            or not _hex(item["sha256"], required=True)
        ):
            raise ReleaseError(code + "_ITEM")
        found[name] = (item["size"], item["sha256"])
    if list(found) != sorted(found) or len({name.casefold() for name in found}) != len(found):
        raise ReleaseError(code + "_ORDER_OR_ALIAS")
    return found


def _zip_files(raw: bytes) -> dict[str, bytes]:
    if not raw or len(raw) > 10_737_418_240:
        raise ReleaseError("SOURCE_ZIP_SIZE")
    result: dict[str, bytes] = {}
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            if archive.comment or not archive.infolist() or len(archive.infolist()) > 10_000:
                raise ReleaseError("SOURCE_ZIP_METADATA")
            names = [item.filename for item in archive.infolist()]
            if (
                names != sorted(names)
                or len(set(names)) != len(names)
                or len({name.casefold() for name in names}) != len(names)
            ):
                raise ReleaseError("SOURCE_ZIP_ORDER_OR_ALIAS")
            for info in archive.infolist():
                name = _safe_bundle_path(info.filename)
                mode = (info.external_attr >> 16) & 0o777777
                if (
                    info.is_dir()
                    or info.compress_type != zipfile.ZIP_STORED
                    or info.date_time != ZIP_EPOCH
                    or info.extra
                    or info.comment
                    or mode != 0o100644
                    or info.file_size > 52_428_800
                ):
                    raise ReleaseError("SOURCE_ZIP_ENTRY_METADATA")
                result[name] = archive.read(info)
    except (zipfile.BadZipFile, RuntimeError, EOFError) as exc:
        raise ReleaseError("SOURCE_ZIP_INVALID") from exc
    return result


def _make_zip(files: dict[str, bytes]) -> bytes:
    if not files or len(files) > 10_000 or len({name.casefold() for name in files}) != len(files):
        raise ReleaseError("SOURCE_ZIP_FILE_SET")
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
        for name in sorted(files):
            _safe_bundle_path(name)
            info = zipfile.ZipInfo(name, date_time=ZIP_EPOCH)
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, files[name])
    return output.getvalue()


def _file_inventory(files: dict[str, bytes]) -> list[dict[str, Any]]:
    return [
        {"path": name, "size": len(files[name]), "sha256": hashlib.sha256(files[name]).hexdigest()}
        for name in sorted(files)
    ]


FUTURE_LINEAGE_RECORD_PATHS = (
    "rollback/parent/release-record.json",
    "rollback/parent/release-record.sha256",
    "rollback/verified/release-record.json",
    "rollback/verified/release-record.sha256",
)
FUTURE_LINEAGE_PATHS = frozenset(FUTURE_LINEAGE_RECORD_PATHS) | {
    "rollback/rollback-lineage-manifest.json",
    "rollback/rollback-lineage-manifest.sha256",
}


def _validated_release_chain(raws: list[bytes]) -> list[dict[str, Any]]:
    if len(raws) != 5:
        raise ReleaseError("LINEAGE_CHAIN_LENGTH")
    records: list[dict[str, Any]] = []
    for index, raw in enumerate(raws):
        digest = hashlib.sha256(raw).hexdigest()
        record = validate_record(
            raw,
            (digest + "\n").encode("ascii"),
            previous=raws[index - 1] if index else None,
        )
        if record["revision"] != index + 1:
            raise ReleaseError("LINEAGE_CHAIN_IDENTITY")
        if records and (
            record["record_id"] != records[0]["record_id"]
            or record["operation"] != records[0]["operation"]
        ):
            raise ReleaseError("LINEAGE_CHAIN_IDENTITY")
        records.append(record)
    if records[3]["status"] != "APPLIED" or records[4]["status"] != "VERIFIED":
        raise ReleaseError("LINEAGE_CHAIN_STATUS")
    return records


def make_future_lineage_zip(raws: list[bytes]) -> bytes:
    """Build the sole post-r5 derivative from the validated r1-r5 chain."""
    records = _validated_release_chain(raws)
    files = {
        "rollback/verified/release-record.json": raws[4],
        "rollback/verified/release-record.sha256": (
            hashlib.sha256(raws[4]).hexdigest() + "\n"
        ).encode("ascii"),
        "rollback/parent/release-record.json": raws[3],
        "rollback/parent/release-record.sha256": (
            hashlib.sha256(raws[3]).hexdigest() + "\n"
        ).encode("ascii"),
    }
    manifest = _canonical_bytes(
        {
            "schema_version": "w12-001.rollback-lineage.v1",
            "record_id": records[4]["record_id"],
            "operation": records[4]["operation"],
            "verified_record_sha256": hashlib.sha256(raws[4]).hexdigest(),
            "parent_record_sha256": hashlib.sha256(raws[3]).hexdigest(),
            "files": _file_inventory(files),
        }
    )
    files["rollback/rollback-lineage-manifest.json"] = manifest
    files["rollback/rollback-lineage-manifest.sha256"] = (
        hashlib.sha256(manifest).hexdigest() + "\n"
    ).encode("ascii")
    return _make_zip(files)


def validate_future_lineage_zip(raw: bytes, *, raws: list[bytes]) -> dict[str, Any]:
    """Check the exact derivative inventory, bytes, parent link, and manifest."""
    records = _validated_release_chain(raws)
    files = _zip_files(raw)
    if set(files) != FUTURE_LINEAGE_PATHS or len(files) != 6:
        raise ReleaseError("FUTURE_LINEAGE_INVENTORY")
    expected_records = {
        "rollback/verified/release-record.json": raws[4],
        "rollback/verified/release-record.sha256": (
            hashlib.sha256(raws[4]).hexdigest() + "\n"
        ).encode("ascii"),
        "rollback/parent/release-record.json": raws[3],
        "rollback/parent/release-record.sha256": (
            hashlib.sha256(raws[3]).hexdigest() + "\n"
        ).encode("ascii"),
    }
    if any(files[name] != expected for name, expected in expected_records.items()):
        raise ReleaseError("FUTURE_LINEAGE_RECORD_BYTES")
    manifest_raw = files["rollback/rollback-lineage-manifest.json"]
    if files["rollback/rollback-lineage-manifest.sha256"] != (
        hashlib.sha256(manifest_raw).hexdigest() + "\n"
    ).encode("ascii"):
        raise ReleaseError("FUTURE_LINEAGE_MANIFEST_SIDECAR")
    manifest = _canonical_document(
        manifest_raw,
        fields=[
            "schema_version",
            "record_id",
            "operation",
            "verified_record_sha256",
            "parent_record_sha256",
            "files",
        ],
        code="FUTURE_LINEAGE_MANIFEST",
    )
    if (
        manifest["schema_version"] != "w12-001.rollback-lineage.v1"
        or manifest["record_id"] != records[4]["record_id"]
        or manifest["operation"] != records[4]["operation"]
        or manifest["verified_record_sha256"] != hashlib.sha256(raws[4]).hexdigest()
        or manifest["parent_record_sha256"] != records[4]["previous_record_sha256"]
    ):
        raise ReleaseError("FUTURE_LINEAGE_MANIFEST_IDENTITY")
    listed = _manifest_files(manifest["files"], code="FUTURE_LINEAGE_FILES")
    if set(listed) != set(FUTURE_LINEAGE_RECORD_PATHS) or any(
        listed[name] != (len(files[name]), hashlib.sha256(files[name]).hexdigest())
        for name in FUTURE_LINEAGE_RECORD_PATHS
    ):
        raise ReleaseError("FUTURE_LINEAGE_FILE_BINDING")
    return manifest


def validate_current_control_bundle(
    raw: bytes,
    *,
    records: list[dict[str, Any]],
    raws: list[bytes],
) -> dict[str, bytes]:
    """Validate the complete current r4 handoff without trusting ZIP filenames."""
    if len(records) != 5 or len(raws) != 5:
        raise ReleaseError("CONTROL_PROOF_CHAIN_LENGTH")
    files = _zip_files(raw)
    payload_names = {
        "release-record.json",
        "release-record.sha256",
        "w12-render-inputs.json",
        "w12-render-inputs.sha256",
        *(
            f"records/r{revision}/{name}"
            for revision in (1, 2, 3)
            for name in ("release-record.json", "release-record.sha256")
        ),
        *(
            f"records/r{revision}/{name}"
            for revision in (2, 3, 4)
            for name in ("transition-evidence.json", "transition-evidence.sha256")
        ),
    }
    if records[4]["operation"] == "rollback":
        payload_names |= FUTURE_LINEAGE_PATHS
    if set(files) != payload_names | {"codebuild-handoff.json", "codebuild-handoff.sha256"} or len(
        files
    ) != (24 if records[4]["operation"] == "rollback" else 18):
        raise ReleaseError("CONTROL_PROOF_INVENTORY")
    handoff_raw = files["codebuild-handoff.json"]
    if files["codebuild-handoff.sha256"] != (hashlib.sha256(handoff_raw).hexdigest() + "\n").encode(
        "ascii"
    ):
        raise ReleaseError("CONTROL_PROOF_HANDOFF_SIDECAR")
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
        code="CONTROL_PROOF_HANDOFF",
    )
    payload = {name: files[name] for name in payload_names}
    if (
        handoff["schema_version"] != "w12-001.codebuild-handoff.v2"
        or handoff["record_id"] != records[4]["record_id"]
        or handoff["operation"] != records[4]["operation"]
        or handoff["files"] != _file_inventory(payload)
    ):
        raise ReleaseError("CONTROL_PROOF_HANDOFF_BINDING")
    if (
        type(handoff["workflow_run_id"]) is not int
        or handoff["workflow_run_id"] != records[3]["gates"]["github_run_id"]
        or not isinstance(handoff["records"], list)
        or len(handoff["records"]) != 4
    ):
        raise ReleaseError("CONTROL_PROOF_RUN_OR_RECORD_COUNT")
    _utc(handoff["created_at_utc"])
    for revision, item in enumerate(handoff["records"], start=1):
        _fields(
            item,
            ["revision", "status", "record_sha256", "artifact_id", "artifact_digest"],
            "CONTROL_PROOF_RECORD_ITEM",
        )
        if (
            item["revision"] != revision
            or item["status"] != records[revision - 1]["status"]
            or item["record_sha256"] != hashlib.sha256(raws[revision - 1]).hexdigest()
            or type(item["artifact_id"]) is not int
            or item["artifact_id"] <= 0
            or not isinstance(item["artifact_digest"], str)
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", item["artifact_digest"])
        ):
            raise ReleaseError("CONTROL_PROOF_RECORD_BINDING")
    _fields(handoff["w6_release"], ["release_hashes_sha256"], "CONTROL_W6_FIELDS")
    _fields(handoff["artifacts"], ["image_digest"], "CONTROL_ARTIFACT_FIELDS")
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
        "CONTROL_TERRAFORM_FIELDS",
    )
    tf = records[3]["terraform"]
    if (
        handoff["w6_release"]["release_hashes_sha256"]
        != records[1]["deployment"]["w6_release_hashes_sha256"]
        or handoff["artifacts"]["image_digest"] != application_image_from_ready(records[1])
        or tuple(
            handoff["terraform"][key]
            for key in (
                "organization",
                "workspace",
                "run_id",
                "plan_id",
                "input_state_version_id",
                "input_state_lineage",
                "input_state_serial",
            )
        )
        != (
            tf["organization"],
            tf["workspace"],
            tf["run_id"],
            tf["plan_id"],
            tf["input_state_version_id"],
            tf["state_lineage"],
            tf["input_state_serial"],
        )
    ):
        raise ReleaseError("CONTROL_PROOF_HCP_OR_ARTIFACT_CHANGED")
    if files["release-record.json"] != raws[3] or files["release-record.sha256"] != (
        hashlib.sha256(raws[3]).hexdigest() + "\n"
    ).encode("ascii"):
        raise ReleaseError("CONTROL_PROOF_APPLIED_CHANGED")
    for revision in (1, 2, 3):
        prefix = f"records/r{revision}/"
        if files[prefix + "release-record.json"] != raws[revision - 1] or files[
            prefix + "release-record.sha256"
        ] != (hashlib.sha256(raws[revision - 1]).hexdigest() + "\n").encode("ascii"):
            raise ReleaseError("CONTROL_PROOF_RECORD_CHAIN_CHANGED")
    for revision in (2, 3, 4):
        prefix = f"records/r{revision}/transition-evidence."
        transition_raw = files[prefix + "json"]
        if files[prefix + "sha256"] != (hashlib.sha256(transition_raw).hexdigest() + "\n").encode(
            "ascii"
        ):
            raise ReleaseError("CONTROL_PROOF_TRANSITION_CHANGED")
    primary = handoff["primary_source"]
    _fields(
        primary,
        ["bucket", "key", "version_id", "object_sha256", "manifest_sha256", "commit", "tree"],
        "CONTROL_PRIMARY_FIELDS",
    )
    if (
        primary["bucket"],
        primary["key"],
        primary["version_id"],
        primary["object_sha256"],
        primary["commit"],
        primary["tree"],
    ) != (
        records[3]["source"]["s3_bucket"],
        SOURCE_KEY,
        records[3]["source"]["s3_version_id"],
        records[3]["source"]["archive_sha256"],
        records[3]["source"]["commit"],
        records[3]["source"]["tree"],
    ):
        raise ReleaseError("CONTROL_PROOF_PRIMARY_CHANGED")
    render = validate_render_inputs(
        files["w12-render-inputs.json"],
        files["w12-render-inputs.sha256"],
        ready=records[1],
        ready_sha256=hashlib.sha256(raws[1]).hexdigest(),
        approved=records[2],
        approved_sha256=hashlib.sha256(raws[2]).hexdigest(),
        applied=records[3],
        enforce_current=False,
    )
    if tuple(
        handoff["terraform"][key]
        for key in (
            "output_state_version_id",
            "output_state_lineage",
            "output_state_serial",
        )
    ) != (render["applied_state_version_id"], render["state_lineage"], render["state_serial"]):
        raise ReleaseError("CONTROL_PROOF_OUTPUT_STATE_CHANGED")
    return files


def make_primary_source_bundle(
    tracked: dict[str, bytes], *, commit: str, tree: str
) -> tuple[bytes, str, str]:
    """Produce the non-recursive source ZIP from exact tracked regular files."""
    if (
        not HEX40.fullmatch(commit)
        or not HEX40.fullmatch(tree)
        or not tracked
        or any(
            name in (BOOTSTRAP_JSON, BOOTSTRAP_SHA, W6_HASHES_JSON, W6_HASHES_SHA)
            for name in tracked
        )
    ):
        raise ReleaseError("SOURCE_COMMIT_TREE_OR_RESERVED_PATH")
    for name, contents in tracked.items():
        _safe_bundle_path(name)
        if not isinstance(contents, bytes):
            raise ReleaseError("SOURCE_FILE_BYTES")
    w6 = {name: contents for name, contents in tracked.items() if name.startswith("deploy/k8s/")}
    if not w6:
        raise ReleaseError("W6_SOURCE_EMPTY")
    release = {
        "schema_version": "w6-release.hashes.v1",
        "repository": GITHUB_REPOSITORY,
        "commit": commit,
        "tree": tree,
        "files": _file_inventory(w6),
    }
    w6_raw = _canonical_bytes(release)
    payload = dict(tracked)
    payload[W6_HASHES_JSON] = w6_raw
    payload[W6_HASHES_SHA] = (hashlib.sha256(w6_raw).hexdigest() + "\n").encode("ascii")
    manifest = {
        "schema_version": "w12-001.source.v1",
        "repository": GITHUB_REPOSITORY,
        "commit": commit,
        "tree": tree,
        "files": _file_inventory(payload),
        "w6_release_hashes_sha256": hashlib.sha256(w6_raw).hexdigest(),
    }
    manifest_raw = _canonical_bytes(manifest)
    payload[BOOTSTRAP_JSON] = manifest_raw
    payload[BOOTSTRAP_SHA] = (hashlib.sha256(manifest_raw).hexdigest() + "\n").encode("ascii")
    archive = _make_zip(payload)
    return archive, hashlib.sha256(manifest_raw).hexdigest(), hashlib.sha256(w6_raw).hexdigest()


def validate_primary_source_bundle(
    raw: bytes,
    *,
    archive_sha256: str,
    manifest_sha256: str,
    w6_sha256: str,
    commit: str,
    tree: str,
) -> dict[str, bytes]:
    """Stage A authenticates the bootstrap pair; Stage B checks exact payload coverage."""
    if not all(
        _hex(value, required=True) for value in (archive_sha256, manifest_sha256, w6_sha256)
    ):
        raise ReleaseError("SOURCE_DIGEST_REQUIRED")
    if hashlib.sha256(raw).hexdigest() != archive_sha256:
        raise ReleaseError("SOURCE_ARCHIVE_DIGEST_MISMATCH")
    files = _zip_files(raw)
    if BOOTSTRAP_JSON not in files or BOOTSTRAP_SHA not in files:
        raise ReleaseError("SOURCE_BOOTSTRAP_PAIR_MISSING")
    manifest_raw = files[BOOTSTRAP_JSON]
    actual_manifest_sha = hashlib.sha256(manifest_raw).hexdigest()
    if actual_manifest_sha != manifest_sha256 or files[BOOTSTRAP_SHA] != (
        actual_manifest_sha + "\n"
    ).encode("ascii"):
        raise ReleaseError("SOURCE_BOOTSTRAP_DIGEST_MISMATCH")
    manifest = _canonical_document(
        manifest_raw,
        fields=[
            "schema_version",
            "repository",
            "commit",
            "tree",
            "files",
            "w6_release_hashes_sha256",
        ],
        code="SOURCE_MANIFEST",
    )
    if (
        manifest["schema_version"],
        manifest["repository"],
        manifest["commit"],
        manifest["tree"],
        manifest["w6_release_hashes_sha256"],
    ) != (
        "w12-001.source.v1",
        GITHUB_REPOSITORY,
        commit,
        tree,
        w6_sha256,
    ):
        raise ReleaseError("SOURCE_MANIFEST_IDENTITY")
    inventory = _manifest_files(manifest["files"], code="SOURCE_MANIFEST")
    if BOOTSTRAP_JSON in inventory or BOOTSTRAP_SHA in inventory:
        raise ReleaseError("SOURCE_BOOTSTRAP_SELF_LISTING")
    payload = {
        name: contents
        for name, contents in files.items()
        if name not in (BOOTSTRAP_JSON, BOOTSTRAP_SHA)
    }
    if set(payload) != set(inventory):
        raise ReleaseError("SOURCE_PAYLOAD_SET_MISMATCH")
    for name, (size, digest) in inventory.items():
        if len(payload[name]) != size or hashlib.sha256(payload[name]).hexdigest() != digest:
            raise ReleaseError("SOURCE_PAYLOAD_BYTES_MISMATCH")
    if W6_HASHES_JSON not in payload or W6_HASHES_SHA not in payload:
        raise ReleaseError("W6_HASHES_MISSING")
    w6_raw = payload[W6_HASHES_JSON]
    if hashlib.sha256(w6_raw).hexdigest() != w6_sha256 or payload[W6_HASHES_SHA] != (
        w6_sha256 + "\n"
    ).encode("ascii"):
        raise ReleaseError("W6_HASHES_DIGEST_MISMATCH")
    w6 = _canonical_document(
        w6_raw, fields=["schema_version", "repository", "commit", "tree", "files"], code="W6_HASHES"
    )
    if (w6["schema_version"], w6["repository"], w6["commit"], w6["tree"]) != (
        "w6-release.hashes.v1",
        GITHUB_REPOSITORY,
        commit,
        tree,
    ):
        raise ReleaseError("W6_HASHES_IDENTITY")
    w6_inventory = _manifest_files(w6["files"], code="W6_HASHES")
    w6_payload = {
        name: contents for name, contents in payload.items() if name.startswith("deploy/k8s/")
    }
    if set(w6_inventory) != set(w6_payload):
        raise ReleaseError("W6_SOURCE_SET_MISMATCH")
    for name, (size, digest) in w6_inventory.items():
        if len(w6_payload[name]) != size or hashlib.sha256(w6_payload[name]).hexdigest() != digest:
            raise ReleaseError("W6_SOURCE_BYTES_MISMATCH")
    return files


def _tracked_regular_files(commit: str, tree: str) -> dict[str, bytes]:
    """Read only exact Git tree blobs; never walk untracked workspace files."""
    if not HEX40.fullmatch(commit) or not HEX40.fullmatch(tree):
        raise ReleaseError("GIT_SOURCE_IDENTITY")
    executable = shutil.which("git")
    if executable is None or not Path(executable).is_absolute():
        raise ReleaseError("GIT_EXECUTABLE_UNAVAILABLE")
    head = subprocess.run(  # noqa: S603 -- exact read-only Git arguments, no shell
        [executable, "rev-parse", "HEAD"],
        cwd=ROOT,
        capture_output=True,
        timeout=10,
        check=False,
    )
    root_tree = subprocess.run(  # noqa: S603 -- exact read-only Git arguments, no shell
        [executable, "rev-parse", "HEAD^{tree}"],
        cwd=ROOT,
        capture_output=True,
        timeout=10,
        check=False,
    )
    if (
        head.returncode
        or root_tree.returncode
        or head.stdout.strip().decode("ascii") != commit
        or root_tree.stdout.strip().decode("ascii") != tree
    ):
        raise ReleaseError("GIT_CHECKOUT_IDENTITY_MISMATCH")
    listing = subprocess.run(  # noqa: S603 -- validated commit and read-only Git query
        [executable, "ls-tree", "-r", "-z", "--full-tree", commit],
        cwd=ROOT,
        capture_output=True,
        timeout=30,
        check=False,
    )
    if listing.returncode or len(listing.stdout) > 20_000_000 or not listing.stdout.endswith(b"\0"):
        raise ReleaseError("GIT_TRACKED_INVENTORY_INCOMPLETE")
    files: dict[str, bytes] = {}
    for entry in listing.stdout[:-1].split(b"\0"):
        metadata, name_bytes = entry.split(b"\t", 1)
        mode, kind, object_id = metadata.decode("ascii").split(" ")
        name = name_bytes.decode("utf-8", "strict")
        _safe_bundle_path(name)
        if (
            mode not in ("100644", "100755")
            or kind != "blob"
            or not HEX40.fullmatch(object_id)
            or name.casefold() in {item.casefold() for item in files}
        ):
            raise ReleaseError("GIT_TRACKED_PATH_OR_TYPE_UNSAFE")
        content = subprocess.run(  # noqa: S603 -- validated Git object ID, no shell
            [executable, "cat-file", "blob", object_id],
            cwd=ROOT,
            capture_output=True,
            timeout=30,
            check=False,
        )
        if content.returncode or len(content.stdout) > 52_428_800:
            raise ReleaseError("GIT_BLOB_UNAVAILABLE")
        files[name] = content.stdout
    return files


def _terraform_module_sources(blob: bytes) -> list[str]:
    """Extract literal module sources, rejecting ambiguous HCL module blocks."""
    try:
        source = blob.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise ReleaseError("TERRAFORM_MODULE_UTF8") from exc
    starts = list(re.finditer(r'(?m)^[ \t]*module[ \t]+"[^"\r\n]+"[ \t]*\{', source))
    found: list[str] = []
    for match in starts:
        cursor = match.end()
        depth = 1
        quoted = False
        line_comment = False
        block_comment = False
        while cursor < len(source) and depth:
            char = source[cursor]
            following = source[cursor : cursor + 2]
            if line_comment:
                if char == "\n":
                    line_comment = False
            elif block_comment:
                if following == "*/":
                    block_comment = False
                    cursor += 1
            elif quoted:
                if char == "\\":
                    cursor += 1
                elif char == '"':
                    quoted = False
            elif following in ("//", "/*"):
                if following == "//":
                    line_comment = True
                else:
                    block_comment = True
                cursor += 1
            elif char == "#":
                line_comment = True
            elif char == '"':
                quoted = True
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
            cursor += 1
        if depth or quoted or block_comment:
            raise ReleaseError("TERRAFORM_MODULE_BLOCK_AMBIGUOUS")
        body = source[match.end() : cursor - 1]
        if "<<" in body:
            raise ReleaseError("TERRAFORM_MODULE_HEREDOC_AMBIGUOUS")
        declarations = re.findall(r"(?m)^[ \t]*source[ \t]*=", body)
        values = re.findall(
            r'(?m)^[ \t]*source[ \t]*=[ \t]*"([^"\r\n]+)"[ \t]*(?:#[^\r\n]*)?$',
            body,
        )
        if len(declarations) != 1 or len(values) != 1 or "${" in values[0] or "\\" in values[0]:
            raise ReleaseError("TERRAFORM_MODULE_SOURCE_NONLITERAL")
        found.append(values[0])
    if len(starts) != len(re.findall(r"(?m)^[ \t]*module[ \t]+", source)):
        raise ReleaseError("TERRAFORM_MODULE_DECLARATION_AMBIGUOUS")
    return found


def terraform_configuration_manifest(
    commit: str,
    tree: str,
    *,
    tracked_files: dict[str, bytes] | None = None,
) -> bytes:
    """Hash exact Git blobs in the root and recursive literal local-module closure."""
    if not HEX40.fullmatch(commit) or not HEX40.fullmatch(tree):
        raise ReleaseError("TERRAFORM_CONFIGURATION_COMMIT")
    tracked = _tracked_regular_files(commit, tree) if tracked_files is None else tracked_files
    root = "infra/environments/sandbox"
    if not isinstance(tracked, dict) or not any(path.startswith(root + "/") for path in tracked):
        raise ReleaseError("TERRAFORM_CONFIGURATION_ROOT_MISSING")
    if any(
        not isinstance(path, str) or not isinstance(blob, bytes) for path, blob in tracked.items()
    ):
        raise ReleaseError("TERRAFORM_CONFIGURATION_BLOB_TYPE")
    pending = [root]
    visited: set[str] = set()
    modules: set[str] = set()
    selected: set[str] = set()
    while pending:
        current = pending.pop()
        if current in visited:
            continue
        visited.add(current)
        current_files = {path for path in tracked if path.startswith(current + "/")}
        if not current_files or not any(path.endswith(".tf") for path in current_files):
            raise ReleaseError("TERRAFORM_LOCAL_MODULE_UNRESOLVED")
        selected.update(current_files)
        for path in sorted(current_files):
            if not path.endswith(".tf"):
                continue
            for source in _terraform_module_sources(tracked[path]):
                if source.startswith(("./", "../")):
                    target = posixpath.normpath(posixpath.join(current, source))
                    if target in (".", "..") or target.startswith("../") or target.startswith("/"):
                        raise ReleaseError("TERRAFORM_LOCAL_MODULE_ESCAPE")
                    if target != root:
                        modules.add(target)
                    pending.append(target)
                elif source.startswith(".") or source.startswith("/") or ":\\" in source:
                    raise ReleaseError("TERRAFORM_LOCAL_MODULE_AMBIGUOUS")
    for path in selected:
        _safe_bundle_path(path)
        lowered = path.casefold()
        if (
            lowered.endswith((".tfstate", ".tfstate.backup", ".tfplan", ".plan", ".pem", ".key"))
            or "/.terraform/" in lowered
            or "/credentials" in lowered
            or lowered.endswith("terraform.tfvars")
            or (b"-----BEGIN " + b"PRIVATE KEY-----") in tracked[path]
            or re.search(rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", tracked[path])
        ):
            raise ReleaseError("TERRAFORM_CONFIGURATION_SENSITIVE_BLOB")
    if len({path.casefold() for path in selected}) != len(selected):
        raise ReleaseError("TERRAFORM_CONFIGURATION_DUPLICATE_PATH")
    manifest = {
        "schema_version": "w12-001.terraform-configuration-manifest.v1",
        "repository": GITHUB_REPOSITORY,
        "commit": commit,
        "root": root,
        "module_roots": sorted(modules),
        "files": [
            {
                "path": path,
                "size": len(tracked[path]),
                "sha256": hashlib.sha256(tracked[path]).hexdigest(),
            }
            for path in sorted(selected)
        ],
    }
    return _canonical_bytes(manifest)


def validate_terraform_configuration_binding(record: dict[str, Any]) -> str:
    """Bind the record to committed configuration, never the working tree or HCP archive."""
    raw = terraform_configuration_manifest(record["source"]["commit"], record["source"]["tree"])
    digest = hashlib.sha256(raw).hexdigest()
    expected = record["terraform"]["configuration_sha256"]
    if expected not in (None, digest):
        raise ReleaseError("TERRAFORM_CONFIGURATION_MANIFEST_MISMATCH")
    return digest


def _s3_client() -> Any:
    import boto3  # type: ignore[import-untyped]

    return boto3.client("s3", region_name=_config()["aws_region"])


def _s3_full_checksum(raw: bytes) -> str:
    return base64.b64encode(hashlib.sha256(raw).digest()).decode("ascii")


def _s3_read_exact(client: Any, bucket: str, key: str, version: str, digest: str) -> bytes:
    response = client.get_object(Bucket=bucket, Key=key, VersionId=version, ChecksumMode="ENABLED")
    raw = response["Body"].read(1_073_741_825)
    if not isinstance(raw, bytes):
        raise ReleaseError("S3_VERSION_BODY_TYPE")
    if (
        len(raw) > 1_073_741_824
        or response.get("VersionId") != version
        or response.get("ServerSideEncryption") != "aws:kms"
        or response.get("ChecksumSHA256") != _s3_full_checksum(raw)
        or hashlib.sha256(raw).hexdigest() != digest
    ):
        raise ReleaseError("S3_VERSION_READBACK_MISMATCH")
    return raw


def _s3_upload_exact(
    client: Any, *, bucket: str, key: str, raw: bytes, metadata: dict[str, str], kms_key: str
) -> str:
    """Reconcile same-release versions; never select the bucket's latest version."""
    if key not in (SOURCE_KEY, CONTROL_KEY) or not kms_key.startswith("arn:aws:kms:"):
        raise ReleaseError("S3_UPLOAD_SCOPE")
    status = client.get_bucket_versioning(Bucket=bucket)
    if status.get("Status") != "Enabled":
        raise ReleaseError("S3_VERSIONING_REQUIRED")
    digest = hashlib.sha256(raw).hexdigest()
    paginator = client.get_paginator("list_object_versions")
    matches: list[str] = []
    for page in paginator.paginate(Bucket=bucket, Prefix=key):
        if page.get("IsTruncated") and not page.get("NextKeyMarker"):
            raise ReleaseError("S3_VERSION_LOOKUP_INCOMPLETE", "INDETERMINATE")
        for item in page.get("Versions", []):
            if item.get("Key") != key:
                continue
            version = item.get("VersionId")
            if not isinstance(version, str) or not version or version == "null":
                raise ReleaseError("S3_VERSION_ID_MISSING", "INDETERMINATE")
            head = client.head_object(
                Bucket=bucket, Key=key, VersionId=version, ChecksumMode="ENABLED"
            )
            if (
                head.get("Metadata", {}).get("record-id") == metadata["record-id"]
                and head.get("Metadata", {}).get("record-revision") == metadata["record-revision"]
            ):
                if head.get("Metadata") != metadata or head.get(
                    "ChecksumSHA256"
                ) != _s3_full_checksum(raw):
                    raise ReleaseError("S3_CONFLICTING_RELEASE_VERSION")
                matches.append(version)
    if len(matches) > 1:
        raise ReleaseError("S3_MULTIPLE_RELEASE_VERSIONS", "INDETERMINATE")
    if len(matches) == 1:
        _s3_read_exact(client, bucket, key, matches[0], digest)
        return matches[0]
    try:
        response = client.put_object(
            Bucket=bucket,
            Key=key,
            Body=raw,
            ContentType="application/zip",
            ServerSideEncryption="aws:kms",
            SSEKMSKeyId=kms_key,
            ChecksumSHA256=_s3_full_checksum(raw),
            Metadata=metadata,
        )
    except Exception as exc:
        # A lost response may hide a successful write. Inspect versions once;
        # never issue a second PutObject for an ambiguous mutation.
        reconciled: list[str] = []
        try:
            for page in client.get_paginator("list_object_versions").paginate(
                Bucket=bucket, Prefix=key
            ):
                for item in page.get("Versions", []):
                    if item.get("Key") != key or not item.get("VersionId"):
                        continue
                    candidate = item["VersionId"]
                    head = client.head_object(
                        Bucket=bucket, Key=key, VersionId=candidate, ChecksumMode="ENABLED"
                    )
                    if (
                        head.get("Metadata", {}).get("record-id") == metadata["record-id"]
                        and head.get("Metadata", {}).get("record-revision")
                        == metadata["record-revision"]
                    ):
                        if head.get("Metadata") != metadata or head.get(
                            "ChecksumSHA256"
                        ) != _s3_full_checksum(raw):
                            raise ReleaseError("S3_CONFLICTING_RELEASE_VERSION")
                        reconciled.append(candidate)
        except ReleaseError:
            raise
        except Exception as read_exc:
            raise ReleaseError(
                "S3_UPLOAD_RECONCILIATION_UNAVAILABLE", "INDETERMINATE"
            ) from read_exc
        if len(reconciled) == 1:
            _s3_read_exact(client, bucket, key, reconciled[0], digest)
            return reconciled[0]
        raise ReleaseError("S3_UPLOAD_AMBIGUOUS", "INDETERMINATE") from exc
    version = response.get("VersionId")
    if (
        not isinstance(version, str)
        or not version
        or version == "null"
        or response.get("ChecksumSHA256") != _s3_full_checksum(raw)
    ):
        raise ReleaseError("S3_UPLOAD_VERSION_OR_CHECKSUM_MISSING", "INDETERMINATE")
    _s3_read_exact(client, bucket, key, version, digest)
    return version


def _release_publication_key(record_id: str, kind: str) -> str:
    """Derive only reviewed per-release keys from a validated UUIDv4."""
    try:
        parsed = uuid.UUID(record_id)
    except (ValueError, TypeError, AttributeError) as exc:
        raise ReleaseError("PUBLICATION_RECORD_ID") from exc
    if parsed.version != 4 or str(parsed) != record_id:
        raise ReleaseError("PUBLICATION_RECORD_ID")
    names = {
        "verified_record": "verified_record_key_template",
        "verified_sidecar": "verified_sidecar_key_template",
        "future_lineage": "future_lineage_key_template",
        "verified_transition": "verified_transition_key_template",
        "verified_transition_sidecar": "verified_transition_sidecar_key_template",
        "opa_receipt": "opa_receipt_key_template",
        "opa_receipt_sidecar": "opa_receipt_sidecar_key_template",
    }
    if kind not in names:
        raise ReleaseError("PUBLICATION_OBJECT_KIND")
    template = _config()[names[kind]]
    if not isinstance(template, str):
        raise ReleaseError("PUBLICATION_KEY_TEMPLATE")
    key = template.replace("{record_id}", record_id)
    if not key.startswith(f"w12-001/releases/{record_id}/") or "{" in key or "}" in key:
        raise ReleaseError("PUBLICATION_KEY_TEMPLATE")
    return key


def _provider_utc(value: Any) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ReleaseError("S3_VERSION_TIMESTAMP", "INDETERMINATE")
    observed = value.astimezone(UTC)
    base = observed.strftime(UTC_FORMAT[:-1])
    fractional = f"{observed.microsecond:06d}".rstrip("0")
    return base + ("." + fractional if fractional else "") + "Z"


def _publish_bound_object(
    client: Any,
    *,
    bucket: str,
    key: str,
    raw: bytes,
    kms_key: str,
    record_id: str,
    revision: int,
    content_type: str,
) -> dict[str, str]:
    """One write attempt, followed by exact-version readback; no discovery fallback."""
    if key not in {
        _release_publication_key(record_id, kind)
        for kind in (
            "verified_record",
            "verified_sidecar",
            "future_lineage",
            "verified_transition",
            "verified_transition_sidecar",
            "opa_receipt",
            "opa_receipt_sidecar",
        )
    } or not re.fullmatch(r"arn:aws:kms:ap-southeast-1:[0-9]{12}:key/[0-9a-f-]{36}", kms_key):
        raise ReleaseError("PUBLICATION_SCOPE")
    if client.get_bucket_versioning(Bucket=bucket).get("Status") != "Enabled":
        raise ReleaseError("PUBLICATION_VERSIONING_REQUIRED", "INDETERMINATE")
    digest = hashlib.sha256(raw).hexdigest()
    try:
        response = client.put_object(
            Bucket=bucket,
            Key=key,
            Body=raw,
            ContentType=content_type,
            ServerSideEncryption="aws:kms",
            SSEKMSKeyId=kms_key,
            ChecksumSHA256=_s3_full_checksum(raw),
            Metadata={
                "record-id": record_id,
                "record-revision": str(revision),
                "object-sha256": digest,
            },
        )
    except Exception as exc:
        raise ReleaseError("PUBLICATION_WRITE_AMBIGUOUS", "INDETERMINATE") from exc
    version = response.get("VersionId")
    if not isinstance(version, str) or not version or version == "null":
        raise ReleaseError("PUBLICATION_VERSION_MISSING", "INDETERMINATE")
    observed = _s3_read_exact(client, bucket, key, version, digest)
    if observed != raw:
        raise ReleaseError("PUBLICATION_READBACK_CHANGED", "INDETERMINATE")
    head = client.head_object(Bucket=bucket, Key=key, VersionId=version, ChecksumMode="ENABLED")
    if (
        head.get("VersionId") != version
        or head.get("ServerSideEncryption") != "aws:kms"
        or head.get("SSEKMSKeyId") != kms_key
        or head.get("ChecksumSHA256") != _s3_full_checksum(raw)
    ):
        raise ReleaseError("PUBLICATION_HEAD_MISMATCH", "INDETERMINATE")
    return {
        "bucket": bucket,
        "key": key,
        "version_id": version,
        "sha256": digest,
        "last_modified_utc": _provider_utc(head.get("LastModified")),
        "kms_key_arn": kms_key,
    }


def publish_verified_pair_and_lineage(
    client: Any,
    *,
    bucket: str,
    kms_key: str,
    chain_raws: list[bytes],
) -> tuple[dict[str, dict[str, str]], dict[str, str], bytes]:
    """Publish r5 first, then the sole derivative; never rewrite r5."""
    records = _validated_release_chain(chain_raws)
    record_id = records[4]["record_id"]
    verified_raw = chain_raws[4]
    verified_sha = hashlib.sha256(verified_raw).hexdigest()
    published_r5 = {}
    for kind, raw, content_type in (
        ("verified_record", verified_raw, "application/json"),
        ("verified_sidecar", (verified_sha + "\n").encode("ascii"), "text/plain"),
    ):
        published_r5[kind] = _publish_bound_object(
            client,
            bucket=bucket,
            key=_release_publication_key(record_id, kind),
            raw=raw,
            kms_key=kms_key,
            record_id=record_id,
            revision=5,
            content_type=content_type,
        )
    lineage_raw = make_future_lineage_zip(chain_raws)
    validate_future_lineage_zip(lineage_raw, raws=chain_raws)
    lineage_sha = hashlib.sha256(lineage_raw).hexdigest()
    published_lineage = _publish_bound_object(
        client,
        bucket=bucket,
        key=_release_publication_key(record_id, "future_lineage"),
        raw=lineage_raw,
        kms_key=kms_key,
        record_id=record_id,
        revision=5,
        content_type="application/zip",
    )
    if (
        published_lineage["sha256"] != lineage_sha
        or validate_future_lineage_zip(
            _s3_read_exact(
                client,
                bucket,
                published_lineage["key"],
                published_lineage["version_id"],
                lineage_sha,
            ),
            raws=chain_raws,
        )["verified_record_sha256"]
        != verified_sha
    ):
        raise ReleaseError("FUTURE_LINEAGE_READBACK", "INDETERMINATE")
    return published_r5, published_lineage, lineage_raw


def _publication_timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{0,5}[1-9])?Z", value
    ):
        raise ReleaseError("PUBLICATION_TIMESTAMP_FORMAT")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReleaseError("PUBLICATION_TIMESTAMP_FORMAT") from exc


def validate_publication_selector(
    raw: bytes, *, verified: dict[str, Any], verified_sha256: str, lineage_sha256: str
) -> dict[str, Any]:
    """Validate untrusted local coordinates; this grants no cloud authority."""
    if (
        not raw
        or len(raw) > _config()["publication_selector_max_bytes"]
        or raw.startswith(b"\xef\xbb\xbf")
    ):
        raise ReleaseError("PUBLICATION_SELECTOR_BYTES")
    try:
        selector = json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=_unique_pairs,
            parse_constant=_reject_constant,
            parse_float=lambda _: (_ for _ in ()).throw(ReleaseError("PUBLICATION_SELECTOR_FLOAT")),
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ReleaseError("PUBLICATION_SELECTOR_JSON") from exc
    selector = _fields(
        selector,
        [
            "schema_version",
            "record_id",
            "operation",
            "account_id",
            "region",
            "verified_record_sha256",
            "record_object",
            "sidecar_object",
            "lineage_object",
        ],
        "PUBLICATION_SELECTOR_FIELDS",
    )
    _walk(selector)
    if (
        selector["schema_version"] != _config()["publication_selector_schema_version"]
        or selector["record_id"] != verified["record_id"]
        or selector["operation"] != verified["operation"]
        or selector["account_id"] != verified["deployment"]["account_id"]
        or selector["region"] != _config()["aws_region"]
        or selector["verified_record_sha256"] != verified_sha256
    ):
        raise ReleaseError("PUBLICATION_SELECTOR_IDENTITY")
    if not isinstance(selector["account_id"], str) or not re.fullmatch(
        r"[0-9]{12}", selector["account_id"]
    ):
        raise ReleaseError("PUBLICATION_SELECTOR_ACCOUNT")
    if not _hex(lineage_sha256, required=True):
        raise ReleaseError("PUBLICATION_LINEAGE_DIGEST")
    expected = (
        (
            "record_object",
            _release_publication_key(verified["record_id"], "verified_record"),
            verified_sha256,
        ),
        (
            "sidecar_object",
            _release_publication_key(verified["record_id"], "verified_sidecar"),
            hashlib.sha256((verified_sha256 + "\n").encode("ascii")).hexdigest(),
        ),
        (
            "lineage_object",
            _release_publication_key(verified["record_id"], "future_lineage"),
            lineage_sha256,
        ),
    )
    for field, key, digest in expected:
        item = _fields(
            selector[field],
            ["bucket", "key", "version_id", "sha256", "last_modified_utc", "kms_key_arn"],
            "PUBLICATION_SELECTOR_OBJECT_FIELDS",
        )
        if (
            item["bucket"] != verified["source"]["s3_bucket"]
            or item["key"] != key
            or not isinstance(item["version_id"], str)
            or not item["version_id"]
            or item["version_id"] == "null"
            or item["sha256"] != digest
            or not isinstance(item["kms_key_arn"], str)
            or not item["kms_key_arn"].startswith(
                f"arn:aws:kms:{_config()['aws_region']}:{selector['account_id']}:key/"
            )
        ):
            raise ReleaseError("PUBLICATION_SELECTOR_OBJECT_IDENTITY")
        _publication_timestamp(item["last_modified_utc"])
    return selector


def _read_selected_object(client: Any, identity: dict[str, str], *, kms_key_arn: str) -> bytes:
    """Read one exact S3 version and compare provider identity with the selector."""
    if identity["kms_key_arn"] != kms_key_arn:
        raise ReleaseError("PUBLICATION_KMS_SUBSTITUTION", "INDETERMINATE")
    raw = _s3_read_exact(
        client, identity["bucket"], identity["key"], identity["version_id"], identity["sha256"]
    )
    head = client.head_object(
        Bucket=identity["bucket"],
        Key=identity["key"],
        VersionId=identity["version_id"],
        ChecksumMode="ENABLED",
    )
    if (
        head.get("VersionId") != identity["version_id"]
        or head.get("ServerSideEncryption") != "aws:kms"
        or head.get("SSEKMSKeyId") != kms_key_arn
        or head.get("ChecksumSHA256") != _s3_full_checksum(raw)
        or _provider_utc(head.get("LastModified")) != identity["last_modified_utc"]
    ):
        raise ReleaseError("PUBLICATION_PROVIDER_IDENTITY_CHANGED", "INDETERMINATE")
    return raw


def retention_anchor_from_publication(
    verified_created_at_utc: str,
    record_last_modified_utc: str,
    sidecar_last_modified_utc: str,
    lineage_last_modified_utc: str,
    *,
    now: datetime,
) -> tuple[datetime, datetime]:
    if now.tzinfo is None:
        raise ReleaseError("PUBLICATION_CLOCK_INVALID", "INDETERMINATE")
    moments = [
        _publication_timestamp(value)
        for value in (
            verified_created_at_utc,
            record_last_modified_utc,
            sidecar_last_modified_utc,
            lineage_last_modified_utc,
        )
    ]
    if any(moment > now for moment in moments):
        raise ReleaseError("PUBLICATION_FUTURE_TIMESTAMP", "INDETERMINATE")
    anchor = max(moments)
    return anchor, anchor + timedelta(days=180)


def validate_publication_proof(
    proof_root: Path,
    *,
    client: Any,
    kms_key_arn: str,
    now: datetime,
) -> dict[str, Any]:
    """Derive a path-free V3 binding from eleven local files and exact S3 versions."""
    if not proof_root.is_dir() or proof_root.is_symlink() or now.tzinfo is None:
        raise ReleaseError("PUBLICATION_PROOF_ROOT", "INDETERMINATE")
    expected = {"publication-selector.json"} | {
        f"records/r{revision}/{name}"
        for revision in range(1, 6)
        for name in ("release-record.json", "release-record.sha256")
    }
    actual: set[str] = set()
    for item in proof_root.rglob("*"):
        if item.is_symlink() or not (item.is_file() or item.is_dir()):
            raise ReleaseError("PUBLICATION_PROOF_UNSAFE_ENTRY", "INDETERMINATE")
        if item.is_file():
            relative = item.relative_to(proof_root).as_posix()
            _safe_bundle_path(relative)
            actual.add(relative)
    if actual != expected or len(actual) != 11:
        raise ReleaseError("PUBLICATION_PROOF_INVENTORY", "INDETERMINATE")
    raws: list[bytes] = []
    records: list[dict[str, Any]] = []
    for index in range(1, 6):
        pair = proof_root / f"records/r{index}"
        raw = (pair / "release-record.json").read_bytes()
        sidecar = (pair / "release-record.sha256").read_bytes()
        record = validate_record(raw, sidecar, previous=raws[-1] if raws else None)
        raws.append(raw)
        records.append(record)
    if [item["status"] for item in records] != [
        "REQUESTED",
        "READY_FOR_OWNER",
        "APPROVED",
        "APPLIED",
        "VERIFIED",
    ] or any(item["record_id"] != records[0]["record_id"] for item in records):
        raise ReleaseError("PUBLICATION_PROOF_CHAIN", "INDETERMINATE")
    verified = records[4]
    if (
        verified["deployment"]["region"] != _config()["aws_region"]
        or not re.fullmatch(r"[0-9]{12}", verified["deployment"]["account_id"])
        or not kms_key_arn.startswith(
            f"arn:aws:kms:{_config()['aws_region']}:{verified['deployment']['account_id']}:key/"
        )
    ):
        raise ReleaseError("PUBLICATION_PROOF_ACCOUNT_OR_KMS", "INDETERMINATE")
    verified_sha = hashlib.sha256(raws[4]).hexdigest()
    selector_raw = (proof_root / "publication-selector.json").read_bytes()
    try:
        untrusted = json.loads(
            selector_raw.decode("utf-8", "strict"), object_pairs_hook=_unique_pairs
        )
        lineage_sha = untrusted["lineage_object"]["sha256"]
    except (UnicodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise ReleaseError("PUBLICATION_SELECTOR_UNREADABLE", "INDETERMINATE") from exc
    selector = validate_publication_selector(
        selector_raw,
        verified=verified,
        verified_sha256=verified_sha,
        lineage_sha256=lineage_sha,
    )
    if any(
        selector[name]["kms_key_arn"] != kms_key_arn
        for name in ("record_object", "sidecar_object", "lineage_object")
    ):
        raise ReleaseError("PUBLICATION_SELECTOR_KMS_CHANGED", "INDETERMINATE")
    published = {
        name: _read_selected_object(client, selector[name], kms_key_arn=kms_key_arn)
        for name in ("record_object", "sidecar_object", "lineage_object")
    }
    if published["record_object"] != raws[4] or published["sidecar_object"] != (
        verified_sha + "\n"
    ).encode("ascii"):
        raise ReleaseError("PUBLICATION_VERIFIED_PAIR_CHANGED", "INDETERMINATE")
    validate_future_lineage_zip(published["lineage_object"], raws=raws)
    if (
        selector["lineage_object"]["sha256"]
        != hashlib.sha256(published["lineage_object"]).hexdigest()
    ):
        raise ReleaseError("PUBLICATION_LINEAGE_CHANGED", "INDETERMINATE")
    anchor, retention = retention_anchor_from_publication(
        verified["created_at_utc"],
        selector["record_object"]["last_modified_utc"],
        selector["sidecar_object"]["last_modified_utc"],
        selector["lineage_object"]["last_modified_utc"],
        now=now,
    )
    protected = []
    for name, kind, coverage in (
        ("record_object", "verified_record", "VERIFIED_SELF_PUBLICATION"),
        ("sidecar_object", "verified_sidecar", "VERIFIED_SELF_PUBLICATION"),
        ("lineage_object", "future_lineage", "VERIFIED_LINEAGE_DERIVATIVE"),
    ):
        item = selector[name]
        protected.append(
            {
                "bucket": item["bucket"],
                "key": item["key"],
                "version_id": item["version_id"],
                "sha256": item["sha256"],
                "evidence_kind": kind,
                "coverage": coverage,
            }
        )
    by_object: dict[tuple[str, str, str], dict[str, Any]] = {}
    for evidence in verified["evidence"]:
        if not evidence["uri"].startswith("w12-s3v://"):
            continue
        locator = decode_s3v_locator(evidence["uri"])
        object_key = (locator["bucket"], locator["key"], locator["version_id"])
        by_object.setdefault(object_key, {"entries": [], "whole": []})[
            "whole"
            if locator["entry"] is None
            or evidence["kind"] in ("codebuild-control-bundle", "rollback-lineage-archive")
            else "entries"
        ].append((evidence, locator["entry"]))
    current_control_files: dict[str, bytes] | None = None
    primary_source_files: dict[str, bytes] | None = None
    rendered_archive_raw: bytes | None = None
    for (bucket, key, version), observations in by_object.items():
        whole = observations["whole"]
        if len(whole) != 1 or bucket != verified["source"]["s3_bucket"]:
            raise ReleaseError("PUBLICATION_OBJECT_COVERAGE_AMBIGUOUS", "INDETERMINATE")
        evidence, _ = whole[0]
        digest = evidence["sha256"]
        raw = _s3_read_exact(client, bucket, key, version, digest)
        head = client.head_object(Bucket=bucket, Key=key, VersionId=version, ChecksumMode="ENABLED")
        if (
            head.get("VersionId") != version
            or head.get("SSEKMSKeyId") != kms_key_arn
            or head.get("ServerSideEncryption") != "aws:kms"
            or head.get("ChecksumSHA256") != _s3_full_checksum(raw)
        ):
            raise ReleaseError("PUBLICATION_EVIDENCE_PROVIDER_CHANGED", "INDETERMINATE")
        if observations["entries"]:
            entries = _zip_files(raw)
            for entry_evidence, entry_name in observations["entries"]:
                if (
                    entry_name not in entries
                    or hashlib.sha256(entries[entry_name]).hexdigest() != entry_evidence["sha256"]
                ):
                    raise ReleaseError("PUBLICATION_EVIDENCE_ENTRY_CHANGED", "INDETERMINATE")
        if evidence["kind"] in ("codebuild-control-bundle", "rollback-lineage-archive"):
            if whole[0][1] not in _zip_files(raw):
                raise ReleaseError("PUBLICATION_EVIDENCE_SELECTOR_CHANGED", "INDETERMINATE")
        if evidence["kind"] == "source_bundle":
            indexed = {item["kind"]: item for item in verified["evidence"]}
            if "w12_source_manifest" not in indexed or "w6_release_hashes" not in indexed:
                raise ReleaseError("PUBLICATION_SOURCE_ENTRY_COVERAGE", "INDETERMINATE")
            primary_source_files = validate_primary_source_bundle(
                raw,
                archive_sha256=digest,
                manifest_sha256=indexed["w12_source_manifest"]["sha256"],
                w6_sha256=indexed["w6_release_hashes"]["sha256"],
                commit=verified["source"]["commit"],
                tree=verified["source"]["tree"],
            )
        elif evidence["kind"] == "codebuild-control-bundle":
            current_control_files = validate_current_control_bundle(
                raw,
                records=records,
                raws=raws,
            )
        elif evidence["kind"] == "rendered_release_archive":
            rendered_archive_raw = raw
        protected.append(
            {
                "bucket": bucket,
                "key": key,
                "version_id": version,
                "sha256": digest,
                "evidence_kind": evidence["kind"],
                "coverage": "R5_LOCATOR",
            }
        )
    protected.sort(key=lambda item: (item["bucket"], item["key"], item["version_id"]))
    if current_control_files is None:
        raise ReleaseError("PUBLICATION_CONTROL_PROOF_MISSING", "INDETERMINATE")
    if primary_source_files is None or rendered_archive_raw is None:
        raise ReleaseError("PUBLICATION_RENDER_PROOF_MISSING", "INDETERMINATE")
    rendered_members = _zip_files(rendered_archive_raw)
    if set(rendered_members) < {"w12-rendered-release.json", "w12-rendered-release.sha256"}:
        raise ReleaseError("PUBLICATION_RENDER_INVENTORY_MISSING", "INDETERMINATE")
    rendered_manifest = rendered_members.pop("w12-rendered-release.json")
    rendered_sidecar = rendered_members.pop("w12-rendered-release.sha256")
    renderer_blob = primary_source_files.get("tools/w6_001_k8s.py")
    if renderer_blob is None:
        raise ReleaseError("PUBLICATION_RENDERER_BLOB_MISSING", "INDETERMINATE")
    validate_rendered_release(
        rendered_manifest,
        rendered_sidecar,
        archive_files=rendered_members,
        ready_sha256=hashlib.sha256(raws[1]).hexdigest(),
        approved_sha256=hashlib.sha256(raws[2]).hexdigest(),
        applied_sha256=hashlib.sha256(raws[3]).hexdigest(),
        source_sha256=records[3]["source"]["archive_sha256"],
        w6_sha256=records[1]["deployment"]["w6_release_hashes_sha256"],
        render_inputs_sha256=records[3]["deployment"]["render_inputs_sha256"],
        renderer_sha256=hashlib.sha256(renderer_blob).hexdigest(),
    )
    if verified["operation"] == "rollback":
        inbound_files, _, _, _ = load_prior_rollback_lineage(
            records[0],
            client=client,
            kms_key_arn=kms_key_arn,
        )
        if any(
            current_control_files.get(name) != content for name, content in inbound_files.items()
        ):
            raise ReleaseError("PUBLICATION_INBOUND_LINEAGE_CHANGED", "INDETERMINATE")
    if len({(item["bucket"], item["key"], item["version_id"]) for item in protected}) != len(
        protected
    ):
        raise ReleaseError("PUBLICATION_DUPLICATE_PROTECTED_OBJECT", "INDETERMINATE")
    return {
        "record_id": verified["record_id"],
        "operation": verified["operation"],
        "verified_record_sha256": verified_sha,
        "verified_created_at_utc": verified["created_at_utc"],
        "verified_record_object": {
            key: selector["record_object"][key]
            for key in ("bucket", "key", "version_id", "sha256", "last_modified_utc")
        },
        "verified_sidecar_object": {
            key: selector["sidecar_object"][key]
            for key in ("bucket", "key", "version_id", "sha256", "last_modified_utc")
        },
        "publication_anchor_utc": anchor.strftime(UTC_FORMAT),
        "retain_until_utc": retention.strftime(UTC_FORMAT),
        "kms_key_arn": kms_key_arn,
        "protected_objects": protected,
    }


def load_prior_rollback_lineage(
    requested: dict[str, Any],
    *,
    client: Any,
    kms_key_arn: str,
) -> tuple[dict[str, bytes], list[dict[str, Any]], list[bytes], dict[str, Any]]:
    """Read only the exact prior lineage and its r5-bound control ZIP."""
    if requested["operation"] != "rollback":
        raise ReleaseError("ROLLBACK_OPERATION_REQUIRED")
    locator = decode_s3v_locator(requested["recovery"]["rollback_ref"])
    evidence = {
        item["kind"]: item
        for item in requested["evidence"]
        if item["kind"]
        in {
            "rollback-lineage-archive",
            "rollback-lineage-manifest",
        }
    }
    if set(evidence) != {"rollback-lineage-archive", "rollback-lineage-manifest"}:
        raise ReleaseError("ROLLBACK_REQUESTED_EVIDENCE")
    archive_identity = evidence["rollback-lineage-archive"]
    archive = _s3_read_exact(
        client, locator["bucket"], locator["key"], locator["version_id"], archive_identity["sha256"]
    )
    head = client.head_object(
        Bucket=locator["bucket"],
        Key=locator["key"],
        VersionId=locator["version_id"],
        ChecksumMode="ENABLED",
    )
    if (
        head.get("VersionId") != locator["version_id"]
        or head.get("ServerSideEncryption") != "aws:kms"
        or head.get("SSEKMSKeyId") != kms_key_arn
        or head.get("ChecksumSHA256") != _s3_full_checksum(archive)
    ):
        raise ReleaseError("ROLLBACK_LINEAGE_PROVIDER_IDENTITY", "INDETERMINATE")
    lineage_files = _zip_files(archive)
    if set(lineage_files) != FUTURE_LINEAGE_PATHS or len(lineage_files) != 6:
        raise ReleaseError("ROLLBACK_LINEAGE_INVENTORY")
    prior_r4 = lineage_files["rollback/parent/release-record.json"]
    prior_r5 = lineage_files["rollback/verified/release-record.json"]
    prior_verified = validate_record(
        prior_r5,
        lineage_files["rollback/verified/release-record.sha256"],
        previous=prior_r4,
    )
    if (
        prior_verified["status"] != "VERIFIED"
        or hashlib.sha256(prior_r5).hexdigest()
        != requested["recovery"]["previous_good_record_sha256"]
    ):
        raise ReleaseError("ROLLBACK_TARGET_VERIFIED_IDENTITY")
    control_evidence = [
        item for item in prior_verified["evidence"] if item["kind"] == "codebuild-control-bundle"
    ]
    if len(control_evidence) != 1:
        raise ReleaseError("ROLLBACK_PRIOR_CONTROL_IDENTITY")
    control_locator = decode_s3v_locator(control_evidence[0]["uri"])
    if (
        control_locator["bucket"] != locator["bucket"]
        or control_locator["key"] != CONTROL_KEY
        or control_locator["entry"] != "codebuild-handoff.json"
    ):
        raise ReleaseError("ROLLBACK_PRIOR_CONTROL_LOCATOR")
    control_raw = _s3_read_exact(
        client,
        control_locator["bucket"],
        control_locator["key"],
        control_locator["version_id"],
        control_evidence[0]["sha256"],
    )
    control_head = client.head_object(
        Bucket=control_locator["bucket"],
        Key=control_locator["key"],
        VersionId=control_locator["version_id"],
        ChecksumMode="ENABLED",
    )
    if (
        control_head.get("SSEKMSKeyId") != kms_key_arn
        or control_head.get("VersionId") != control_locator["version_id"]
        or control_head.get("ChecksumSHA256") != _s3_full_checksum(control_raw)
    ):
        raise ReleaseError("ROLLBACK_PRIOR_CONTROL_PROVIDER_IDENTITY", "INDETERMINATE")
    control_files = _zip_files(control_raw)
    expected_deploy = {
        "codebuild-handoff.json",
        "codebuild-handoff.sha256",
        "release-record.json",
        "release-record.sha256",
        "w12-render-inputs.json",
        "w12-render-inputs.sha256",
        *(
            f"records/r{revision}/{name}"
            for revision in (1, 2, 3)
            for name in ("release-record.json", "release-record.sha256")
        ),
        *(
            f"records/r{revision}/{name}"
            for revision in (2, 3, 4)
            for name in ("transition-evidence.json", "transition-evidence.sha256")
        ),
    }
    expected_control = expected_deploy | (
        FUTURE_LINEAGE_PATHS if prior_verified["operation"] == "rollback" else set()
    )
    if set(control_files) != expected_control or len(control_files) != (
        24 if prior_verified["operation"] == "rollback" else 18
    ):
        raise ReleaseError("ROLLBACK_PRIOR_CONTROL_INVENTORY")
    handoff_raw = control_files["codebuild-handoff.json"]
    if control_files["codebuild-handoff.sha256"] != (
        hashlib.sha256(handoff_raw).hexdigest() + "\n"
    ).encode("ascii"):
        raise ReleaseError("ROLLBACK_PRIOR_CONTROL_HANDOFF_SIDECAR")
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
        code="ROLLBACK_PRIOR_HANDOFF",
    )
    payload_files = {
        name: raw
        for name, raw in control_files.items()
        if name not in ("codebuild-handoff.json", "codebuild-handoff.sha256")
    }
    if (
        handoff["schema_version"] != "w12-001.codebuild-handoff.v2"
        or handoff["record_id"] != prior_verified["record_id"]
        or handoff["operation"] != prior_verified["operation"]
        or handoff["files"] != _file_inventory(payload_files)
    ):
        raise ReleaseError("ROLLBACK_PRIOR_HANDOFF_BINDING")
    prior_raws = [
        control_files[f"records/r{revision}/release-record.json"] for revision in (1, 2, 3)
    ] + [control_files["release-record.json"], prior_r5]
    if prior_raws[3] != prior_r4 or control_files["release-record.sha256"] != (
        hashlib.sha256(prior_r4).hexdigest() + "\n"
    ).encode("ascii"):
        raise ReleaseError("ROLLBACK_PRIOR_PARENT_SUBSTITUTION")
    prior_records = _validated_release_chain(prior_raws)
    manifest = validate_future_lineage_zip(archive, raws=prior_raws)
    if (
        hashlib.sha256(lineage_files["rollback/rollback-lineage-manifest.json"]).hexdigest()
        != evidence["rollback-lineage-manifest"]["sha256"]
    ):
        raise ReleaseError("ROLLBACK_LINEAGE_MANIFEST_DIGEST")
    prior_render = validate_render_inputs(
        control_files["w12-render-inputs.json"],
        control_files["w12-render-inputs.sha256"],
        ready=prior_records[1],
        ready_sha256=hashlib.sha256(prior_raws[1]).hexdigest(),
        approved=prior_records[2],
        approved_sha256=hashlib.sha256(prior_raws[2]).hexdigest(),
        applied=prior_records[3],
        enforce_current=False,
    )
    if (
        manifest["record_id"] != prior_verified["record_id"]
        or requested["deployment"]["region"] != prior_verified["deployment"]["region"]
        or requested["deployment"]["environment"] != prior_verified["deployment"]["environment"]
    ):
        raise ReleaseError("ROLLBACK_PRIOR_ENVIRONMENT")
    return lineage_files, prior_records, prior_raws, prior_render


def application_image_from_ready(ready: dict[str, Any]) -> str:
    """Derive the application role from the two READY-bound artifact fields."""
    if ready.get("status") != "READY_FOR_OWNER" or ready.get("revision") != 2:
        raise ReleaseError("READY_RECORD_REQUIRED")
    artifacts = ready["artifacts"]
    repository, digest = artifacts["container_repository"], artifacts["image_digest"]
    if (
        not isinstance(repository, str)
        or not re.fullmatch(
            r"[a-z0-9][a-z0-9.-]*(?::[0-9]{1,5})?/[a-z0-9][a-z0-9._/-]*", repository
        )
        or not isinstance(digest, str)
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest)
    ):
        raise ReleaseError("READY_APPLICATION_IMAGE_INVALID")
    return repository + "@" + digest


def validate_render_inputs(
    raw: bytes,
    sidecar: bytes,
    *,
    ready: dict[str, Any],
    ready_sha256: str,
    approved: dict[str, Any],
    approved_sha256: str,
    applied: dict[str, Any] | None = None,
    current_time: datetime | None = None,
    enforce_current: bool = True,
) -> dict[str, Any]:
    """Check the acyclic READY -> APPROVED -> render-input -> APPLIED binding."""
    cfg = _config()
    document = _canonical_document(raw, fields=cfg["render_input_fields"], code="RENDER_INPUT")
    digest = hashlib.sha256(raw).hexdigest()
    if sidecar != (digest + "\n").encode("ascii"):
        raise ReleaseError("RENDER_INPUT_SIDECAR_MISMATCH")
    if document["schema_version"] != cfg["render_input_schema_version"]:
        raise ReleaseError("RENDER_INPUT_SCHEMA")
    if ready.get("status") != "READY_FOR_OWNER" or approved.get("status") != "APPROVED":
        raise ReleaseError("RENDER_INPUT_PARENT_STATUS")
    expected_app = application_image_from_ready(ready)
    expected_collector = ready["artifacts"]["otel_collector_image"]
    if not isinstance(expected_collector, str) or not re.fullmatch(
        r"[a-z0-9][a-z0-9.-]*(?::[0-9]{1,5})?/[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}",
        expected_collector,
    ):
        raise ReleaseError("READY_COLLECTOR_IMAGE_INVALID")
    if (
        expected_app == expected_collector
        or expected_app.rsplit("@", 1)[1] == expected_collector.rsplit("@", 1)[1]
    ):
        raise ReleaseError("IMAGE_ROLE_CONFUSION")
    expected = {
        "ready_record_sha256": ready_sha256,
        "approved_record_sha256": approved_sha256,
        "source_archive_sha256": ready["source"]["archive_sha256"],
        "w6_release_hashes_sha256": ready["deployment"]["w6_release_hashes_sha256"],
        "hcp_organization": ready["terraform"]["organization"],
        "hcp_workspace": ready["terraform"]["workspace"],
        "hcp_run_id": ready["terraform"]["run_id"],
        "hcp_plan_id": ready["terraform"]["plan_id"],
        "aws_account_id": ready["deployment"]["account_id"],
        "aws_region": ready["deployment"]["region"],
        "environment": ready["deployment"]["environment"],
        "application_image": expected_app,
        "otel_collector_image": expected_collector,
        "release_binding_sha256": approved_sha256,
    }
    if any(document[name] != value or value is None for name, value in expected.items()):
        raise ReleaseError("RENDER_INPUT_RELEASE_BINDING")
    if (
        not _text(document["state_lineage"])
        or ready["terraform"]["state_lineage"] not in (None, document["state_lineage"])
        or type(document["state_serial"]) is not int
        or document["state_serial"] < 0
    ):
        raise ReleaseError("RENDER_INPUT_STATE_IDENTITY")
    if (
        not isinstance(document["applied_state_version_id"], str)
        or not document["applied_state_version_id"]
    ):
        raise ReleaseError("RENDER_INPUT_STATE_VERSION")
    endpoint = document["opensearch_https_endpoint"]
    parsed = urllib.parse.urlsplit(endpoint) if isinstance(endpoint, str) else None
    if (
        parsed is None
        or parsed.scheme != "https"
        or not parsed.hostname
        or parsed.hostname != parsed.hostname.lower()
        or parsed.username
        or parsed.password
        or parsed.path
        or parsed.query
        or parsed.fragment
        or parsed.netloc != parsed.hostname
        or endpoint != f"https://{parsed.hostname}"
    ):
        raise ReleaseError("RENDER_INPUT_OPENSEARCH_ENDPOINT")
    if not isinstance(document["opensearch_domain_arn"], str) or not re.fullmatch(
        r"arn:(?:aws|aws-us-gov|aws-cn):es:[a-z0-9-]+:[0-9]{12}:domain/[A-Za-z0-9_-]+",
        document["opensearch_domain_arn"],
    ):
        raise ReleaseError("RENDER_INPUT_OPENSEARCH_ARN")
    if not isinstance(document["bedrock_inference_profile_arn"], str) or not re.fullmatch(
        r"arn:(?:aws|aws-us-gov|aws-cn):bedrock:[a-z0-9-]+:(?:[0-9]{12})?:inference-profile/[A-Za-z0-9._-]+",
        document["bedrock_inference_profile_arn"],
    ):
        raise ReleaseError("RENDER_INPUT_BEDROCK_ARN")
    created, expiry = _utc(document["created_at_utc"]), _utc(document["expires_at_utc"])
    now = current_time or datetime.now(UTC)
    if not created < expiry <= created + timedelta(hours=2) or (
        enforce_current and not created <= now < expiry
    ):
        raise ReleaseError("RENDER_INPUT_EXPIRED")
    if applied is not None:
        if (
            applied.get("status") != "APPLIED"
            or applied["deployment"]["render_inputs_sha256"] != digest
        ):
            raise ReleaseError("APPLIED_RENDER_INPUT_MISMATCH")
    return document


def validate_rendered_release(
    raw: bytes,
    sidecar: bytes,
    *,
    archive_files: dict[str, bytes],
    ready_sha256: str,
    approved_sha256: str,
    applied_sha256: str,
    source_sha256: str,
    w6_sha256: str,
    render_inputs_sha256: str,
    renderer_sha256: str,
) -> dict[str, Any]:
    """Require exact rendered-file coverage before trusting the deployable ZIP."""
    cfg = _config()
    document = _canonical_document(
        raw, fields=cfg["rendered_release_fields"], code="RENDERED_RELEASE"
    )
    digest = hashlib.sha256(raw).hexdigest()
    if (
        sidecar != (digest + "\n").encode("ascii")
        or document["schema_version"] != cfg["rendered_release_schema_version"]
    ):
        raise ReleaseError("RENDERED_RELEASE_SCHEMA_OR_SIDECAR")
    expected = {
        "ready_record_sha256": ready_sha256,
        "approved_record_sha256": approved_sha256,
        "applied_record_sha256": applied_sha256,
        "source_archive_sha256": source_sha256,
        "w6_release_hashes_sha256": w6_sha256,
        "render_inputs_sha256": render_inputs_sha256,
        "renderer_path": "tools/w6_001_k8s.py",
        "renderer_sha256": renderer_sha256,
    }
    if any(document[name] != value or not value for name, value in expected.items()):
        raise ReleaseError("RENDERED_RELEASE_BINDING")
    _utc(document["created_at_utc"])
    inventory = _manifest_files(document["files"], code="RENDERED_RELEASE")
    if set(inventory) != set(archive_files) or set(inventory) != W12_RENDERED_FILE_NAMES:
        raise ReleaseError("RENDERED_RELEASE_FILE_SET")
    for name, (size, checksum) in inventory.items():
        payload = archive_files[name]
        if len(payload) != size or hashlib.sha256(payload).hexdigest() != checksum:
            raise ReleaseError("RENDERED_RELEASE_FILE_BYTES")
    return document


def validate_opa_receipt(
    raw: bytes,
    sidecar: bytes,
    *,
    record: dict[str, Any],
    record_sha256: str,
    current_time: datetime | None = None,
) -> dict[str, Any]:
    """Validate the independent, secret-free owner-local plan-review receipt."""
    cfg = _config()
    if (
        not raw
        or len(raw) > cfg["opa_receipt_max_bytes"]
        or raw.startswith(b"\xef\xbb\xbf")
        or not raw.endswith(b"\n")
        or raw.endswith(b"\n\n")
    ):
        raise ReleaseError("OPA_RECEIPT_BYTES")
    try:
        value = json.loads(
            raw[:-1].decode("utf-8", "strict"),
            object_pairs_hook=_unique_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseError("OPA_RECEIPT_JSON") from exc
    value = _fields(value, cfg["opa_receipt_fields"], "OPA_RECEIPT_FIELDS")
    for field, names in (
        ("source", cfg["opa_receipt_source_fields"]),
        ("hcp", cfg["opa_receipt_hcp_fields"]),
        ("opa", cfg["opa_receipt_opa_fields"]),
        ("infracost", cfg["opa_receipt_infracost_fields"]),
        ("evidence", cfg["opa_receipt_evidence_fields"]),
    ):
        _fields(value[field], names, "OPA_RECEIPT_" + field.upper())
    if _canonical_bytes(value) != raw or sidecar != (hashlib.sha256(raw).hexdigest() + "\n").encode(
        "ascii"
    ):
        raise ReleaseError("OPA_RECEIPT_CANONICAL_OR_DIGEST")
    try:
        identity = uuid.UUID(value["receipt_id"])
    except (ValueError, TypeError, AttributeError) as exc:
        raise ReleaseError("OPA_RECEIPT_ID") from exc
    if (
        value["schema_version"] != cfg["opa_receipt_schema_version"]
        or identity.version != 4
        or str(identity) != value["receipt_id"]
        or type(value["revision"]) is not int
        or value["revision"] < 1
    ):
        raise ReleaseError("OPA_RECEIPT_IDENTITY")
    created, expiry = _utc(value["created_at_utc"]), _utc(value["expires_at_utc"])
    now = current_time or datetime.now(UTC)
    if (
        not created
        <= now
        < expiry
        <= created + timedelta(seconds=cfg["opa_receipt_validity_seconds"])
    ):
        raise ReleaseError("OPA_RECEIPT_EXPIRED")
    source = value["source"]
    if value["record_sha256"] != record_sha256 or source != {
        "repository": GITHUB_REPOSITORY,
        "commit": record["source"]["commit"],
        "operation": record["operation"],
    }:
        raise ReleaseError("OPA_RECEIPT_RECORD_BINDING")
    hcp, tf = value["hcp"], record["terraform"]
    fixed = ("organization", "project", "workspace")
    observed = {
        "configuration_version_id": "configuration_version_id",
        "run_id": "run_id",
        "plan_id": "plan_id",
    }
    if (
        any(hcp[name] != tf[name] for name in fixed)
        or any(
            not _text(hcp[name]) or tf[field] not in (None, hcp[name])
            for name, field in observed.items()
        )
        or not _hex(hcp["plan_json_sha256"], required=True)
    ):
        raise ReleaseError("OPA_RECEIPT_HCP_BINDING")
    initial = _empty_input_state(
        hcp["input_state_version_id"], hcp["state_lineage"], hcp["state_serial"]
    )
    if initial and record["operation"] != "deploy":
        raise ReleaseError("OPA_RECEIPT_INITIAL_STATE_OPERATION")
    if (
        _empty_input_state(
            tf["input_state_version_id"], tf["state_lineage"], tf["input_state_serial"]
        )
        != initial
    ):
        raise ReleaseError("OPA_RECEIPT_INPUT_STATE_SUBSTITUTION")
    state_mapping = {
        "input_state_version_id": "input_state_version_id",
        "state_lineage": "state_lineage",
        "state_serial": "input_state_serial",
    }
    if any(tf[field] not in (None, hcp[name]) for name, field in state_mapping.items()):
        raise ReleaseError("OPA_RECEIPT_HCP_STATE_BINDING")
    policy = value["opa"]
    if (policy["executable_version"], policy["package"], policy["decision_entrypoint"]) != (
        "1.20.0",
        "enterprise_ai.terraform.plan",
        "data.enterprise_ai.terraform.plan.decision",
    ) or any(
        not _hex(policy[name], required=True)
        for name in ("executable_sha256", "policy_sha256", "exceptions_sha256")
    ):
        raise ReleaseError("OPA_RECEIPT_POLICY_IDENTITY")
    if (
        policy["result"] != "PASS"
        or type(policy["violation_count"]) is not int
        or policy["violation_count"] != 0
        or policy["waiver_used"] is not False
        or policy["override_used"] is not False
    ):
        raise ReleaseError("OPA_RECEIPT_POLICY_NOT_PASS")
    cost = value["infracost"]
    if (
        not _text(cost["result_id"])
        or cost["status"] != "PASS"
        or cost["waiver_used"] is not False
        or cost["override_used"] is not False
        or record["gates"]["run_task_result_id"] not in (None, cost["result_id"])
    ):
        raise ReleaseError("OPA_RECEIPT_COST_NOT_PASS")
    if value["decision"] != "PASS" or any(
        not _hex(item, required=True) for item in value["evidence"].values()
    ):
        raise ReleaseError("OPA_RECEIPT_NOT_PASS")
    return value


def _write_new_pair(data_path: Path, sidecar_path: Path, raw: bytes) -> str:
    if data_path.resolve() == sidecar_path.resolve() or data_path.exists() or sidecar_path.exists():
        raise ReleaseError("OUTPUT_ALREADY_EXISTS")
    digest = hashlib.sha256(raw).hexdigest()
    created: list[Path] = []
    try:
        for path, data in ((data_path, raw), (sidecar_path, (digest + "\n").encode("ascii"))):
            with path.open("xb") as output:
                created.append(path)
                os.chmod(path, 0o600)
                output.write(data)
                output.flush()
                os.fsync(output.fileno())
    except BaseException:
        for path in created:
            path.unlink(missing_ok=True)
        raise
    return digest


def _read_record(
    args: argparse.Namespace, *, requested: bool = False
) -> tuple[bytes, dict[str, Any], str]:
    raw = Path(args.record).read_bytes()
    sidecar = Path(args.sha256_file).read_bytes()
    prior = (
        Path(args.previous_record).read_bytes() if getattr(args, "previous_record", None) else None
    )
    record = validate_record(raw, sidecar, previous=prior, requested=requested)
    return raw, record, hashlib.sha256(raw).hexdigest()


class _NoApiRedirect(urllib.request.HTTPRedirectHandler):
    """Keep API credentials on the exact approved host and path."""

    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        return None


def _github_request(
    method: str, path: str, token: str, body: dict[str, Any] | None = None
) -> tuple[int, Any]:
    payload = None if body is None else json.dumps(body, separators=(",", ":")).encode()
    request = urllib.request.Request(
        "https://api.github.com/repos/" + GITHUB_REPOSITORY + path,
        data=payload,
        method=method,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer " + token,
            "X-GitHub-Api-Version": _config()["github_api_version"],
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.build_opener(_NoApiRedirect()).open(request, timeout=20) as response:
            data = response.read(2_000_001)
            if len(data) > 2_000_000:
                raise ReleaseError("GITHUB_RESPONSE_TOO_LARGE", "INDETERMINATE")
            return response.status, json.loads(data) if data else None
    except urllib.error.HTTPError as exc:
        raise ReleaseError(
            "GITHUB_HTTP_" + str(exc.code), "INDETERMINATE" if exc.code >= 500 else "FAIL"
        ) from None
    except (urllib.error.URLError, TimeoutError) as exc:
        raise ReleaseError("GITHUB_TRANSPORT", "INDETERMINATE") from exc


def _github_token() -> str:
    token = os.environ.get("GH_TOKEN", "")
    if not token:
        raise ReleaseError("GH_TOKEN_REQUIRED")
    return token


def _valid_run(run: Any, commit: str) -> tuple[int, str, str]:
    if not isinstance(run, dict) or type(run.get("id")) is not int or run["id"] <= 0:
        raise ReleaseError("GITHUB_RUN_ID_MISSING", "INDETERMINATE")
    run_id = run["id"]
    api_url = f"https://api.github.com/repos/{GITHUB_REPOSITORY}/actions/runs/{run_id}"
    html_url = f"https://github.com/{GITHUB_REPOSITORY}/actions/runs/{run_id}"
    if (run.get("url"), run.get("html_url"), run.get("head_sha"), run.get("head_branch")) != (
        api_url,
        html_url,
        commit,
        "main",
    ) or not str(run.get("path", "")).startswith(".github/workflows/" + GITHUB_WORKFLOW + "@"):
        raise ReleaseError("GITHUB_RUN_IDENTITY", "INDETERMINATE")
    return run_id, api_url, html_url


def _lookup_existing(
    record: dict[str, Any],
    digest: str,
    receipt_digest: str,
    token: str,
    *,
    exclude_run_id: int | None = None,
) -> tuple[int, str, str] | None:
    status, listing = _github_request(
        "GET", "/actions/workflows/" + GITHUB_WORKFLOW + "/runs?per_page=100", token
    )
    if (
        status != 200
        or not isinstance(listing, dict)
        or not isinstance(listing.get("workflow_runs"), list)
        or listing.get("total_count", 0) > 100
    ):
        raise ReleaseError("RUN_LOOKUP_INCOMPLETE", "INDETERMINATE")
    matches: list[tuple[int, str, str]] = []
    for run in listing["workflow_runs"]:
        if not isinstance(run, dict) or type(run.get("id")) is not int:
            raise ReleaseError("RUN_LOOKUP_MALFORMED", "INDETERMINATE")
        run_id = run["id"]
        if run_id == exclude_run_id:
            continue
        _, artifacts = _github_request(
            "GET", f"/actions/runs/{run_id}/artifacts?per_page=100", token
        )
        entries = artifacts.get("artifacts", []) if isinstance(artifacts, dict) else []
        if not isinstance(entries, list) or (
            isinstance(artifacts, dict) and artifacts.get("total_count", 0) > 100
        ):
            raise ReleaseError("ARTIFACT_LOOKUP_INCOMPLETE", "INDETERMINATE")
        expected_name = f"w12-001-requested-{record['record_id']}-r{record['revision']}"
        candidates = [
            item for item in entries if isinstance(item, dict) and item.get("name") == expected_name
        ]
        if not candidates and run.get("status") != "completed":
            raise ReleaseError("ACTIVE_RUN_WITHOUT_RECORD", "INDETERMINATE")
        for item in candidates:
            if item.get("expired") or item.get("workflow_run", {}).get("id") != run_id:
                raise ReleaseError("ARTIFACT_UNINSPECTABLE", "INDETERMINATE")
            # Artifact metadata alone cannot prove record bytes. The named artifact
            # must be downloaded and validated before it can establish a match.
            artifact_id = item.get("id")
            if type(artifact_id) is not int or artifact_id <= 0:
                raise ReleaseError("ARTIFACT_ID_MISSING", "INDETERMINATE")
            files, _ = _github_artifact_files(
                artifact_id,
                run_id,
                token,
                {
                    "release-record.json",
                    "release-record.sha256",
                    "opa-receipt.json",
                    "opa-receipt.sha256",
                },
            )
            raw = files["release-record.json"]
            prior_record = validate_record(raw, files["release-record.sha256"], requested=True)
            prior_receipt_raw = files["opa-receipt.json"]
            validate_opa_receipt(
                prior_receipt_raw,
                files["opa-receipt.sha256"],
                record=prior_record,
                record_sha256=hashlib.sha256(raw).hexdigest(),
            )
            if (prior_record["record_id"], prior_record["revision"], prior_record["operation"]) == (
                record["record_id"],
                record["revision"],
                record["operation"],
            ):
                if (
                    hashlib.sha256(raw).hexdigest() != digest
                    or hashlib.sha256(prior_receipt_raw).hexdigest() != receipt_digest
                    or prior_record["source"]["commit"] != record["source"]["commit"]
                ):
                    raise ReleaseError("CONFLICTING_DUPLICATE")
                matches.append(_valid_run(run, record["source"]["commit"]))
    if len(matches) > 1:
        raise ReleaseError("MULTIPLE_MATCHING_RUNS", "INDETERMINATE")
    return matches[0] if matches else None


def _trigger(args: argparse.Namespace) -> dict[str, Any]:
    raw, record, digest = _read_record(args, requested=True)
    validate_terraform_configuration_binding(record)
    receipt_raw = Path(args.opa_receipt).read_bytes()
    receipt_sidecar = Path(args.opa_receipt_sha256_file).read_bytes()
    validate_opa_receipt(receipt_raw, receipt_sidecar, record=record, record_sha256=digest)
    receipt_digest = hashlib.sha256(receipt_raw).hexdigest()
    if not HEX40.fullmatch(args.commit) or args.commit != record["source"]["commit"]:
        raise ReleaseError("SOURCE_COMMIT_MISMATCH")
    encoded = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    if len(encoded) > _config()["record_max_b64url_chars"]:
        raise ReleaseError("B64URL_OVERSIZE")
    receipt_encoded = base64.urlsafe_b64encode(receipt_raw).decode("ascii").rstrip("=")
    if len(receipt_encoded) > _config()["opa_receipt_max_b64url_chars"]:
        raise ReleaseError("OPA_RECEIPT_TRANSPORT_OVERSIZE")
    if (
        sum(
            map(
                len,
                (
                    encoded,
                    digest,
                    receipt_encoded,
                    receipt_digest,
                    record["operation"],
                    args.commit,
                ),
            )
        )
        > 60_000
    ):
        raise ReleaseError("DISPATCH_INPUTS_OVERSIZE")
    token = _github_token()
    main_status, main_ref = _github_request("GET", "/git/ref/heads/main", token)
    if (
        main_status != 200
        or not isinstance(main_ref, dict)
        or main_ref.get("object", {}).get("sha") != args.commit
    ):
        raise ReleaseError("MAIN_COMMIT_MISMATCH")
    existing = _lookup_existing(record, digest, receipt_digest, token)
    if existing:
        run_id, api_url, html_url = existing
        state = "EXISTING"
    else:
        status, dispatched = _github_request(
            "POST",
            "/actions/workflows/" + GITHUB_WORKFLOW + "/dispatches",
            token,
            {
                "ref": "main",
                "inputs": {
                    "record_b64url": encoded,
                    "record_sha256": digest,
                    "opa_receipt_b64url": receipt_encoded,
                    "opa_receipt_sha256": receipt_digest,
                    "operation": record["operation"],
                    "source_commit": args.commit,
                },
            },
        )
        if status != 200 or not isinstance(dispatched, dict):
            raise ReleaseError("DISPATCH_RESPONSE_AMBIGUOUS", "INDETERMINATE")
        candidate_run_id = dispatched.get("workflow_run_id")
        if type(candidate_run_id) is not int or candidate_run_id <= 0:
            raise ReleaseError("DISPATCH_RUN_ID_MISSING", "INDETERMINATE")
        run_id = candidate_run_id
        api_url = f"https://api.github.com/repos/{GITHUB_REPOSITORY}/actions/runs/{run_id}"
        html_url = f"https://github.com/{GITHUB_REPOSITORY}/actions/runs/{run_id}"
        if (dispatched.get("run_url"), dispatched.get("html_url")) != (api_url, html_url):
            raise ReleaseError("DISPATCH_URL_MISMATCH", "INDETERMINATE")
        _, run = _github_request("GET", f"/actions/runs/{run_id}", token)
        _valid_run(run, args.commit)
        state = "DISPATCHED"
    return {
        "record_id": record["record_id"],
        "revision": record["revision"],
        "record_sha256": digest,
        "workflow_run_id": run_id,
        "run_url": api_url,
        "html_url": html_url,
        "status": state,
    }


def workflow_preflight() -> dict[str, str]:
    """Validate dispatch data before artifact upload or credential-bearing jobs."""
    encoded = os.environ.get("W12_RECORD_B64URL", "")
    digest = os.environ.get("W12_RECORD_SHA256", "")
    operation = os.environ.get("W12_OPERATION", "")
    commit = os.environ.get("W12_SOURCE_COMMIT", "")
    receipt_encoded = os.environ.get("W12_OPA_RECEIPT_B64URL", "")
    receipt_digest = os.environ.get("W12_OPA_RECEIPT_SHA256", "")
    if os.environ.get("GITHUB_REPOSITORY") != GITHUB_REPOSITORY:
        raise ReleaseError("WORKFLOW_REPOSITORY")
    if os.environ.get("GITHUB_REF") != "refs/heads/main" or os.environ.get("GITHUB_SHA") != commit:
        raise ReleaseError("WORKFLOW_REF_OR_HEAD")
    if not HEX40.fullmatch(commit):
        raise ReleaseError("WORKFLOW_COMMIT")
    raw = _strict_transport(encoded, digest, receipt=False)
    record = validate_record(raw, (digest + "\n").encode("ascii"), requested=True)
    validate_terraform_configuration_binding(record)
    if record["operation"] != operation or record["source"]["commit"] != commit:
        raise ReleaseError("WORKFLOW_RECORD_BINDING")
    receipt_raw = _strict_transport(receipt_encoded, receipt_digest, receipt=True)
    validate_opa_receipt(
        receipt_raw, (receipt_digest + "\n").encode("ascii"), record=record, record_sha256=digest
    )
    actor = os.environ.get("GITHUB_ACTOR_ID", "")
    approved_actors = os.environ.get("W12_APPROVED_ACTOR_IDS", "")
    if (
        not actor.isdecimal()
        or not approved_actors
        or actor not in approved_actors.split(",")
        or os.environ.get("GITHUB_RUN_ATTEMPT") != "1"
        or os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
    ):
        raise ReleaseError("WORKFLOW_ACTOR_NOT_APPROVED")
    event = json.loads(
        Path(os.environ["GITHUB_EVENT_PATH"]).read_bytes(), object_pairs_hook=_unique_pairs
    )
    if event.get("sender", {}).get("id") != int(actor) or event.get("ref") != "refs/heads/main":
        raise ReleaseError("WORKFLOW_SENDER_OR_REF")
    # The calling workflow sets RUNNER_TEMP to a runner-owned path outside checkout.
    temporary = Path(os.environ["RUNNER_TEMP"]).resolve()
    workspace = Path(os.environ["GITHUB_WORKSPACE"]).resolve()
    if temporary == workspace or workspace in temporary.parents or temporary in workspace.parents:
        raise ReleaseError("TEMPORARY_PATH_BOUNDARY")
    directory = Path(tempfile.mkdtemp(prefix="w12-record-", dir=temporary))
    os.chmod(directory, 0o700)
    try:
        record_path = directory / "release-record.json"
        sidecar_path = directory / "release-record.sha256"
        for path, value in (
            (record_path, raw),
            (sidecar_path, (digest + "\n").encode("ascii")),
            (directory / "opa-receipt.json", receipt_raw),
            (directory / "opa-receipt.sha256", (receipt_digest + "\n").encode("ascii")),
        ):
            with path.open("xb") as output:
                os.chmod(path, 0o600)
                output.write(value)
        result = {
            "record_id": record["record_id"],
            "revision": str(record["revision"]),
            "record_sha256": digest,
            "opa_receipt_sha256": receipt_digest,
            "record_dir": str(directory),
        }
        # File-command output contains only the temporary path and redacted IDs.
        with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
            for key, value in result.items():
                output.write(f"{key}={value}\n")
        return result
    except BaseException:
        shutil.rmtree(directory)
        raise


def workflow_consume(artifact_id: int, expected_digest: str, directory: Path) -> dict[str, Any]:
    """Revalidate current-run artifact metadata and its downloaded bytes."""
    if artifact_id <= 0 or not HEX64.fullmatch(expected_digest):
        raise ReleaseError("ARTIFACT_IDENTITY")
    run_id = int(os.environ["GITHUB_RUN_ID"])
    _, metadata = _github_request("GET", f"/actions/artifacts/{artifact_id}", _github_token())
    if (
        not isinstance(metadata, dict)
        or metadata.get("id") != artifact_id
        or metadata.get("expired") is not False
        or metadata.get("workflow_run", {}).get("id") != run_id
    ):
        raise ReleaseError("FOREIGN_OR_EXPIRED_ARTIFACT")
    raw = (directory / "release-record.json").read_bytes()
    record = validate_record(
        raw, (directory / "release-record.sha256").read_bytes(), requested=True
    )
    if hashlib.sha256(raw).hexdigest() != expected_digest:
        raise ReleaseError("DOWNSTREAM_RECORD_CHANGED")
    if metadata.get("name") != f"w12-001-requested-{record['record_id']}-r{record['revision']}":
        raise ReleaseError("ARTIFACT_NAME_MISMATCH")
    receipt_raw = (directory / "opa-receipt.json").read_bytes()
    validate_opa_receipt(
        receipt_raw,
        (directory / "opa-receipt.sha256").read_bytes(),
        record=record,
        record_sha256=expected_digest,
    )
    return record


def _env_artifact(prefix: str) -> tuple[int, str, Path]:
    identity = os.environ.get(prefix + "_ARTIFACT_ID", "")
    digest = os.environ.get(prefix + "_ARTIFACT_DIGEST", "")
    directory = os.environ.get(prefix + "_DIR", "")
    if (
        not identity.isdecimal()
        or int(identity) <= 0
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest)
        or not directory
    ):
        raise ReleaseError("WORKFLOW_ARTIFACT_INPUT_INCOMPLETE", "INDETERMINATE")
    root = Path(directory).resolve(strict=True)
    temporary = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    if root == temporary or temporary not in root.parents:
        raise ReleaseError("WORKFLOW_ARTIFACT_PATH_BOUNDARY")
    return int(identity), digest, root


def _workflow_requested() -> tuple[dict[str, Any], bytes, dict[str, Any]]:
    artifact_id, artifact_digest, directory = _env_artifact("W12_REQUESTED")
    metadata = _github_artifact_metadata(
        artifact_id, int(os.environ["GITHUB_RUN_ID"]), _github_token()
    )
    if metadata["digest"] != artifact_digest:
        raise ReleaseError("REQUESTED_ARTIFACT_CONTAINER_CHANGED")
    raw = (directory / "release-record.json").read_bytes()
    record = workflow_consume(artifact_id, os.environ["W12_RECORD_SHA256"], directory)
    receipt_raw = (directory / "opa-receipt.json").read_bytes()
    if hashlib.sha256(receipt_raw).hexdigest() != os.environ["W12_OPA_RECEIPT_SHA256"]:
        raise ReleaseError("OPA_RECEIPT_DIGEST_CHANGED")
    receipt = validate_opa_receipt(
        receipt_raw,
        (directory / "opa-receipt.sha256").read_bytes(),
        record=record,
        record_sha256=hashlib.sha256(raw).hexdigest(),
    )
    return record, raw, receipt


def workflow_conflict_check() -> None:
    directory = Path(os.environ["W12_RECORD_DIR"]).resolve(strict=True)
    raw = (directory / "release-record.json").read_bytes()
    record = validate_record(
        raw, (directory / "release-record.sha256").read_bytes(), requested=True
    )
    receipt_raw = (directory / "opa-receipt.json").read_bytes()
    validate_opa_receipt(
        receipt_raw,
        (directory / "opa-receipt.sha256").read_bytes(),
        record=record,
        record_sha256=hashlib.sha256(raw).hexdigest(),
    )
    existing = _lookup_existing(
        record,
        hashlib.sha256(raw).hexdigest(),
        hashlib.sha256(receipt_raw).hexdigest(),
        _github_token(),
        exclude_run_id=int(os.environ["GITHUB_RUN_ID"]),
    )
    if existing is not None:
        raise ReleaseError("CONFLICTING_ACTIVE_RELEASE", "INDETERMINATE")


def workflow_cleanup() -> None:
    directory = os.environ.get("W12_RECORD_DIR", "")
    if directory:
        root = Path(directory).resolve(strict=False)
        temporary = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
        if temporary not in root.parents or not root.name.startswith("w12-record-"):
            raise ReleaseError("CLEANUP_PATH_BOUNDARY")
        shutil.rmtree(root)


def workflow_receipt_validation_gate() -> None:
    _workflow_requested()


def workflow_consume_env() -> None:
    identity = os.environ.get("W12_ARTIFACT_ID", "")
    if not identity.isdecimal() or int(identity) <= 0:
        raise ReleaseError("ARTIFACT_IDENTITY")
    directory = Path(os.environ["W12_CONSUMED_DIR"])
    record = workflow_consume(
        int(identity),
        os.environ["W12_RECORD_SHA256"],
        directory,
    )
    receipt_raw = (directory / "opa-receipt.json").read_bytes()
    if hashlib.sha256(receipt_raw).hexdigest() != os.environ["W12_OPA_RECEIPT_SHA256"]:
        raise ReleaseError("OPA_RECEIPT_DIGEST_CHANGED")
    validate_opa_receipt(
        receipt_raw,
        (directory / "opa-receipt.sha256").read_bytes(),
        record=record,
        record_sha256=os.environ["W12_RECORD_SHA256"],
    )


def _bounded_process(
    args: list[str],
    *,
    cwd: Path | None = None,
    input_bytes: bytes | None = None,
    timeout: int = 300,
    limit: int = 5_000_000,
) -> bytes:
    result = subprocess.run(  # noqa: S603 -- callers supply bounded, explicit argv; no shell
        args, cwd=cwd, input=input_bytes, capture_output=True, timeout=timeout, check=False
    )
    if result.returncode != 0 or len(result.stdout) > limit or len(result.stderr) > limit:
        # Never print scanner output, Docker credentials, source or model content.
        raise ReleaseError("BOUNDED_PROCESS_FAILED")
    return result.stdout


def _hcp_output_value(state_id: str, name: str, *, token: str | None = None) -> Any:
    status, response = _hcp_request(
        "GET", f"/state-versions/{state_id}/outputs", token or _hcp_token()
    )
    data = response.get("data") if isinstance(response, dict) else None
    if status != 200 or not isinstance(data, list):
        raise ReleaseError("HCP_OUTPUTS_UNAVAILABLE", "INDETERMINATE")
    matches = [item for item in data if item.get("attributes", {}).get("name") == name]
    if len(matches) != 1 or matches[0].get("attributes", {}).get("sensitive") is not False:
        raise ReleaseError("HCP_OUTPUT_MISSING_OR_SENSITIVE")
    return matches[0]["attributes"].get("value")


def _toolchain(
    image: str, command: list[str], *, mount: Path | None = None, timeout: int = 600
) -> bytes:
    if not re.fullmatch(r"[a-z0-9][a-z0-9./_-]+@sha256:[0-9a-f]{64}", image):
        raise ReleaseError("BUILD_TOOLCHAIN_NOT_IMMUTABLE")
    args = [
        "docker",
        "run",
        "--rm",
        "--network=host",
        "--read-only",
        "--security-opt=no-new-privileges",
    ]
    if mount is not None:
        args.extend(["--mount", f"type=bind,src={mount},dst=/work", "--workdir", "/work"])
    docker_config_value = os.environ.get("DOCKER_CONFIG")
    docker_config = Path(docker_config_value) if docker_config_value else None
    if docker_config is not None and docker_config.is_dir():
        args.extend(["--mount", f"type=bind,src={docker_config},dst=/root/.docker,readonly"])
    for name in ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL"):
        if name in os.environ:
            args.extend(["--env", name])
    return _bounded_process(args + [image, *command], timeout=timeout)


def workflow_build() -> None:
    """Build from exact tracked source, then bind scans and one S3 version."""
    workflow_consume_env()
    directory = Path(os.environ["W12_CONSUMED_DIR"])
    raw = (directory / "release-record.json").read_bytes()
    requested = validate_record(
        raw, (directory / "release-record.sha256").read_bytes(), requested=True
    )
    tree_files = _tracked_regular_files(requested["source"]["commit"], requested["source"]["tree"])
    archive, manifest_sha, w6_sha = make_primary_source_bundle(
        tree_files, commit=requested["source"]["commit"], tree=requested["source"]["tree"]
    )
    archive_sha = hashlib.sha256(archive).hexdigest()
    validate_primary_source_bundle(
        archive,
        archive_sha256=archive_sha,
        manifest_sha256=manifest_sha,
        w6_sha256=w6_sha,
        commit=requested["source"]["commit"],
        tree=requested["source"]["tree"],
    )
    bucket = os.environ.get("W12_SOURCE_BUCKET", "")
    read_token = os.environ.get("TFC_READ_TOKEN", "")
    if (
        not read_token
        or not bucket
        or bucket
        != _hcp_output_value(
            requested["terraform"]["input_state_version_id"],
            "platform_bucket_name",
            token=read_token,
        )
    ):
        raise ReleaseError("SOURCE_BUCKET_STATE_BINDING")
    import boto3

    sts = boto3.client("sts")
    account = sts.get_caller_identity().get("Account")
    repository = os.environ.get("W12_IMAGE_REPOSITORY", "")
    expected_repository = (
        f"{account}.dkr.ecr.{_config()['aws_region']}.amazonaws.com/enterprise-ai/sandbox/api"
    )
    if repository != expected_repository or not re.fullmatch(r"[0-9]{12}", str(account)):
        raise ReleaseError("ECR_REPOSITORY_IDENTITY")
    kms_key = os.environ.get("W12_RELEASE_KMS_KEY_ARN", "")
    if not kms_key.startswith(f"arn:aws:kms:{_config()['aws_region']}:{account}:key/"):
        raise ReleaseError("SOURCE_KMS_KEY_IDENTITY")
    version = _s3_upload_exact(
        _s3_client(),
        bucket=bucket,
        key=SOURCE_KEY,
        raw=archive,
        kms_key=kms_key,
        metadata={
            "record-id": requested["record_id"],
            "record-revision": "1",
            "source-commit": requested["source"]["commit"],
            "archive-sha256": archive_sha,
            "record-sha256": hashlib.sha256(raw).hexdigest(),
        },
    )
    verified = _s3_read_exact(_s3_client(), bucket, SOURCE_KEY, version, archive_sha)
    validate_primary_source_bundle(
        verified,
        archive_sha256=archive_sha,
        manifest_sha256=manifest_sha,
        w6_sha256=w6_sha,
        commit=requested["source"]["commit"],
        tree=requested["source"]["tree"],
    )
    toolchain = os.environ.get("W12_BUILD_TOOLCHAIN_DIGEST", "")
    if not re.fullmatch(r"[a-z0-9][a-z0-9./_-]+@sha256:[0-9a-f]{64}", toolchain):
        raise ReleaseError("BUILD_TOOLCHAIN_IDENTITY")
    with tempfile.TemporaryDirectory(
        prefix="w12-build-", dir=os.environ["RUNNER_TEMP"]
    ) as temporary:
        build_root = Path(temporary)
        docker_config = build_root / "docker-config"
        docker_config.mkdir(mode=0o700)
        previous_docker_config = os.environ.get("DOCKER_CONFIG")
        os.environ["DOCKER_CONFIG"] = str(docker_config)
        for name, contents in tree_files.items():
            path = build_root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(contents)
        registry = repository.split("/", 1)[0]
        authorization = boto3.client(
            "ecr", region_name=_config()["aws_region"]
        ).get_authorization_token()["authorizationData"]
        if (
            len(authorization) != 1
            or authorization[0].get("proxyEndpoint") != "https://" + registry
        ):
            raise ReleaseError("ECR_AUTHORIZATION_IDENTITY")
        user, password = base64.b64decode(
            authorization[0]["authorizationToken"], validate=True
        ).split(b":", 1)
        if user != b"AWS":
            raise ReleaseError("ECR_AUTHORIZATION_USER")
        _bounded_process(
            ["docker", "login", "--username", "AWS", "--password-stdin", registry],
            input_bytes=password + b"\n",
            timeout=30,
        )
        tag = repository + ":w12-" + requested["source"]["commit"]
        metadata_path = build_root / "build-metadata.json"
        _bounded_process(
            [
                "docker",
                "buildx",
                "build",
                "--push",
                "--provenance=true",
                "--sbom=true",
                "--tag",
                tag,
                "--metadata-file",
                str(metadata_path),
                str(build_root),
            ],
            timeout=1800,
        )
        metadata = json.loads(metadata_path.read_bytes(), object_pairs_hook=_unique_pairs)
        image_digest = metadata.get("containerimage.digest")
        if not isinstance(image_digest, str) or not re.fullmatch(
            r"sha256:[0-9a-f]{64}", image_digest
        ):
            raise ReleaseError("BUILT_IMAGE_DIGEST_MISSING")
        observed = boto3.client("ecr", region_name=_config()["aws_region"]).describe_images(
            repositoryName="enterprise-ai/sandbox/api",
            imageIds=[{"imageTag": "w12-" + requested["source"]["commit"]}],
        )["imageDetails"]
        if len(observed) != 1 or observed[0].get("imageDigest") != image_digest:
            raise ReleaseError("ECR_IMAGE_DIGEST_MISMATCH")
        immutable = repository + "@" + image_digest
        trivy = _toolchain(
            toolchain, ["trivy", "image", "--quiet", "--format", "json", immutable], timeout=900
        )
        grype = _toolchain(toolchain, ["grype", immutable, "-o", "json"], timeout=900)
        trivy_doc, grype_doc = json.loads(trivy), json.loads(grype)
        if any(
            finding.get("Severity") in ("HIGH", "CRITICAL")
            for result in trivy_doc.get("Results", [])
            for finding in result.get("Vulnerabilities", []) or []
        ):
            raise ReleaseError("TRIVY_HIGH_OR_CRITICAL_FINDING")
        if any(
            item.get("vulnerability", {}).get("severity", "").upper() in ("HIGH", "CRITICAL")
            for item in grype_doc.get("matches", [])
        ):
            raise ReleaseError("GRYPE_HIGH_OR_CRITICAL_FINDING")
        sbom = _toolchain(toolchain, ["syft", immutable, "-o", "cyclonedx-json"], timeout=900)
        if not isinstance(json.loads(sbom), dict):
            raise ReleaseError("SBOM_INVALID")
        provenance = _canonical_bytes(
            {
                "schema_version": "w12-001.provenance.v1",
                "repository": GITHUB_REPOSITORY,
                "commit": requested["source"]["commit"],
                "tree": requested["source"]["tree"],
                "source_archive_sha256": archive_sha,
                "source_version_id": version,
                "image": immutable,
                "toolchain": toolchain,
                "workflow_run_id": int(os.environ["GITHUB_RUN_ID"]),
                "trivy_sha256": hashlib.sha256(trivy).hexdigest(),
                "grype_sha256": hashlib.sha256(grype).hexdigest(),
            }
        )
        (build_root / "provenance.json").write_bytes(provenance)
        (build_root / "sbom.json").write_bytes(sbom)
        _toolchain(
            toolchain,
            [
                "cosign",
                "attest",
                "--yes",
                "--type",
                "cyclonedx",
                "--predicate",
                "/work/sbom.json",
                immutable,
            ],
            mount=build_root,
            timeout=900,
        )
        _toolchain(
            toolchain,
            [
                "cosign",
                "attest",
                "--yes",
                "--type",
                "slsaprovenance",
                "--predicate",
                "/work/provenance.json",
                immutable,
            ],
            mount=build_root,
            timeout=900,
        )
        _toolchain(
            toolchain,
            ["cosign", "sign", "--yes", "--bundle", "/work/signature.bundle", immutable],
            mount=build_root,
            timeout=900,
        )
        signature = (build_root / "signature.bundle").read_bytes()
        if not signature or len(signature) > 524_288:
            raise ReleaseError("SIGNATURE_BUNDLE_MISSING")
        certificate_identity = os.environ.get("W12_COSIGN_CERT_IDENTITY", "")
        oidc_issuer = os.environ.get("W12_COSIGN_OIDC_ISSUER", "")
        if not certificate_identity or not oidc_issuer.startswith("https://"):
            raise ReleaseError("COSIGN_VERIFIER_IDENTITY_REQUIRED")
        _toolchain(
            toolchain,
            [
                "cosign",
                "verify",
                "--certificate-identity",
                certificate_identity,
                "--certificate-oidc-issuer",
                oidc_issuer,
                immutable,
            ],
            mount=build_root,
            timeout=900,
        )
        evidence_dir = Path(os.environ["RUNNER_TEMP"]) / "w12-build-evidence"
        evidence_dir.mkdir(mode=0o700, exist_ok=False)
        (evidence_dir / "signature.bundle").write_bytes(signature)
        summary = _canonical_bytes(
            {
                "schema_version": "w12-001.build-summary.v1",
                "record_id": requested["record_id"],
                "source_commit": requested["source"]["commit"],
                "image": immutable,
                "source_archive_sha256": archive_sha,
                "sbom_sha256": hashlib.sha256(sbom).hexdigest(),
                "provenance_sha256": hashlib.sha256(provenance).hexdigest(),
                "signature_sha256": hashlib.sha256(signature).hexdigest(),
                "trivy_sha256": hashlib.sha256(trivy).hexdigest(),
                "grype_sha256": hashlib.sha256(grype).hexdigest(),
            }
        )
        (evidence_dir / "build-summary.json").write_bytes(summary)
        output = {
            "image_digest": image_digest,
            "sbom_sha256": hashlib.sha256(sbom).hexdigest(),
            "provenance_sha256": hashlib.sha256(provenance).hexdigest(),
            "signature_sha256": hashlib.sha256(signature).hexdigest(),
            "source_archive_sha256": archive_sha,
            "s3_version_id": version,
            "source_manifest_sha256": manifest_sha,
            "w6_release_hashes_sha256": w6_sha,
        }
        with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as stream:
            for key, value in output.items():
                stream.write(f"{key}={value}\n")
        if previous_docker_config is None:
            os.environ.pop("DOCKER_CONFIG", None)
        else:
            os.environ["DOCKER_CONFIG"] = previous_docker_config


def _write_workflow_pair(directory: Path, stem: str, raw: bytes) -> str:
    temporary = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    target = directory.resolve(strict=False)
    if temporary not in target.parents:
        raise ReleaseError("WORKFLOW_OUTPUT_BOUNDARY")
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    return _write_new_pair(directory / (stem + ".json"), directory / (stem + ".sha256"), raw)


def _append_workflow_output(values: dict[str, str]) -> None:
    with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as stream:
        for name, value in values.items():
            if not re.fullmatch(r"[a-z][a-z0-9_]*", name) or "\n" in value or "\r" in value:
                raise ReleaseError("WORKFLOW_OUTPUT_UNSAFE")
            stream.write(f"{name}={value}\n")


def _transition_record(
    parent: dict[str, Any], parent_raw: bytes, status: str
) -> tuple[dict[str, Any], bytes]:
    if status not in _config()["status_transitions"].get(parent["status"], []):
        raise ReleaseError("RELEASE_STATUS_TRANSITION")
    result = json.loads(json.dumps(parent))
    result["revision"] = parent["revision"] + 1
    result["previous_record_sha256"] = hashlib.sha256(parent_raw).hexdigest()
    result["status"] = status
    result["created_at_utc"] = datetime.now(UTC).strftime(UTC_FORMAT)
    result["expires_at_utc"] = (
        datetime.now(UTC) + timedelta(seconds=_config()["record_expiry_seconds"])
    ).strftime(UTC_FORMAT)
    return result, _canonical_bytes(result)


def _bind_observed_plan_to_ready(
    requested: dict[str, Any], ready: dict[str, Any], receipt: dict[str, Any]
) -> None:
    """Carry the independently checked post-plan identities into revision two."""
    observed = receipt["hcp"]
    ready["terraform"].update(
        {
            "configuration_version_id": observed["configuration_version_id"],
            "run_id": observed["run_id"],
            "plan_id": observed["plan_id"],
            "input_state_version_id": observed["input_state_version_id"],
            "state_lineage": observed["state_lineage"],
            "input_state_serial": observed["state_serial"],
            "configuration_sha256": validate_terraform_configuration_binding(requested),
        }
    )


def workflow_prepare_ready() -> None:
    requested, requested_raw, receipt = _workflow_requested()
    ready, _ = _transition_record(requested, requested_raw, "READY_FOR_OWNER")
    _bind_observed_plan_to_ready(requested, ready, receipt)
    build_artifact = os.environ.get("W12_BUILD_ARTIFACT_ID", "")
    build_digest = os.environ.get("W12_BUILD_ARTIFACT_DIGEST", "")
    signature_sha = os.environ.get("W12_SIGNATURE_SHA256", "")
    if (
        not build_artifact.isdecimal()
        or int(build_artifact) <= 0
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", build_digest)
        or not _hex(signature_sha, required=True)
    ):
        raise ReleaseError("READY_BUILD_ARTIFACT_IDENTITY")
    build_files, build_metadata = _github_artifact_files(
        int(build_artifact),
        int(os.environ["GITHUB_RUN_ID"]),
        _github_token(),
        {"build-summary.json", "signature.bundle"},
    )
    if (
        build_metadata["digest"] != build_digest
        or build_metadata.get("name") != f"w12-001-build-{requested['record_id']}-r1"
        or hashlib.sha256(build_files["signature.bundle"]).hexdigest() != signature_sha
    ):
        raise ReleaseError("READY_BUILD_ARTIFACT_CHANGED")
    build_summary = _canonical_document(
        build_files["build-summary.json"],
        fields=[
            "schema_version",
            "record_id",
            "source_commit",
            "image",
            "source_archive_sha256",
            "sbom_sha256",
            "provenance_sha256",
            "signature_sha256",
            "trivy_sha256",
            "grype_sha256",
        ],
        code="BUILD_SUMMARY",
    )
    if (
        build_summary["schema_version"] != "w12-001.build-summary.v1"
        or build_summary["record_id"] != requested["record_id"]
        or build_summary["source_commit"] != requested["source"]["commit"]
        or build_summary["signature_sha256"] != signature_sha
    ):
        raise ReleaseError("READY_BUILD_SUMMARY_IDENTITY")
    source = ready["source"]
    bucket = os.environ.get("W12_SOURCE_BUCKET", "")
    version = os.environ.get("W12_S3_VERSION_ID", "")
    manifest_sha = os.environ.get("W12_SOURCE_MANIFEST_SHA256", "")
    w6_sha = os.environ.get("W12_W6_RELEASE_HASHES_SHA256", "")
    archive_sha = os.environ.get("W12_SOURCE_ARCHIVE_SHA256", "")
    if (
        not bucket
        or not version
        or version == "null"
        or any(not _hex(item, required=True) for item in (manifest_sha, w6_sha, archive_sha))
    ):
        raise ReleaseError("READY_SOURCE_IDENTITY_INCOMPLETE")
    kms_key = os.environ.get("W12_RELEASE_KMS_KEY_ARN", "")
    account = os.environ.get("W12_DEPLOYMENT_ACCOUNT_ID", "")
    if not re.fullmatch(r"[0-9]{12}", account) or not kms_key.startswith(
        f"arn:aws:kms:{_config()['aws_region']}:{account}:key/"
    ):
        raise ReleaseError("READY_SOURCE_KMS_IDENTITY")
    source_client = _s3_client()
    source_raw = _s3_read_exact(source_client, bucket, SOURCE_KEY, version, archive_sha)
    source_head = source_client.head_object(
        Bucket=bucket,
        Key=SOURCE_KEY,
        VersionId=version,
        ChecksumMode="ENABLED",
    )
    if (
        source_head.get("VersionId") != version
        or source_head.get("ServerSideEncryption") != "aws:kms"
        or source_head.get("SSEKMSKeyId") != kms_key
        or source_head.get("ChecksumSHA256") != _s3_full_checksum(source_raw)
    ):
        raise ReleaseError("READY_SOURCE_PROVIDER_IDENTITY", "INDETERMINATE")
    validate_primary_source_bundle(
        source_raw,
        archive_sha256=archive_sha,
        manifest_sha256=manifest_sha,
        w6_sha256=w6_sha,
        commit=requested["source"]["commit"],
        tree=requested["source"]["tree"],
    )
    source.update(
        {
            "archive_sha256": archive_sha,
            "s3_bucket": bucket,
            "s3_key": SOURCE_KEY,
            "s3_version_id": version,
        }
    )
    artifacts = ready["artifacts"]
    artifacts.update(
        {
            "container_repository": os.environ.get("W12_IMAGE_REPOSITORY", ""),
            "image_digest": os.environ.get("W12_IMAGE_DIGEST", ""),
            "otel_collector_image": os.environ.get("W12_OTEL_COLLECTOR_IMAGE", ""),
            "model_package_arn": os.environ.get("W12_MODEL_PACKAGE_ARN") or None,
            "sbom_sha256": os.environ.get("W12_SBOM_SHA256", ""),
            "provenance_sha256": os.environ.get("W12_PROVENANCE_SHA256", ""),
            "signature_ref": (
                f"urn:github-artifact:{build_artifact}:signature.bundle:{signature_sha}"
            ),
        }
    )
    if (
        build_summary["image"]
        != artifacts["container_repository"] + "@" + artifacts["image_digest"]
        or build_summary["source_archive_sha256"] != archive_sha
        or build_summary["sbom_sha256"] != artifacts["sbom_sha256"]
        or build_summary["provenance_sha256"] != artifacts["provenance_sha256"]
    ):
        raise ReleaseError("READY_BUILD_OUTPUT_SUBSTITUTION")
    if (
        artifacts["container_repository"] + "@" + artifacts["image_digest"]
        == artifacts["otel_collector_image"]
    ):
        raise ReleaseError("READY_IMAGE_ROLE_CONFUSION")
    gates = ready["gates"]
    environment_id = os.environ.get("W12_GITHUB_ENVIRONMENT_ID", "")
    if not environment_id.isdecimal() or int(environment_id) <= 0:
        raise ReleaseError("GITHUB_ENVIRONMENT_ID_REQUIRED")
    gates.update(
        {
            "opa_status": "PASS",
            "opa_evidence_sha256": hashlib.sha256(
                (Path(os.environ["W12_REQUESTED_DIR"]) / "opa-receipt.json").read_bytes()
            ).hexdigest(),
            "run_task_status": "PASS",
            "run_task_result_id": receipt["infracost"]["result_id"],
            "scan_status": "PASS",
            "github_run_id": int(os.environ["GITHUB_RUN_ID"]),
            "github_environment_id": int(environment_id),
            "github_approval_status": "NOT_RUN",
            "hcp_approval_status": "NOT_RUN",
        }
    )
    deployment = ready["deployment"]
    if not re.fullmatch(r"[0-9]{12}", account):
        raise ReleaseError("READY_AWS_ACCOUNT_ID_REQUIRED")
    deployment.update(
        {
            "account_id": account,
            "render_contract": "w12-001.render.v1",
            "render_inputs_sha256": None,
            "w6_release_hashes_sha256": w6_sha,
            "derivative_manifest_sha256": None,
            "root_fingerprint_sha256": os.environ.get("W12_ROOT_FINGERPRINT_SHA256", ""),
            "trust_bundle_sha256": os.environ.get("W12_TRUST_BUNDLE_SHA256", ""),
        }
    )
    rollback_target: dict[str, Any] | None = None
    if requested["operation"] == "rollback":
        kms_key = os.environ.get("W12_RELEASE_KMS_KEY_ARN", "")
        if not kms_key.startswith(f"arn:aws:kms:{_config()['aws_region']}:{account}:key/"):
            raise ReleaseError("ROLLBACK_READER_KMS_IDENTITY")
        prior_files, prior_records, prior_raws, prior_render = load_prior_rollback_lineage(
            requested,
            client=_s3_client(),
            kms_key_arn=kms_key,
        )
        prior_verified = prior_records[4]
        if (
            prior_verified["deployment"]["account_id"] != account
            or prior_verified["deployment"]["environment"] != deployment["environment"]
            or prior_verified["deployment"]["region"] != deployment["region"]
            or application_image_from_ready(prior_records[1]) != application_image_from_ready(ready)
            or prior_records[1]["artifacts"]["otel_collector_image"]
            != artifacts["otel_collector_image"]
            or prior_verified["deployment"]["root_fingerprint_sha256"]
            != deployment["root_fingerprint_sha256"]
            or prior_verified["deployment"]["trust_bundle_sha256"]
            != deployment["trust_bundle_sha256"]
        ):
            raise ReleaseError("ROLLBACK_TARGET_IMAGE_TRUST_OR_ACCOUNT_CHANGED")
        token = os.environ.get("TFC_READ_TOKEN", "")
        if not token:
            raise ReleaseError("READY_READ_ONLY_HCP_TOKEN_REQUIRED")
        run = _hcp_run(requested, requested["terraform"]["run_id"], token)
        _hcp_vcs_binding(requested, run, token)
        tf = requested["terraform"]
        relationships = run.get("relationships", {})
        if (
            relationships.get("plan", {}).get("data", {}).get("id"),
            relationships.get("configuration-version", {}).get("data", {}).get("id"),
            relationships.get("input-state-version", {}).get("data", {}).get("id"),
        ) != (tf["plan_id"], tf["configuration_version_id"], tf["input_state_version_id"]):
            raise ReleaseError("ROLLBACK_HCP_PLAN_STATE_IDENTITY")
        state, state_lineage, state_serial = _hcp_state_identity(
            tf["input_state_version_id"], token
        )
        if (
            state.get("id") != tf["input_state_version_id"]
            or state_lineage != tf["state_lineage"]
            or state_serial != tf["input_state_serial"]
        ):
            raise ReleaseError("ROLLBACK_HCP_INPUT_STATE_CHANGED")
        _, plan_response = _hcp_request("GET", f"/plans/{tf['plan_id']}", token)
        if (
            plan_response.get("data", {}).get("id") != tf["plan_id"]
            or plan_response.get("data", {}).get("attributes", {}).get("status") != "finished"
        ):
            raise ReleaseError("ROLLBACK_HCP_PLAN_NOT_FINISHED", "INDETERMINATE")
        plan_raw = _hcp_plan_json_bytes(tf["plan_id"], token)
        if hashlib.sha256(plan_raw).hexdigest() != receipt["hcp"]["plan_json_sha256"]:
            raise ReleaseError("ROLLBACK_HCP_PLAN_CHANGED", "INDETERMINATE")
        try:
            plan_json = json.loads(
                plan_raw, object_pairs_hook=_unique_pairs, parse_constant=_reject_constant
            )
            proposed_profile = plan_json["planned_values"]["outputs"][
                "bedrock_inference_profile_arn"
            ]["value"]
        except (UnicodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
            raise ReleaseError("ROLLBACK_PLAN_BEDROCK_OUTPUT_UNKNOWN", "INDETERMINATE") from exc
        if (
            not isinstance(proposed_profile, str)
            or proposed_profile != prior_render["bedrock_inference_profile_arn"]
        ):
            raise ReleaseError("ROLLBACK_PLAN_BEDROCK_IDENTITY_CHANGED", "INDETERMINATE")
        ref = decode_s3v_locator(requested["recovery"]["rollback_ref"])
        rollback_target = {
            "files": prior_files,
            "records": prior_records,
            "raws": prior_raws,
            "render": prior_render,
            "ref": ref,
        }
    ready["evidence"] = sorted(
        requested["evidence"]
        + [
            {
                "kind": "build_artifact",
                "uri": f"urn:github-artifact:{build_artifact}",
                "sha256": build_digest[7:],
            },
            {
                "kind": "source_bundle",
                "uri": encode_s3v_locator(bucket, SOURCE_KEY, version),
                "sha256": archive_sha,
            },
            {
                "kind": "w12_source_manifest",
                "uri": encode_s3v_locator(bucket, SOURCE_KEY, version, entry=BOOTSTRAP_JSON),
                "sha256": manifest_sha,
            },
            {
                "kind": "w6_release_hashes",
                "uri": encode_s3v_locator(bucket, SOURCE_KEY, version, entry=W6_HASHES_JSON),
                "sha256": w6_sha,
            },
            *(
                [
                    {
                        "kind": "rollback-verified-record",
                        "uri": encode_s3v_locator(
                            rollback_target["ref"]["bucket"],
                            rollback_target["ref"]["key"],
                            rollback_target["ref"]["version_id"],
                            entry="rollback/verified/release-record.json",
                        ),
                        "sha256": hashlib.sha256(rollback_target["raws"][4]).hexdigest(),
                    },
                    {
                        "kind": "rollback-parent-record",
                        "uri": encode_s3v_locator(
                            rollback_target["ref"]["bucket"],
                            rollback_target["ref"]["key"],
                            rollback_target["ref"]["version_id"],
                            entry="rollback/parent/release-record.json",
                        ),
                        "sha256": hashlib.sha256(rollback_target["raws"][3]).hexdigest(),
                    },
                ]
                if rollback_target is not None
                else []
            ),
        ],
        key=lambda item: (item["kind"], item["uri"]),
    )
    raw = _canonical_bytes(ready)
    ready_sha = hashlib.sha256(raw).hexdigest()
    validate_record(raw, (ready_sha + "\n").encode("ascii"), previous=requested_raw)
    directory = Path(os.environ["W12_READY_DIR"])
    _write_workflow_pair(directory, "release-record", raw)
    transition = _canonical_bytes(
        {
            "schema_version": "w12-001.ready-evidence.v1",
            "record_id": ready["record_id"],
            "from_revision": 1,
            "to_revision": 2,
            "parent_record_sha256": hashlib.sha256(requested_raw).hexdigest(),
            "source_manifest_sha256": manifest_sha,
            "w6_release_hashes_sha256": w6_sha,
            "source_archive_sha256": archive_sha,
            "source_version_id": version,
            "opa_receipt_sha256": gates["opa_evidence_sha256"],
            "infracost_result_id": gates["run_task_result_id"],
            "observed_at_utc": datetime.now(UTC).strftime(UTC_FORMAT),
        }
    )
    _write_new_pair(
        directory / "transition-evidence.json", directory / "transition-evidence.sha256", transition
    )
    _append_workflow_output({"ready_record_sha256": ready_sha})


def workflow_cleanup_ready() -> None:
    directory = os.environ.get("W12_READY_DIR", "")
    if directory:
        target = Path(directory).resolve(strict=False)
        temporary = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
        if temporary not in target.parents or target.name != "w12-ready":
            raise ReleaseError("READY_CLEANUP_BOUNDARY")
        shutil.rmtree(target, ignore_errors=False)


def _workflow_ready() -> tuple[dict[str, Any], bytes, dict[str, Any], bytes, dict[str, Any]]:
    requested, requested_raw, receipt = _workflow_requested()
    artifact_id, artifact_digest, directory = _env_artifact("W12_READY")
    metadata = _github_artifact_metadata(
        artifact_id, int(os.environ["GITHUB_RUN_ID"]), _github_token()
    )
    raw = (directory / "release-record.json").read_bytes()
    ready = validate_record(
        raw, (directory / "release-record.sha256").read_bytes(), previous=requested_raw
    )
    if (
        metadata["digest"] != artifact_digest
        or metadata.get("name") != f"w12-001-ready-for-owner-{ready['record_id']}-r2"
        or hashlib.sha256(raw).hexdigest() != os.environ["W12_READY_RECORD_SHA256"]
        or ready["status"] != "READY_FOR_OWNER"
        or ready["record_id"] != requested["record_id"]
    ):
        raise ReleaseError("READY_CURRENT_RUN_ARTIFACT_MISMATCH")
    transition_raw = (directory / "transition-evidence.json").read_bytes()
    transition_sidecar = (directory / "transition-evidence.sha256").read_bytes()
    transition = _canonical_document(
        transition_raw,
        fields=[
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
        code="READY_EVIDENCE",
    )
    if (
        transition_sidecar != (hashlib.sha256(transition_raw).hexdigest() + "\n").encode("ascii")
        or transition["schema_version"] != "w12-001.ready-evidence.v1"
        or transition["parent_record_sha256"] != hashlib.sha256(requested_raw).hexdigest()
        or transition["record_id"] != ready["record_id"]
        or transition["source_version_id"] != ready["source"]["s3_version_id"]
    ):
        raise ReleaseError("READY_TRANSITION_EVIDENCE_MISMATCH")
    if (
        ready["gates"]["opa_evidence_sha256"]
        != hashlib.sha256(
            (Path(os.environ["W12_REQUESTED_DIR"]) / "opa-receipt.json").read_bytes()
        ).hexdigest()
        or ready["gates"]["run_task_result_id"] != receipt["infracost"]["result_id"]
    ):
        raise ReleaseError("READY_RECEIPT_BINDING")
    remote, _ = _github_artifact_files(
        artifact_id,
        int(os.environ["GITHUB_RUN_ID"]),
        _github_token(),
        {
            "release-record.json",
            "release-record.sha256",
            "transition-evidence.json",
            "transition-evidence.sha256",
        },
    )
    if remote != {name: (directory / name).read_bytes() for name in remote}:
        raise ReleaseError("READY_DOWNLOADED_BYTES_CHANGED")
    return ready, raw, requested, requested_raw, receipt


def _github_approval_subset(ready: dict[str, Any], ready_raw: bytes) -> dict[str, Any]:
    run_id = int(os.environ["GITHUB_RUN_ID"])
    _, run = _github_request("GET", f"/actions/runs/{run_id}", _github_token())
    _valid_run(run, ready["source"]["commit"])
    if run.get("run_attempt") != 1:
        raise ReleaseError("GITHUB_RERUN_NOT_APPROVED")
    environment = os.environ.get("W12_GITHUB_ENVIRONMENT_ID", "")
    if not environment.isdecimal() or int(environment) != ready["gates"]["github_environment_id"]:
        raise ReleaseError("GITHUB_APPROVAL_ENVIRONMENT_ID")
    status, approvals = _github_request("GET", f"/actions/runs/{run_id}/approvals", _github_token())
    if status != 200 or not isinstance(approvals, list):
        raise ReleaseError("GITHUB_APPROVAL_HISTORY_UNAVAILABLE", "INDETERMINATE")
    expected_comment = (
        f"W12-001 APPROVE record={ready['record_id']} revision=2 "
        f"ready_sha256={hashlib.sha256(ready_raw).hexdigest()} run_id={run_id}"
    )
    matches: list[dict[str, Any]] = []
    for item in approvals:
        if not isinstance(item, dict) or item.get("state") not in ("approved", "rejected"):
            raise ReleaseError("GITHUB_APPROVAL_HISTORY_UNKNOWN", "INDETERMINATE")
        environments = item.get("environments")
        if not isinstance(environments, list) or len(environments) != 1:
            raise ReleaseError("GITHUB_APPROVAL_ENVIRONMENT_AMBIGUOUS")
        env = environments[0]
        same = env.get("id") == int(environment) and env.get("name") == "sandbox"
        if item["state"] == "rejected" and same:
            raise ReleaseError("GITHUB_APPROVAL_REJECTED")
        if item["state"] == "approved" and not same:
            raise ReleaseError("GITHUB_FOREIGN_APPROVED_ENVIRONMENT")
        if same and item["state"] == "approved":
            if (
                item.get("comment") != expected_comment
                or not isinstance(env.get("node_id"), str)
                or not env["node_id"]
            ):
                raise ReleaseError("GITHUB_APPROVAL_COMMENT_OR_ENVIRONMENT")
            matches.append(item)
    if len(matches) != 1:
        raise ReleaseError("GITHUB_APPROVAL_COUNT", "INDETERMINATE" if not matches else "FAIL")
    item = matches[0]
    user = item.get("user", {})
    allowlist = os.environ.get("W12_APPROVED_REVIEWER_IDS", "").split(",")
    actor = os.environ.get("GITHUB_ACTOR_ID", "")
    self_review = os.environ.get("W12_ALLOW_SELF_REVIEW", "")
    if (
        self_review not in ("true", "false")
        or type(user.get("id")) is not int
        or str(user["id"]) not in allowlist
        or user.get("type") != "User"
        or not all(isinstance(user.get(key), str) and user[key] for key in ("login", "node_id"))
        or (self_review == "false" and str(user["id"]) == actor)
    ):
        raise ReleaseError("GITHUB_REVIEWER_IDENTITY")
    env = item["environments"][0]
    return {
        "repository": GITHUB_REPOSITORY,
        "workflow_run_id": run_id,
        "run_attempt": 1,
        "environment_id": int(environment),
        "environment_node_id": env["node_id"],
        "environment_name": "sandbox",
        "state": "approved",
        "comment_sha256": hashlib.sha256(expected_comment.encode()).hexdigest(),
        "approver_id": user["id"],
        "approver_login": user["login"],
        "approver_node_id": user["node_id"],
        "approver_type": user["type"],
    }


def workflow_verify_github_approval() -> None:
    ready, raw, _, _, _ = _workflow_ready()
    subset = _github_approval_subset(ready, raw)
    digest = hashlib.sha256(_canonical_bytes(subset)).hexdigest()
    _append_workflow_output({"github_approval_subset_sha256": digest})


def _hcp_automation_identity(token: str) -> dict[str, Any]:
    status, response = _hcp_request("GET", "/account/details", token)
    data = response.get("data") if isinstance(response, dict) else None
    if status != 200 or not isinstance(data, dict) or data.get("type") != "users":
        raise ReleaseError("HCP_AUTOMATION_ACCOUNT_UNAVAILABLE", "INDETERMINATE")
    attrs = data.get("attributes", {})
    auth = data.get("relationships", {}).get("authenticated-resource", {}).get("data", {})
    owner_team = os.environ.get("W12_HCP_OWNER_TEAM_ID", "")
    service_user = os.environ.get("W12_HCP_SERVICE_USER_ID", "")
    if (
        not owner_team
        or not service_user
        or data.get("id") != service_user
        or attrs.get("is-service-account") is not True
        or auth.get("type") != "teams"
        or auth.get("id") != owner_team
    ):
        raise ReleaseError("HCP_AUTOMATION_IDENTITY_MISMATCH")
    subset = {
        "api_base": "https://app.terraform.io/api/v2",
        "account_user_id": service_user,
        "account_user_type": "users",
        "username": attrs.get("username"),
        "is_service_account": True,
        "auth_method": "team-token",
        "resource_type": "teams",
        "resource_id": owner_team,
    }
    if not isinstance(subset["username"], str) or not subset["username"]:
        raise ReleaseError("HCP_AUTOMATION_USERNAME_MISSING")
    digest = hashlib.sha256(_canonical_bytes(subset)).hexdigest()
    subset["canonical_subset_sha256"] = digest
    subset["client_observed_at_utc"] = datetime.now(UTC).strftime(UTC_FORMAT)
    return subset


def _hcp_preapply(
    ready: dict[str, Any], receipt: dict[str, Any], token: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    tf = ready["terraform"]
    cfg = _config()
    if (tf["organization"], tf["project"], tf["workspace"]) != (
        cfg["hcp_organization"],
        cfg["hcp_project"],
        cfg["hcp_sandbox_workspace"],
    ):
        raise ReleaseError("HCP_READY_WORKSPACE_MISMATCH")
    path = (
        f"/organizations/{urllib.parse.quote(tf['organization'], safe='')}"
        f"/workspaces/{urllib.parse.quote(tf['workspace'], safe='')}"
    )
    status, response = _hcp_request("GET", path, token)
    workspace = response.get("data") if isinstance(response, dict) else None
    if status != 200 or not isinstance(workspace, dict) or not workspace.get("id"):
        raise ReleaseError("HCP_WORKSPACE_UNAVAILABLE", "INDETERMINATE")
    attrs = workspace.get("attributes", {})
    vcs = attrs.get("vcs-repo", {})
    project = workspace.get("relationships", {}).get("project", {}).get("data", {})
    if (
        attrs.get("auto-apply") is not False
        or attrs.get("execution-mode") != "remote"
        or attrs.get("working-directory") != "infra/environments/sandbox"
        or vcs.get("identifier") != GITHUB_REPOSITORY
        or vcs.get("branch") not in ("main", None)
        or not project.get("id")
    ):
        raise ReleaseError("HCP_WORKSPACE_CONFIGURATION_MISMATCH")
    project_status, project_response = _hcp_request("GET", f"/projects/{project['id']}", token)
    project_data = project_response.get("data") if isinstance(project_response, dict) else None
    if (
        project_status != 200
        or not isinstance(project_data, dict)
        or project_data.get("id") != project["id"]
        or project_data.get("attributes", {}).get("name") != tf["project"]
    ):
        raise ReleaseError("HCP_PROJECT_IDENTITY_MISMATCH")
    run = _hcp_run(ready, tf["run_id"], token)
    relationships = run.get("relationships", {})
    if relationships.get("workspace", {}).get("data", {}).get("id") != workspace["id"]:
        raise ReleaseError("HCP_RUN_WORKSPACE_CHANGED")
    expected = {
        "plan": tf["plan_id"],
        "configuration-version": tf["configuration_version_id"],
        "input-state-version": tf["input_state_version_id"],
    }
    if any(
        (relationships.get(name, {}).get("data") or {}).get("id") != value
        for name, value in expected.items()
    ):
        raise ReleaseError("HCP_RUN_RELATIONSHIP_CHANGED")
    attrs = run.get("attributes", {})
    if (
        attrs.get("status") not in ("policy_checked", "post_plan_completed")
        or run.get("actions", {}).get("is-confirmable") is not True
        or attrs.get("is-speculative") is not False
    ):
        raise ReleaseError("HCP_RUN_NOT_CONFIRMABLE")
    config_status, config_response = _hcp_request(
        "GET",
        f"/configuration-versions/{tf['configuration_version_id']}?include=ingress_attributes",
        token,
    )
    config = config_response.get("data") if isinstance(config_response, dict) else None
    ingress_ref = (
        config.get("relationships", {}).get("ingress-attributes", {}).get("data", {})
        if isinstance(config, dict)
        else {}
    )
    included = config_response.get("included", []) if isinstance(config_response, dict) else []
    ingress_matches = [
        item
        for item in included
        if item.get("id") == ingress_ref.get("id") and item.get("type") == ingress_ref.get("type")
    ]
    if (
        config_status != 200
        or not isinstance(config, dict)
        or config.get("id") != tf["configuration_version_id"]
        or config.get("attributes", {}).get("source") != "tfe-vcs"
        or len(ingress_matches) != 1
        or ingress_matches[0].get("attributes", {}).get("commit-sha") != ready["source"]["commit"]
    ):
        raise ReleaseError("HCP_VCS_COMMIT_CHANGED")
    initial = _empty_input_state(
        tf["input_state_version_id"], tf["state_lineage"], tf["input_state_serial"]
    )
    if initial:
        if ready["operation"] != "deploy":
            raise ReleaseError("HCP_INITIAL_STATE_OPERATION")
        _hcp_initial_state_empty(ready, workspace["id"], token)
    else:
        state, state_lineage, state_serial = _hcp_state_identity(
            tf["input_state_version_id"], token
        )
        if state.get("id") != tf["input_state_version_id"] or (state_lineage, state_serial) != (
            tf["state_lineage"],
            tf["input_state_serial"],
        ):
            raise ReleaseError("HCP_INPUT_STATE_CHANGED")
        current_status, current_response = _hcp_request(
            "GET", f"/workspaces/{workspace['id']}/current-state-version", token
        )
        current = current_response.get("data") if isinstance(current_response, dict) else None
        if (
            current_status != 200
            or not isinstance(current, dict)
            or current.get("id") != state["id"]
        ):
            raise ReleaseError("HCP_CURRENT_STATE_REPLACED")
    plan_status, plan_response = _hcp_request("GET", f"/plans/{tf['plan_id']}", token)
    plan = plan_response.get("data") if isinstance(plan_response, dict) else None
    if (
        plan_status != 200
        or not isinstance(plan, dict)
        or plan.get("id") != tf["plan_id"]
        or plan.get("attributes", {}).get("status") != "finished"
    ):
        raise ReleaseError("HCP_PLAN_CHANGED")
    if (
        hashlib.sha256(_hcp_plan_json_bytes(tf["plan_id"], token)).hexdigest()
        != receipt["hcp"]["plan_json_sha256"]
    ):
        raise ReleaseError("HCP_PLAN_JSON_CHANGED")
    task_status, task_response = _hcp_request(
        "GET", f"/task-results/{receipt['infracost']['result_id']}", token
    )
    task = task_response.get("data") if isinstance(task_response, dict) else None
    if (
        task_status != 200
        or not isinstance(task, dict)
        or task.get("id") != receipt["infracost"]["result_id"]
        or task.get("attributes", {}).get("status") != "passed"
    ):
        raise ReleaseError("INFRACOST_RESULT_CHANGED")
    return run, workspace


def _hcp_relationships_match(left: dict[str, Any], right: dict[str, Any]) -> bool:
    names = ("workspace", "plan", "configuration-version", "input-state-version")
    return all(
        (left.get("relationships", {}).get(name, {}).get("data") or {}).get("id")
        == (right.get("relationships", {}).get(name, {}).get("data") or {}).get("id")
        for name in names
    )


def workflow_apply_wait() -> None:
    ready, ready_raw, requested, requested_raw, receipt = _workflow_ready()
    github = _github_approval_subset(ready, ready_raw)
    approval_digest = hashlib.sha256(_canonical_bytes(github)).hexdigest()
    if approval_digest != os.environ.get("W12_GITHUB_APPROVAL_SUBSET_SHA256"):
        raise ReleaseError("GITHUB_APPROVAL_CHANGED")
    if datetime.now(UTC) >= _utc(ready["expires_at_utc"]):
        raise ReleaseError("READY_RECORD_EXPIRED")
    # The receipt validator rechecks its short validity window immediately before apply.
    validate_opa_receipt(
        (Path(os.environ["W12_REQUESTED_DIR"]) / "opa-receipt.json").read_bytes(),
        (Path(os.environ["W12_REQUESTED_DIR"]) / "opa-receipt.sha256").read_bytes(),
        record=requested,
        record_sha256=hashlib.sha256(requested_raw).hexdigest(),
    )
    token = _hcp_token()
    identity = _hcp_automation_identity(token)
    pre, workspace = _hcp_preapply(ready, receipt, token)
    tf = ready["terraform"]
    path = f"/runs/{tf['run_id']}/actions/apply"
    comment = (
        f"W12-001 record={ready['record_id']} revision=2 "
        f"ready_sha256={hashlib.sha256(ready_raw).hexdigest()} "
        f"github_run_id={os.environ['GITHUB_RUN_ID']} "
        f"github_approval_sha256={approval_digest}"
    )
    request_body = {"comment": comment}
    request_raw = json.dumps(request_body, separators=(",", ":")).encode("utf-8")
    requested_at = datetime.now(UTC).strftime(UTC_FORMAT)
    try:
        status, response = _hcp_request("POST", path, token, request_body)
    except ReleaseError as exc:
        if exc.classification == "INDETERMINATE":
            # A read diagnoses the exact run; it never retries or claims the POST.
            _hcp_run(ready, tf["run_id"], token)
            raise ReleaseError("HCP_APPLY_POST_AMBIGUOUS", "INDETERMINATE") from exc
        raise
    if status != 202 or response is not None:
        raise ReleaseError("HCP_APPLY_NOT_ACCEPTED")
    post = _hcp_run(ready, tf["run_id"], token)
    if (
        not _hcp_relationships_match(pre, post)
        or post.get("actions", {}).get("is-confirmable") is not False
        or post.get("attributes", {}).get("status")
        not in ("confirmed", "apply_queued", "applying", "applied")
    ):
        raise ReleaseError("HCP_APPLY_READBACK_MISMATCH")
    apply_data = post.get("relationships", {}).get("apply", {}).get("data")
    apply_id = apply_data.get("id") if isinstance(apply_data, dict) else None
    github_evidence = {
        "repository": github["repository"],
        "workflow_run_id": github["workflow_run_id"],
        "run_attempt": github["run_attempt"],
        "environment_id": github["environment_id"],
        "environment_name": github["environment_name"],
        "state": github["state"],
        "comment_sha256": github["comment_sha256"],
        "approver_id": github["approver_id"],
        "approver_login": github["approver_login"],
        "approver_node_id": github["approver_node_id"],
        "approver_type": github["approver_type"],
        "canonical_subset_sha256": approval_digest,
        "client_observed_at_utc": datetime.now(UTC).strftime(UTC_FORMAT),
    }
    post_subset = {
        "id": post["id"],
        "status": post["attributes"]["status"],
        "is_confirmable": post["actions"]["is-confirmable"],
        "plan_id": post["relationships"]["plan"]["data"]["id"],
        "configuration_version_id": post["relationships"]["configuration-version"]["data"]["id"],
        "input_state_version_id": (
            post["relationships"].get("input-state-version", {}).get("data") or {}
        ).get("id"),
    }
    apply_evidence = {
        "organization": tf["organization"],
        "project": tf["project"],
        "workspace": tf["workspace"],
        "configuration_version_id": tf["configuration_version_id"],
        "run_id": tf["run_id"],
        "plan_id": tf["plan_id"],
        "input_state_version_id": tf["input_state_version_id"],
        "state_lineage": tf["state_lineage"],
        "input_state_serial": tf["input_state_serial"],
        "pre_status": pre["attributes"]["status"],
        "pre_is_confirmable": True,
        "request_method": "POST",
        "request_path": path,
        "request_body_sha256": hashlib.sha256(request_raw).hexdigest(),
        "response_status": 202,
        "post_status": post["attributes"]["status"],
        "post_is_confirmable": False,
        "apply_id": apply_id,
        "post_run_subset_sha256": hashlib.sha256(_canonical_bytes(post_subset)).hexdigest(),
        "client_requested_at_utc": requested_at,
        "client_observed_at_utc": datetime.now(UTC).strftime(UTC_FORMAT),
    }
    approved, _ = _transition_record(ready, ready_raw, "APPROVED")
    approved["gates"]["github_approval_status"] = "PASS"
    approved["gates"]["hcp_approval_status"] = "PASS"
    approved_raw = _canonical_bytes(approved)
    approved_sha = hashlib.sha256(approved_raw).hexdigest()
    validate_record(approved_raw, (approved_sha + "\n").encode("ascii"), previous=ready_raw)
    approved_dir = Path(os.environ["W12_APPROVED_DIR"])
    _write_workflow_pair(approved_dir, "release-record", approved_raw)
    evidence = _canonical_bytes(
        {
            "schema_version": "w12-001.approval-evidence.v1",
            "transition": "READY_FOR_OWNER_TO_APPROVED",
            "record_id": ready["record_id"],
            "from_revision": 2,
            "to_revision": 3,
            "parent_record_sha256": hashlib.sha256(ready_raw).hexdigest(),
            "github_approval": github_evidence,
            "hcp_authenticated_resource": identity,
            "hcp_apply": apply_evidence,
            "observed_at_utc": datetime.now(UTC).strftime(UTC_FORMAT),
        }
    )
    _write_new_pair(
        approved_dir / "transition-evidence.json",
        approved_dir / "transition-evidence.sha256",
        evidence,
    )
    _append_workflow_output({"approved_record_sha256": approved_sha})
    deadline = time.monotonic() + _config()["hcp_apply_deadline_seconds"]
    final = post
    while final.get("attributes", {}).get("status") not in (
        "applied",
        "errored",
        "canceled",
        "discarded",
    ):
        if time.monotonic() >= deadline:
            raise ReleaseError("HCP_APPLY_DEADLINE", "INDETERMINATE")
        time.sleep(10)
        final = _hcp_run(ready, tf["run_id"], token)
        if not _hcp_relationships_match(pre, final):
            raise ReleaseError("HCP_RUN_REPLACED_DURING_APPLY")
    if final.get("attributes", {}).get("status") != "applied":
        raise ReleaseError("HCP_APPLY_FAILED")
    final_apply = final.get("relationships", {}).get("apply", {}).get("data", {})
    if (
        not isinstance(final_apply, dict)
        or not final_apply.get("id")
        or apply_id not in (None, final_apply["id"])
    ):
        raise ReleaseError("HCP_APPLY_ID_CHANGED")
    state_status, state_response = _hcp_request(
        "GET", f"/workspaces/{workspace['id']}/current-state-version", token
    )
    state = state_response.get("data") if isinstance(state_response, dict) else None
    if (
        state_status != 200
        or not isinstance(state, dict)
        or not state.get("id")
        or state["id"] == tf["input_state_version_id"]
    ):
        raise ReleaseError("HCP_APPLIED_STATE_MISSING", "INDETERMINATE")
    state, output_state_lineage, output_state_serial = _hcp_state_identity(
        state["id"], token, state=state
    )
    initial = _empty_input_state(
        tf["input_state_version_id"], tf["state_lineage"], tf["input_state_serial"]
    )
    if not initial and (
        output_state_lineage != tf["state_lineage"]
        or output_state_serial <= tf["input_state_serial"]
    ):
        raise ReleaseError("HCP_APPLIED_STATE_LINEAGE")
    output_names = (
        "opensearch_domain_arn",
        "opensearch_https_endpoint",
        "bedrock_inference_profile_arn",
    )
    outputs = {name: _hcp_output_value(state["id"], name) for name in output_names}
    render = {
        "schema_version": _config()["render_input_schema_version"],
        "ready_record_sha256": hashlib.sha256(ready_raw).hexdigest(),
        "approved_record_sha256": approved_sha,
        "source_archive_sha256": ready["source"]["archive_sha256"],
        "w6_release_hashes_sha256": ready["deployment"]["w6_release_hashes_sha256"],
        "hcp_organization": tf["organization"],
        "hcp_workspace": tf["workspace"],
        "hcp_run_id": tf["run_id"],
        "hcp_plan_id": tf["plan_id"],
        "applied_state_version_id": state["id"],
        "state_lineage": output_state_lineage,
        "state_serial": output_state_serial,
        "aws_account_id": ready["deployment"]["account_id"],
        "aws_region": ready["deployment"]["region"],
        "environment": ready["deployment"]["environment"],
        "application_image": application_image_from_ready(ready),
        "otel_collector_image": ready["artifacts"]["otel_collector_image"],
        "opensearch_domain_arn": outputs["opensearch_domain_arn"],
        "opensearch_https_endpoint": outputs["opensearch_https_endpoint"],
        "bedrock_inference_profile_arn": outputs["bedrock_inference_profile_arn"],
        "release_binding_sha256": approved_sha,
        "created_at_utc": datetime.now(UTC).strftime(UTC_FORMAT),
        "expires_at_utc": (datetime.now(UTC) + timedelta(hours=2)).strftime(UTC_FORMAT),
    }
    render_raw = _canonical_bytes(render)
    render_sha = hashlib.sha256(render_raw).hexdigest()
    validate_render_inputs(
        render_raw,
        (render_sha + "\n").encode("ascii"),
        ready=ready,
        ready_sha256=hashlib.sha256(ready_raw).hexdigest(),
        approved=approved,
        approved_sha256=approved_sha,
    )
    applied, _ = _transition_record(approved, approved_raw, "APPLIED")
    applied["deployment"]["render_inputs_sha256"] = render_sha
    applied_raw = _canonical_bytes(applied)
    applied_sha = hashlib.sha256(applied_raw).hexdigest()
    validate_record(applied_raw, (applied_sha + "\n").encode("ascii"), previous=approved_raw)
    validate_render_inputs(
        render_raw,
        (render_sha + "\n").encode("ascii"),
        ready=ready,
        ready_sha256=hashlib.sha256(ready_raw).hexdigest(),
        approved=approved,
        approved_sha256=approved_sha,
        applied=applied,
    )
    applied_dir = Path(os.environ["W12_APPLIED_DIR"])
    _write_workflow_pair(applied_dir, "release-record", applied_raw)
    _write_new_pair(
        applied_dir / "w12-render-inputs.json", applied_dir / "w12-render-inputs.sha256", render_raw
    )
    applied_evidence = _canonical_bytes(
        {
            "schema_version": "w12-001.applied-evidence.v1",
            "record_id": ready["record_id"],
            "from_revision": 3,
            "to_revision": 4,
            "parent_record_sha256": approved_sha,
            "hcp_run_id": tf["run_id"],
            "hcp_plan_id": tf["plan_id"],
            "hcp_apply_id": final_apply["id"],
            "input_state_version_id": tf["input_state_version_id"],
            "output_state_version_id": state["id"],
            "output_state_lineage": output_state_lineage,
            "output_state_serial": output_state_serial,
            "render_inputs_sha256": render_sha,
            "observed_at_utc": datetime.now(UTC).strftime(UTC_FORMAT),
        }
    )
    _write_new_pair(
        applied_dir / "transition-evidence.json",
        applied_dir / "transition-evidence.sha256",
        applied_evidence,
    )
    _append_workflow_output({"applied_record_sha256": applied_sha})


def workflow_cleanup_transitions() -> None:
    temporary = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    for name in ("W12_APPROVED_DIR", "W12_APPLIED_DIR"):
        value = os.environ.get(name, "")
        if value:
            target = Path(value).resolve(strict=False)
            if temporary not in target.parents or target.name not in (
                "w12-approved",
                "w12-applied",
            ):
                raise ReleaseError("TRANSITION_CLEANUP_BOUNDARY")
            if target.exists():
                shutil.rmtree(target)


def _workflow_chain_from_artifacts() -> tuple[
    list[dict[str, Any]], list[bytes], list[dict[str, Any]], dict[str, bytes]
]:
    run_id = int(os.environ["GITHUB_RUN_ID"])
    token = _github_token()
    specifications = (
        (
            "REQUESTED",
            "W12_REQUESTED",
            {
                "release-record.json",
                "release-record.sha256",
                "opa-receipt.json",
                "opa-receipt.sha256",
            },
        ),
        (
            "READY_FOR_OWNER",
            "W12_READY",
            {
                "release-record.json",
                "release-record.sha256",
                "transition-evidence.json",
                "transition-evidence.sha256",
            },
        ),
        (
            "APPROVED",
            "W12_APPROVED",
            {
                "release-record.json",
                "release-record.sha256",
                "transition-evidence.json",
                "transition-evidence.sha256",
            },
        ),
        (
            "APPLIED",
            "W12_APPLIED",
            {
                "release-record.json",
                "release-record.sha256",
                "transition-evidence.json",
                "transition-evidence.sha256",
                "w12-render-inputs.json",
                "w12-render-inputs.sha256",
            },
        ),
    )
    records: list[dict[str, Any]] = []
    raws: list[bytes] = []
    identities: list[dict[str, Any]] = []
    applied_files: dict[str, bytes] = {}
    for revision, (status, prefix, expected) in enumerate(specifications, start=1):
        id_string = os.environ.get(prefix + "_ARTIFACT_ID", "")
        artifact_digest = os.environ.get(prefix + "_ARTIFACT_DIGEST", "")
        if (
            not id_string.isdecimal()
            or int(id_string) <= 0
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", artifact_digest)
        ):
            raise ReleaseError("RELEASE_ARTIFACT_IDENTITY_INCOMPLETE", "INDETERMINATE")
        artifact_id = int(id_string)
        files, metadata = _github_artifact_files(artifact_id, run_id, token, expected)
        if metadata["digest"] != artifact_digest:
            raise ReleaseError("RELEASE_ARTIFACT_CONTAINER_CHANGED")
        raw = files["release-record.json"]
        record = validate_record(
            raw, files["release-record.sha256"], previous=raws[-1] if raws else None
        )
        expected_name = (
            f"w12-001-{status.lower().replace('_', '-')}-{record['record_id']}-r{revision}"
        )
        if revision == 1:
            expected_name = f"w12-001-requested-{record['record_id']}-r1"
        if (
            metadata.get("name") != expected_name
            or record["status"] != status
            or record["revision"] != revision
            or (records and record["record_id"] != records[0]["record_id"])
        ):
            raise ReleaseError("RELEASE_ARTIFACT_NAME_OR_CHAIN")
        named_digest = "W12_RECORD_SHA256" if revision == 1 else prefix + "_RECORD_SHA256"
        if hashlib.sha256(raw).hexdigest() != os.environ.get(named_digest):
            raise ReleaseError("RELEASE_RECORD_OUTPUT_DIGEST_CHANGED")
        if revision == 1:
            validate_opa_receipt(
                files["opa-receipt.json"],
                files["opa-receipt.sha256"],
                record=record,
                record_sha256=hashlib.sha256(raw).hexdigest(),
            )
        else:
            evidence = files["transition-evidence.json"]
            if files["transition-evidence.sha256"] != (
                hashlib.sha256(evidence).hexdigest() + "\n"
            ).encode("ascii"):
                raise ReleaseError("TRANSITION_EVIDENCE_SIDECAR_MISMATCH")
            transition = _canonical_document(
                evidence,
                fields=(
                    [
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
                    ]
                    if revision == 2
                    else _config()["approval_evidence_fields"]
                    if revision == 3
                    else [
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
                    ]
                ),
                code="TRANSITION_EVIDENCE",
            )
            if (
                transition["record_id"] != record["record_id"]
                or transition["from_revision"] != revision - 1
                or transition["to_revision"] != revision
                or transition["parent_record_sha256"] != record["previous_record_sha256"]
            ):
                raise ReleaseError("TRANSITION_EVIDENCE_CHAIN")
        records.append(record)
        raws.append(raw)
        identities.append(
            {
                "revision": revision,
                "status": status,
                "record_sha256": hashlib.sha256(raw).hexdigest(),
                "artifact_id": artifact_id,
                "artifact_digest": artifact_digest,
            }
        )
        if revision == 4:
            applied_files = files
    validate_render_inputs(
        applied_files["w12-render-inputs.json"],
        applied_files["w12-render-inputs.sha256"],
        ready=records[1],
        ready_sha256=identities[1]["record_sha256"],
        approved=records[2],
        approved_sha256=identities[2]["record_sha256"],
        applied=records[3],
    )
    return records, raws, identities, applied_files


def workflow_validate_applied() -> None:
    records, raws, _, files = _workflow_chain_from_artifacts()
    directory = Path(os.environ["W12_APPLIED_DIR"])
    if any((directory / name).read_bytes() != contents for name, contents in files.items()):
        raise ReleaseError("APPLIED_DOWNLOADED_BYTES_CHANGED")
    if (
        records[3]["status"] != "APPLIED"
        or hashlib.sha256(raws[3]).hexdigest() != os.environ["W12_APPLIED_RECORD_SHA256"]
    ):
        raise ReleaseError("APPLIED_RECORD_NOT_BOUND")


def _s3_result_version(
    client: Any, *, bucket: str, key: str, expected_metadata: dict[str, str], kms_key_arn: str
) -> tuple[str, str, bytes]:
    response = client.list_object_versions(Bucket=bucket, Prefix=key)
    if response.get("IsTruncated") is True:
        raise ReleaseError("RESULT_VERSION_LOOKUP_INCOMPLETE", "INDETERMINATE")
    versions = [item for item in response.get("Versions", []) if item.get("Key") == key]
    if len(versions) != 1:
        raise ReleaseError("RESULT_VERSION_AMBIGUOUS", "INDETERMINATE")
    version = versions[0].get("VersionId")
    if not isinstance(version, str) or not version or version == "null":
        raise ReleaseError("RESULT_VERSION_MISSING", "INDETERMINATE")
    head = client.head_object(Bucket=bucket, Key=key, VersionId=version, ChecksumMode="ENABLED")
    if (
        head.get("VersionId") != version
        or head.get("ServerSideEncryption") != "aws:kms"
        or head.get("SSEKMSKeyId") != kms_key_arn
    ):
        raise ReleaseError("RESULT_KMS_OR_VERSION_CHANGED", "INDETERMINATE")
    metadata = head.get("Metadata", {})
    if any(metadata.get(name) != value for name, value in expected_metadata.items()):
        raise ReleaseError("RESULT_METADATA_MISMATCH")
    digest = metadata.get("result-sha256") or metadata.get("archive-sha256")
    if not _hex(digest, required=True) or head.get("ChecksumSHA256") != base64.b64encode(
        bytes.fromhex(digest)
    ).decode("ascii"):
        raise ReleaseError("RESULT_FULL_CHECKSUM_MISMATCH")
    return version, digest, _s3_read_exact(client, bucket, key, version, digest)


def validate_codebuild_result(
    raw: bytes,
    *,
    applied: dict[str, Any],
    applied_sha256: str,
    build_id: str,
    source_version: str,
    control_version: str,
    control_sha256: str,
    handoff_sha256: str,
) -> dict[str, Any]:
    result = _canonical_document(
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
    for field, names in (
        ("build", ["project_name", "build_id", "build_arn", "build_number"]),
        (
            "inputs",
            [
                "primary_source_version_id",
                "control_source_version_id",
                "source_archive_sha256",
                "control_archive_sha256",
                "applied_record_sha256",
                "source_manifest_sha256",
                "codebuild_handoff_sha256",
                "image_digest",
                "hcp_run_id",
            ],
        ),
        ("deployment", ["namespace", "workload", "derivative_manifest_sha256", "rollout_status"]),
        ("probe", ["job_name", "status", "evidence_sha256"]),
        ("cleanup", ["job_deleted", "pod_absent"]),
    ):
        _fields(result[field], names, "CODEBUILD_RESULT_" + field.upper())
    if (
        result["schema_version"] != "w12-001.codebuild-result.v1"
        or result["record_id"] != applied["record_id"]
        or result["record_revision"] != 4
        or result["operation"] != applied["operation"]
        or result["status"] != "PASS"
    ):
        raise ReleaseError("CODEBUILD_RESULT_IDENTITY_OR_STATUS")
    _utc(result["observed_at_utc"])
    build = result["build"]
    if (
        build["project_name"] != "enterprise-ai-capstone-deploy"
        or build["build_id"] != build_id
        or type(build["build_number"]) is not int
        or build["build_number"] <= 0
        or not isinstance(build["build_arn"], str)
        or not build["build_arn"].endswith(":build/" + build_id)
    ):
        raise ReleaseError("CODEBUILD_RESULT_BUILD_IDENTITY")
    inputs = result["inputs"]
    expected = {
        "primary_source_version_id": source_version,
        "control_source_version_id": control_version,
        "source_archive_sha256": applied["source"]["archive_sha256"],
        "control_archive_sha256": control_sha256,
        "applied_record_sha256": applied_sha256,
        "codebuild_handoff_sha256": handoff_sha256,
        "image_digest": applied["artifacts"]["image_digest"],
        "hcp_run_id": applied["terraform"]["run_id"],
    }
    if any(inputs[name] != value for name, value in expected.items()) or not _hex(
        inputs["source_manifest_sha256"], required=True
    ):
        raise ReleaseError("CODEBUILD_RESULT_INPUT_BINDING")
    deploy = result["deployment"]
    probe = result["probe"]
    if (
        deploy["namespace"] != "enterprise-ai-sandbox"
        or deploy["workload"] != "enterprise-ai-api"
        or deploy["rollout_status"] != "PASS"
        or not _hex(deploy["derivative_manifest_sha256"], required=True)
        or probe["job_name"] != "enterprise-ai-capstone-probe"
        or probe["status"] != "PASS"
        or not _hex(probe["evidence_sha256"], required=True)
        or result["cleanup"] != {"job_deleted": True, "pod_absent": True}
    ):
        raise ReleaseError("CODEBUILD_RESULT_GATES_NOT_PASS")
    if SENSITIVE.search(raw.decode("utf-8")) or any(
        term in raw.lower()
        for term in (b"private key", b"raw_plan", b"raw_state", b"model_prompt", b"model_response")
    ):
        raise ReleaseError("CODEBUILD_RESULT_CONFIDENTIAL_CONTENT")
    return result


def workflow_codebuild() -> None:
    import boto3

    records, raws, identities, applied_files = _workflow_chain_from_artifacts()
    requested, ready, approved, applied = records
    bucket = applied["source"]["s3_bucket"]
    if bucket != os.environ.get("W12_SOURCE_BUCKET"):
        raise ReleaseError("CODEBUILD_BUCKET_OWNER_BINDING")
    requested_id, ready_id, approved_id = (item["artifact_id"] for item in identities[:3])
    token = _github_token()
    run_id = int(os.environ["GITHUB_RUN_ID"])
    requested_files, _ = _github_artifact_files(
        requested_id,
        run_id,
        token,
        {"release-record.json", "release-record.sha256", "opa-receipt.json", "opa-receipt.sha256"},
    )
    ready_files, _ = _github_artifact_files(
        ready_id,
        run_id,
        token,
        {
            "release-record.json",
            "release-record.sha256",
            "transition-evidence.json",
            "transition-evidence.sha256",
        },
    )
    approved_files, _ = _github_artifact_files(
        approved_id,
        run_id,
        token,
        {
            "release-record.json",
            "release-record.sha256",
            "transition-evidence.json",
            "transition-evidence.sha256",
        },
    )
    source_manifest = next(
        (item for item in ready["evidence"] if item["kind"] == "w12_source_manifest"), None
    )
    if source_manifest is None:
        raise ReleaseError("SOURCE_MANIFEST_EVIDENCE_MISSING")
    source_sha = source_manifest["sha256"]
    source_client = _s3_client()
    primary_bytes = _s3_read_exact(
        source_client,
        bucket,
        SOURCE_KEY,
        ready["source"]["s3_version_id"],
        ready["source"]["archive_sha256"],
    )
    primary_files = validate_primary_source_bundle(
        primary_bytes,
        archive_sha256=ready["source"]["archive_sha256"],
        manifest_sha256=source_sha,
        w6_sha256=ready["deployment"]["w6_release_hashes_sha256"],
        commit=ready["source"]["commit"],
        tree=ready["source"]["tree"],
    )
    transition_raw = applied_files["transition-evidence.json"]
    transition = _canonical_document(
        transition_raw,
        fields=[
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
        code="APPLIED_EVIDENCE",
    )
    render = validate_render_inputs(
        applied_files["w12-render-inputs.json"],
        applied_files["w12-render-inputs.sha256"],
        ready=ready,
        ready_sha256=identities[1]["record_sha256"],
        approved=approved,
        approved_sha256=identities[2]["record_sha256"],
        applied=applied,
    )
    if (
        transition["output_state_version_id"] != render["applied_state_version_id"]
        or transition["output_state_lineage"] != render["state_lineage"]
        or transition["output_state_serial"] != render["state_serial"]
        or transition["render_inputs_sha256"] != applied["deployment"]["render_inputs_sha256"]
    ):
        raise ReleaseError("APPLIED_OUTPUT_STATE_BINDING")
    handoff = {
        "schema_version": "w12-001.codebuild-handoff.v2",
        "record_id": applied["record_id"],
        "operation": applied["operation"],
        "workflow_run_id": run_id,
        "primary_source": {
            "bucket": bucket,
            "key": SOURCE_KEY,
            "version_id": applied["source"]["s3_version_id"],
            "object_sha256": applied["source"]["archive_sha256"],
            "manifest_sha256": source_sha,
            "commit": applied["source"]["commit"],
            "tree": applied["source"]["tree"],
        },
        "records": identities,
        "w6_release": {"release_hashes_sha256": ready["deployment"]["w6_release_hashes_sha256"]},
        "artifacts": {"image_digest": application_image_from_ready(ready)},
        "terraform": {
            "organization": ready["terraform"]["organization"],
            "workspace": ready["terraform"]["workspace"],
            "run_id": ready["terraform"]["run_id"],
            "plan_id": ready["terraform"]["plan_id"],
            "input_state_version_id": ready["terraform"]["input_state_version_id"],
            "input_state_lineage": ready["terraform"]["state_lineage"],
            "input_state_serial": ready["terraform"]["input_state_serial"],
            "output_state_version_id": transition["output_state_version_id"],
            "output_state_lineage": transition["output_state_lineage"],
            "output_state_serial": transition["output_state_serial"],
        },
        "created_at_utc": datetime.now(UTC).strftime(UTC_FORMAT),
    }
    kms_key = os.environ.get("W12_RELEASE_KMS_KEY_ARN", "")
    if not kms_key.startswith(
        f"arn:aws:kms:{_config()['aws_region']}:{applied['deployment']['account_id']}:key/"
    ):
        raise ReleaseError("CONTROL_KMS_KEY_IDENTITY")
    control_files = {
        "release-record.json": raws[3],
        "release-record.sha256": (identities[3]["record_sha256"] + "\n").encode("ascii"),
        "w12-render-inputs.json": applied_files["w12-render-inputs.json"],
        "w12-render-inputs.sha256": applied_files["w12-render-inputs.sha256"],
    }
    if applied["operation"] == "rollback":
        prior_files, prior_records, _, prior_render = load_prior_rollback_lineage(
            requested,
            client=source_client,
            kms_key_arn=kms_key,
        )
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
            raise ReleaseError("ROLLBACK_APPLIED_TARGET_IDENTITY_CHANGED", "INDETERMINATE")
        control_files.update(prior_files)
    for revision, files in ((1, requested_files), (2, ready_files), (3, approved_files)):
        for name in ("release-record.json", "release-record.sha256"):
            control_files[f"records/r{revision}/{name}"] = files[name]
    for revision, files in ((2, ready_files), (3, approved_files), (4, applied_files)):
        for name in ("transition-evidence.json", "transition-evidence.sha256"):
            control_files[f"records/r{revision}/{name}"] = files[name]
    handoff["files"] = _file_inventory(control_files)
    handoff_raw = _canonical_bytes(handoff)
    handoff_sha = hashlib.sha256(handoff_raw).hexdigest()
    control_files["codebuild-handoff.json"] = handoff_raw
    control_files["codebuild-handoff.sha256"] = (handoff_sha + "\n").encode("ascii")
    if len(control_files) != (24 if applied["operation"] == "rollback" else 18):
        raise ReleaseError("CONTROL_BUNDLE_OPERATION_INVENTORY")
    control_raw = _make_zip(control_files)
    control_sha = hashlib.sha256(control_raw).hexdigest()
    version = _s3_upload_exact(
        source_client,
        bucket=bucket,
        key=CONTROL_KEY,
        raw=control_raw,
        kms_key=kms_key,
        metadata={
            "record-id": applied["record_id"],
            "record-revision": "4",
            "source-commit": applied["source"]["commit"],
            "archive-sha256": control_sha,
            "record-sha256": identities[3]["record_sha256"],
        },
    )
    if (
        _zip_files(_s3_read_exact(source_client, bucket, CONTROL_KEY, version, control_sha))
        != control_files
    ):
        raise ReleaseError("CONTROL_BUNDLE_READBACK_MISMATCH")
    account = boto3.client("sts").get_caller_identity().get("Account")
    if account != applied["deployment"]["account_id"]:
        raise ReleaseError("CODEBUILD_CALLER_ACCOUNT_MISMATCH")
    override_values = {
        "W12_RECORD_SHA256": identities[3]["record_sha256"],
        "W12_SOURCE_VERSION_ID": applied["source"]["s3_version_id"],
        "W12_CONTROL_VERSION_ID": version,
        "W12_SOURCE_ARCHIVE_SHA256": applied["source"]["archive_sha256"],
        "W12_CONTROL_ARCHIVE_SHA256": control_sha,
        "W12_SOURCE_MANIFEST_SHA256": source_sha,
        "W12_RELEASE_KMS_KEY_ARN": kms_key,
        "W12_CODEBUILD_HANDOFF_SHA256": handoff_sha,
        "W12_GIT_COMMIT": applied["source"]["commit"],
        "W12_IMAGE_DIGEST": applied["artifacts"]["image_digest"],
        "W12_HCP_RUN_ID": applied["terraform"]["run_id"],
        "W12_OPERATION": applied["operation"],
    }
    request = {
        "projectName": "enterprise-ai-capstone-deploy",
        "sourceVersion": applied["source"]["s3_version_id"],
        "secondarySourcesVersionOverride": [
            {"sourceIdentifier": "W12_CONTROL", "sourceVersion": version}
        ],
        "environmentVariablesOverride": [
            {"name": name, "value": value, "type": "PLAINTEXT"}
            for name, value in override_values.items()
        ],
        "idempotencyToken": hashlib.sha256(
            f"{applied['record_id']}:4:{applied['operation']}:{version}".encode()
        ).hexdigest(),
    }
    client = boto3.client("codebuild", region_name=_config()["aws_region"])
    try:
        started = client.start_build(**request)["build"]
    except Exception as exc:
        raise ReleaseError("CODEBUILD_START_AMBIGUOUS", "INDETERMINATE") from exc
    build_id = started.get("id")
    build_arn = started.get("arn")
    if (
        not isinstance(build_id, str)
        or not re.fullmatch(r"enterprise-ai-capstone-deploy:[0-9a-f-]{36}", build_id)
        or build_arn != f"arn:aws:codebuild:{_config()['aws_region']}:{account}:build/{build_id}"
    ):
        raise ReleaseError("CODEBUILD_START_IDENTITY_AMBIGUOUS", "INDETERMINATE")
    uuid_part = build_id.split(":", 1)[1]
    deadline = (
        time.monotonic()
        + (
            _config()["codebuild_queue_timeout_minutes"]
            + _config()["codebuild_build_timeout_minutes"]
        )
        * 60
    )
    while True:
        response = client.batch_get_builds(ids=[build_id])
        builds = response.get("builds", [])
        if len(builds) != 1:
            raise ReleaseError("CODEBUILD_BUILD_NOT_INSPECTABLE", "INDETERMINATE")
        build = builds[0]
        secondary = build.get("secondarySourcesVersion", [])
        if (
            build.get("id") != build_id
            or build.get("arn") != build_arn
            or build.get("projectName") != request["projectName"]
            or build.get("sourceVersion") != request["sourceVersion"]
            or secondary != request["secondarySourcesVersionOverride"]
        ):
            raise ReleaseError("CODEBUILD_SOURCE_VERSION_SUBSTITUTION", "INDETERMINATE")
        status = build.get("buildStatus")
        if status == "SUCCEEDED":
            break
        if status in ("FAILED", "FAULT", "STOPPED", "TIMED_OUT"):
            raise ReleaseError("CODEBUILD_BUILD_FAILED")
        if time.monotonic() >= deadline:
            raise ReleaseError("CODEBUILD_BUILD_DEADLINE", "INDETERMINATE")
        time.sleep(10)
    prefix = f"w12-001/results/{applied['record_id']}/r4/{uuid_part}/"
    result_key = prefix + "codebuild-result.json"
    archive_key = prefix + "w12-rendered-release.zip"
    result_version, result_sha, result_raw = _s3_result_version(
        source_client,
        bucket=bucket,
        key=result_key,
        kms_key_arn=kms_key,
        expected_metadata={
            "record-id": applied["record_id"],
            "record-revision": "4",
            "build-uuid": uuid_part,
            "record-sha256": identities[3]["record_sha256"],
        },
    )
    result = validate_codebuild_result(
        result_raw,
        applied=applied,
        applied_sha256=identities[3]["record_sha256"],
        build_id=build_id,
        source_version=applied["source"]["s3_version_id"],
        control_version=version,
        control_sha256=control_sha,
        handoff_sha256=handoff_sha,
    )
    archive_version, archive_sha, archive_raw = _s3_result_version(
        source_client,
        bucket=bucket,
        key=archive_key,
        kms_key_arn=kms_key,
        expected_metadata={
            "record-id": applied["record_id"],
            "record-revision": "4",
            "build-uuid": uuid_part,
            "record-sha256": identities[3]["record_sha256"],
        },
    )
    archive_files = _zip_files(archive_raw)
    inventory_raw = archive_files.pop("w12-rendered-release.json")
    inventory_sidecar = archive_files.pop("w12-rendered-release.sha256")
    validate_rendered_release(
        inventory_raw,
        inventory_sidecar,
        archive_files=archive_files,
        ready_sha256=identities[1]["record_sha256"],
        approved_sha256=identities[2]["record_sha256"],
        applied_sha256=identities[3]["record_sha256"],
        source_sha256=applied["source"]["archive_sha256"],
        w6_sha256=ready["deployment"]["w6_release_hashes_sha256"],
        render_inputs_sha256=applied["deployment"]["render_inputs_sha256"],
        renderer_sha256=hashlib.sha256(primary_files["tools/w6_001_k8s.py"]).hexdigest(),
    )
    if (
        hashlib.sha256(inventory_raw).hexdigest()
        != result["deployment"]["derivative_manifest_sha256"]
    ):
        raise ReleaseError("CODEBUILD_RENDERED_INVENTORY_CHANGED")
    result_dir = Path(os.environ["W12_RESULT_DIR"])
    _write_workflow_pair(result_dir, "codebuild-result", result_raw)
    _append_workflow_output(
        {
            "codebuild_build_id": build_id,
            "codebuild_build_arn": build_arn,
            "derivative_manifest_sha256": result["deployment"]["derivative_manifest_sha256"],
            "result_locator": encode_s3v_locator(bucket, result_key, result_version),
            "result_sha256": result_sha,
            "rendered_archive_locator": encode_s3v_locator(bucket, archive_key, archive_version),
            "rendered_archive_sha256": archive_sha,
            "control_version_id": version,
            "control_archive_sha256": control_sha,
            "codebuild_handoff_sha256": handoff_sha,
        }
    )


def workflow_verify() -> None:
    records, raws, identities, applied_files = _workflow_chain_from_artifacts()
    applied = records[3]
    local_applied = Path(os.environ["W12_APPLIED_DIR"])
    if any((local_applied / name).read_bytes() != raw for name, raw in applied_files.items()):
        raise ReleaseError("VERIFY_APPLIED_DOWNLOAD_CHANGED")
    result_id = os.environ.get("W12_RESULT_ARTIFACT_ID", "")
    if not result_id.isdecimal() or int(result_id) <= 0:
        raise ReleaseError("VERIFY_RESULT_ARTIFACT_ID")
    files, metadata = _github_artifact_files(
        int(result_id),
        int(os.environ["GITHUB_RUN_ID"]),
        _github_token(),
        {"codebuild-result.json"},
    )
    if (
        metadata["digest"] != os.environ.get("W12_RESULT_ARTIFACT_DIGEST")
        or metadata.get("name") != f"w12-001-codebuild-{applied['record_id']}-r4"
    ):
        raise ReleaseError("VERIFY_RESULT_ARTIFACT_MISMATCH")
    raw = files["codebuild-result.json"]
    if raw != (
        Path(os.environ["W12_RESULT_DIR"]) / "codebuild-result.json"
    ).read_bytes() or hashlib.sha256(raw).hexdigest() != os.environ.get("W12_RESULT_SHA256"):
        raise ReleaseError("VERIFY_RESULT_BYTES_MISMATCH")
    result = validate_codebuild_result(
        raw,
        applied=applied,
        applied_sha256=identities[3]["record_sha256"],
        build_id=os.environ["W12_CODEBUILD_BUILD_ID"],
        source_version=applied["source"]["s3_version_id"],
        control_version=os.environ["W12_CONTROL_VERSION_ID"],
        control_sha256=os.environ["W12_CONTROL_ARCHIVE_SHA256"],
        handoff_sha256=os.environ["W12_CODEBUILD_HANDOFF_SHA256"],
    )
    if result["build"]["build_arn"] != os.environ["W12_CODEBUILD_BUILD_ARN"]:
        raise ReleaseError("VERIFY_BUILD_ARN_MISMATCH")
    bucket = applied["source"]["s3_bucket"]
    uuid_part = result["build"]["build_id"].split(":", 1)[1]
    prefix = f"w12-001/results/{applied['record_id']}/r4/{uuid_part}/"
    locator_expectations = (
        ("W12_RESULT_LOCATOR", prefix + "codebuild-result.json"),
        ("W12_RENDERED_ARCHIVE_LOCATOR", prefix + "w12-rendered-release.zip"),
    )
    for name, key in locator_expectations:
        locator = decode_s3v_locator(os.environ.get(name, ""))
        if (
            locator["bucket"] != bucket
            or locator["key"] != key
            or locator["entry"] is not None
            or not locator["version_id"]
        ):
            raise ReleaseError("VERIFY_RESULT_LOCATOR_MISMATCH")
    if not _hex(os.environ.get("W12_RENDERED_ARCHIVE_SHA256"), required=True) or result[
        "deployment"
    ]["derivative_manifest_sha256"] != os.environ.get("W12_DERIVATIVE_MANIFEST_SHA256"):
        raise ReleaseError("VERIFY_RENDERED_DIGEST_MISMATCH")
    kms_key = os.environ.get("W12_RELEASE_KMS_KEY_ARN", "")
    if not kms_key.startswith(
        f"arn:aws:kms:{_config()['aws_region']}:{applied['deployment']['account_id']}:key/"
    ):
        raise ReleaseError("VERIFIED_PUBLICATION_KMS_IDENTITY")
    client = _s3_client()
    transition = _canonical_bytes(
        {
            "schema_version": "w12-001.verified-evidence.v1",
            "record_id": applied["record_id"],
            "from_revision": 4,
            "to_revision": 5,
            "parent_record_sha256": identities[3]["record_sha256"],
            "control_bundle_version_id": os.environ["W12_CONTROL_VERSION_ID"],
            "control_bundle_sha256": os.environ["W12_CONTROL_ARCHIVE_SHA256"],
            "codebuild_handoff_sha256": os.environ["W12_CODEBUILD_HANDOFF_SHA256"],
            "codebuild_build_id": result["build"]["build_id"],
            "codebuild_build_arn": result["build"]["build_arn"],
            "primary_source_version_id": result["inputs"]["primary_source_version_id"],
            "control_source_version_id": result["inputs"]["control_source_version_id"],
            "codebuild_result_sha256": os.environ["W12_RESULT_SHA256"],
            "rendered_archive_sha256": os.environ["W12_RENDERED_ARCHIVE_SHA256"],
            "derivative_manifest_sha256": result["deployment"]["derivative_manifest_sha256"],
            "deployment_status": "PASS",
            "probe_status": "PASS",
            "slo_status": "INSUFFICIENT_DATA",
            "rollback_status": "NOT_RUN",
            "teardown_status": "NOT_RUN",
            "observed_at_utc": datetime.now(UTC).strftime(UTC_FORMAT),
        }
    )
    requested_files, _ = _github_artifact_files(
        identities[0]["artifact_id"],
        int(os.environ["GITHUB_RUN_ID"]),
        _github_token(),
        {"release-record.json", "release-record.sha256", "opa-receipt.json", "opa-receipt.sha256"},
    )
    receipt_raw = requested_files["opa-receipt.json"]
    if requested_files["opa-receipt.sha256"] != (
        hashlib.sha256(receipt_raw).hexdigest() + "\n"
    ).encode("ascii"):
        raise ReleaseError("VERIFIED_OPA_RECEIPT_SIDECAR")
    validate_opa_receipt(
        receipt_raw,
        requested_files["opa-receipt.sha256"],
        record=records[0],
        record_sha256=identities[0]["record_sha256"],
    )
    published_pre_r5 = {}
    for kind, raw, content_type in (
        ("opa_receipt", receipt_raw, "application/json"),
        ("opa_receipt_sidecar", requested_files["opa-receipt.sha256"], "text/plain"),
        ("verified_transition", transition, "application/json"),
        (
            "verified_transition_sidecar",
            (hashlib.sha256(transition).hexdigest() + "\n").encode("ascii"),
            "text/plain",
        ),
    ):
        published_pre_r5[kind] = _publish_bound_object(
            client,
            bucket=bucket,
            key=_release_publication_key(applied["record_id"], kind),
            raw=raw,
            kms_key=kms_key,
            record_id=applied["record_id"],
            revision=5,
            content_type=content_type,
        )
    verified, _ = _transition_record(applied, raws[3], "VERIFIED")
    verified["deployment"]["derivative_manifest_sha256"] = result["deployment"][
        "derivative_manifest_sha256"
    ]
    verified["evidence"] = sorted(
        applied["evidence"]
        + [
            {
                "kind": "codebuild-control-bundle",
                "uri": encode_s3v_locator(
                    bucket,
                    CONTROL_KEY,
                    os.environ["W12_CONTROL_VERSION_ID"],
                    entry="codebuild-handoff.json",
                ),
                "sha256": os.environ["W12_CONTROL_ARCHIVE_SHA256"],
            },
            {
                "kind": "codebuild_result",
                "uri": os.environ["W12_RESULT_LOCATOR"],
                "sha256": os.environ["W12_RESULT_SHA256"],
            },
            {
                "kind": "rendered_release_archive",
                "uri": os.environ["W12_RENDERED_ARCHIVE_LOCATOR"],
                "sha256": os.environ["W12_RENDERED_ARCHIVE_SHA256"],
            },
            *(
                {
                    "kind": kind,
                    "uri": encode_s3v_locator(bucket, item["key"], item["version_id"]),
                    "sha256": item["sha256"],
                }
                for kind, item in published_pre_r5.items()
            ),
        ],
        key=lambda item: (item["kind"], item["uri"]),
    )
    verified_raw = _canonical_bytes(verified)
    verified_sha = hashlib.sha256(verified_raw).hexdigest()
    validate_record(verified_raw, (verified_sha + "\n").encode("ascii"), previous=raws[3])
    directory = Path(os.environ["W12_VERIFIED_DIR"])
    _write_workflow_pair(directory, "release-record", verified_raw)
    _write_new_pair(
        directory / "transition-evidence.json", directory / "transition-evidence.sha256", transition
    )
    chain_raws = [*raws, verified_raw]
    published_r5, published_lineage, lineage_raw = publish_verified_pair_and_lineage(
        client,
        bucket=bucket,
        kms_key=kms_key,
        chain_raws=chain_raws,
    )
    lineage_sha = hashlib.sha256(lineage_raw).hexdigest()
    selector = _canonical_bytes(
        {
            "schema_version": _config()["publication_selector_schema_version"],
            "record_id": verified["record_id"],
            "operation": verified["operation"],
            "account_id": verified["deployment"]["account_id"],
            "region": _config()["aws_region"],
            "verified_record_sha256": verified_sha,
            "record_object": published_r5["verified_record"],
            "sidecar_object": published_r5["verified_sidecar"],
            "lineage_object": published_lineage,
        }
    )
    validate_publication_selector(
        selector, verified=verified, verified_sha256=verified_sha, lineage_sha256=lineage_sha
    )
    proof_root = directory / "proof-root"
    if proof_root.exists():
        raise ReleaseError("PUBLICATION_PROOF_ROOT_EXISTS")
    proof_root.mkdir(mode=0o700)
    for index, raw in enumerate(chain_raws, start=1):
        pair = proof_root / f"records/r{index}"
        pair.mkdir(mode=0o700, parents=True, exist_ok=False)
        _write_new_pair(pair / "release-record.json", pair / "release-record.sha256", raw)
    with (proof_root / "publication-selector.json").open("xb") as output:
        os.fchmod(output.fileno(), 0o600)
        output.write(selector)
        output.flush()
        os.fsync(output.fileno())


def workflow_publish() -> None:
    """Emit bounded job outcomes without upgrading a skipped or failed gate."""
    names = (
        "W12_PREFLIGHT_STATUS",
        "W12_RECEIPT_STATUS",
        "W12_BUILD_STATUS",
        "W12_READY_STATUS",
        "W12_APPLY_STATUS",
        "W12_DEPLOY_STATUS",
        "W12_VERIFY_STATUS",
    )
    outcomes = {
        name.removeprefix("W12_").removesuffix("_STATUS").lower(): os.environ.get(name, "unknown")
        for name in names
    }
    if any(
        value not in ("success", "failure", "cancelled", "skipped") for value in outcomes.values()
    ):
        classification = "INDETERMINATE"
    elif all(value == "success" for value in outcomes.values()):
        classification = "WORKFLOW_STAGES_SUCCEEDED"
    else:
        classification = "NOT_VERIFIED"
    output = {
        "schema_version": "w12-001.workflow-status.v1",
        "classification": classification,
        "workflow_run_id": os.environ.get("GITHUB_RUN_ID"),
        "record_sha256": os.environ.get("W12_RECORD_SHA256") or None,
        "requested_artifact_id": os.environ.get("W12_RECORD_ARTIFACT_ID") or None,
        "requested_artifact_digest": os.environ.get("W12_RECORD_ARTIFACT_DIGEST") or None,
        "jobs": outcomes,
    }
    print(json.dumps(output, separators=(",", ":")))


def _github_artifact_metadata(artifact_id: int, run_id: int, token: str) -> dict[str, Any]:
    if type(artifact_id) is not int or artifact_id <= 0 or type(run_id) is not int or run_id <= 0:
        raise ReleaseError("ARTIFACT_IDENTITY")
    status, response = _github_request("GET", f"/actions/artifacts/{artifact_id}", token)
    if (
        status != 200
        or not isinstance(response, dict)
        or response.get("id") != artifact_id
        or response.get("expired") is not False
        or response.get("workflow_run", {}).get("id") != run_id
    ):
        raise ReleaseError("FOREIGN_OR_EXPIRED_ARTIFACT")
    container_digest = response.get("digest")
    if not isinstance(container_digest, str) or not re.fullmatch(
        r"sha256:[0-9a-f]{64}", container_digest
    ):
        raise ReleaseError("ARTIFACT_CONTAINER_DIGEST_MISSING", "INDETERMINATE")
    return response


def _github_artifact_files(
    artifact_id: int, run_id: int, token: str, expected: set[str]
) -> tuple[dict[str, bytes], dict[str, Any]]:
    metadata = _github_artifact_metadata(artifact_id, run_id, token)

    class NoCredentialRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(
            self,
            request: urllib.request.Request,
            fp: Any,
            code: int,
            msg: str,
            headers: Any,
            newurl: str,
        ) -> urllib.request.Request | None:
            target = urllib.parse.urlsplit(newurl)
            host = target.hostname or ""
            if (
                target.scheme != "https"
                or not (
                    host == "api.github.com"
                    or host.endswith(".actions.githubusercontent.com")
                    or host.endswith(".blob.core.windows.net")
                )
                or target.username
                or target.password
            ):
                raise ReleaseError("ARTIFACT_REDIRECT_HOST")
            return urllib.request.Request(  # noqa: S310 -- HTTPS host checked; no credential forwarded
                newurl, method="GET"
            )

    request = urllib.request.Request(
        f"https://api.github.com/repos/{GITHUB_REPOSITORY}/actions/artifacts/{artifact_id}/zip",
        headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": _config()["github_api_version"],
        },
        method="GET",
    )
    try:
        with urllib.request.build_opener(NoCredentialRedirect()).open(
            request, timeout=_config()["github_read_timeout_seconds"]
        ) as response:
            artifact_limit = (
                1_048_576 if expected == {"build-summary.json", "signature.bundle"} else 196_608
            )
            blob = response.read(artifact_limit + 1)
    except (urllib.error.URLError, TimeoutError) as exc:
        raise ReleaseError("ARTIFACT_DOWNLOAD", "INDETERMINATE") from exc
    if len(blob) > artifact_limit or hashlib.sha256(blob).hexdigest() != metadata["digest"][7:]:
        raise ReleaseError("ARTIFACT_CONTAINER_CHANGED")
    try:
        with zipfile.ZipFile(io.BytesIO(blob)) as archive:
            if set(archive.namelist()) != expected or len(archive.namelist()) != len(expected):
                raise ReleaseError("ARTIFACT_CONTENTS")
            file_limit = (
                524_288 if expected == {"build-summary.json", "signature.bundle"} else 65_536
            )
            if any(item.file_size > file_limit for item in archive.infolist()):
                raise ReleaseError("ARTIFACT_FILE_OVERSIZE")
            files = {name: archive.read(name) for name in expected}
    except zipfile.BadZipFile as exc:
        raise ReleaseError("ARTIFACT_INVALID") from exc
    return files, metadata


def _hcp_request(
    method: str, path: str, token: str, body: dict[str, Any] | None = None
) -> tuple[int, Any]:
    payload = None if body is None else json.dumps(body, separators=(",", ":")).encode()
    request = urllib.request.Request(
        "https://app.terraform.io/api/v2" + path,
        data=payload,
        method=method,
        headers={"Authorization": "Bearer " + token, "Content-Type": "application/vnd.api+json"},
    )
    try:
        with urllib.request.build_opener(_NoApiRedirect()).open(request, timeout=20) as response:
            data = response.read(5_000_001)
            if len(data) > 5_000_000:
                raise ReleaseError("HCP_RESPONSE_TOO_LARGE", "INDETERMINATE")
            return response.status, json.loads(data) if data else None
    except urllib.error.HTTPError as exc:
        raise ReleaseError(
            "HCP_HTTP_" + str(exc.code), "INDETERMINATE" if exc.code >= 500 else "FAIL"
        ) from None
    except (urllib.error.URLError, TimeoutError) as exc:
        raise ReleaseError("HCP_TRANSPORT", "INDETERMINATE") from exc


def _hcp_plan_json_bytes(plan_id: str, token: str) -> bytes:
    """Retain the exact plan JSON octets and never forward the token on redirect."""
    if not re.fullmatch(r"plan-[A-Za-z0-9]+", plan_id):
        raise ReleaseError("HCP_PLAN_ID")

    class NoCredentialRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(
            self,
            request: urllib.request.Request,
            fp: Any,
            code: int,
            msg: str,
            headers: Any,
            newurl: str,
        ) -> urllib.request.Request | None:
            target = urllib.parse.urlsplit(newurl)
            if (
                target.scheme != "https"
                or target.hostname not in {"app.terraform.io", "archivist.terraform.io"}
                or target.username
                or target.password
            ):
                raise ReleaseError("HCP_PLAN_REDIRECT_HOST")
            return urllib.request.Request(  # noqa: S310 -- HTTPS host checked; no credential forwarded
                newurl, method="GET", headers={"Accept": "application/json"}
            )

    request = urllib.request.Request(
        f"https://app.terraform.io/api/v2/plans/{plan_id}/json-output",
        method="GET",
        headers={"Authorization": "Bearer " + token, "Accept": "application/json"},
    )
    try:
        with urllib.request.build_opener(NoCredentialRedirect()).open(
            request, timeout=20
        ) as response:
            if response.status != 200 or urllib.parse.urlsplit(response.url).hostname not in {
                "app.terraform.io",
                "archivist.terraform.io",
            }:
                raise ReleaseError("HCP_PLAN_JSON_RESPONSE")
            raw = response.read(20_000_001)
    except urllib.error.HTTPError as exc:
        raise ReleaseError(
            "HCP_PLAN_HTTP_" + str(exc.code), "INDETERMINATE" if exc.code >= 500 else "FAIL"
        ) from None
    except (urllib.error.URLError, TimeoutError) as exc:
        raise ReleaseError("HCP_PLAN_TRANSPORT", "INDETERMINATE") from exc
    if not isinstance(raw, bytes) or not raw or len(raw) > 20_000_000:
        raise ReleaseError("HCP_PLAN_JSON_OVERSIZE")
    return raw


def _hcp_state_identity(
    state_id: str, token: str, *, state: dict[str, Any] | None = None
) -> tuple[dict[str, Any], str, int]:
    """Resolve exact state lineage/serial without retaining raw state material."""
    if not re.fullmatch(r"sv-[A-Za-z0-9]+", state_id):
        raise ReleaseError("HCP_STATE_VERSION_ID")
    fetched_exact = False
    if state is None or state.get("id") != state_id:
        status, response = _hcp_request("GET", f"/state-versions/{state_id}", token)
        state = response.get("data") if isinstance(response, dict) else None
        if status != 200 or not isinstance(state, dict) or state.get("id") != state_id:
            raise ReleaseError("HCP_STATE_VERSION_UNAVAILABLE", "INDETERMINATE")
        fetched_exact = True
    attributes = state.get("attributes", {})
    lineage, serial = attributes.get("lineage"), attributes.get("serial")
    if _text(lineage) and type(serial) is int and serial >= 0:
        return state, lineage, serial

    hosted_url = attributes.get("hosted-state-download-url")
    if not isinstance(hosted_url, str) and not fetched_exact:
        status, response = _hcp_request("GET", f"/state-versions/{state_id}", token)
        exact = response.get("data") if isinstance(response, dict) else None
        if status != 200 or not isinstance(exact, dict) or exact.get("id") != state_id:
            raise ReleaseError("HCP_STATE_VERSION_UNAVAILABLE", "INDETERMINATE")
        state = exact
        attributes = state.get("attributes", {})
        lineage, serial = attributes.get("lineage"), attributes.get("serial")
        if _text(lineage) and type(serial) is int and serial >= 0:
            return state, lineage, serial
        hosted_url = attributes.get("hosted-state-download-url")
    if not isinstance(hosted_url, str):
        raise ReleaseError("HCP_STATE_LINEAGE_UNAVAILABLE", "INDETERMINATE")
    target = urllib.parse.urlsplit(hosted_url)
    if (
        target.scheme != "https"
        or target.hostname not in {"app.terraform.io", "archivist.terraform.io"}
        or target.username
        or target.password
        or target.fragment
    ):
        raise ReleaseError("HCP_STATE_DOWNLOAD_HOST")

    class NoCredentialRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(
            self,
            request: urllib.request.Request,
            fp: Any,
            code: int,
            msg: str,
            headers: Any,
            newurl: str,
        ) -> urllib.request.Request | None:
            redirect = urllib.parse.urlsplit(newurl)
            if (
                redirect.scheme != "https"
                or redirect.hostname not in {"app.terraform.io", "archivist.terraform.io"}
                or redirect.username
                or redirect.password
                or redirect.fragment
            ):
                raise ReleaseError("HCP_STATE_REDIRECT_HOST")
            return urllib.request.Request(  # noqa: S310 -- bounded HTTPS host; no credential
                newurl, method="GET", headers={"Accept": "application/json"}
            )

    request_headers = {"Accept": "application/json"}
    if target.hostname == "app.terraform.io":
        request_headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(  # noqa: S310 -- exact HCP-provided HTTPS URL validated above
        hosted_url, method="GET", headers=request_headers
    )
    try:
        with urllib.request.build_opener(NoCredentialRedirect()).open(
            request, timeout=20
        ) as response:
            final = urllib.parse.urlsplit(response.url)
            if response.status != 200 or final.hostname not in {
                "app.terraform.io",
                "archivist.terraform.io",
            }:
                raise ReleaseError("HCP_STATE_DOWNLOAD_RESPONSE", "INDETERMINATE")
            raw = response.read(100_000_001)
    except urllib.error.HTTPError as exc:
        raise ReleaseError(
            "HCP_STATE_HTTP_" + str(exc.code),
            "INDETERMINATE" if exc.code >= 500 else "FAIL",
        ) from None
    except (urllib.error.URLError, TimeoutError) as exc:
        raise ReleaseError("HCP_STATE_TRANSPORT", "INDETERMINATE") from exc
    if not isinstance(raw, bytes) or not raw or len(raw) > 100_000_000:
        raise ReleaseError("HCP_STATE_DOCUMENT_OVERSIZE", "INDETERMINATE")
    try:
        document = json.loads(raw, object_pairs_hook=_unique_pairs, parse_constant=_reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseError("HCP_STATE_DOCUMENT_INVALID", "INDETERMINATE") from exc
    if not isinstance(document, dict):
        raise ReleaseError("HCP_STATE_DOCUMENT_INVALID", "INDETERMINATE")
    resolved_lineage, resolved_serial = document.get("lineage"), document.get("serial")
    if (
        not _text(resolved_lineage)
        or type(resolved_serial) is not int
        or resolved_serial < 0
        or (type(serial) is int and serial != resolved_serial)
    ):
        raise ReleaseError("HCP_STATE_DOCUMENT_IDENTITY_MISMATCH", "INDETERMINATE")
    return state, cast(str, resolved_lineage), resolved_serial


def _hcp_token() -> str:
    token = os.environ.get("TFC_TOKEN", "")
    if not token:
        raise ReleaseError("TFC_TOKEN_REQUIRED")
    return token


def _hcp_run(record: dict[str, Any], run_id: str, token: str) -> dict[str, Any]:
    if not re.fullmatch(r"run-[A-Za-z0-9]+", run_id):
        raise ReleaseError("HCP_RUN_ID")
    _, response = _hcp_request("GET", f"/runs/{run_id}?include=plan,configuration_version", token)
    run = response.get("data") if isinstance(response, dict) else None
    if not isinstance(run, dict) or run.get("id") != run_id:
        raise ReleaseError("HCP_RUN_MISMATCH")
    attrs = run.get("attributes", {})
    relationships = run.get("relationships", {})
    workspace = relationships.get("workspace", {}).get("data", {}).get("id")
    if record["terraform"]["run_id"] not in (None, run_id) or not workspace:
        raise ReleaseError("HCP_RUN_OR_WORKSPACE_MISMATCH")
    if (
        attrs.get("plan-only") is not False
        or attrs.get("save-plan") is not False
        or ("is-speculative" in attrs and attrs["is-speculative"] is not False)
    ):
        raise ReleaseError("HCP_SPECULATIVE_RUN")
    return run


def _hcp_vcs_binding(record: dict[str, Any], run: dict[str, Any], token: str) -> None:
    """Require the owner-reviewed VCS workspace and exact ingress commit."""
    tf = record["terraform"]
    status, response = _hcp_request(
        "GET",
        f"/organizations/{urllib.parse.quote(tf['organization'], safe='')}/workspaces/"
        f"{urllib.parse.quote(tf['workspace'], safe='')}",
        token,
    )
    workspace = response.get("data") if isinstance(response, dict) else None
    if status != 200 or not isinstance(workspace, dict) or not workspace.get("id"):
        raise ReleaseError("HCP_WORKSPACE_UNAVAILABLE", "INDETERMINATE")
    attrs = workspace.get("attributes", {})
    vcs = attrs.get("vcs-repo", {})
    project_id = workspace.get("relationships", {}).get("project", {}).get("data", {}).get("id")
    if (
        attrs.get("name") != tf["workspace"]
        or attrs.get("auto-apply") is not False
        or attrs.get("execution-mode") != "remote"
        or attrs.get("working-directory") != "infra/environments/sandbox"
        or not isinstance(vcs, dict)
        or vcs.get("identifier") != GITHUB_REPOSITORY
        or vcs.get("branch") not in (None, "main")
        or not project_id
        or run.get("relationships", {}).get("workspace", {}).get("data", {}).get("id")
        != workspace["id"]
    ):
        raise ReleaseError("HCP_WORKSPACE_VCS_BINDING")
    project_status, project_response = _hcp_request("GET", f"/projects/{project_id}", token)
    project = project_response.get("data") if isinstance(project_response, dict) else None
    if (
        project_status != 200
        or not isinstance(project, dict)
        or project.get("id") != project_id
        or project.get("attributes", {}).get("name") != tf["project"]
    ):
        raise ReleaseError("HCP_PROJECT_BINDING")
    config_id = (
        run.get("relationships", {}).get("configuration-version", {}).get("data") or {}
    ).get("id")
    if not isinstance(config_id, str) or tf["configuration_version_id"] not in (
        None,
        config_id,
    ):
        raise ReleaseError("HCP_CONFIGURATION_VERSION_BINDING")
    config_status, config_response = _hcp_request(
        "GET",
        f"/configuration-versions/{config_id}?include=ingress_attributes",
        token,
    )
    config = config_response.get("data") if isinstance(config_response, dict) else None
    ingress_ref = (
        config.get("relationships", {}).get("ingress-attributes", {}).get("data", {})
        if isinstance(config, dict)
        else {}
    )
    included = config_response.get("included", []) if isinstance(config_response, dict) else []
    matches = [
        item
        for item in included
        if isinstance(item, dict)
        and item.get("id") == ingress_ref.get("id")
        and item.get("type") == ingress_ref.get("type")
    ]
    if (
        config_status != 200
        or not isinstance(config, dict)
        or config.get("id") != config_id
        or config.get("attributes", {}).get("source") not in ("tfe-vcs", "github")
        or len(matches) != 1
        or matches[0].get("attributes", {}).get("commit-sha") != record["source"]["commit"]
    ):
        raise ReleaseError("HCP_CONFIGURATION_COMMIT_BINDING")


def _hcp_initial_state_empty(record: dict[str, Any], workspace_id: str, token: str) -> None:
    """Prove the initial-state representation without requesting raw state."""
    tf = record["terraform"]
    path = (
        "/state-versions?filter%5Bworkspace%5D%5Bname%5D="
        + urllib.parse.quote(tf["workspace"], safe="")
        + "&filter%5Borganization%5D%5Bname%5D="
        + urllib.parse.quote(tf["organization"], safe="")
        + "&page%5Bsize%5D=1"
    )
    status, response = _hcp_request("GET", path, token)
    data = response.get("data") if isinstance(response, dict) else None
    if status != 200 or not isinstance(data, list) or data:
        raise ReleaseError("HCP_INITIAL_STATE_NOT_EMPTY")
    workspace_status, workspace_response = _hcp_request("GET", f"/workspaces/{workspace_id}", token)
    workspace = workspace_response.get("data") if isinstance(workspace_response, dict) else None
    current = (
        workspace.get("relationships", {}).get("current-state-version", {}).get("data")
        if isinstance(workspace, dict)
        else None
    )
    if (
        workspace_status != 200
        or not isinstance(workspace, dict)
        or workspace.get("id") != workspace_id
        or current is not None
    ):
        raise ReleaseError("HCP_INITIAL_CURRENT_STATE_PRESENT")


def _hcp_infracost_binding(workspace_id: str, task_result: dict[str, Any], token: str) -> None:
    """Match the passing result to the one configured post-plan workspace task."""
    attrs = task_result.get("attributes", {})
    status, response = _hcp_request("GET", f"/workspaces/{workspace_id}/tasks", token)
    bindings = response.get("data") if isinstance(response, dict) else None
    if (
        status != 200
        or not isinstance(bindings, list)
        or response.get("links", {}).get("next") is not None
    ):
        raise ReleaseError("INFRACOST_BINDING_UNAVAILABLE")
    matches = [
        item
        for item in bindings
        if isinstance(item, dict)
        and item.get("id") == attrs.get("workspace-task-id")
        and (item.get("relationships", {}).get("task", {}).get("data") or {}).get("id")
        == attrs.get("task-id")
        and (item.get("relationships", {}).get("workspace", {}).get("data") or {}).get("id")
        == workspace_id
        and item.get("attributes", {}).get("stages") == ["post_plan"]
    ]
    if len(matches) != 1 or attrs.get("task-name") != "Infracost":
        raise ReleaseError("INFRACOST_WORKSPACE_TASK_MISMATCH")


def _hcp_apply_not_started(run: dict[str, Any], token: str) -> None:
    """A pending apply object may exist before anyone confirms the run."""
    apply_id = (run.get("relationships", {}).get("apply", {}).get("data") or {}).get("id")
    if apply_id is None:
        return
    status, response = _hcp_request("GET", f"/applies/{apply_id}", token)
    apply = response.get("data") if isinstance(response, dict) else None
    attrs = apply.get("attributes", {}) if isinstance(apply, dict) else {}
    timestamps = attrs.get("status-timestamps", {})
    if (
        status != 200
        or not isinstance(apply, dict)
        or apply.get("id") != apply_id
        or attrs.get("status") != "pending"
        or not isinstance(timestamps, dict)
        or timestamps.get("queued-at") is not None
        or timestamps.get("started-at") is not None
    ):
        raise ReleaseError("HCP_APPLY_ALREADY_STARTED")


def _hcp_plan_is_zero_change(plan: dict[str, Any]) -> bool:
    """Recognize only a complete plan with no infrastructure, output, or action changes."""

    resource_changes = plan.get("resource_changes")
    if not isinstance(resource_changes, list):
        return False
    for entry in resource_changes:
        if (
            not isinstance(entry, dict)
            or not isinstance(entry.get("change"), dict)
            or entry["change"].get("actions") != ["no-op"]
        ):
            return False

    resource_drift = plan.get("resource_drift", [])
    if not isinstance(resource_drift, list):
        return False
    for entry in resource_drift:
        if (
            not isinstance(entry, dict)
            or not isinstance(entry.get("change"), dict)
            or entry["change"].get("actions") != ["no-op"]
        ):
            return False

    output_changes = plan.get("output_changes", {})
    if not isinstance(output_changes, dict):
        return False
    for change in output_changes.values():
        if not isinstance(change, dict) or change.get("actions") != ["no-op"]:
            return False

    deferred_changes = plan.get("deferred_changes", [])
    action_invocations = plan.get("action_invocations", [])
    return (
        isinstance(deferred_changes, list)
        and isinstance(action_invocations, list)
        and not deferred_changes
        and not action_invocations
    )


def _review_plan(args: argparse.Namespace) -> dict[str, Any]:
    _, record, digest = _read_record(args, requested=True)
    configuration_sha = validate_terraform_configuration_binding(record)
    tf = record["terraform"]
    if tf["run_id"] not in (None, args.run_id):
        raise ReleaseError("REQUESTED_HCP_RUN_MISMATCH")
    token = _hcp_token()
    run = _hcp_run(record, args.run_id, token)
    _hcp_vcs_binding(record, run, token)
    run_attrs = run.get("attributes", {})
    run_status = run_attrs.get("status")
    if run_attrs.get("auto-apply") is not False or run_status not in {
        "post_plan_completed",
        "planned_and_finished",
    }:
        raise ReleaseError("HCP_RUN_APPLY_UNSAFE")
    _hcp_apply_not_started(run, token)
    relationships = run["relationships"]
    plan_id = (relationships.get("plan", {}).get("data") or {}).get("id")
    state_id = (relationships.get("input-state-version", {}).get("data") or {}).get("id")
    config_id = (relationships.get("configuration-version", {}).get("data") or {}).get("id")
    if (
        not isinstance(plan_id, str)
        or not isinstance(config_id, str)
        or tf["plan_id"] not in (None, plan_id)
        or tf["configuration_version_id"] not in (None, config_id)
        or tf["input_state_version_id"] not in (None, state_id)
        or _empty_input_state(
            tf["input_state_version_id"], tf["state_lineage"], tf["input_state_serial"]
        )
        != (state_id is None)
    ):
        raise ReleaseError("HCP_PLAN_CONFIG_OR_STATE_MISMATCH")
    if state_id is None:
        if record["operation"] != "deploy" or not _empty_input_state(
            tf["input_state_version_id"], tf["state_lineage"], tf["input_state_serial"]
        ):
            raise ReleaseError("HCP_INITIAL_STATE_BINDING")
        _hcp_initial_state_empty(record, relationships["workspace"]["data"]["id"], token)
        state_lineage = None
        state_serial = None
    else:
        state, state_lineage, state_serial = _hcp_state_identity(state_id, token)
        if (
            state.get("id") != state_id
            or _empty_input_state(state_id, state_lineage, state_serial)
            or (tf["state_lineage"], tf["input_state_serial"])
            not in (
                (None, None),
                (state_lineage, state_serial),
            )
        ):
            raise ReleaseError("HCP_STATE_LINEAGE_OR_SERIAL_MISMATCH")
    _, plan = _hcp_request("GET", f"/plans/{plan_id}", token)
    if (
        plan.get("data", {}).get("id") != plan_id
        or plan.get("data", {}).get("attributes", {}).get("status") != "finished"
    ):
        raise ReleaseError("HCP_PLAN_UNFINISHED", "INDETERMINATE")
    plan_raw = _hcp_plan_json_bytes(plan_id, token)
    try:
        plan_json = json.loads(
            plan_raw, object_pairs_hook=_unique_pairs, parse_constant=_reject_constant
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseError("HCP_PLAN_JSON_INVALID") from exc
    if not isinstance(plan_json, dict) or not isinstance(plan_json.get("resource_changes"), list):
        raise ReleaseError("HCP_PLAN_JSON_INCOMPLETE")
    if run_status == "planned_and_finished" and not _hcp_plan_is_zero_change(plan_json):
        raise ReleaseError("HCP_FINAL_RUN_NOT_ZERO_CHANGE")
    plan_sha = hashlib.sha256(plan_raw).hexdigest()
    _, stages = _hcp_request("GET", f"/runs/{args.run_id}/task-stages", token)
    entries = stages.get("data", []) if isinstance(stages, dict) else []
    post_plan = [s for s in entries if s.get("attributes", {}).get("stage") == "post_plan"]
    if len(post_plan) != 1 or post_plan[0].get("attributes", {}).get("status") != "passed":
        raise ReleaseError("INFRACOST_POST_PLAN_NOT_PASSED")
    task_results = post_plan[0].get("relationships", {}).get("task-results", {}).get("data", [])
    if len(task_results) != 1 or not isinstance(task_results[0].get("id"), str):
        raise ReleaseError("INFRACOST_RESULT_AMBIGUOUS")
    task_id = task_results[0]["id"]
    if record["gates"]["run_task_result_id"] not in (None, task_id):
        raise ReleaseError("INFRACOST_RECORD_BINDING")
    _, task = _hcp_request("GET", f"/task-results/{task_id}", token)
    task_attrs = task.get("data", {}).get("attributes", {})
    if (
        task.get("data", {}).get("id") != task_id
        or task_attrs.get("status") != "passed"
        or task_attrs.get("task-name") != "Infracost"
        or task_attrs.get("stage") != "post_plan"
        or task_attrs.get("is-speculative") is not False
        or (
            task.get("data", {}).get("relationships", {}).get("task-stage", {}).get("data") or {}
        ).get("id")
        != post_plan[0].get("id")
    ):
        raise ReleaseError("INFRACOST_RESULT_NOT_PASSED")
    _hcp_infracost_binding(relationships["workspace"]["data"]["id"], task["data"], token)
    from tools.platformctl.policy_runner import (
        capstone_source_commit,
        normalize_plan,
        parse_production_decision,
    )

    executable = Path(args.opa_bin).resolve(strict=True)
    expected_executable_sha = os.environ.get("W12_OPA_EXECUTABLE_SHA256", "")
    if (
        not HEX64.fullmatch(expected_executable_sha)
        or hashlib.sha256(executable.read_bytes()).hexdigest() != expected_executable_sha
    ):
        raise ReleaseError("OPA_EXECUTABLE_IDENTITY_REQUIRED")
    version = subprocess.run(  # noqa: S603 -- owner-bound executable path and digest
        [str(executable), "version"], capture_output=True, text=True, timeout=60, check=False
    )
    if version.returncode != 0 or version.stdout.splitlines()[:1] != ["Version: 1.20.0"]:
        raise ReleaseError("OPA_VERSION_MISMATCH")
    policy_path = ROOT / "policies/opa/terraform_plan.rego"
    exceptions_path = ROOT / "policies/opa/exceptions.json"
    policy_sha = hashlib.sha256(policy_path.read_bytes()).hexdigest()
    exceptions_sha = hashlib.sha256(exceptions_path.read_bytes()).hexdigest()
    try:
        exception_registry = json.loads(
            exceptions_path.read_bytes(), object_pairs_hook=_unique_pairs
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ReleaseError("OPA_EXCEPTION_REGISTRY_INVALID") from exc
    if exception_registry != {"schema_version": "w5-003.policy-exceptions.v1", "exceptions": []}:
        raise ReleaseError("OPA_WAIVER_OR_OVERRIDE_PROHIBITED")
    with capstone_source_commit(record["source"]["commit"], record["source"]["tree"]):
        normalized = normalize_plan(
            plan_json, evaluation_time=datetime.now(UTC).strftime(UTC_FORMAT)
        )
    evaluation_context = normalized["evaluation_context"]
    if not isinstance(evaluation_context, dict):
        raise ReleaseError("OPA_EVALUATION_CONTEXT_INVALID")
    evaluation_context["operation"] = {
        "schema_version": "w12-001.plan-review.v1",
        "action": "PLAN_REVIEW",
        "profile": ("INITIAL_EMPTY_STATE" if state_id is None else "RECOVERY_EXISTING_STATE"),
        "record_sha256": digest,
        "source_commit": record["source"]["commit"],
        "source_tree": record["source"]["tree"],
        "configuration_version_id": config_id,
        "run_id": args.run_id,
        "plan_id": plan_id,
        "plan_json_sha256": plan_sha,
        "workspace": tf["workspace"],
        "input_state_version_id": state_id,
    }
    normalized_raw = json.dumps(
        normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    result = subprocess.run(  # noqa: S603 -- owner-bound executable path and digest
        [
            str(executable),
            "eval",
            "--format=json",
            "--stdin-input",
            "--data",
            str(policy_path),
            "--data",
            str(exceptions_path),
            "data.enterprise_ai.terraform.plan.decision",
        ],
        input=normalized_raw,
        capture_output=True,
        timeout=120,
        check=False,
    )
    if result.returncode != 0 or len(result.stdout) > 262_144:
        raise ReleaseError("OPA_EXECUTION_FAILED")
    try:
        decision = parse_production_decision(result.stdout)
    except ValueError as exc:
        raise ReleaseError("OPA_RESULT_INDETERMINATE", "INDETERMINATE") from exc
    if decision["allow"] is not True or decision["findings"]:
        raise ReleaseError("OPA_DENIED")
    if (policy_sha, exceptions_sha) != (
        hashlib.sha256(policy_path.read_bytes()).hexdigest(),
        hashlib.sha256(exceptions_path.read_bytes()).hexdigest(),
    ):
        raise ReleaseError("OPA_SOURCE_CHANGED")
    now = datetime.now(UTC)
    receipt = {
        "schema_version": _config()["opa_receipt_schema_version"],
        "receipt_id": str(uuid.uuid4()),
        "revision": 1,
        "created_at_utc": now.strftime(UTC_FORMAT),
        "expires_at_utc": (
            now + timedelta(seconds=_config()["opa_receipt_validity_seconds"])
        ).strftime(UTC_FORMAT),
        "record_sha256": digest,
        "source": {
            "repository": GITHUB_REPOSITORY,
            "commit": record["source"]["commit"],
            "operation": record["operation"],
        },
        "hcp": {
            "organization": tf["organization"],
            "project": tf["project"],
            "workspace": tf["workspace"],
            "configuration_version_id": config_id,
            "run_id": args.run_id,
            "plan_id": plan_id,
            "input_state_version_id": state_id,
            "state_lineage": state_lineage,
            "state_serial": state_serial,
            "plan_json_sha256": plan_sha,
        },
        "opa": {
            "executable_version": "1.20.0",
            "executable_sha256": expected_executable_sha,
            "package": "enterprise_ai.terraform.plan",
            "decision_entrypoint": "data.enterprise_ai.terraform.plan.decision",
            "policy_sha256": policy_sha,
            "exceptions_sha256": exceptions_sha,
            "result": "PASS",
            "violation_count": 0,
            "waiver_used": False,
            "override_used": False,
        },
        "infracost": {
            "result_id": task_id,
            "status": "PASS",
            "waiver_used": False,
            "override_used": False,
        },
        "evidence": {
            "normalized_plan_sha256": hashlib.sha256(normalized_raw).hexdigest(),
            "opa_output_sha256": hashlib.sha256(result.stdout).hexdigest(),
            "infracost_result_sha256": hashlib.sha256(_canonical_bytes(task)).hexdigest(),
        },
        "decision": "PASS",
    }
    raw = _canonical_bytes(receipt)
    validate_opa_receipt(
        raw,
        (hashlib.sha256(raw).hexdigest() + "\n").encode("ascii"),
        record=record,
        record_sha256=digest,
    )
    receipt_sha = _write_new_pair(Path(args.receipt_output), Path(args.receipt_sha256_file), raw)
    return {
        "record_sha256": digest,
        "configuration_sha256": configuration_sha,
        "receipt_id": receipt["receipt_id"],
        "opa_receipt_sha256": receipt_sha,
        "hcp_run_id": args.run_id,
        "hcp_plan_id": plan_id,
        "status": "PASS",
    }


def _approve(args: argparse.Namespace) -> dict[str, Any]:
    _, record, digest = _read_record(args)
    if args.target != "github" or record["status"] != "READY_FOR_OWNER" or record["revision"] != 2:
        raise ReleaseError("GITHUB_READY_APPROVAL_REQUIRED")
    if not args.environment_id or not args.run_id.isdigit() or not args.ready_artifact_id:
        raise ReleaseError("GITHUB_APPROVAL_ID")
    token = _github_token()
    _, run = _github_request("GET", f"/actions/runs/{args.run_id}", token)
    _valid_run(run, record["source"]["commit"])
    if (
        record["gates"]["github_run_id"] != int(args.run_id)
        or record["gates"]["github_environment_id"] != args.environment_id
    ):
        raise ReleaseError("GITHUB_APPROVAL_RECORD_MISMATCH")
    artifact = _github_artifact_metadata(args.ready_artifact_id, int(args.run_id), token)
    if artifact.get("name") != f"w12-001-ready-for-owner-{record['record_id']}-r2":
        raise ReleaseError("GITHUB_READY_ARTIFACT_MISMATCH")
    files, _ = _github_artifact_files(
        args.ready_artifact_id,
        int(args.run_id),
        token,
        {
            "release-record.json",
            "release-record.sha256",
            "transition-evidence.json",
            "transition-evidence.sha256",
        },
    )
    if (
        files["release-record.json"] != Path(args.record).read_bytes()
        or files["release-record.sha256"] != Path(args.sha256_file).read_bytes()
    ):
        raise ReleaseError("GITHUB_READY_BYTES_MISMATCH")
    transition_raw = files["transition-evidence.json"]
    if files["transition-evidence.sha256"] != (
        hashlib.sha256(transition_raw).hexdigest() + "\n"
    ).encode("ascii"):
        raise ReleaseError("GITHUB_READY_TRANSITION_DIGEST")
    transition = _canonical_document(
        transition_raw,
        fields=[
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
        code="READY_EVIDENCE",
    )
    if (
        transition["schema_version"] != "w12-001.ready-evidence.v1"
        or transition["record_id"] != record["record_id"]
        or transition["parent_record_sha256"] != record["previous_record_sha256"]
    ):
        raise ReleaseError("GITHUB_READY_TRANSITION_MISMATCH")
    _, pending = _github_request("GET", f"/actions/runs/{args.run_id}/pending_deployments", token)
    if (
        not isinstance(pending, list)
        or len(pending) != 1
        or pending[0].get("environment", {}).get("id") != args.environment_id
        or pending[0].get("environment", {}).get("name") != "sandbox"
    ):
        raise ReleaseError("GITHUB_PENDING_DEPLOYMENT_MISMATCH")
    comment = (
        f"W12-001 APPROVE record={record['record_id']} revision=2 "
        f"ready_sha256={digest} run_id={args.run_id}"
    )
    try:
        status, response = _github_request(
            "POST",
            f"/actions/runs/{args.run_id}/pending_deployments",
            token,
            {"environment_ids": [args.environment_id], "state": "approved", "comment": comment},
        )
    except ReleaseError as exc:
        if exc.code.startswith("GITHUB_TRANSPORT") or exc.classification == "INDETERMINATE":
            raise ReleaseError("GITHUB_APPROVAL_AMBIGUOUS", "INDETERMINATE") from exc
        raise
    if status not in (200, 201, 202) or not isinstance(response, list):
        raise ReleaseError("GITHUB_APPROVAL_AMBIGUOUS", "INDETERMINATE")
    deployment_ids: list[int] = []
    for item in response:
        if isinstance(item, dict) and type(item.get("id")) is int and item["id"] > 0:
            deployment_ids.append(cast(int, item["id"]))
    deployment_ids.sort()
    if not deployment_ids or len(deployment_ids) != len(response):
        raise ReleaseError("GITHUB_APPROVAL_RESPONSE_AMBIGUOUS", "INDETERMINATE")
    return {
        "record_id": record["record_id"],
        "revision": 2,
        "ready_record_sha256": digest,
        "workflow_run_id": int(args.run_id),
        "environment_id": args.environment_id,
        "deployment_ids": deployment_ids,
        "state": "APPROVAL_SUBMITTED",
    }


def _watch(args: argparse.Namespace) -> dict[str, Any]:
    _, record, digest = _read_record(args)
    if args.target == "github":
        _, item = _github_request("GET", f"/actions/runs/{int(args.id)}", _github_token())
        _valid_run(item, record["source"]["commit"])
        state = item.get("conclusion") or item.get("status")
    elif args.target == "hcp":
        state = _hcp_run(record, args.id, _hcp_token())["attributes"]["status"]
    else:
        raise ReleaseError("CODEBUILD_WATCH_REQUIRES_OWNER_AWS_CONTEXT", "INDETERMINATE")
    return {
        "target": args.target,
        "id": args.id,
        "status": state,
        "observed_at_utc": datetime.now(UTC).strftime(UTC_FORMAT),
        "record_sha256": digest,
    }


def _cancel(args: argparse.Namespace) -> dict[str, Any]:
    _, record, digest = _read_record(args)
    if args.target == "github":
        _, run = _github_request("GET", f"/actions/runs/{int(args.id)}", _github_token())
        _valid_run(run, record["source"]["commit"])
        status, _ = _github_request("POST", f"/actions/runs/{int(args.id)}/cancel", _github_token())
    elif args.target == "hcp":
        _hcp_run(record, args.id, _hcp_token())
        status, _ = _hcp_request("POST", f"/runs/{args.id}/actions/cancel", _hcp_token())
    else:
        raise ReleaseError("CODEBUILD_CANCEL_REQUIRES_OWNER_AWS_CONTEXT", "INDETERMINATE")
    if status not in (200, 202, 204):
        raise ReleaseError("CANCEL_AMBIGUOUS", "INDETERMINATE")
    return {
        "target": args.target,
        "id": args.id,
        "status": "CANCEL_REQUESTED",
        "record_sha256": digest,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Owner-controlled W12 release gates")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("validate", "trigger", "review-plan", "approve", "watch", "cancel"):
        command = commands.add_parser(name)
        command.add_argument("--record", required=True)
        command.add_argument("--sha256-file", required=True)
        command.add_argument("--previous-record")
        if name == "trigger":
            command.add_argument("--commit", required=True)
            command.add_argument("--opa-receipt", required=True)
            command.add_argument("--opa-receipt-sha256-file", required=True)
        elif name == "review-plan":
            command.add_argument("--run-id", required=True)
            command.add_argument("--opa-bin", required=True)
            command.add_argument("--receipt-output", required=True)
            command.add_argument("--receipt-sha256-file", required=True)
        elif name == "approve":
            command.add_argument("--target", choices=("github",), required=True)
            command.add_argument("--run-id", required=True)
            command.add_argument("--environment-id", type=int)
            command.add_argument("--ready-artifact-id", type=int, required=True)
        elif name in ("watch", "cancel"):
            command.add_argument("--target", choices=("github", "hcp", "codebuild"), required=True)
            command.add_argument("--id", required=True)
            if name == "cancel":
                command.add_argument("--reason", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "validate":
            _, record, digest = _read_record(args)
            result: dict[str, Any] = {
                "schema_version": record["schema_version"],
                "record_id": record["record_id"],
                "revision": record["revision"],
                "status": record["status"],
                "sha256": digest,
                "valid": True,
            }
        elif args.command == "trigger":
            result = _trigger(args)
        elif args.command == "review-plan":
            result = _review_plan(args)
        elif args.command == "approve":
            result = _approve(args)
        elif args.command == "watch":
            result = _watch(args)
        elif args.command == "cancel":
            result = _cancel(args)
        else:
            raise ReleaseError("UNKNOWN_SUBCOMMAND")
    except ReleaseError as exc:
        print(json.dumps({"code": exc.code, "message": exc.classification}), file=sys.stderr)
        return {"FAIL": 4, "INDETERMINATE": 5}.get(exc.classification, 2)
    except (OSError, UnicodeError) as exc:
        del exc
        print('{"code":"INPUT_IO","message":"FAIL"}', file=sys.stderr)
        return 2
    print(json.dumps(result, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
