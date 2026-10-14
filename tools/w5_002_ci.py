"""Deterministic, content-safe W5-002 CI report validation helpers."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
import tarfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import cast

CONFIG_SCHEMA_V1 = "w5-002.ci-config.v1"
CONFIG_SCHEMA = "w5-002.ci-config.v2"
IMAGE_SCHEMA_V1 = "w5-002.image-identity.v1"
IMAGE_SCHEMA = "w5-002.image-identity.v2"
PLAN_SCHEMA = "w5-002.plan-summary.v1"
PROVENANCE_SCHEMA_V1 = "w5-002.provenance.v1"
PROVENANCE_SCHEMA = "w5-002.provenance.v2"
ELIGIBILITY_SCHEMA_V1 = "w5-002.eligibility.v1"
ELIGIBILITY_SCHEMA = "w5-002.eligibility.v2"
ROLLBACK_SCHEMA = "w5-002.rollback-identity.v2"
CLEANUP_SCHEMA = "w5-002.cleanup-retention.v2"
SCAN_SCHEMA = "w5-002.scan-summary.v2"
MAXIMUM_FILE_BYTES = 52_428_800
MAXIMUM_RUN_BYTES = 104_857_600
REPOSITORY = "gprai/enterprize_ai_platform"
REF = "refs/heads/main"
ENVIRONMENT = "sandbox"
PLATFORM = "linux/amd64"
BASE_IMAGE_V1 = (
    "python:3.11.16-slim-bookworm@sha256:"
    "b1add8a6f2aca6bcfcf0b9c9b522352f7ce0d62a3d556a2f2f32511aa0cca250"
)
PYTHON_VERSION = "3.13.15"
PYTHON_REQUIREMENT = ">=3.13,<3.14"
BASELINE_HEAD = "9963f2b24d9c42c03c62b97615fd650ab0eb5bc8"
BASELINE_SOURCE_COMPOSITION = (
    "sha256:c81d465fe06e4d9948fd6ef3e7d65608b34bfaf2c3df5b82dc968daf9f8cbecc"
)
BUILDER_TAG = "cgr.dev/vayunetrix.com/python:3.13.15-dev"
BUILDER_INDEX_DIGEST = "sha256:fb566a1a7663cdf0041186af5484204650d880ee305a4a42cdf92b6c8706a1bd"
BUILDER_MANIFEST_DIGEST = "sha256:023795336613750af2cd86cf06503b5b74370c6a561d2a22219a2e80c6fe4811"
BUILDER_IMAGE = f"{BUILDER_TAG}@{BUILDER_MANIFEST_DIGEST}"
RUNTIME_TAG = "cgr.dev/vayunetrix.com/python:3.13.15"
RUNTIME_INDEX_DIGEST = "sha256:7a212636a3bd38fa184cf1f0ccfe025d683d7f32fd8bad810e437aa351d3b634"
RUNTIME_MANIFEST_DIGEST = "sha256:f7cc453a5d7ac0cf86f585e22b6e404eaa10f69db5d00da50f9940e2806358fa"
RUNTIME_IMAGE = f"{RUNTIME_TAG}@{RUNTIME_MANIFEST_DIGEST}"
BASE_IMAGE = RUNTIME_IMAGE
REPORT_PATHS_V1 = (
    "reports/w5-002/image-identity.json",
    "reports/w5-002/trivy-filesystem.json",
    "reports/w5-002/trivy-image.json",
    "reports/w5-002/grype-image.json",
    "reports/w5-002/sbom.spdx.json",
    "reports/w5-002/sbom.cyclonedx.json",
    "reports/w5-002/provenance.json",
    "reports/w5-002/eligibility.json",
    "reports/w5-002/terraform-plan-summary.json",
)
REPORT_PATHS = (
    *REPORT_PATHS_V1[:-1],
    "reports/w5-002/rollback-identity.json",
    "reports/w5-002/cleanup-retention.json",
    REPORT_PATHS_V1[-1],
)
SUPPLY_CHAIN_NAMES_V1 = tuple(Path(path).name for path in REPORT_PATHS_V1[:-1])
SUPPLY_CHAIN_NAMES = tuple(Path(path).name for path in REPORT_PATHS[:-1])
PLAN_NAMES = (Path(REPORT_PATHS[-1]).name,)
EXPECTED_TOOL_VERSIONS_V1 = {
    "actionlint": "1.7.12",
    "checkov": "3.3.16",
    "grype": "0.118.0",
    "opa": "1.20.0",
    "syft": "1.51.1",
    "terraform": "1.16.1",
    "tflint": "0.60.0",
    "trivy": "0.74.0",
}
EXPECTED_TOOL_VERSIONS = {
    "actionlint": "1.7.12",
    "buildkit": "0.30.0",
    "chainctl": "0.2.346",
    "checkov": "3.3.16",
    "cosign": "3.1.2",
    "docker": "29.7.2",
    "grype": "0.118.0",
    "opa": "1.20.0",
    "python": PYTHON_VERSION,
    "syft": "1.51.1",
    "terraform": "1.16.1",
    "tflint": "0.60.0",
    "trivy": "0.74.0",
    "uv": "0.12.9",
}
SENSITIVE_KEY_PARTS = (
    "access_key",
    "authorization",
    "credential",
    "credentials",
    "environment_dump",
    "password",
    "private_key",
    "provider_response",
    "raw_plan",
    "secret",
    "secrets",
    "session_token",
)
SENSITIVE_VALUE_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)aws_secret_access_key\s*[:=]"),
    re.compile(r"(?i)authorization\s*:\s*bearer\s+\S+"),
)
COMMIT_PATTERN = re.compile(r"[0-9a-f]{40}")
DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
LOCK_REQUIREMENT_PATTERN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s\\]+)(?:\s|\\|$)")
PYTORCH_INDEX_URL = "https://download.pytorch.org/whl/cpu"
FORBIDDEN_LOCK_PACKAGE_PREFIXES = ("cuda", "nvidia", "triton")


class ContractError(ValueError):
    """Raised when a W5-002 input violates its exact contract."""


class ReconciliationStatus(StrEnum):
    PASS = "PASS"  # noqa: S105 - evidence status, not a credential.
    FAIL = "FAIL"
    INDETERMINATE = "INDETERMINATE"


@dataclass(frozen=True)
class VulnerabilityWaiver:
    waiver_id: str
    finding_ids: tuple[str, ...]
    approved_at: datetime
    expires_at: datetime
    approval_sha256: str


@dataclass(frozen=True)
class PurlReconciliation:
    sbom_sha256: str
    sbom_format: str
    trivy_sha256: str
    grype_sha256: str
    publisher_identity: str | None
    advisory_identity: str | None
    package_name: str
    package_version: str
    ecosystem: str
    original_purl: str
    normalized_purl: str
    normalization_reason: str
    coverage_result: ReconciliationStatus
    skipped_package_count: int


def validate_vulnerability_waiver(value: VulnerabilityWaiver, *, now: datetime) -> None:
    if (
        not value.waiver_id
        or not value.finding_ids
        or len(value.finding_ids) != len(set(value.finding_ids))
        or now.tzinfo is None
        or value.approved_at.tzinfo is None
        or value.expires_at.tzinfo is None
        or value.approved_at > now
        or value.expires_at <= now
        or value.expires_at <= value.approved_at
        or re.fullmatch(r"[0-9a-f]{64}", value.approval_sha256) is None
    ):
        raise ContractError("vulnerability waiver is missing, malformed, or expired")


def validate_purl_reconciliation(value: PurlReconciliation) -> ReconciliationStatus:
    from urllib.parse import unquote

    for digest in (value.sbom_sha256, value.trivy_sha256, value.grype_sha256):
        if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise ContractError("PURL reconciliation evidence identity is malformed")
    if value.sbom_format not in {"SPDX", "CycloneDX"}:
        raise ContractError("PURL reconciliation SBOM format differs")
    if value.original_purl != value.normalized_purl and not value.normalization_reason:
        raise ContractError("PURL normalization requires a recorded reason")
    expected_identity = (
        value.ecosystem.casefold(),
        value.package_name.casefold(),
        value.package_version,
    )
    for purl in (value.original_purl, value.normalized_purl):
        match = re.fullmatch(r"pkg:([^/]+)/([^@]+)@([^?#]+)(?:[?#].*)?", purl)
        if (
            match is None
            or (
                unquote(match.group(1)).casefold(),
                unquote(match.group(2)).casefold(),
                unquote(match.group(3)),
            )
            != expected_identity
        ):
            raise ContractError("PURL normalization changed package semantics")
    if value.skipped_package_count < 0:
        raise ContractError("skipped-package count is invalid")
    if value.skipped_package_count or value.coverage_result is ReconciliationStatus.INDETERMINATE:
        return ReconciliationStatus.INDETERMINATE
    return value.coverage_result


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _validate_finite(value: object, location: str = "$") -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise ContractError(f"non-finite number at {location}")
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ContractError(f"non-string key at {location}")
            _validate_finite(item, f"{location}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _validate_finite(item, f"{location}[{index}]")


def canonical_json(value: object) -> str:
    """Serialize JSON deterministically with one final newline."""
    _validate_finite(value)
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    )


def load_json(path: Path) -> object:
    """Load strict UTF-8 JSON while rejecting duplicate keys and a BOM."""
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ContractError(f"cannot read {path.name}") from exc
    if len(raw) > MAXIMUM_FILE_BYTES:
        raise ContractError(f"report exceeds maximum size: {path.name}")
    if raw.startswith(b"\xef\xbb\xbf"):
        raise ContractError(f"UTF-8 BOM is prohibited: {path.name}")
    try:
        text = raw.decode("utf-8")
        value = cast(
            object,
            json.loads(text, object_pairs_hook=_reject_duplicate_keys),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContractError(f"invalid JSON: {path.name}") from exc
    _validate_finite(value)
    return value


def write_json(path: Path, value: object) -> None:
    """Write one canonical JSON file without following a pre-existing symlink."""
    if path.is_symlink():
        raise ContractError(f"refusing symlink output: {path.name}")
    existing_parents = (parent for parent in path.parents if parent.exists())
    if any(parent.is_symlink() for parent in existing_parents):
        raise ContractError(f"refusing symlinked output parent: {path.name}")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(canonical_json(value), encoding="utf-8", newline="\n")
    except OSError as exc:
        raise ContractError(f"cannot write {path.name}") from exc


def _object(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ContractError(f"{label} must be an object with string keys")
    return cast(dict[str, object], value)


def _exact_keys(data: Mapping[str, object], expected: set[str], label: str) -> None:
    if set(data) != expected:
        raise ContractError(f"{label} keys do not match the approved schema")


def _commit(value: object, label: str = "source_commit") -> str:
    if not isinstance(value, str) or COMMIT_PATTERN.fullmatch(value) is None:
        raise ContractError(f"{label} must be a lowercase 40-character commit SHA")
    return value


def _digest(value: object, label: str = "image_digest") -> str:
    if not isinstance(value, str) or DIGEST_PATTERN.fullmatch(value) is None:
        raise ContractError(f"{label} must be a lowercase sha256 digest")
    return value


def _timestamp(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        raise ContractError(f"{label} must be an RFC 3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ContractError(f"{label} must be an RFC 3339 timestamp") from exc
    if parsed.tzinfo is None:
        raise ContractError(f"{label} must include a timezone")
    return parsed


def assert_content_safe(value: object, location: str = "$") -> None:
    """Reject secret-bearing keys and obvious credential material."""
    if isinstance(value, dict):
        for raw_key, item in value.items():
            if not isinstance(raw_key, str):
                raise ContractError(f"non-string key at {location}")
            key = raw_key.casefold()
            sensitive_suffixes = (
                "_access_key",
                "_password",
                "_private_key",
                "_secret",
                "_session_token",
            )
            if key in SENSITIVE_KEY_PARTS or key.endswith(sensitive_suffixes):
                raise ContractError(f"sensitive field prohibited at {location}.{raw_key}")
            assert_content_safe(item, f"{location}.{raw_key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            assert_content_safe(item, f"{location}[{index}]")
    elif isinstance(value, str):
        if any(pattern.search(value) for pattern in SENSITIVE_VALUE_PATTERNS):
            raise ContractError(f"sensitive value prohibited at {location}")


def _validate_image_identity_v1(value: object) -> dict[str, object]:
    data = _object(value, IMAGE_SCHEMA_V1)
    _exact_keys(
        data,
        {"base_image", "image_digest", "platform", "schema_version", "source_commit"},
        IMAGE_SCHEMA_V1,
    )
    if data["schema_version"] != IMAGE_SCHEMA_V1:
        raise ContractError("unexpected image identity schema")
    _commit(data["source_commit"])
    _digest(data["image_digest"])
    if data["platform"] != PLATFORM or data["base_image"] != BASE_IMAGE_V1:
        raise ContractError("image identity differs from the approved immutable identity")
    return data


def validate_plan_summary(value: object) -> dict[str, object]:
    data = _object(value, PLAN_SCHEMA)
    _exact_keys(
        data,
        {
            "changes",
            "environment",
            "expires_at",
            "generated_at",
            "raw_plan_retained",
            "redacted",
            "ref",
            "repository",
            "schema_version",
            "source_commit",
            "terraform_version",
        },
        PLAN_SCHEMA,
    )
    if data["schema_version"] != PLAN_SCHEMA:
        raise ContractError("unexpected plan summary schema")
    if (
        data["repository"] != REPOSITORY
        or data["ref"] != REF
        or data["environment"] != ENVIRONMENT
        or data["terraform_version"] != "1.16.1"
    ):
        raise ContractError("plan identity differs from the approved trust contract")
    _commit(data["source_commit"])
    generated = _timestamp(data["generated_at"], "generated_at")
    expires = _timestamp(data["expires_at"], "expires_at")
    lifetime = (expires - generated).total_seconds()
    if lifetime <= 0 or lifetime > 86_400:
        raise ContractError("plan summary lifetime must be within 24 hours")
    if expires <= datetime.now(tz=expires.tzinfo):
        raise ContractError("plan summary is expired")
    if data["redacted"] is not True or data["raw_plan_retained"] is not False:
        raise ContractError("plan summary must be redacted and retain no raw plan")
    changes = _object(data["changes"], "changes")
    _exact_keys(changes, {"add", "change", "destroy", "no_op", "read"}, "changes")
    invalid_counts = (
        not isinstance(count, int) or isinstance(count, bool) or count < 0
        for count in changes.values()
    )
    if any(invalid_counts):
        raise ContractError("plan change counts must be non-negative integers")
    return data


def _validate_provenance_v1(value: object) -> dict[str, object]:
    data = _object(value, PROVENANCE_SCHEMA_V1)
    _exact_keys(
        data,
        {"image_digest", "reports", "schema_version", "source_commit", "tool_versions"},
        PROVENANCE_SCHEMA_V1,
    )
    if data["schema_version"] != PROVENANCE_SCHEMA_V1:
        raise ContractError("unexpected provenance schema")
    _commit(data["source_commit"])
    _digest(data["image_digest"])
    tools = _object(data["tool_versions"], "tool_versions")
    if tools != EXPECTED_TOOL_VERSIONS_V1:
        raise ContractError("tool versions differ from approved immutable identities")
    reports = data["reports"]
    if not isinstance(reports, list) or any(not isinstance(item, str) for item in reports):
        raise ContractError("provenance reports must be an ordered string list")
    expected_names = SUPPLY_CHAIN_NAMES_V1[:6]
    if len(reports) != len(expected_names):
        raise ContractError("provenance must bind all six candidate input reports")
    for report, expected_name in zip(cast(list[str], reports), expected_names, strict=True):
        prefix = f"{expected_name}:"
        if not report.startswith(prefix):
            raise ContractError("provenance report ordering differs from the allowlist")
        _digest(report.removeprefix(prefix), "report digest")
    return data


def _validate_eligibility_v1(value: object) -> dict[str, object]:
    data = _object(value, ELIGIBILITY_SCHEMA_V1)
    _exact_keys(
        data,
        {
            "critical_vulnerabilities",
            "deployable",
            "eligible_for_owner_approval",
            "image_digest",
            "mandatory_gates",
            "schema_version",
            "source_commit",
            "w5_001_status",
        },
        ELIGIBILITY_SCHEMA_V1,
    )
    if data["schema_version"] != ELIGIBILITY_SCHEMA_V1:
        raise ContractError("unexpected eligibility schema")
    _commit(data["source_commit"])
    _digest(data["image_digest"])
    if data["w5_001_status"] != "FAIL" or data["deployable"] is not False:
        raise ContractError("W5-001 FAIL and non-deployable Phase A status must be preserved")
    critical = data["critical_vulnerabilities"]
    if not isinstance(critical, int) or isinstance(critical, bool) or critical < 0:
        raise ContractError("critical_vulnerabilities must be a non-negative integer")
    gates = _object(data["mandatory_gates"], "mandatory_gates")
    expected_gates = {
        "candidate_identity",
        "cyclonedx_sbom",
        "grype_image",
        "spdx_sbom",
        "trivy_filesystem",
        "trivy_image",
    }
    if set(gates) != expected_gates or any(
        not isinstance(result, bool) for result in gates.values()
    ):
        raise ContractError("mandatory_gates must contain boolean results")
    expected = critical == 0 and all(cast(bool, result) for result in gates.values())
    if data["eligible_for_owner_approval"] is not expected:
        raise ContractError("eligibility does not reconcile to the mandatory gates")
    return data


def _validate_schema_v1(value: object) -> dict[str, object]:
    data = _object(value, "report")
    schema = data.get("schema_version")
    validators = {
        IMAGE_SCHEMA_V1: _validate_image_identity_v1,
        PLAN_SCHEMA: validate_plan_summary,
        PROVENANCE_SCHEMA_V1: _validate_provenance_v1,
        ELIGIBILITY_SCHEMA_V1: _validate_eligibility_v1,
    }
    validator = validators.get(schema) if isinstance(schema, str) else None
    if validator is None:
        raise ContractError("unknown or missing W5-002 schema")
    result = validator(data)
    assert_content_safe(result)
    return result


def _validate_config_v1(value: object) -> dict[str, object]:
    data = _object(value, CONFIG_SCHEMA_V1)
    _exact_keys(
        data,
        {
            "actions",
            "artifact_limits",
            "artifacts",
            "build",
            "github",
            "plan",
            "python",
            "reports",
            "runner",
            "schema_version",
            "security",
            "terraform",
            "tools",
            "w5_001",
        },
        CONFIG_SCHEMA_V1,
    )
    if data.get("schema_version") != CONFIG_SCHEMA_V1:
        raise ContractError("unexpected configuration schema")
    if data.get("reports") != list(REPORT_PATHS_V1):
        raise ContractError("configuration report allowlist differs from the approved order")
    github = _object(data.get("github"), "github")
    expected_github = {
        "audience": "sts.amazonaws.com",
        "environment": ENVIRONMENT,
        "oidc_provider": (
            "arn:aws:iam::526338061652:oidc-provider/token.actions.githubusercontent.com"
        ),
        "ref": REF,
        "repository": REPOSITORY,
        "role": ("arn:aws:iam::526338061652:role/enterprise-ai-platform-sandbox-github-oidc"),
        "session_duration_seconds": 900,
        "subject": f"repo:{REPOSITORY}:environment:{ENVIRONMENT}",
    }
    if github != expected_github:
        raise ContractError("GitHub/OIDC identity differs from the approved trust contract")
    actions = _object(data.get("actions"), "actions")
    if actions != {
        "checkout": "9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
        "configure_aws_credentials": "e6de054238d6b7531b4efff3b6587d9aade6a06c",
        "setup_buildx": "d7f5e7f509e45cec5c76c4d5afdd7de93d0b3df5",
        "setup_python": "5fda3b95a4ea91299a34e894583c3862153e4b97",
        "setup_terraform": "dfe3c3f87815947d99a8997f908cb6525fc44e9e",
        "upload_artifact": "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
    }:
        raise ContractError("GitHub Action identities differ from the approved commits")
    if data.get("artifact_limits") != {
        "maximum_file_bytes": MAXIMUM_FILE_BYTES,
        "maximum_run_bytes": MAXIMUM_RUN_BYTES,
        "retention_days": 7,
    } or data.get("artifacts") != {
        "plan": "w5-002-plan-summary",
        "supply_chain": "w5-002-supply-chain",
    }:
        raise ContractError("artifact names or limits differ from the approved contract")
    if data.get("build") != {
        "base_image": BASE_IMAGE_V1,
        "builder": "enterprise-ai-platform-w5-002",
        "buildkit_image": (
            "moby/buildkit:v0.30.0@sha256:"
            "57269d1784e49b46228c45a1a1b870fbe40e0a639ab60b37b032d83af5bccdfc"
        ),
        "buildkit_index": (
            "sha256:0168606be2315b7c807a03b3d8aa79beefdb31c98740cebdffdfeebf31190c9f"
        ),
        "buildkit_version": "0.30.0",
        "output": "oci-archive",
        "platform": PLATFORM,
    }:
        raise ContractError("build identity differs from the approved immutable identity")
    if data.get("plan") != {
        "backend": False,
        "maximum_age_hours": 24,
        "refresh": False,
        "terraform_actions": ["create", "read", "update", "delete", "no-op"],
    }:
        raise ContractError("speculative plan contract differs from the approved boundary")
    if data.get("python") != {
        "emit_index_url": True,
        "forbidden_lock_package_prefixes": list(FORBIDDEN_LOCK_PACKAGE_PREFIXES),
        "install_arguments": ["--require-hashes", "--no-deps"],
        "pip": "26.2.1",
        "pip_tools": "7.6.1",
        "pip_tools_sha256": ("695556edeb647eb94ee8345cc7108657fdb7fb16b3876623a399b4f61bbede01"),
        "pytorch_backend": "cpu",
        "pytorch_index_url": PYTORCH_INDEX_URL,
        "resolver": "backtracking",
        "target_platform": "x86_64-unknown-linux-gnu",
        "uv": "0.12.9",
        "uv_sha256": ("ec7a99cd05e0cd7f80243f135ce1361c76835cb0ee60055d14d20eba8eba1460"),
        "version": "3.11.16",
    }:
        raise ContractError("Python lock resolver identity differs from the approved contract")
    if data.get("runner") != {
        "github_hosted": "ubuntu-latest",
        "maximum_complete_minutes": 60,
    }:
        raise ContractError("runner boundary differs from the approved Phase A contract")
    security = _object(data.get("security"), "security")
    if security != {
        "critical_vulnerabilities_block": True,
        "high_vulnerabilities_block": False,
        "phase_a_waivers": False,
        "qdrant_required": False,
    }:
        raise ContractError("security policy differs from the approved Phase A contract")
    if data.get("terraform") != {
        "aws_provider": "6.55.0",
        "aws_provider_linux_amd64_archive_sha256": (
            "f7383732f8704099db2166a3516e0a803bf46f42c30cd20a0471b55658ae6e51"
        ),
        "aws_provider_windows_amd64_archive_sha256": (
            "e1bf63e8a6b9790836f74848b458cdf679a7841e66a25b4b9f6034efc9310b34"
        ),
        "linux_amd64_archive_sha256": (
            "745d33b4b02b7980c62a38ec1beea24ee084ea8caf3f503c200554bd9a0cbe49"
        ),
        "platforms": ["linux_amd64", "windows_amd64"],
        "version": "1.16.1",
        "windows_amd64_archive_sha256": (
            "5c6c6d8fedf56ce29c55f0c1fc91de3c259f42c2d220a28e827b5b60fd47bfa1"
        ),
    }:
        raise ContractError("Terraform/provider identity differs from the approved contract")
    tools = _object(data.get("tools"), "tools")
    expected_tools = {
        "actionlint": {
            "path": "E:/AI/.tools/actionlint/1.7.12/actionlint.exe",
            "version": "1.7.12",
        },
        "checkov": {
            "path": "E:/AI/.venvs/enterprise-ai-platform-checkov-3.3.16",
            "version": "3.3.16",
        },
        "grype": {
            "path": "E:/AI/.tools/grype/0.118.0/grype.exe",
            "version": "0.118.0",
        },
        "opa": {
            "path": "E:/AI/.tools/opa/1.20.0/opa.exe",
            "version": "1.20.0",
        },
        "syft": {
            "path": "E:/AI/.tools/syft/1.51.1/syft.exe",
            "version": "1.51.1",
        },
        "tflint": {
            "aws_ruleset": "0.48.0",
            "path": "E:/AI/.tools/tflint/0.60.0/tflint.exe",
            "version": "0.60.0",
        },
        "trivy": {
            "path": "E:/AI/.tools/trivy/0.74.0/trivy.exe",
            "version": "0.74.0",
        },
    }
    if tools != expected_tools:
        raise ContractError("security tools differ from approved immutable identities")
    w5_001 = _object(data.get("w5_001"), "w5_001")
    if w5_001 != {"formal_status": "FAIL"}:
        raise ContractError("W5-001 formal FAIL must remain explicit")
    assert_content_safe(data)
    return data


def _source_identity(value: object) -> dict[str, object]:
    data = _object(value, "source_identity")
    _exact_keys(
        data,
        {"baseline_head", "source_commit", "source_composition_sha256"},
        "source_identity",
    )
    if data["baseline_head"] != BASELINE_HEAD:
        raise ContractError("source identity does not preserve the approved baseline HEAD")
    composition = _digest(data["source_composition_sha256"], "source_composition_sha256")
    commit = data["source_commit"]
    if commit is not None:
        _commit(commit)
        if commit == BASELINE_HEAD and composition != BASELINE_SOURCE_COMPOSITION:
            raise ContractError("baseline HEAD cannot identify uncommitted migration content")
    return data


def _qualified_image(value: object, role: str) -> dict[str, object]:
    data = _object(value, f"{role}_image")
    _exact_keys(
        data,
        {
            "architecture",
            "glibc",
            "index_digest",
            "manifest_digest",
            "os",
            "os_family",
            "python_package",
            "reference",
            "tag",
        },
        f"{role}_image",
    )
    expected = {
        "builder": {
            "architecture": "amd64",
            "glibc": "2.44-r5",
            "index_digest": BUILDER_INDEX_DIGEST,
            "manifest_digest": BUILDER_MANIFEST_DIGEST,
            "os": "linux",
            "os_family": "wolfi",
            "python_package": "3.13.15-r7",
            "reference": BUILDER_IMAGE,
            "tag": BUILDER_TAG,
        },
        "runtime": {
            "architecture": "amd64",
            "glibc": "2.44-r5",
            "index_digest": RUNTIME_INDEX_DIGEST,
            "manifest_digest": RUNTIME_MANIFEST_DIGEST,
            "os": "linux",
            "os_family": "wolfi",
            "python_package": "3.13.15-r7",
            "reference": RUNTIME_IMAGE,
            "tag": RUNTIME_TAG,
        },
    }
    if data != expected[role]:
        raise ContractError(f"{role} image differs from the qualified immutable identity")
    return data


def _validate_image_identity_v2(value: object) -> dict[str, object]:
    data = _object(value, IMAGE_SCHEMA)
    _exact_keys(
        data,
        {
            "application_image",
            "builder_image",
            "inputs",
            "platform",
            "python_version",
            "runtime_image",
            "schema_version",
            "source_identity",
        },
        IMAGE_SCHEMA,
    )
    if data["schema_version"] != IMAGE_SCHEMA:
        raise ContractError("unexpected image identity schema")
    if data["platform"] != PLATFORM or data["python_version"] != PYTHON_VERSION:
        raise ContractError("application platform or Python identity differs from approval")
    _source_identity(data["source_identity"])
    _qualified_image(data["builder_image"], "builder")
    _qualified_image(data["runtime_image"], "runtime")
    application = _object(data["application_image"], "application_image")
    _exact_keys(
        application,
        {"configuration_digest", "manifest_digest", "oci_archive_sha256"},
        "application_image",
    )
    for key in application:
        _digest(application[key], key)
    inputs = _object(data["inputs"], "inputs")
    _exact_keys(
        inputs,
        {
            "dockerfile_sha256",
            "requirements_checkov_lock_sha256",
            "requirements_ci_lock_sha256",
            "requirements_runtime_lock_sha256",
        },
        "inputs",
    )
    _exact_keys(
        inputs,
        {
            "dockerfile_sha256",
            "requirements_checkov_lock_sha256",
            "requirements_ci_lock_sha256",
            "requirements_runtime_lock_sha256",
        },
        "inputs",
    )
    for key in inputs:
        _digest(inputs[key], key)
    return data


def validate_image_identity(value: object) -> dict[str, object]:
    data = _object(value, "image identity")
    if data.get("schema_version") == IMAGE_SCHEMA_V1:
        return _validate_image_identity_v1(data)
    return _validate_image_identity_v2(data)


def _validate_provenance_v2(value: object) -> dict[str, object]:
    data = _object(value, PROVENANCE_SCHEMA)
    _exact_keys(
        data,
        {
            "application_manifest_digest",
            "image_identity_report_sha256",
            "reports",
            "scanner_databases",
            "schema_version",
            "source_identity",
            "tool_versions",
        },
        PROVENANCE_SCHEMA,
    )
    if data["schema_version"] != PROVENANCE_SCHEMA:
        raise ContractError("unexpected provenance schema")
    _source_identity(data["source_identity"])
    _digest(data["application_manifest_digest"], "application_manifest_digest")
    _digest(data["image_identity_report_sha256"], "image_identity_report_sha256")
    if _object(data["tool_versions"], "tool_versions") != EXPECTED_TOOL_VERSIONS:
        raise ContractError("tool versions differ from approved immutable identities")
    databases = _object(data["scanner_databases"], "scanner_databases")
    _exact_keys(databases, {"grype", "trivy"}, "scanner_databases")
    for identity in databases.values():
        _digest(identity, "scanner database identity")
    reports = data["reports"]
    expected_names = SUPPLY_CHAIN_NAMES[:6]
    if not isinstance(reports, list) or len(reports) != len(expected_names):
        raise ContractError("provenance must bind all six candidate input reports")
    for report, expected_name in zip(cast(list[object], reports), expected_names, strict=True):
        if not isinstance(report, str):
            raise ContractError("provenance report identities must be strings")
        prefix = f"{expected_name}:"
        if not report.startswith(prefix):
            raise ContractError("provenance report ordering differs from the v2 allowlist")
        _digest(report.removeprefix(prefix), "report digest")
    return data


def validate_provenance(value: object) -> dict[str, object]:
    data = _object(value, "provenance")
    if data.get("schema_version") == PROVENANCE_SCHEMA_V1:
        return _validate_provenance_v1(data)
    return _validate_provenance_v2(data)


def _validate_rollback(value: object) -> dict[str, object]:
    data = _object(value, ROLLBACK_SCHEMA)
    _exact_keys(
        data,
        {
            "application_image",
            "deployment_status",
            "inputs",
            "rollback_status",
            "schema_version",
            "source_identity",
        },
        ROLLBACK_SCHEMA,
    )
    if data["schema_version"] != ROLLBACK_SCHEMA:
        raise ContractError("unexpected rollback schema")
    _source_identity(data["source_identity"])
    application = _object(data["application_image"], "application_image")
    _exact_keys(
        application,
        {"configuration_digest", "manifest_digest", "oci_archive_sha256"},
        "application_image",
    )
    inputs = _object(data["inputs"], "inputs")
    for identity in (*application.values(), *inputs.values()):
        _digest(identity, "rollback identity")
    if data["rollback_status"] != "IDENTITY_RECORDED" or data["deployment_status"] != "NOT RUN":
        raise ContractError("rollback must remain an identity-only, non-deployment record")
    return data


def _validate_cleanup(value: object) -> dict[str, object]:
    data = _object(value, CLEANUP_SCHEMA)
    _exact_keys(
        data,
        {
            "cloud_activity",
            "deployment_status",
            "historical_evidence",
            "migration_created_temporary_resources",
            "repository_unapproved_runtime_residue",
            "retained_evidence",
            "schema_version",
            "shared_resources",
        },
        CLEANUP_SCHEMA,
    )
    if data != {
        "cloud_activity": "NOT RUN",
        "deployment_status": "NOT RUN",
        "historical_evidence": "RETAINED",
        "migration_created_temporary_resources": "REMOVED",
        "repository_unapproved_runtime_residue": "ZERO",
        "retained_evidence": list(SUPPLY_CHAIN_NAMES),
        "schema_version": CLEANUP_SCHEMA,
        "shared_resources": "RETAINED",
    }:
        raise ContractError("cleanup and retention record differs from the approved boundary")
    return data


def _validate_eligibility_v2(value: object) -> dict[str, object]:
    data = _object(value, ELIGIBILITY_SCHEMA)
    _exact_keys(
        data,
        {
            "application_manifest_digest",
            "cleanup_retention_report_sha256",
            "critical_vulnerabilities",
            "deployable",
            "eligible_for_owner_approval",
            "formal_w5_002_status",
            "mandatory_gates",
            "provenance_report_sha256",
            "rollback_identity_report_sha256",
            "schema_version",
            "source_identity",
            "vulnerability_free_claim",
            "w5_001_status",
        },
        ELIGIBILITY_SCHEMA,
    )
    if data["schema_version"] != ELIGIBILITY_SCHEMA:
        raise ContractError("unexpected eligibility schema")
    _source_identity(data["source_identity"])
    for key in (
        "application_manifest_digest",
        "cleanup_retention_report_sha256",
        "provenance_report_sha256",
        "rollback_identity_report_sha256",
    ):
        _digest(data[key], key)
    if (
        data["w5_001_status"] != "FAIL"
        or data["formal_w5_002_status"] != "FAIL"
        or data["deployable"] is not False
        or data["vulnerability_free_claim"] is not False
    ):
        raise ContractError("formal failures, non-deployable state, and claim limits must persist")
    critical = _object(data["critical_vulnerabilities"], "critical_vulnerabilities")
    _exact_keys(critical, {"grype", "trivy"}, "critical_vulnerabilities")
    if any(
        not isinstance(count, int) or isinstance(count, bool) or count < 0
        for count in critical.values()
    ):
        raise ContractError("critical vulnerability counts must be non-negative integers")
    gates = _object(data["mandatory_gates"], "mandatory_gates")
    expected_gates = {
        "candidate_identity",
        "cleanup",
        "cyclonedx_sbom",
        "grype_image",
        "provenance",
        "rollback_identity",
        "scanner_reconciliation",
        "spdx_sbom",
        "trivy_filesystem",
        "trivy_image",
    }
    if set(gates) != expected_gates or any(
        not isinstance(result, bool) for result in gates.values()
    ):
        raise ContractError("mandatory gates must contain the exact boolean v2 results")
    expected = all(count == 0 for count in critical.values()) and all(
        cast(bool, result) for result in gates.values()
    )
    if data["eligible_for_owner_approval"] is not expected:
        raise ContractError("eligibility does not reconcile to zero-Critical mandatory gates")
    return data


def validate_eligibility(value: object) -> dict[str, object]:
    data = _object(value, "eligibility")
    if data.get("schema_version") == ELIGIBILITY_SCHEMA_V1:
        return _validate_eligibility_v1(data)
    return _validate_eligibility_v2(data)


def validate_schema(value: object) -> dict[str, object]:
    data = _object(value, "report")
    schema = data.get("schema_version")
    validators = {
        IMAGE_SCHEMA_V1: _validate_image_identity_v1,
        IMAGE_SCHEMA: _validate_image_identity_v2,
        PLAN_SCHEMA: validate_plan_summary,
        PROVENANCE_SCHEMA_V1: _validate_provenance_v1,
        PROVENANCE_SCHEMA: _validate_provenance_v2,
        ELIGIBILITY_SCHEMA_V1: _validate_eligibility_v1,
        ELIGIBILITY_SCHEMA: _validate_eligibility_v2,
        ROLLBACK_SCHEMA: _validate_rollback,
        CLEANUP_SCHEMA: _validate_cleanup,
    }
    validator = validators.get(schema) if isinstance(schema, str) else None
    if validator is None:
        raise ContractError("unknown or missing W5-002 schema")
    result = validator(data)
    assert_content_safe(result)
    return result


def _validate_config_v2(value: object) -> dict[str, object]:
    data = _object(value, CONFIG_SCHEMA)
    _exact_keys(
        data,
        {
            "actions",
            "artifact_limits",
            "artifacts",
            "base_qualification",
            "build",
            "github",
            "historical",
            "plan",
            "python",
            "remediation",
            "reports",
            "runner",
            "schema_version",
            "security",
            "terraform",
            "tools",
            "w5_001",
        },
        CONFIG_SCHEMA,
    )
    if data["schema_version"] != CONFIG_SCHEMA or data["reports"] != list(REPORT_PATHS):
        raise ContractError("v2 configuration schema or report allowlist differs from approval")
    if data["actions"] != {
        "checkout": "9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
        "configure_aws_credentials": "e6de054238d6b7531b4efff3b6587d9aade6a06c",
        "setup_buildx": "d7f5e7f509e45cec5c76c4d5afdd7de93d0b3df5",
        "setup_chainctl": "be0acd273acf04bfdf91f51198327e719f6af978",
        "setup_python": "5fda3b95a4ea91299a34e894583c3862153e4b97",
        "setup_terraform": "dfe3c3f87815947d99a8997f908cb6525fc44e9e",
        "upload_artifact": "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
    }:
        raise ContractError("v2 GitHub Action identities differ from approved commits")
    expected_builder = {
        "index_digest": BUILDER_INDEX_DIGEST,
        "manifest_digest": BUILDER_MANIFEST_DIGEST,
        "reference": BUILDER_IMAGE,
        "tag": BUILDER_TAG,
    }
    expected_runtime = {
        "index_digest": RUNTIME_INDEX_DIGEST,
        "manifest_digest": RUNTIME_MANIFEST_DIGEST,
        "reference": RUNTIME_IMAGE,
        "tag": RUNTIME_TAG,
    }
    if data["build"] != {
        "builder": "enterprise-ai-platform-w5-002-py313",
        "builder_image": expected_builder,
        "buildkit_image": (
            "moby/buildkit:v0.30.0@sha256:"
            "57269d1784e49b46228c45a1a1b870fbe40e0a639ab60b37b032d83af5bccdfc"
        ),
        "buildkit_index": "sha256:0168606be2315b7c807a03b3d8aa79beefdb31c98740cebdffdfeebf31190c9f",
        "buildkit_version": "0.30.0",
        "output": "oci-archive",
        "platform": PLATFORM,
        "runtime_contract": {
            "entrypoint": "/venv/bin/python",
            "gid": 65532,
            "package_manager": False,
            "read_only_root": True,
            "shell": False,
            "uid": 65532,
            "writable_tmp": "/tmp",  # noqa: S108 - mandated bounded runtime mount
        },
        "runtime_image": expected_runtime,
    }:
        raise ContractError("v2 build identity differs from qualified immutable manifests")
    github = _object(data["github"], "github")
    if github != {
        "audience": "sts.amazonaws.com",
        "chainguard": {
            "access": "pull-only/viewer",
            "hosted_execution": "NOT RUN",
            "identity_variable": "CHAINGUARD_PULL_IDENTITY",
            "long_lived_credentials": False,
            "organization": "vayunetrix.com",
            "pr_oidc": False,
            "ref": REF,
            "registry_scope": "cgr.dev/vayunetrix.com/python",
            "repository": REPOSITORY,
            "workflow": ".github/workflows/security-scan.yml",
        },
        "environment": ENVIRONMENT,
        "oidc_provider": (
            "arn:aws:iam::526338061652:oidc-provider/token.actions.githubusercontent.com"
        ),
        "ref": REF,
        "repository": REPOSITORY,
        "role": "arn:aws:iam::526338061652:role/enterprise-ai-platform-sandbox-github-oidc",
        "session_duration_seconds": 900,
        "subject": f"repo:{REPOSITORY}:environment:{ENVIRONMENT}",
    }:
        raise ContractError("GitHub/OIDC identities differ from the approved trust contracts")
    if data["python"] != {
        "emit_index_url": True,
        "forbidden_lock_package_prefixes": list(FORBIDDEN_LOCK_PACKAGE_PREFIXES),
        "free_threaded": False,
        "implementation": "CPython",
        "install_arguments": ["--require-hashes", "--no-deps"],
        "jit": False,
        "no_build": True,
        "no_python_downloads": True,
        "pip": "26.2.1",
        "pytorch_backend": "cpu",
        "pytorch_index_url": PYTORCH_INDEX_URL,
        "requires_python": PYTHON_REQUIREMENT,
        "resolver": "uv",
        "target_platform": "x86_64-unknown-linux-gnu",
        "uv": "0.12.9",
        "uv_sha256": "ec7a99cd05e0cd7f80243f135ce1361c76835cb0ee60055d14d20eba8eba1460",
        "version": PYTHON_VERSION,
    }:
        raise ContractError("Python 3.13 lock resolver contract differs from approval")
    if data["base_qualification"] != {
        "accepted_findings": [
            {"id": "CVE-2026-19672", "package": "python-3.13 3.13.15-r7", "severity": "Medium"},
            {"id": "CVE-2025-15367", "package": "python-3.13 3.13.15-r7", "severity": "Medium"},
            {"id": "CVE-2026-18374", "package": "glibc-2.44 2.44-r5", "severity": "Medium"},
            {"id": "CVE-2026-15310", "package": "python-3.13 3.13.15-r7", "severity": "Low"},
        ],
        "builder": {"grype_critical": 0, "trivy_critical": 0, "trivy_purl_skips": 147},
        "claim": "zero-Critical at the recorded scanner database snapshots",
        "runtime": {"grype_critical": 0, "trivy_critical": 0, "trivy_purl_skips": 48},
        "vulnerability_free_claim": False,
    }:
        raise ContractError("base qualification facts differ from owner-accepted evidence")
    if data["remediation"] != {
        "freshness": {"maximum_age_hours": 24, "stale_status": "INDETERMINATE"},
        "high_findings": {"inventory_required": True, "unresolved_status": "WAIVED_OR_FAIL"},
        "purl": {
            "normalization_reason_required": True,
            "publisher_advisory_optional": True,
            "skipped_packages_status": "INDETERMINATE",
        },
        "scanner_reconciliation": {
            "disagreement_status": "INDETERMINATE",
            "sbom_formats": ["SPDX", "CycloneDX"],
        },
        "waivers": {"expiry_required": True, "new_waivers_allowed": False},
        "zero_critical_required": True,
    }:
        raise ContractError("W7 supply-chain remediation policy differs")
    if data["historical"] != {
        "config_schema": CONFIG_SCHEMA_V1,
        "python": "3.11.16",
        "status": "RETAINED EVIDENCE ONLY",
        "w5_002_formal_status": "FAIL",
    }:
        raise ContractError("historical Python 3.11 evidence status must be preserved")
    if data["security"] != {
        "critical_vulnerabilities_block": True,
        "final_composed_image_qualification_required": True,
        "high_vulnerabilities_block": False,
        "phase_a_waivers": False,
        "qdrant_required": False,
        "scanner_disagreement_blocks": True,
        "vulnerability_free_claim": False,
    }:
        raise ContractError("security policy differs from the approved zero-Critical contract")
    if data["artifact_limits"] != {
        "maximum_file_bytes": MAXIMUM_FILE_BYTES,
        "maximum_run_bytes": MAXIMUM_RUN_BYTES,
        "retention_days": 7,
    } or data["artifacts"] != {
        "plan": "w5-002-plan-summary",
        "supply_chain": "w5-002-supply-chain-v2",
    }:
        raise ContractError("artifact names or limits differ from the v2 contract")
    if data["plan"] != {
        "backend": False,
        "maximum_age_hours": 24,
        "refresh": False,
        "terraform_actions": ["create", "read", "update", "delete", "no-op"],
    }:
        raise ContractError("speculative plan contract differs from the approved boundary")
    if data["runner"] != {"github_hosted": "ubuntu-latest", "maximum_complete_minutes": 60}:
        raise ContractError("runner boundary differs from approval")
    if data["terraform"] != {
        "aws_provider": "6.55.0",
        "aws_provider_linux_amd64_archive_sha256": (
            "f7383732f8704099db2166a3516e0a803bf46f42c30cd20a0471b55658ae6e51"
        ),
        "aws_provider_windows_amd64_archive_sha256": (
            "e1bf63e8a6b9790836f74848b458cdf679a7841e66a25b4b9f6034efc9310b34"
        ),
        "linux_amd64_archive_sha256": (
            "745d33b4b02b7980c62a38ec1beea24ee084ea8caf3f503c200554bd9a0cbe49"
        ),
        "platforms": ["linux_amd64", "windows_amd64"],
        "version": "1.16.1",
        "windows_amd64_archive_sha256": (
            "5c6c6d8fedf56ce29c55f0c1fc91de3c259f42c2d220a28e827b5b60fd47bfa1"
        ),
    }:
        raise ContractError("Terraform/provider identity differs from the approved contract")
    if data["tools"] != {
        "actionlint": {
            "path": "E:/AI/.tools/actionlint/1.7.12/actionlint.exe",
            "version": "1.7.12",
        },
        "chainctl": {"path": "E:/AI/.tools/chainctl/0.2.346/chainctl.exe", "version": "0.2.346"},
        "checkov": {
            "path": "E:/AI/.venvs/enterprise-ai-platform-checkov-3.3.16",
            "version": "3.3.16",
        },
        "cosign": {"path": "E:/AI/.tools/cosign/3.1.2/cosign.exe", "version": "3.1.2"},
        "grype": {"path": "E:/AI/.tools/grype/0.118.0/grype.exe", "version": "0.118.0"},
        "opa": {"path": "E:/AI/.tools/opa/1.20.0/opa.exe", "version": "1.20.0"},
        "syft": {"path": "E:/AI/.tools/syft/1.51.1/syft.exe", "version": "1.51.1"},
        "tflint": {
            "aws_ruleset": "0.48.0",
            "path": "E:/AI/.tools/tflint/0.60.0/tflint.exe",
            "version": "0.60.0",
        },
        "trivy": {"path": "E:/AI/.tools/trivy/0.74.0/trivy.exe", "version": "0.74.0"},
        "uv": {
            "path": "E:/AI/.tools/uv/0.12.9/uv-x86_64-unknown-linux-gnu/uv",
            "version": "0.12.9",
        },
    }:
        raise ContractError("security tools differ from approved immutable identities")
    if data["w5_001"] != {"formal_status": "FAIL"}:
        raise ContractError("W5-001 formal FAIL must remain explicit")
    assert_content_safe(data)
    return data


def validate_config(value: object) -> dict[str, object]:
    data = _object(value, "configuration")
    if data.get("schema_version") == CONFIG_SCHEMA_V1:
        return _validate_config_v1(data)
    return _validate_config_v2(data)


def validate_dependency_lock(path: Path, profile: str) -> dict[str, str]:
    """Validate a generated lock without resolving or installing dependencies."""
    if profile not in {"runtime", "ci", "checkov"}:
        raise ContractError("unknown dependency lock profile")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ContractError(f"cannot read dependency lock: {path.name}") from exc
    if len(raw) > MAXIMUM_FILE_BYTES:
        raise ContractError(f"dependency lock exceeds maximum size: {path.name}")
    if raw.startswith(b"\xef\xbb\xbf"):
        raise ContractError(f"UTF-8 BOM is prohibited: {path.name}")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ContractError(f"dependency lock is not UTF-8: {path.name}") from exc
    lowered = text.casefold()
    vcs_markers = ("git+", "hg+", "svn+", "bzr+")
    if "--hash=sha256:" not in text or any(marker in lowered for marker in vcs_markers):
        raise ContractError("dependency lock must be hash-locked and contain no VCS source")
    required_provenance = (
        "autogenerated by uv",
        "--generate-hashes",
        "--no-build",
        "--no-python-downloads",
        "--python-platform x86_64-unknown-linux-gnu",
        "--python-version 3.13.15",
    )
    if any(marker not in text for marker in required_provenance):
        raise ContractError("dependency lock lacks exact Python 3.13.15 uv provenance")
    if any(marker in lowered for marker in ("--editable", "file://", " @ ", "--find-links", "../")):
        raise ContractError("dependency lock contains an editable, direct, or local source")

    source_directives = {
        line.strip()
        for line in text.splitlines()
        if line.strip().startswith(("--index-url", "--extra-index-url", "--trusted-host"))
    }

    packages: dict[str, str] = {}
    for line in text.splitlines():
        match = LOCK_REQUIREMENT_PATTERN.match(line)
        if match is None:
            continue
        name = match.group(1).casefold().replace("_", "-")
        if name in packages:
            raise ContractError(f"duplicate dependency lock package: {name}")
        packages[name] = match.group(2)
    if not packages:
        raise ContractError("dependency lock contains no exact package pins")

    prohibited = sorted(
        name for name in packages if name.startswith(FORBIDDEN_LOCK_PACKAGE_PREFIXES)
    )
    if prohibited:
        raise ContractError("dependency lock contains a prohibited GPU package: " + prohibited[0])

    if profile in {"runtime", "ci"}:
        torch_version = packages.get("torch")
        if torch_version is None or re.fullmatch(r"2\.13(?:\.\d+)?\+cpu", torch_version) is None:
            raise ContractError("dependency lock must contain an approved Torch 2.13 CPU pin")
        approved_directives = {
            "--index-url https://pypi.org/simple",
            f"--index-url {PYTORCH_INDEX_URL}",
            f"--extra-index-url {PYTORCH_INDEX_URL}",
        }
        if not source_directives.intersection(
            {
                f"--index-url {PYTORCH_INDEX_URL}",
                f"--extra-index-url {PYTORCH_INDEX_URL}",
            }
        ):
            raise ContractError("dependency lock does not preserve the approved PyTorch CPU index")
        if not source_directives or not source_directives.issubset(approved_directives):
            raise ContractError("dependency lock contains an unapproved package index")
    elif "torch" in packages:
        raise ContractError("isolated Checkov lock must not contain Torch")
    elif source_directives or PYTORCH_INDEX_URL in text:
        raise ContractError("isolated Checkov lock must use implicit PyPI only")
    return packages


def _assert_canonical(path: Path, value: object) -> None:
    if path.read_text(encoding="utf-8") != canonical_json(value):
        raise ContractError(f"non-canonical JSON: {path.name}")


def file_sha256(path: Path) -> str:
    """Return a lowercase digest without exposing file content."""
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def source_composition_sha256(repository_root: Path) -> str:
    """Bind the Dockerfile, runtime lock, and tracked application Python composition."""
    relative_paths = [Path("docker/application.Dockerfile"), Path("requirements-runtime.lock")]
    relative_paths.extend(
        path.relative_to(repository_root)
        for path in (repository_root / "src").rglob("*.py")
        if path.is_file()
    )
    ordered = sorted(relative_paths, key=lambda path: path.as_posix())
    if len(ordered) != 125:
        raise ContractError("source composition must contain the approved 125 paths")
    digest = hashlib.sha256()
    for relative in ordered:
        absolute = repository_root / relative
        digest.update(relative.as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(file_sha256(absolute).encode("ascii"))
        digest.update(b"\n")
    return f"sha256:{digest.hexdigest()}"


def _strict_json_bytes(raw: bytes, label: str) -> object:
    if len(raw) > MAXIMUM_FILE_BYTES:
        raise ContractError(f"{label} exceeds maximum size")
    try:
        value = cast(
            object,
            json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContractError(f"invalid JSON: {label}") from exc
    _validate_finite(value)
    return value


def _oci_application_identity(archive: Path) -> dict[str, str]:
    if archive.is_symlink() or not archive.is_file():
        raise ContractError("OCI archive is missing or unsafe")
    try:
        with tarfile.open(archive, mode="r:*") as stream:

            def member_bytes(name: str) -> bytes:
                try:
                    member = stream.getmember(name)
                except KeyError as exc:
                    raise ContractError(f"OCI archive is missing {name}") from exc
                if not member.isfile() or member.size > MAXIMUM_FILE_BYTES:
                    raise ContractError(f"OCI archive member is unsafe: {name}")
                extracted = stream.extractfile(member)
                if extracted is None:
                    raise ContractError(f"OCI archive member is unreadable: {name}")
                return extracted.read(MAXIMUM_FILE_BYTES + 1)

            layout = _object(
                _strict_json_bytes(member_bytes("oci-layout"), "oci-layout"),
                "oci-layout",
            )
            if layout != {"imageLayoutVersion": "1.0.0"}:
                raise ContractError("unexpected OCI layout version")
            index = _object(_strict_json_bytes(member_bytes("index.json"), "index.json"), "index")
            manifests = index.get("manifests")
            if not isinstance(manifests, list) or len(manifests) != 1:
                raise ContractError("OCI archive must contain exactly one application manifest")
            descriptor = _object(manifests[0], "application manifest descriptor")
            manifest_digest = _digest(descriptor.get("digest"), "application manifest digest")
            manifest_raw = member_bytes(f"blobs/sha256/{manifest_digest.removeprefix('sha256:')}")
            if f"sha256:{hashlib.sha256(manifest_raw).hexdigest()}" != manifest_digest:
                raise ContractError("application manifest content does not match its digest")
            manifest = _object(_strict_json_bytes(manifest_raw, "application manifest"), "manifest")
            configuration = _object(manifest.get("config"), "application configuration descriptor")
            configuration_digest = _digest(
                configuration.get("digest"), "application configuration digest"
            )
            configuration_raw = member_bytes(
                f"blobs/sha256/{configuration_digest.removeprefix('sha256:')}"
            )
            if f"sha256:{hashlib.sha256(configuration_raw).hexdigest()}" != configuration_digest:
                raise ContractError("application configuration does not match its digest")
    except (OSError, tarfile.TarError) as exc:
        raise ContractError("cannot inspect OCI archive") from exc
    return {
        "configuration_digest": configuration_digest,
        "manifest_digest": manifest_digest,
        "oci_archive_sha256": f"sha256:{file_sha256(archive)}",
    }


def _write_image_identity_v1(output: Path, source_commit: str, image_digest: str) -> None:
    value = {
        "base_image": BASE_IMAGE_V1,
        "image_digest": _digest(image_digest),
        "platform": PLATFORM,
        "schema_version": IMAGE_SCHEMA_V1,
        "source_commit": _commit(source_commit),
    }
    write_json(output, _validate_image_identity_v1(value))


def write_image_identity(
    output: Path,
    repository_root: Path,
    oci_archive: Path,
    source_commit: str | None,
) -> None:
    composition = source_composition_sha256(repository_root)
    if source_commit is not None:
        _commit(source_commit)
    value = {
        "application_image": _oci_application_identity(oci_archive),
        "builder_image": {
            "architecture": "amd64",
            "glibc": "2.44-r5",
            "index_digest": BUILDER_INDEX_DIGEST,
            "manifest_digest": BUILDER_MANIFEST_DIGEST,
            "os": "linux",
            "os_family": "wolfi",
            "python_package": "3.13.15-r7",
            "reference": BUILDER_IMAGE,
            "tag": BUILDER_TAG,
        },
        "inputs": {
            "dockerfile_sha256": (
                f"sha256:{file_sha256(repository_root / 'docker/application.Dockerfile')}"
            ),
            "requirements_checkov_lock_sha256": (
                f"sha256:{file_sha256(repository_root / 'requirements-checkov.lock')}"
            ),
            "requirements_ci_lock_sha256": (
                f"sha256:{file_sha256(repository_root / 'requirements-ci.lock')}"
            ),
            "requirements_runtime_lock_sha256": (
                f"sha256:{file_sha256(repository_root / 'requirements-runtime.lock')}"
            ),
        },
        "platform": PLATFORM,
        "python_version": PYTHON_VERSION,
        "runtime_image": {
            "architecture": "amd64",
            "glibc": "2.44-r5",
            "index_digest": RUNTIME_INDEX_DIGEST,
            "manifest_digest": RUNTIME_MANIFEST_DIGEST,
            "os": "linux",
            "os_family": "wolfi",
            "python_package": "3.13.15-r7",
            "reference": RUNTIME_IMAGE,
            "tag": RUNTIME_TAG,
        },
        "schema_version": IMAGE_SCHEMA,
        "source_identity": {
            "baseline_head": BASELINE_HEAD,
            "source_commit": source_commit,
            "source_composition_sha256": composition,
        },
    }
    write_json(output, validate_image_identity(value))


def _severity_counts(value: object) -> dict[str, int]:
    """Count normalized scanner severity fields without retaining finding content."""
    counts = {"critical": 0, "high": 0, "low": 0, "medium": 0}
    if isinstance(value, dict):
        for key in ("Severity", "severity"):
            severity = value.get(key)
            normalized = severity.casefold() if isinstance(severity, str) else ""
            if normalized in counts:
                counts[normalized] += 1
        for item in value.values():
            child = _severity_counts(item)
            for severity, count in child.items():
                counts[severity] += count
    elif isinstance(value, list):
        for item in value:
            child = _severity_counts(item)
            for severity, count in child.items():
                counts[severity] += count
    return counts


def write_scan_summary(
    raw_input: Path,
    output: Path,
    image_identity_path: Path,
    scanner: str,
    scope: str,
    scanner_database_identity: str,
) -> None:
    """Reduce native scanner JSON to bounded non-sensitive counts and identity."""
    if scanner not in {"grype", "trivy"} or scope not in {"filesystem", "oci"}:
        raise ContractError("scanner and scope must use approved labels")
    raw = load_json(raw_input)
    identity = validate_image_identity(load_json(image_identity_path))
    if identity["schema_version"] != IMAGE_SCHEMA:
        raise ContractError("v2 scan summaries require a v2 image identity")
    application = _object(identity["application_image"], "application_image")
    source = _object(identity["source_identity"], "source_identity")
    counts = _severity_counts(raw)
    value = {
        "application_manifest_digest": application["manifest_digest"],
        "critical_vulnerabilities": counts["critical"],
        "high_vulnerabilities": counts["high"],
        "low_vulnerabilities": counts["low"],
        "medium_vulnerabilities": counts["medium"],
        "raw_report_sha256": f"sha256:{file_sha256(raw_input)}",
        "scanner": scanner,
        "scanner_database_identity": _digest(
            scanner_database_identity, "scanner_database_identity"
        ),
        "scanner_version": EXPECTED_TOOL_VERSIONS[scanner],
        "schema_version": SCAN_SCHEMA,
        "scope": scope,
        "source_composition_sha256": source["source_composition_sha256"],
    }
    write_json(output, _validate_scan_summary(value, output.name))


def _validate_scan_summary_v1(value: object, name: str) -> dict[str, object]:
    data = _object(value, name)
    _exact_keys(
        data,
        {
            "critical_vulnerabilities",
            "high_vulnerabilities",
            "image_digest",
            "raw_report_sha256",
            "scanner",
            "scope",
            "source_commit",
        },
        name,
    )
    _commit(data["source_commit"])
    _digest(data["image_digest"])
    _digest(data["raw_report_sha256"], "raw_report_sha256")
    for key in ("critical_vulnerabilities", "high_vulnerabilities"):
        count = data[key]
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            raise ContractError(f"{key} must be a non-negative integer")
    expected = {
        "grype-image.json": ("grype", "oci"),
        "trivy-filesystem.json": ("trivy", "filesystem"),
        "trivy-image.json": ("trivy", "oci"),
    }
    if (data["scanner"], data["scope"]) != expected[name]:
        raise ContractError(f"{name} scanner identity differs from the approved scope")
    return data


def _validate_scan_summary_v2(value: object, name: str) -> dict[str, object]:
    data = _object(value, name)
    _exact_keys(
        data,
        {
            "application_manifest_digest",
            "critical_vulnerabilities",
            "high_vulnerabilities",
            "low_vulnerabilities",
            "medium_vulnerabilities",
            "raw_report_sha256",
            "scanner",
            "scanner_database_identity",
            "scanner_version",
            "schema_version",
            "scope",
            "source_composition_sha256",
        },
        name,
    )
    if data["schema_version"] != SCAN_SCHEMA:
        raise ContractError("unexpected scan summary schema")
    for key in (
        "application_manifest_digest",
        "raw_report_sha256",
        "scanner_database_identity",
        "source_composition_sha256",
    ):
        _digest(data[key], key)
    for key in (
        "critical_vulnerabilities",
        "high_vulnerabilities",
        "low_vulnerabilities",
        "medium_vulnerabilities",
    ):
        count = data[key]
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            raise ContractError(f"{key} must be a non-negative integer")
    expected = {
        "grype-image.json": ("grype", "oci"),
        "trivy-filesystem.json": ("trivy", "filesystem"),
        "trivy-image.json": ("trivy", "oci"),
    }
    scanner, scope = expected[name]
    if (data["scanner"], data["scope"], data["scanner_version"]) != (
        scanner,
        scope,
        EXPECTED_TOOL_VERSIONS[scanner],
    ):
        raise ContractError(f"{name} scanner identity differs from the approved scope")
    return data


def _validate_scan_summary(value: object, name: str) -> dict[str, object]:
    data = _object(value, name)
    if data.get("schema_version") == SCAN_SCHEMA:
        return _validate_scan_summary_v2(data, name)
    return _validate_scan_summary_v1(data, name)


def _validate_sbom(path: Path, name: str) -> int:
    data = _object(load_json(path), name)
    if name == "sbom.spdx.json":
        packages = data.get("packages")
        if not isinstance(data.get("spdxVersion"), str) or not str(data["spdxVersion"]).startswith(
            "SPDX-"
        ):
            raise ContractError("SPDX SBOM does not identify SPDX")
        if not isinstance(packages, list) or not packages:
            raise ContractError("SPDX SBOM contains no package inventory")
        return len(packages)
    components = data.get("components")
    if data.get("bomFormat") != "CycloneDX":
        raise ContractError("CycloneDX SBOM does not identify CycloneDX")
    if not isinstance(components, list) or not components:
        raise ContractError("CycloneDX SBOM contains no component inventory")
    return len(components)


def _write_supply_chain_records_v1(
    directory: Path,
    source_commit: str,
    image_digest: str,
) -> None:
    source = _commit(source_commit)
    digest = _digest(image_digest)
    input_names = SUPPLY_CHAIN_NAMES_V1[:6]
    inputs: list[Path] = []
    critical = 0
    for name in input_names:
        path = directory / name
        value = load_json(path)
        assert_content_safe(value)
        if name.startswith(("trivy-", "grype-")):
            summary = _validate_scan_summary_v1(value, name)
            critical += cast(int, summary["critical_vulnerabilities"])
        inputs.append(path)
    provenance = {
        "image_digest": digest,
        "reports": [f"{path.name}:sha256:{file_sha256(path)}" for path in inputs],
        "schema_version": PROVENANCE_SCHEMA_V1,
        "source_commit": source,
        "tool_versions": EXPECTED_TOOL_VERSIONS_V1,
    }
    gates = {
        "candidate_identity": True,
        "cyclonedx_sbom": True,
        "grype_image": True,
        "spdx_sbom": True,
        "trivy_filesystem": True,
        "trivy_image": True,
    }
    eligibility = {
        "critical_vulnerabilities": critical,
        "deployable": False,
        "eligible_for_owner_approval": critical == 0,
        "image_digest": digest,
        "mandatory_gates": gates,
        "schema_version": ELIGIBILITY_SCHEMA_V1,
        "source_commit": source,
        "w5_001_status": "FAIL",
    }
    write_json(directory / "provenance.json", _validate_provenance_v1(provenance))
    write_json(directory / "eligibility.json", _validate_eligibility_v1(eligibility))
    if critical:
        raise ContractError("CRITICAL vulnerabilities reject the Phase A candidate")


def write_cleanup_retention(output: Path) -> None:
    value = {
        "cloud_activity": "NOT RUN",
        "deployment_status": "NOT RUN",
        "historical_evidence": "RETAINED",
        "migration_created_temporary_resources": "REMOVED",
        "repository_unapproved_runtime_residue": "ZERO",
        "retained_evidence": list(SUPPLY_CHAIN_NAMES),
        "schema_version": CLEANUP_SCHEMA,
        "shared_resources": "RETAINED",
    }
    write_json(output, _validate_cleanup(value))


def write_supply_chain_records(directory: Path) -> None:
    image_path = directory / "image-identity.json"
    image = validate_image_identity(load_json(image_path))
    if image["schema_version"] != IMAGE_SCHEMA:
        raise ContractError("v2 reconciliation requires a v2 image identity")
    source = _source_identity(image["source_identity"])
    application = _object(image["application_image"], "application_image")
    application_digest = _digest(application["manifest_digest"], "application_manifest_digest")
    inputs = _object(image["inputs"], "inputs")
    scan_names = ("trivy-filesystem.json", "trivy-image.json", "grype-image.json")
    scans: dict[str, dict[str, object]] = {}
    for name in scan_names:
        summary = _validate_scan_summary_v2(load_json(directory / name), name)
        if (
            summary["application_manifest_digest"] != application_digest
            or summary["source_composition_sha256"] != source["source_composition_sha256"]
        ):
            raise ContractError("scan summary does not bind the v2 candidate identity")
        scans[name] = summary
    if (
        scans["trivy-filesystem.json"]["scanner_database_identity"]
        != scans["trivy-image.json"]["scanner_database_identity"]
    ):
        raise ContractError("Trivy scans must use one database identity")
    _validate_sbom(directory / "sbom.spdx.json", "sbom.spdx.json")
    _validate_sbom(directory / "sbom.cyclonedx.json", "sbom.cyclonedx.json")
    cleanup = _validate_cleanup(load_json(directory / "cleanup-retention.json"))
    input_names = SUPPLY_CHAIN_NAMES[:6]
    report_paths = [directory / name for name in input_names]
    provenance = {
        "application_manifest_digest": application_digest,
        "image_identity_report_sha256": f"sha256:{file_sha256(image_path)}",
        "reports": [f"{path.name}:sha256:{file_sha256(path)}" for path in report_paths],
        "scanner_databases": {
            "grype": scans["grype-image.json"]["scanner_database_identity"],
            "trivy": scans["trivy-image.json"]["scanner_database_identity"],
        },
        "schema_version": PROVENANCE_SCHEMA,
        "source_identity": source,
        "tool_versions": EXPECTED_TOOL_VERSIONS,
    }
    rollback = {
        "application_image": application,
        "deployment_status": "NOT RUN",
        "inputs": inputs,
        "rollback_status": "IDENTITY_RECORDED",
        "schema_version": ROLLBACK_SCHEMA,
        "source_identity": source,
    }
    trivy_critical = cast(int, scans["trivy-filesystem.json"]["critical_vulnerabilities"]) + cast(
        int, scans["trivy-image.json"]["critical_vulnerabilities"]
    )
    grype_critical = cast(int, scans["grype-image.json"]["critical_vulnerabilities"])
    gates = {
        "candidate_identity": True,
        "cleanup": cleanup["migration_created_temporary_resources"] == "REMOVED",
        "cyclonedx_sbom": True,
        "grype_image": True,
        "provenance": True,
        "rollback_identity": True,
        "scanner_reconciliation": trivy_critical == 0 and grype_critical == 0,
        "spdx_sbom": True,
        "trivy_filesystem": True,
        "trivy_image": True,
    }
    provenance_path = directory / "provenance.json"
    rollback_path = directory / "rollback-identity.json"
    write_json(provenance_path, validate_provenance(provenance))
    write_json(rollback_path, _validate_rollback(rollback))
    eligibility = {
        "application_manifest_digest": application_digest,
        "cleanup_retention_report_sha256": (
            f"sha256:{file_sha256(directory / 'cleanup-retention.json')}"
        ),
        "critical_vulnerabilities": {"grype": grype_critical, "trivy": trivy_critical},
        "deployable": False,
        "eligible_for_owner_approval": (
            trivy_critical == 0 and grype_critical == 0 and all(gates.values())
        ),
        "formal_w5_002_status": "FAIL",
        "mandatory_gates": gates,
        "provenance_report_sha256": f"sha256:{file_sha256(provenance_path)}",
        "rollback_identity_report_sha256": f"sha256:{file_sha256(rollback_path)}",
        "schema_version": ELIGIBILITY_SCHEMA,
        "source_identity": source,
        "vulnerability_free_claim": False,
        "w5_001_status": "FAIL",
    }
    write_json(directory / "eligibility.json", validate_eligibility(eligibility))
    if trivy_critical or grype_critical:
        raise ContractError("CRITICAL vulnerabilities reject the Python 3.13 candidate")


def validate_report_set(directory: Path, profile: str) -> None:
    if profile not in {"plan", "supply-chain"}:
        raise ContractError("unknown report profile")
    if not directory.is_dir() or directory.is_symlink():
        raise ContractError("report directory is missing or unsafe")
    actual = tuple(sorted(path.name for path in directory.iterdir()))
    if profile == "plan":
        expected: tuple[str, ...] = PLAN_NAMES
    elif actual == tuple(sorted(SUPPLY_CHAIN_NAMES_V1)):
        expected = SUPPLY_CHAIN_NAMES_V1
    else:
        expected = SUPPLY_CHAIN_NAMES
    if actual != tuple(sorted(expected)):
        raise ContractError("report set is missing, partial, or contains an unknown file")
    total = 0
    v1_identities: set[tuple[str, str]] = set()
    v2_identities: set[tuple[str, str]] = set()
    for name in expected:
        path = directory / name
        if path.is_symlink():
            raise ContractError(f"symlink report prohibited: {name}")
        size = path.stat().st_size
        if size > MAXIMUM_FILE_BYTES:
            raise ContractError(f"report exceeds maximum size: {name}")
        total += size
        data = _object(load_json(path), name)
        assert_content_safe(data)
        if name in {
            "cleanup-retention.json",
            "eligibility.json",
            "image-identity.json",
            "provenance.json",
            "rollback-identity.json",
            "terraform-plan-summary.json",
        }:
            validate_schema(data)
            _assert_canonical(path, data)
        elif name in {"grype-image.json", "trivy-filesystem.json", "trivy-image.json"}:
            summary = _validate_scan_summary(data, name)
            _assert_canonical(path, data)
            if summary.get("schema_version") == SCAN_SCHEMA:
                v2_identities.add(
                    (
                        _digest(summary["source_composition_sha256"]),
                        _digest(summary["application_manifest_digest"]),
                    )
                )
        elif name in {"sbom.cyclonedx.json", "sbom.spdx.json"}:
            _validate_sbom(path, name)
        if profile == "supply-chain" and "source_commit" in data and "image_digest" in data:
            v1_identities.add((_commit(data["source_commit"]), _digest(data["image_digest"])))
        if profile == "supply-chain" and "source_identity" in data:
            source = _source_identity(data["source_identity"])
            application_digest = data.get("application_manifest_digest")
            if application_digest is None and "application_image" in data:
                application_digest = _object(data["application_image"], "application_image").get(
                    "manifest_digest"
                )
            if application_digest is not None:
                v2_identities.add(
                    (
                        _digest(source["source_composition_sha256"]),
                        _digest(application_digest),
                    )
                )
    if total > MAXIMUM_RUN_BYTES:
        raise ContractError("report set exceeds maximum run size")
    if profile == "supply-chain" and len(v1_identities | v2_identities) != 1:
        raise ContractError("supply-chain reports do not share one candidate identity")


def _plan_change_counts(value: object) -> dict[str, int]:
    root = _object(value, "Terraform plan JSON")
    changes = root.get("resource_changes")
    if not isinstance(changes, list):
        raise ContractError("Terraform plan JSON must contain resource_changes")
    counts = {"add": 0, "change": 0, "destroy": 0, "no_op": 0, "read": 0}
    action_map = {
        ("create",): "add",
        ("delete",): "destroy",
        ("delete", "create"): "change",
        ("create", "delete"): "change",
        ("no-op",): "no_op",
        ("read",): "read",
        ("update",): "change",
    }
    for item in changes:
        change = _object(_object(item, "resource change").get("change"), "change")
        actions = change.get("actions")
        if not isinstance(actions, list) or any(not isinstance(action, str) for action in actions):
            raise ContractError("Terraform resource actions must be an ordered string list")
        bucket = action_map.get(tuple(cast(list[str], actions)))
        if bucket is None:
            raise ContractError("Terraform plan contains an unsupported action sequence")
        counts[bucket] += 1
    return counts


def write_plan_summary(
    output: Path,
    plan: object,
    source_commit: str,
    generated_at: str,
) -> None:
    generated = _timestamp(generated_at, "generated_at")
    expires = generated + timedelta(hours=24)
    value = {
        "changes": _plan_change_counts(plan),
        "environment": ENVIRONMENT,
        "expires_at": expires.isoformat(),
        "generated_at": generated.isoformat(),
        "raw_plan_retained": False,
        "redacted": True,
        "ref": REF,
        "repository": REPOSITORY,
        "schema_version": PLAN_SCHEMA,
        "source_commit": _commit(source_commit),
        "terraform_version": "1.16.1",
    }
    write_json(output, validate_plan_summary(value))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate bounded W5-002 CI contracts")
    subparsers = parser.add_subparsers(dest="command", required=True)
    config = subparsers.add_parser("validate-config")
    config.add_argument("--config", type=Path, required=True)
    locks = subparsers.add_parser("validate-locks")
    locks.add_argument("--runtime", type=Path, required=True)
    locks.add_argument("--ci", type=Path, required=True)
    locks.add_argument("--checkov", type=Path, required=True)
    report = subparsers.add_parser("validate-report")
    report.add_argument("--input", type=Path, required=True)
    reports = subparsers.add_parser("validate-reports")
    reports.add_argument("--reports-dir", type=Path, required=True)
    reports.add_argument("--profile", choices=("plan", "supply-chain"), required=True)
    canonicalize = subparsers.add_parser("canonicalize")
    canonicalize.add_argument("--input", type=Path, required=True)
    canonicalize.add_argument("--output", type=Path, required=True)
    identity = subparsers.add_parser("write-image-identity")
    identity.add_argument("--output", type=Path, required=True)
    identity.add_argument("--repository-root", type=Path, required=True)
    identity.add_argument("--oci-archive", type=Path, required=True)
    identity.add_argument("--source-commit")
    reconcile = subparsers.add_parser("reconcile-supply-chain")
    reconcile.add_argument("--reports-dir", type=Path, required=True)
    scan = subparsers.add_parser("write-scan-summary")
    scan.add_argument("--input", type=Path, required=True)
    scan.add_argument("--output", type=Path, required=True)
    scan.add_argument("--image-identity", type=Path, required=True)
    scan.add_argument("--scanner-database-identity", required=True)
    scan.add_argument("--scanner", choices=("grype", "trivy"), required=True)
    scan.add_argument("--scope", choices=("filesystem", "oci"), required=True)
    cleanup = subparsers.add_parser("write-cleanup-retention")
    cleanup.add_argument("--output", type=Path, required=True)
    plan = subparsers.add_parser("write-plan-summary")
    plan.add_argument("--input", type=Path, required=True)
    plan.add_argument("--output", type=Path, required=True)
    plan.add_argument("--source-commit", required=True)
    plan.add_argument("--generated-at", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the local helper without network or external-process access."""
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "validate-config":
            validate_config(load_json(arguments.config))
        elif arguments.command == "validate-locks":
            validate_dependency_lock(arguments.runtime, "runtime")
            validate_dependency_lock(arguments.ci, "ci")
            validate_dependency_lock(arguments.checkov, "checkov")
        elif arguments.command == "validate-report":
            validate_schema(load_json(arguments.input))
        elif arguments.command == "validate-reports":
            validate_report_set(arguments.reports_dir, arguments.profile)
        elif arguments.command == "canonicalize":
            value = validate_schema(load_json(arguments.input))
            write_json(arguments.output, value)
        elif arguments.command == "write-image-identity":
            write_image_identity(
                arguments.output,
                arguments.repository_root,
                arguments.oci_archive,
                arguments.source_commit,
            )
        elif arguments.command == "reconcile-supply-chain":
            write_supply_chain_records(arguments.reports_dir)
        elif arguments.command == "write-scan-summary":
            write_scan_summary(
                arguments.input,
                arguments.output,
                arguments.image_identity,
                arguments.scanner,
                arguments.scope,
                arguments.scanner_database_identity,
            )
        elif arguments.command == "write-cleanup-retention":
            write_cleanup_retention(arguments.output)
        elif arguments.command == "write-plan-summary":
            write_plan_summary(
                arguments.output,
                load_json(arguments.input),
                arguments.source_commit,
                arguments.generated_at,
            )
        else:
            raise ContractError("unsupported command")
    except ContractError as exc:
        print(f"W5-002 VALIDATION FAIL: {exc}", file=sys.stderr)
        return 1
    except OSError:
        print("W5-002 VALIDATION FAIL: bounded file operation failed", file=sys.stderr)
        return 1
    print("W5-002 VALIDATION PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
