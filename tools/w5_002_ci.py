"""Deterministic, content-safe W5-002 CI report validation helpers."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta
from pathlib import Path
from typing import cast

CONFIG_SCHEMA = "w5-002.ci-config.v1"
IMAGE_SCHEMA = "w5-002.image-identity.v1"
PLAN_SCHEMA = "w5-002.plan-summary.v1"
PROVENANCE_SCHEMA = "w5-002.provenance.v1"
ELIGIBILITY_SCHEMA = "w5-002.eligibility.v1"
MAXIMUM_FILE_BYTES = 52_428_800
MAXIMUM_RUN_BYTES = 104_857_600
REPOSITORY = "gprai/enterprize_ai_platform"
REF = "refs/heads/main"
ENVIRONMENT = "sandbox"
PLATFORM = "linux/amd64"
BASE_IMAGE = (
    "python:3.11.16-slim-bookworm@sha256:"
    "b1add8a6f2aca6bcfcf0b9c9b522352f7ce0d62a3d556a2f2f32511aa0cca250"
)
REPORT_PATHS = (
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
SUPPLY_CHAIN_NAMES = tuple(Path(path).name for path in REPORT_PATHS[:-1])
PLAN_NAMES = (Path(REPORT_PATHS[-1]).name,)
EXPECTED_TOOL_VERSIONS = {
    "actionlint": "1.7.12",
    "checkov": "3.3.16",
    "grype": "0.118.0",
    "opa": "1.20.0",
    "syft": "1.51.1",
    "terraform": "1.16.1",
    "tflint": "0.60.0",
    "trivy": "0.74.0",
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


def validate_image_identity(value: object) -> dict[str, object]:
    data = _object(value, IMAGE_SCHEMA)
    _exact_keys(
        data,
        {"base_image", "image_digest", "platform", "schema_version", "source_commit"},
        IMAGE_SCHEMA,
    )
    if data["schema_version"] != IMAGE_SCHEMA:
        raise ContractError("unexpected image identity schema")
    _commit(data["source_commit"])
    _digest(data["image_digest"])
    if data["platform"] != PLATFORM or data["base_image"] != BASE_IMAGE:
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


def validate_provenance(value: object) -> dict[str, object]:
    data = _object(value, PROVENANCE_SCHEMA)
    _exact_keys(
        data,
        {"image_digest", "reports", "schema_version", "source_commit", "tool_versions"},
        PROVENANCE_SCHEMA,
    )
    if data["schema_version"] != PROVENANCE_SCHEMA:
        raise ContractError("unexpected provenance schema")
    _commit(data["source_commit"])
    _digest(data["image_digest"])
    tools = _object(data["tool_versions"], "tool_versions")
    if tools != EXPECTED_TOOL_VERSIONS:
        raise ContractError("tool versions differ from approved immutable identities")
    reports = data["reports"]
    if not isinstance(reports, list) or any(not isinstance(item, str) for item in reports):
        raise ContractError("provenance reports must be an ordered string list")
    expected_names = SUPPLY_CHAIN_NAMES[:6]
    if len(reports) != len(expected_names):
        raise ContractError("provenance must bind all six candidate input reports")
    for report, expected_name in zip(cast(list[str], reports), expected_names, strict=True):
        prefix = f"{expected_name}:"
        if not report.startswith(prefix):
            raise ContractError("provenance report ordering differs from the allowlist")
        _digest(report.removeprefix(prefix), "report digest")
    return data


def validate_eligibility(value: object) -> dict[str, object]:
    data = _object(value, ELIGIBILITY_SCHEMA)
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
        ELIGIBILITY_SCHEMA,
    )
    if data["schema_version"] != ELIGIBILITY_SCHEMA:
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


def validate_schema(value: object) -> dict[str, object]:
    data = _object(value, "report")
    schema = data.get("schema_version")
    validators = {
        IMAGE_SCHEMA: validate_image_identity,
        PLAN_SCHEMA: validate_plan_summary,
        PROVENANCE_SCHEMA: validate_provenance,
        ELIGIBILITY_SCHEMA: validate_eligibility,
    }
    validator = validators.get(schema) if isinstance(schema, str) else None
    if validator is None:
        raise ContractError("unknown or missing W5-002 schema")
    result = validator(data)
    assert_content_safe(result)
    return result


def validate_config(value: object) -> dict[str, object]:
    data = _object(value, CONFIG_SCHEMA)
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
        CONFIG_SCHEMA,
    )
    if data.get("schema_version") != CONFIG_SCHEMA:
        raise ContractError("unexpected configuration schema")
    if data.get("reports") != list(REPORT_PATHS):
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
        "base_image": BASE_IMAGE,
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
    if "--hash=sha256:" not in text or "git+" in text.casefold():
        raise ContractError("dependency lock must be hash-locked and contain no VCS source")

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
        if (
            torch_version is None
            or re.fullmatch(r"2\.13(?:\.\d+)?(?:\+cpu)?", torch_version) is None
        ):
            raise ContractError("dependency lock must contain an approved Torch 2.13 CPU pin")
        cpu_directives = {
            f"--index-url {PYTORCH_INDEX_URL}",
            f"--extra-index-url {PYTORCH_INDEX_URL}",
        }
        if not cpu_directives.intersection(line.strip() for line in text.splitlines()):
            raise ContractError("dependency lock does not preserve the approved PyTorch CPU index")
    elif "torch" in packages:
        raise ContractError("isolated Checkov lock must not contain Torch")
    return packages


def _assert_canonical(path: Path, value: object) -> None:
    if path.read_text(encoding="utf-8") != canonical_json(value):
        raise ContractError(f"non-canonical JSON: {path.name}")


def validate_report_set(directory: Path, profile: str) -> None:
    if profile not in {"plan", "supply-chain"}:
        raise ContractError("unknown report profile")
    expected = SUPPLY_CHAIN_NAMES if profile == "supply-chain" else PLAN_NAMES
    if not directory.is_dir() or directory.is_symlink():
        raise ContractError("report directory is missing or unsafe")
    actual = tuple(sorted(path.name for path in directory.iterdir()))
    if actual != tuple(sorted(expected)):
        raise ContractError("report set is missing, partial, or contains an unknown file")
    total = 0
    identities: set[tuple[str, str]] = set()
    for name in expected:
        path = directory / name
        if path.is_symlink():
            raise ContractError(f"symlink report prohibited: {name}")
        size = path.stat().st_size
        if size > MAXIMUM_FILE_BYTES:
            raise ContractError(f"report exceeds maximum size: {name}")
        total += size
        value = load_json(path)
        data = _object(value, name)
        assert_content_safe(data)
        if name in {
            "image-identity.json",
            "provenance.json",
            "eligibility.json",
            "terraform-plan-summary.json",
        }:
            validate_schema(data)
            _assert_canonical(path, data)
        elif name in {
            "grype-image.json",
            "trivy-filesystem.json",
            "trivy-image.json",
        }:
            _validate_scan_summary(data, name)
            _assert_canonical(path, data)
        if profile == "supply-chain" and name in {
            "image-identity.json",
            "grype-image.json",
            "provenance.json",
            "eligibility.json",
            "trivy-filesystem.json",
            "trivy-image.json",
        }:
            identities.add(
                (
                    _commit(data.get("source_commit")),
                    _digest(data.get("image_digest")),
                )
            )
    if total > MAXIMUM_RUN_BYTES:
        raise ContractError("report set exceeds maximum run size")
    if profile == "supply-chain" and len(identities) != 1:
        raise ContractError("supply-chain reports do not share one candidate identity")


def file_sha256(path: Path) -> str:
    """Return a lowercase digest without exposing file content."""
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def write_image_identity(output: Path, source_commit: str, image_digest: str) -> None:
    value = {
        "base_image": BASE_IMAGE,
        "image_digest": _digest(image_digest),
        "platform": PLATFORM,
        "schema_version": IMAGE_SCHEMA,
        "source_commit": _commit(source_commit),
    }
    write_json(output, validate_image_identity(value))


def _severity_counts(value: object) -> tuple[int, int]:
    """Count CRITICAL and HIGH fields in a normalized scanner document."""
    critical = 0
    high = 0
    if isinstance(value, dict):
        for key in ("Severity", "severity"):
            severity = value.get(key)
            if isinstance(severity, str):
                normalized = severity.casefold()
                critical += normalized == "critical"
                high += normalized == "high"
        for item in value.values():
            item_critical, item_high = _severity_counts(item)
            critical += item_critical
            high += item_high
    elif isinstance(value, list):
        for item in value:
            item_critical, item_high = _severity_counts(item)
            critical += item_critical
            high += item_high
    return critical, high


def write_scan_summary(
    raw_input: Path,
    output: Path,
    source_commit: str,
    image_digest: str,
    scanner: str,
    scope: str,
) -> None:
    """Reduce native scanner JSON to bounded non-sensitive counts and identity."""
    if scanner not in {"grype", "trivy"} or scope not in {"filesystem", "oci"}:
        raise ContractError("scanner and scope must use approved labels")
    raw = load_json(raw_input)
    critical, high = _severity_counts(raw)
    value = {
        "critical_vulnerabilities": critical,
        "high_vulnerabilities": high,
        "image_digest": _digest(image_digest),
        "raw_report_sha256": f"sha256:{file_sha256(raw_input)}",
        "scanner": scanner,
        "scope": scope,
        "source_commit": _commit(source_commit),
    }
    write_json(output, value)


def _validate_scan_summary(value: object, name: str) -> dict[str, object]:
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


def write_supply_chain_records(
    directory: Path,
    source_commit: str,
    image_digest: str,
) -> None:
    source = _commit(source_commit)
    digest = _digest(image_digest)
    input_names = SUPPLY_CHAIN_NAMES[:6]
    inputs: list[Path] = []
    critical = 0
    for name in input_names:
        path = directory / name
        value = load_json(path)
        assert_content_safe(value)
        if name.startswith(("trivy-", "grype-")):
            summary = _validate_scan_summary(value, name)
            critical += cast(int, summary["critical_vulnerabilities"])
        inputs.append(path)
    provenance = {
        "image_digest": digest,
        "reports": [f"{path.name}:sha256:{file_sha256(path)}" for path in inputs],
        "schema_version": PROVENANCE_SCHEMA,
        "source_commit": source,
        "tool_versions": EXPECTED_TOOL_VERSIONS,
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
        "schema_version": ELIGIBILITY_SCHEMA,
        "source_commit": source,
        "w5_001_status": "FAIL",
    }
    write_json(directory / "provenance.json", validate_provenance(provenance))
    write_json(directory / "eligibility.json", validate_eligibility(eligibility))
    if critical:
        raise ContractError("CRITICAL vulnerabilities reject the Phase A candidate")


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
    identity.add_argument("--source-commit", required=True)
    identity.add_argument("--image-digest", required=True)
    reconcile = subparsers.add_parser("reconcile-supply-chain")
    reconcile.add_argument("--reports-dir", type=Path, required=True)
    reconcile.add_argument("--source-commit", required=True)
    reconcile.add_argument("--image-digest", required=True)
    scan = subparsers.add_parser("write-scan-summary")
    scan.add_argument("--input", type=Path, required=True)
    scan.add_argument("--output", type=Path, required=True)
    scan.add_argument("--source-commit", required=True)
    scan.add_argument("--image-digest", required=True)
    scan.add_argument("--scanner", choices=("grype", "trivy"), required=True)
    scan.add_argument("--scope", choices=("filesystem", "oci"), required=True)
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
                arguments.source_commit,
                arguments.image_digest,
            )
        elif arguments.command == "reconcile-supply-chain":
            write_supply_chain_records(
                arguments.reports_dir,
                arguments.source_commit,
                arguments.image_digest,
            )
        elif arguments.command == "write-scan-summary":
            write_scan_summary(
                arguments.input,
                arguments.output,
                arguments.source_commit,
                arguments.image_digest,
                arguments.scanner,
                arguments.scope,
            )
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
