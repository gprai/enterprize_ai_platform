"""Fail-closed W6-004 immutable-image evidence validation."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from .live_validation import W6004Error, validate_evidence_record

DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
IMAGE_SCHEMA = "w6-004.image.v1"
REPOSITORY = "526338061652.dkr.ecr.ap-southeast-1.amazonaws.com/enterprise-ai/sandbox/api"


class ImageLifecycleError(ValueError):
    """Raised when image evidence is incomplete or inconsistent."""


def validate_image_evidence(
    value: object,
    *,
    now: datetime | None = None,
    consumed_approvals: Sequence[str] = (),
) -> Mapping[str, object]:
    """Validate source, build, scan, SBOM, provenance and registry identities."""

    try:
        evidence = validate_evidence_record(
            value,
            expected_schema=IMAGE_SCHEMA,
            now=now,
            consumed_approvals=consumed_approvals,
        )
    except W6004Error as exc:
        raise ImageLifecycleError(str(exc)) from exc
    for field in ("base_image_digest", "oci_digest", "registry_digest"):
        digest = evidence.get(field)
        if not isinstance(digest, str) or DIGEST.fullmatch(digest) is None:
            raise ImageLifecycleError(f"{field} must be an immutable digest")
    if evidence.get("oci_digest") != evidence.get("registry_digest"):
        raise ImageLifecycleError("registry-returned digest differs from the OCI identity")
    if evidence.get("repository_uri") != REPOSITORY:
        raise ImageLifecycleError("repository_uri differs from the approved ECR repository")
    return evidence


class CoverageResult(StrEnum):
    COVERED = "COVERED"
    SKIPPED = "SKIPPED"
    INDETERMINATE = "INDETERMINATE"


@dataclass(frozen=True)
class OciIdentity:
    index_digest: str
    manifest_digest: str
    configuration_digest: str
    archive_sha256: str


@dataclass(frozen=True)
class PackageReconciliation:
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
    coverage: CoverageResult
    skipped_package_count: int


def validate_oci_identity(value: OciIdentity) -> OciIdentity:
    for field in (value.index_digest, value.manifest_digest, value.configuration_digest):
        if DIGEST.fullmatch(field) is None:
            raise ImageLifecycleError("OCI identity must use immutable typed digests")
    if len({value.index_digest, value.manifest_digest, value.configuration_digest}) != 3:
        raise ImageLifecycleError("OCI index, manifest and configuration identities are distinct")
    if re.fullmatch(r"[0-9a-f]{64}", value.archive_sha256) is None:
        raise ImageLifecycleError("OCI archive SHA-256 is malformed")
    if value.archive_sha256 in {
        value.index_digest.removeprefix("sha256:"),
        value.manifest_digest.removeprefix("sha256:"),
        value.configuration_digest.removeprefix("sha256:"),
    }:
        raise ImageLifecycleError("OCI archive identity must remain distinct from OCI digests")
    return value


def validate_package_reconciliation(value: PackageReconciliation) -> PackageReconciliation:
    from urllib.parse import unquote

    for digest in (value.sbom_sha256, value.trivy_sha256, value.grype_sha256):
        if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise ImageLifecycleError("supply-chain evidence SHA-256 is malformed")
    if value.sbom_format not in {"SPDX", "CycloneDX"}:
        raise ImageLifecycleError("SBOM format differs")
    if not all((value.package_name, value.package_version, value.ecosystem, value.original_purl)):
        raise ImageLifecycleError("package identity is incomplete")
    if value.original_purl != value.normalized_purl and not value.normalization_reason:
        raise ImageLifecycleError("PURL normalization requires a reason")
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
            raise ImageLifecycleError("PURL normalization changed package semantics")
    if value.skipped_package_count < 0:
        raise ImageLifecycleError("skipped-package count is invalid")
    if value.skipped_package_count and value.coverage is CoverageResult.COVERED:
        raise ImageLifecycleError("skipped packages cannot be classified as fully covered")
    return value
