"""Fail-closed W6-004 immutable-image evidence validation."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from datetime import datetime

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
