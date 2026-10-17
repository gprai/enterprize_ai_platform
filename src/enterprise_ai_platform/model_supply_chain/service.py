"""Fail-closed W9-004 evidence reconciliation and registry admission."""

from __future__ import annotations

import hashlib
import tarfile
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath

from enterprise_ai_platform.retrieval.models import Classification

from .errors import SupplyChainAdmissionError, SupplyChainValidationError
from .models import (
    CandidateIdentity,
    EligibilityStatus,
    EvidenceStatus,
    Finding,
    ModelInventory,
    OpaDecision,
    ProvenanceEvidence,
    RiskTreatment,
    SbomEvidence,
    ScannerEvidence,
    SourceLicenseEvidence,
    SupplyChainEligibility,
)
from .policy import SupplyChainPolicy


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as error:
        raise SupplyChainValidationError("candidate artifact cannot be read") from error
    return digest.hexdigest()


def inspect_model_archive(path: Path, policy: SupplyChainPolicy) -> ModelInventory:
    if not path.is_file():
        raise SupplyChainValidationError("candidate artifact must be a regular file")
    if path.stat().st_size > policy.limits.maximum_artifact_bytes:
        raise SupplyChainAdmissionError("candidate artifact exceeds the approved size limit")
    forbidden: set[str] = set()
    weights: set[str] = set()
    total = 0
    names: set[str] = set()
    try:
        with tarfile.open(path, mode="r:*") as archive:
            members = archive.getmembers()
            if not members or len(members) > policy.limits.maximum_archive_entries:
                raise SupplyChainAdmissionError("archive entry count is outside policy")
            for member in members:
                if member.isfile():
                    total += member.size
                normalized = PurePosixPath(member.name.replace("\\", "/"))
                parts = normalized.parts
                if (
                    normalized.is_absolute()
                    or ".." in parts
                    or any(":" in part for part in parts)
                    or member.issym()
                    or member.islnk()
                ):
                    forbidden.add(member.name)
                    continue
                folded = normalized.as_posix().casefold()
                if folded in names:
                    forbidden.add(member.name)
                    continue
                names.add(folded)
                if member.isfile():
                    suffix = normalized.suffix.casefold()
                    if suffix in policy.security.allowed_weight_extensions:
                        weights.add(normalized.as_posix())
                    elif suffix in policy.security.denied_extensions:
                        forbidden.add(normalized.as_posix())
    except (OSError, tarfile.TarError) as error:
        raise SupplyChainValidationError("candidate must be a readable tar archive") from error
    if total > policy.limits.maximum_artifact_bytes:
        raise SupplyChainAdmissionError("expanded candidate exceeds the approved size limit")
    status = EvidenceStatus.PASS if weights and not forbidden else EvidenceStatus.FAIL
    return ModelInventory(
        artifact_sha256=sha256_file(path),
        file_count=len(members),
        total_uncompressed_bytes=total,
        weight_files=tuple(sorted(weights)),
        forbidden_files=tuple(sorted(forbidden)),
        status=status,
    )


def _high_finding_keys(eligibility: SupplyChainEligibility) -> set[str]:
    return {
        finding.finding_id
        for scanner in eligibility.scanners
        for finding in scanner.findings
        if finding.severity.value == "HIGH"
    }


def require_registry_eligible(
    eligibility: SupplyChainEligibility,
    *,
    artifact_source_uri: str,
    artifact_sha256: str,
    container_image_digest: str,
    training_request_identity_sha256: str,
    experiment_run_identity_sha256: str,
    evaluation_report_sha256: str,
    tenant_reference_sha256: str,
    classification: str,
    now: datetime,
) -> None:
    if now.tzinfo is None or now.utcoffset() != UTC.utcoffset(now):
        raise SupplyChainValidationError("admission time must use UTC")
    if eligibility.status is not EligibilityStatus.PASS or not eligibility.opa_decision.allow:
        raise SupplyChainAdmissionError("candidate supply-chain eligibility is not PASS")
    if eligibility.generated_at > now or eligibility.provenance.verified_at > now:
        raise SupplyChainAdmissionError("candidate supply-chain evidence is future-dated")
    if now >= eligibility.expires_at or eligibility.provenance.expires_at <= now:
        raise SupplyChainAdmissionError("candidate supply-chain evidence has expired")
    candidate = eligibility.candidate
    expected = (
        (candidate.artifact_source_uri, artifact_source_uri),
        (candidate.artifact_sha256, artifact_sha256),
        (candidate.container_image_digest, container_image_digest),
        (candidate.training_request_identity_sha256, training_request_identity_sha256),
        (candidate.experiment_run_identity_sha256, experiment_run_identity_sha256),
        (candidate.evaluation_report_sha256, evaluation_report_sha256),
        (eligibility.tenant_reference_sha256, tenant_reference_sha256),
        (eligibility.classification.value, classification),
    )
    if any(actual != required for actual, required in expected):
        raise SupplyChainAdmissionError("candidate supply-chain binding differs")
    if any(item.critical_findings for item in eligibility.scanners):
        raise SupplyChainAdmissionError("critical findings are not eligible")
    vulnerability_scanners = tuple(
        item.findings for item in eligibility.scanners if item.scanner in {"grype", "trivy"}
    )
    if scanner_disagreement(vulnerability_scanners):
        raise SupplyChainAdmissionError("vulnerability scanners disagree")
    high_findings = _high_finding_keys(eligibility)
    treatments = {
        item.finding_id
        for item in eligibility.risk_treatments
        if item.candidate_sha256 == artifact_sha256 and item.expires_at > now
    }
    if not high_findings.issubset(treatments):
        raise SupplyChainAdmissionError("high findings require current owner risk treatment")


def scanner_disagreement(scanners: tuple[tuple[Finding, ...], ...]) -> bool:
    normalized = [
        {(item.finding_id, item.component, item.severity.value) for item in findings}
        for findings in scanners
    ]
    return any(findings != normalized[0] for findings in normalized[1:])


def reconcile_candidate(
    *,
    candidate: CandidateIdentity,
    tenant_reference_sha256: str,
    classification: Classification,
    source_license: SourceLicenseEvidence,
    inventory: ModelInventory,
    scanners: tuple[ScannerEvidence, ...],
    sboms: tuple[SbomEvidence, ...],
    provenance: ProvenanceEvidence,
    risk_treatments: tuple[RiskTreatment, ...],
    opa_decision: OpaDecision,
    policy: SupplyChainPolicy,
    generated_at: datetime,
) -> SupplyChainEligibility:
    """Create the immutable result; callers cannot turn failed inputs into PASS."""

    vulnerability_findings = tuple(
        item.findings for item in scanners if item.scanner in {"grype", "trivy"}
    )
    high_findings = {
        finding.finding_id
        for scanner in scanners
        for finding in scanner.findings
        if finding.severity.value == "HIGH"
    }
    active_treatments = {
        item.finding_id
        for item in risk_treatments
        if item.candidate_sha256 == candidate.artifact_sha256
        and item.approved_at <= generated_at < item.expires_at
    }
    local_failure = (
        candidate.artifact_size_bytes > policy.limits.maximum_artifact_bytes
        or classification.value not in policy.security.allowed_classifications
        or source_license.status is EvidenceStatus.FAIL
        or inventory.status is EvidenceStatus.FAIL
        or any(item.status is EvidenceStatus.FAIL for item in scanners)
        or any(item.status is EvidenceStatus.FAIL for item in sboms)
        or provenance.status is EvidenceStatus.FAIL
        or any(item.critical_findings for item in scanners)
        or not high_findings.issubset(active_treatments)
        or scanner_disagreement(vulnerability_findings)
    )
    indeterminate = (
        source_license.status in {EvidenceStatus.INDETERMINATE, EvidenceStatus.NOT_SUPPORTED}
        or inventory.status in {EvidenceStatus.INDETERMINATE, EvidenceStatus.NOT_SUPPORTED}
        or any(
            item.status in {EvidenceStatus.INDETERMINATE, EvidenceStatus.NOT_SUPPORTED}
            for item in scanners
        )
        or any(
            item.status in {EvidenceStatus.INDETERMINATE, EvidenceStatus.NOT_SUPPORTED}
            for item in sboms
        )
        or provenance.status in {EvidenceStatus.INDETERMINATE, EvidenceStatus.NOT_SUPPORTED}
    )
    if local_failure and opa_decision.allow:
        raise SupplyChainValidationError("OPA decision disagrees with failed evidence")
    determinate_failure = local_failure or not opa_decision.allow
    status = (
        EligibilityStatus.FAIL
        if determinate_failure
        else EligibilityStatus.INDETERMINATE
        if indeterminate
        else EligibilityStatus.PASS
    )
    return SupplyChainEligibility(
        candidate=candidate,
        tenant_reference_sha256=tenant_reference_sha256,
        classification=classification,
        source_license=source_license,
        inventory=inventory,
        scanners=scanners,
        sboms=sboms,
        provenance=provenance,
        risk_treatments=risk_treatments,
        opa_decision=opa_decision,
        policy_sha256=policy.identity_sha256,
        generated_at=generated_at,
        expires_at=generated_at + timedelta(hours=policy.limits.evidence_freshness_hours),
        status=status,
    )
