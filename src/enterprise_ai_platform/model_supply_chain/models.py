"""Strict immutable W9-004 model supply-chain evidence contracts."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from enterprise_ai_platform.retrieval.models import Classification

SHA256_PATTERN = r"^[0-9a-f]{64}$"
OCI_DIGEST_PATTERN = r"^sha256:[0-9a-f]{64}$"
SAFE_VALUE_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}$"


class SupplyChainModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid", frozen=True, strict=True, str_strip_whitespace=True, validate_default=True
    )


class EvidenceStatus(StrEnum):
    PASS = "P" + "ASS"
    FAIL = "FAIL"
    INDETERMINATE = "INDETERMINATE"
    NOT_SUPPORTED = "NOT_SUPPORTED"


class EligibilityStatus(StrEnum):
    PASS = "P" + "ASS"
    FAIL = "FAIL"
    INDETERMINATE = "INDETERMINATE"


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Finding(SupplyChainModel):
    finding_id: str = Field(pattern=SAFE_VALUE_PATTERN)
    component: str = Field(pattern=SAFE_VALUE_PATTERN)
    severity: Severity
    installed_version: str = Field(pattern=SAFE_VALUE_PATTERN)
    fixed_version: str | None = Field(default=None, pattern=SAFE_VALUE_PATTERN)


class SourceLicenseEvidence(SupplyChainModel):
    source_repository: str = Field(pattern=SAFE_VALUE_PATTERN)
    source_revision: str = Field(pattern=r"^[0-9a-f]{40}$")
    source_manifest_sha256: str = Field(pattern=SHA256_PATTERN)
    license_spdx: Literal["Apache-2.0"] = "Apache-2.0"
    license_text_sha256: str = Field(pattern=SHA256_PATTERN)
    status: EvidenceStatus


class ScannerEvidence(SupplyChainModel):
    scanner: Literal["trivy", "grype", "model-format", "checkov"]
    scanner_version: str = Field(pattern=SAFE_VALUE_PATTERN)
    database_identity: str = Field(pattern=r"^(sha256:[0-9a-f]{64}|NOT_APPLICABLE)$")
    subject_sha256: str = Field(pattern=SHA256_PATTERN)
    report_sha256: str = Field(pattern=SHA256_PATTERN)
    critical_findings: int = Field(ge=0, le=100_000)
    high_findings: int = Field(ge=0, le=100_000)
    status: EvidenceStatus
    findings: tuple[Finding, ...] = Field(default=(), max_length=10_000)

    @model_validator(mode="after")
    def require_ordered_findings(self) -> ScannerEvidence:
        keys = tuple(
            (item.finding_id, item.component, item.installed_version) for item in self.findings
        )
        if keys != tuple(sorted(set(keys))):
            raise ValueError("scanner findings must be sorted and unique")
        return self


class SbomEvidence(SupplyChainModel):
    format: Literal["spdx-json", "cyclonedx-json"]
    subject_sha256: str = Field(pattern=SHA256_PATTERN)
    report_sha256: str = Field(pattern=SHA256_PATTERN)
    generator: str = Field(pattern=SAFE_VALUE_PATTERN)
    generator_version: str = Field(pattern=SAFE_VALUE_PATTERN)
    status: EvidenceStatus


class ProvenanceEvidence(SupplyChainModel):
    subject_sha256: str = Field(pattern=SHA256_PATTERN)
    statement_sha256: str = Field(pattern=SHA256_PATTERN)
    signature_sha256: str = Field(pattern=SHA256_PATTERN)
    issuer: str = Field(min_length=1, max_length=500)
    subject: str = Field(min_length=1, max_length=500)
    verifier: Literal["cosign"] = "cosign"
    verifier_version: Literal["3.1.2"] = "3.1.2"
    verified_at: datetime
    expires_at: datetime
    status: EvidenceStatus

    @field_validator("verified_at", "expires_at")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
            raise ValueError("provenance timestamps must use UTC")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def require_bounded_expiry(self) -> ProvenanceEvidence:
        if self.expires_at <= self.verified_at:
            raise ValueError("provenance expiry must follow verification")
        return self


class RiskTreatment(SupplyChainModel):
    finding_id: str = Field(pattern=SAFE_VALUE_PATTERN)
    candidate_sha256: str = Field(pattern=SHA256_PATTERN)
    owner_reference_sha256: str = Field(pattern=SHA256_PATTERN)
    approval_reference_sha256: str = Field(pattern=SHA256_PATTERN)
    reason_code: str = Field(pattern=r"^[A-Z][A-Z0-9_]{0,79}$")
    rationale_reference_sha256: str = Field(pattern=SHA256_PATTERN)
    approved_at: datetime
    expires_at: datetime

    @field_validator("approved_at", "expires_at")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
            raise ValueError("risk-treatment timestamps must use UTC")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def require_bounded_expiry(self) -> RiskTreatment:
        if self.expires_at <= self.approved_at:
            raise ValueError("risk-treatment expiry must follow approval")
        return self


class ModelInventory(SupplyChainModel):
    artifact_sha256: str = Field(pattern=SHA256_PATTERN)
    file_count: int = Field(ge=1, le=10_000)
    total_uncompressed_bytes: int = Field(ge=0, le=10_737_418_240)
    weight_files: tuple[str, ...] = Field(max_length=10_000)
    forbidden_files: tuple[str, ...] = Field(default=(), max_length=10_000)
    status: EvidenceStatus

    @model_validator(mode="after")
    def require_ordered_paths(self) -> ModelInventory:
        for paths in (self.weight_files, self.forbidden_files):
            if paths != tuple(sorted(set(paths))):
                raise ValueError("inventory paths must be sorted and unique")
        if self.status is EvidenceStatus.PASS and not self.weight_files:
            raise ValueError("PASS inventory requires at least one safe weight file")
        if self.forbidden_files and self.status is EvidenceStatus.PASS:
            raise ValueError("forbidden files cannot produce PASS")
        return self


class CandidateIdentity(SupplyChainModel):
    artifact_source_uri: str = Field(min_length=1, max_length=2000)
    artifact_sha256: str = Field(pattern=SHA256_PATTERN)
    artifact_size_bytes: int = Field(gt=0, le=10_737_418_240)
    artifact_object_version_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._+=/-]{0,255}$")
    container_image_digest: str = Field(pattern=OCI_DIGEST_PATTERN)
    container_eligibility_sha256: str = Field(pattern=SHA256_PATTERN)
    source_repository: str = Field(pattern=SAFE_VALUE_PATTERN)
    source_revision: str = Field(pattern=r"^[0-9a-f]{40}$")
    source_manifest_sha256: str = Field(pattern=SHA256_PATTERN)
    license_spdx: Literal["Apache-2.0"] = "Apache-2.0"
    license_text_sha256: str = Field(pattern=SHA256_PATTERN)
    evaluation_report_sha256: str = Field(pattern=SHA256_PATTERN)
    reproducible_config_sha256: str = Field(pattern=SHA256_PATTERN)
    training_request_identity_sha256: str = Field(pattern=SHA256_PATTERN)
    experiment_run_identity_sha256: str = Field(pattern=SHA256_PATTERN)
    region: Literal["ap-southeast-1"] = "ap-southeast-1"

    @field_validator("artifact_source_uri")
    @classmethod
    def require_safe_s3_uri(cls, value: str) -> str:
        parsed = urlsplit(value)
        if (
            parsed.scheme != "s3"
            or not parsed.netloc
            or parsed.path in {"", "/"}
            or parsed.query
            or parsed.fragment
            or parsed.username
            or parsed.password
        ):
            raise ValueError("candidate artifact must use a credential-free S3 object URI")
        return value


class OpaDecision(SupplyChainModel):
    policy_sha256: str = Field(pattern=SHA256_PATTERN)
    input_sha256: str = Field(pattern=SHA256_PATTERN)
    decision_sha256: str = Field(pattern=SHA256_PATTERN)
    allow: bool
    reasons: tuple[str, ...] = Field(default=(), max_length=100)

    @field_validator("reasons")
    @classmethod
    def require_ordered_reasons(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))):
            raise ValueError("OPA reasons must be sorted and unique")
        return value


class SupplyChainEligibility(SupplyChainModel):
    schema_version: Literal["w9-004.eligibility.v1"] = "w9-004.eligibility.v1"
    candidate: CandidateIdentity
    tenant_reference_sha256: str = Field(pattern=SHA256_PATTERN)
    classification: Classification
    source_license: SourceLicenseEvidence
    inventory: ModelInventory
    scanners: tuple[ScannerEvidence, ...] = Field(min_length=4, max_length=4)
    sboms: tuple[SbomEvidence, ...] = Field(min_length=2, max_length=2)
    provenance: ProvenanceEvidence
    risk_treatments: tuple[RiskTreatment, ...] = Field(default=(), max_length=100)
    opa_decision: OpaDecision
    policy_sha256: str = Field(pattern=SHA256_PATTERN)
    generated_at: datetime
    expires_at: datetime
    status: EligibilityStatus
    deployment_approval: Literal["NOT_AUTHORIZED"] = "NOT_AUTHORIZED"

    @field_validator("generated_at", "expires_at")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
            raise ValueError("eligibility timestamps must use UTC")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def require_exact_pass_evidence(self) -> SupplyChainEligibility:
        if self.classification not in {Classification.PUBLIC, Classification.INTERNAL}:
            raise ValueError("supply-chain eligibility supports PUBLIC or INTERNAL only")
        if self.expires_at <= self.generated_at:
            raise ValueError("eligibility expiry must follow generation")
        if (self.expires_at - self.generated_at).total_seconds() > 86_400:
            raise ValueError("eligibility freshness exceeds twenty-four hours")
        if self.inventory.artifact_sha256 != self.candidate.artifact_sha256:
            raise ValueError("inventory candidate identity differs")
        source = self.source_license
        if (
            source.source_repository != self.candidate.source_repository
            or source.source_revision != self.candidate.source_revision
            or source.source_manifest_sha256 != self.candidate.source_manifest_sha256
            or source.license_spdx != self.candidate.license_spdx
            or source.license_text_sha256 != self.candidate.license_text_sha256
        ):
            raise ValueError("source-license candidate identity differs")
        expected_scanners = ("checkov", "grype", "model-format", "trivy")
        if tuple(item.scanner for item in self.scanners) != expected_scanners:
            raise ValueError("scanner evidence must be complete and ordered")
        if any(item.subject_sha256 != self.candidate.artifact_sha256 for item in self.scanners):
            raise ValueError("scanner candidate identity differs")
        if tuple(item.format for item in self.sboms) != ("cyclonedx-json", "spdx-json"):
            raise ValueError("SBOM evidence must be complete and ordered")
        if any(item.subject_sha256 != self.candidate.artifact_sha256 for item in self.sboms):
            raise ValueError("SBOM candidate identity differs")
        if self.provenance.subject_sha256 != self.candidate.artifact_sha256:
            raise ValueError("provenance candidate identity differs")
        if self.opa_decision.policy_sha256 != self.policy_sha256:
            raise ValueError("OPA and eligibility policy identities differ")
        treatment_keys = tuple(item.finding_id for item in self.risk_treatments)
        if treatment_keys != tuple(sorted(set(treatment_keys))):
            raise ValueError("risk treatments must be sorted and unique")
        high_findings = {
            finding.finding_id
            for scanner in self.scanners
            for finding in scanner.findings
            if finding.severity is Severity.HIGH
        }
        active_treatments = {
            item.finding_id
            for item in self.risk_treatments
            if item.candidate_sha256 == self.candidate.artifact_sha256
            and item.approved_at <= self.generated_at < item.expires_at
        }
        vulnerability_sets = [
            {
                (finding.finding_id, finding.component, finding.severity.value)
                for finding in scanner.findings
            }
            for scanner in self.scanners
            if scanner.scanner in {"grype", "trivy"}
        ]
        scanners_agree = all(
            findings == vulnerability_sets[0] for findings in vulnerability_sets[1:]
        )
        passes = (
            self.inventory.status is EvidenceStatus.PASS
            and self.source_license.status is EvidenceStatus.PASS
            and all(item.status is EvidenceStatus.PASS for item in self.scanners)
            and all(item.status is EvidenceStatus.PASS for item in self.sboms)
            and self.provenance.status is EvidenceStatus.PASS
            and not any(item.critical_findings for item in self.scanners)
            and high_findings.issubset(active_treatments)
            and scanners_agree
            and self.opa_decision.allow
        )
        if (self.status is EligibilityStatus.PASS) != passes:
            raise ValueError("eligibility status does not match its evidence")
        return self
