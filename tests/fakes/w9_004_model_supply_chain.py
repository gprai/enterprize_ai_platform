"""Deterministic W9-004 evidence fixtures with no file, model, or network access."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from enterprise_ai_platform.model_supply_chain import (
    CandidateIdentity,
    EligibilityStatus,
    EvidenceStatus,
    ModelInventory,
    OpaDecision,
    ProvenanceEvidence,
    SbomEvidence,
    ScannerEvidence,
    SourceLicenseEvidence,
    SupplyChainEligibility,
    load_supply_chain_policy,
)
from enterprise_ai_platform.retrieval.models import Classification

NOW = datetime(2026, 10, 15, 0, 0, tzinfo=UTC)


def make_eligibility(
    *,
    artifact_character: str = "d",
    tenant_reference_sha256: str = "e" * 64,
    container_image_digest: str | None = None,
    training_request_identity_sha256: str = "a" * 64,
    experiment_run_identity_sha256: str = "b" * 64,
    evaluation_report_sha256: str = "c" * 64,
    generated_at: datetime = NOW,
    artifact_source_uri: str = "s3://approved-model-artifacts/model-1.tar.gz",
) -> SupplyChainEligibility:
    artifact_sha256 = artifact_character * 64
    policy = load_supply_chain_policy()
    candidate = CandidateIdentity(
        artifact_source_uri=artifact_source_uri,
        artifact_sha256=artifact_sha256,
        artifact_size_bytes=1024,
        artifact_object_version_id="object-version-1",
        container_image_digest=container_image_digest or f"sha256:{'6' * 64}",
        container_eligibility_sha256="7" * 64,
        source_repository="owner/approved-model",
        source_revision="1" * 40,
        source_manifest_sha256="2" * 64,
        license_text_sha256="3" * 64,
        evaluation_report_sha256=evaluation_report_sha256,
        reproducible_config_sha256="4" * 64,
        training_request_identity_sha256=training_request_identity_sha256,
        experiment_run_identity_sha256=experiment_run_identity_sha256,
    )
    scanners = tuple(
        ScannerEvidence(
            scanner=scanner,
            scanner_version=version,
            database_identity=(
                "NOT_APPLICABLE" if scanner in {"checkov", "model-format"} else f"sha256:{'8' * 64}"
            ),
            subject_sha256=artifact_sha256,
            report_sha256=character * 64,
            critical_findings=0,
            high_findings=0,
            status=EvidenceStatus.PASS,
        )
        for scanner, version, character in (
            ("checkov", "3.3.16", "4"),
            ("grype", "0.118.0", "5"),
            ("model-format", "w9-004.v1", "6"),
            ("trivy", "0.74.0", "7"),
        )
    )
    sboms = (
        SbomEvidence(
            format="cyclonedx-json",
            subject_sha256=artifact_sha256,
            report_sha256="8" * 64,
            generator="syft",
            generator_version="1.51.1",
            status=EvidenceStatus.PASS,
        ),
        SbomEvidence(
            format="spdx-json",
            subject_sha256=artifact_sha256,
            report_sha256="9" * 64,
            generator="syft",
            generator_version="1.51.1",
            status=EvidenceStatus.PASS,
        ),
    )
    return SupplyChainEligibility(
        candidate=candidate,
        tenant_reference_sha256=tenant_reference_sha256,
        classification=Classification.INTERNAL,
        source_license=SourceLicenseEvidence(
            source_repository=candidate.source_repository,
            source_revision=candidate.source_revision,
            source_manifest_sha256=candidate.source_manifest_sha256,
            license_text_sha256=candidate.license_text_sha256,
            status=EvidenceStatus.PASS,
        ),
        inventory=ModelInventory(
            artifact_sha256=artifact_sha256,
            file_count=1,
            total_uncompressed_bytes=1024,
            weight_files=("model.safetensors",),
            status=EvidenceStatus.PASS,
        ),
        scanners=scanners,
        sboms=sboms,
        provenance=ProvenanceEvidence(
            subject_sha256=artifact_sha256,
            statement_sha256="f" * 64,
            signature_sha256="1" * 64,
            issuer="https://token.actions.githubusercontent.com",
            subject="repo:gprai/enterprise_ai_platform:environment:sandbox",
            verified_at=generated_at,
            expires_at=generated_at + timedelta(hours=24),
            status=EvidenceStatus.PASS,
        ),
        opa_decision=OpaDecision(
            policy_sha256=policy.identity_sha256,
            input_sha256="2" * 64,
            decision_sha256="3" * 64,
            allow=True,
        ),
        policy_sha256=policy.identity_sha256,
        generated_at=generated_at,
        expires_at=generated_at + timedelta(hours=24),
        status=EligibilityStatus.PASS,
    )
