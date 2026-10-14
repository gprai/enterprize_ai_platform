"""Deterministic W9-002 lineage fixtures with no service, filesystem, or network access."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from uuid import UUID

from enterprise_ai_platform.agent.authorization import authorization_reference
from enterprise_ai_platform.agent.serialization import hash_identifier
from enterprise_ai_platform.experiment_tracking import (
    ArtifactReference,
    CodeIdentity,
    DatasetIdentity,
    EmbeddingIdentity,
    EvaluationIdentity,
    ExperimentInput,
    ExperimentMetric,
    ExperimentParameter,
    MetricUnit,
    ModelIdentity,
    PromptIdentity,
    RetrievalIdentity,
    RunEnvelope,
    fingerprint,
    load_experiment_policy,
)
from enterprise_ai_platform.rag.prompt import prompt_template_sha256
from enterprise_ai_platform.retrieval.models import (
    APPROVED_EMBEDDING_MODEL_ID,
    APPROVED_EMBEDDING_REVISION,
    AuthContext,
    Classification,
    CollectionSpec,
    Role,
)

NOW = datetime(2026, 10, 14, 0, 0, tzinfo=UTC)


def make_auth(*, tenant_id: str = "tenant-a", subject_id: str = "owner-a") -> AuthContext:
    return AuthContext(
        subject_id=subject_id,
        tenant_id=tenant_id,
        roles=frozenset({Role.ADMIN}),
        clearance=Classification.INTERNAL,
        groups=frozenset(),
        issuer="https://identity.example.invalid",
        audience="enterprise-ai-platform",
        expires_at=NOW + timedelta(hours=1),
        request_id="w9-002-request",
    )


def make_envelope(
    *,
    auth: AuthContext | None = None,
    run_number: int = 1,
    idempotency_key: str | None = None,
) -> RunEnvelope:
    auth = auth or make_auth()
    return RunEnvelope(
        run_id=str(UUID(f"00000000-0000-4000-8000-{run_number:012d}")),
        correlation_id=str(UUID("00000000-0000-4000-8000-000000000902")),
        idempotency_key=idempotency_key or f"{run_number:x}" * 64,
        tenant_reference_sha256=hash_identifier(auth.tenant_id),
        subject_reference_sha256=hash_identifier(auth.subject_id),
        authorization_reference_sha256=authorization_reference(auth),
        classification=Classification.INTERNAL,
        policy_sha256=load_experiment_policy().identity_sha256,
        requested_at=NOW,
        deadline_at=NOW + timedelta(minutes=15),
    )


def make_input(
    *,
    model_revision: str = "model-v1",
    groundedness: str = "0.950000",
    code_sha256: str = "2" * 64,
    parameters: tuple[ExperimentParameter, ...] | None = None,
) -> ExperimentInput:
    return ExperimentInput(
        dataset=DatasetIdentity(
            dataset_version="w3-002.v1",
            manifest_sha256="1" * 64,
            case_inventory_sha256="a" * 64,
            case_count=39,
            classification=Classification.INTERNAL,
        ),
        code=CodeIdentity(git_commit="1" * 40, source_composition_sha256=code_sha256),
        prompt=PromptIdentity(
            prompt_version="w3-001.v1",
            prompt_template_sha256=prompt_template_sha256(),
        ),
        model=ModelIdentity(
            provider="fake",
            model_id="owner/approved-model",
            revision=model_revision,
            artifact_sha256="4" * 64,
            license="Apache-2.0",
            approval_reference_sha256="5" * 64,
        ),
        embedding=EmbeddingIdentity(
            model_id=APPROVED_EMBEDDING_MODEL_ID,
            revision=APPROVED_EMBEDDING_REVISION,
            artifact_sha256="6" * 64,
        ),
        retrieval=RetrievalIdentity(
            store_kind="fake",
            collection_name="approved-corpus",
            collection_spec_sha256=fingerprint(CollectionSpec(name="approved-corpus")),
            collection_revision="collection-v1",
            retrieval_policy_sha256="8" * 64,
        ),
        evaluation=EvaluationIdentity(
            dataset_checksum_sha256="1" * 64,
            configuration_checksum_sha256="9" * 64,
            deterministic_payload_sha256="b" * 64,
            gate_status="PASS",
            baseline_comparison_status="PASS",
        ),
        parameters=parameters or (ExperimentParameter(key="temperature", value="0.0"),),
        metrics=(
            ExperimentMetric(
                name="citation_precision",
                value=Decimal("1.000000"),
                unit=MetricUnit.RATIO,
                derivation="w3-002.metrics.v1",
            ),
            ExperimentMetric(
                name="groundedness",
                value=Decimal(groundedness),
                unit=MetricUnit.RATIO,
                derivation="w3-002.metrics.v1",
            ),
            ExperimentMetric(
                name="safety",
                value=Decimal("1"),
                unit=MetricUnit.BOOLEAN,
                derivation="w3-002.metrics.v1",
            ),
        ),
        artifacts=(
            ArtifactReference(
                kind="evaluation_report",
                path="reports/w9-002/evaluation-summary.json",
                sha256="c" * 64,
                classification="INTERNAL",
            ),
        ),
    )
