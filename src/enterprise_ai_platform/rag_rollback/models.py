"""Strict, immutable, redacted contracts for the W3-004 rollback drill."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Annotated, Literal, TypeAlias

from pydantic import BaseModel, ConfigDict, Field, model_validator

HexDigest: TypeAlias = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
GitSha: TypeAlias = Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
IdentityAlias: TypeAlias = Literal["known-good", "synthetic-regression"]
ExpectedCurrent: TypeAlias = Literal["absent", "known-good", "synthetic-regression"]
DrillStatus: TypeAlias = Literal["PASS", "FAIL", "INDETERMINATE"]


class StrictRollbackModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        validate_default=True,
    )


class BaselineReference(StrictRollbackModel):
    path: Literal["configs/eval/baselines/w3-002-v1.json"]
    sha256: HexDigest


class RepositoryReference(StrictRollbackModel):
    approved_behavior_sha: GitSha


class PromptReference(StrictRollbackModel):
    version: Literal["w3-001.v1"]
    semantic_sha256: HexDigest


class RAGConfigurationReference(StrictRollbackModel):
    path: Literal["configs/rag.yaml"]
    source_sha256: HexDigest
    semantic_sha256: HexDigest


class ProviderReference(StrictRollbackModel):
    profile: Literal[
        "w3-002.controlled-fake.v1",
        "w3-004.synthetic-invalid-citation-q1-q2.v1",
    ]
    model_id: None = None
    network_activity: Literal[False] = False


class RetrieverReference(StrictRollbackModel):
    profile: Literal["w3-002.controlled-retrieval.v1"]
    vector_store: None = None
    index_id: None = None
    collection_name: None = None


class EvidenceReference(StrictRollbackModel):
    dataset_path: Literal["configs/eval/golden.jsonl"]
    dataset_raw_sha256: HexDigest
    dataset_canonical_sha256: HexDigest
    fixture_source_path: Literal["src/enterprise_ai_platform/evaluation/fixtures.py"]
    fixture_source_sha256: HexDigest
    ordinary_corpus_manifest: None = None


class EvaluationReference(StrictRollbackModel):
    config_path: Literal["configs/eval/w3-002.yaml"]
    config_sha256: HexDigest
    evaluator_version: Literal["w3-002.v1"]
    metric_version: Literal["w3-002.metrics.v1"]
    candidate_path: Literal["reports/eval.json"]
    candidate_sha256: HexDigest
    repeat_path: Literal["reports/eval-repeat.json"]
    repeat_sha256: HexDigest
    deterministic_payload_sha256: HexDigest


class GuardrailReference(StrictRollbackModel):
    source_path: Literal["src/enterprise_ai_platform/guardrails/policy.py"]
    source_sha256: HexDigest
    semantic_sha256: HexDigest
    allowed_content_type: Literal["text/plain"]
    max_input_characters: Literal[10_000]


class DrillExpectation(StrictRollbackModel):
    absolute_gate_status: Literal["PASS", "FAIL"]
    baseline_comparison_status: Literal["PASS", "FAIL"]
    overall_status: Literal["PASS", "FAIL"]
    release_eligible: bool
    answered_correct_numerator: int = Field(ge=0, le=24)
    answered_correct_denominator: Literal[24]
    combined_correct_numerator: int = Field(ge=0, le=36)
    combined_correct_denominator: Literal[36]
    invalid_citation_cases: tuple[Literal["Q1", "Q2"], ...]


class RAGIdentityDescriptor(StrictRollbackModel):
    schema_version: Literal["w3-004.rag-identity.v1"]
    identity_alias: IdentityAlias
    baseline: BaselineReference
    repository: RepositoryReference
    prompt: PromptReference
    rag_configuration: RAGConfigurationReference
    provider: ProviderReference
    retriever: RetrieverReference
    evidence: EvidenceReference
    evaluation: EvaluationReference
    guardrail: GuardrailReference
    expectation: DrillExpectation

    @model_validator(mode="after")
    def require_exact_profile_and_expectation(self) -> RAGIdentityDescriptor:
        expected: tuple[
            str,
            str,
            str,
            str,
            bool,
            int,
            int,
            tuple[str, ...],
        ]
        if self.identity_alias == "known-good":
            expected = (
                "w3-002.controlled-fake.v1",
                "PASS",
                "PASS",
                "PASS",
                True,
                24,
                36,
                (),
            )
        else:
            expected = (
                "w3-004.synthetic-invalid-citation-q1-q2.v1",
                "FAIL",
                "FAIL",
                "FAIL",
                False,
                22,
                34,
                ("Q1", "Q2"),
            )
        actual = (
            self.provider.profile,
            self.expectation.absolute_gate_status,
            self.expectation.baseline_comparison_status,
            self.expectation.overall_status,
            self.expectation.release_eligible,
            self.expectation.answered_correct_numerator,
            self.expectation.combined_correct_numerator,
            self.expectation.invalid_citation_cases,
        )
        if actual != expected:
            raise ValueError("identity profile differs from owner approval")
        return self


class ActivationState(StrictRollbackModel):
    schema_version: Literal["w3-004.activation.v1"]
    generation: int = Field(ge=1)
    active_identity: IdentityAlias
    identity_sha256: HexDigest


class ActivationOutcome(StrictRollbackModel):
    status: Literal["ACTIVATED", "ALREADY_ACTIVE"]
    active_identity: IdentityAlias
    identity_sha256: HexDigest
    generation: int = Field(ge=1)


class IdentityValidationResult(StrictRollbackModel):
    status: Literal["VALIDATED"]
    known_good_identity_sha256: HexDigest
    regression_identity_sha256: HexDigest


class EvaluationOutcome(StrictRollbackModel):
    status: Literal["EXPECTED_REGRESSION_DETECTED", "RESTORED_BASELINE_PASS"]
    report_path: Literal["reports/w3-004/regression.json", "reports/w3-004/restored.json"]
    report_sha256: HexDigest
    active_identity: IdentityAlias
    absolute_gate_status: Literal["PASS", "FAIL"]
    baseline_comparison_status: Literal["PASS", "FAIL"]
    overall_status: Literal["PASS", "FAIL"]
    release_eligible: bool


class CleanlinessResult(StrictRollbackModel):
    status: Literal["CLEAN", "ZERO_RESIDUE"]
    approved_artifact_count: int = Field(ge=0, le=4)
    unexpected_residue_count: Literal[0] = 0


class RollbackRecord(StrictRollbackModel):
    schema_version: Literal["w3-004.rollback-record.v1"]
    task_id: Literal["W3-ROLLBACK-001"]
    finalized_at_utc: str
    known_good_identity_sha256: HexDigest
    regression_identity_sha256: HexDigest
    baseline_sha256: HexDigest
    candidate_sha256: HexDigest
    repeat_sha256: HexDigest
    regression_report_sha256: HexDigest
    restored_report_sha256: HexDigest
    regression_status: Literal["FAIL"]
    restored_status: Literal["PASS"]
    active_identity: Literal["known-good"]
    final_status: Literal["PASS"]
    unexpected_residue_count: Literal[0]
    network_activity: Literal[False]
    provider_cost_usd: float = Field(ge=0.0, le=0.0)
    external_archive_retention_days: Literal[180]
    warnings: tuple[Literal["local_deterministic_scope_only"], ...]

    @model_validator(mode="after")
    def require_utc_and_warning(self) -> RollbackRecord:
        try:
            finalized_at = datetime.fromisoformat(self.finalized_at_utc)
        except ValueError:
            raise ValueError("rollback timestamp is invalid") from None
        if finalized_at.utcoffset() != timedelta(0):
            raise ValueError("rollback timestamp must use UTC")
        if self.warnings != ("local_deterministic_scope_only",):
            raise ValueError("rollback warning inventory differs from approval")
        return self
