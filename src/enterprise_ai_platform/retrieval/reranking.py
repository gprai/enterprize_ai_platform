"""Bounded provider-neutral reranking and adoption-decision contracts."""

from __future__ import annotations

import hashlib
import json
import re
from enum import StrEnum
from typing import Final, Literal, Protocol

from pydantic import Field, model_validator

from .errors import RerankerInputLimitError, RerankerValidationError
from .hybrid import APPROVED_HYBRID_POLICY
from .models import StrictModel

RERANKER_SCHEMA_VERSION: Final[Literal["w10-002.reranker.v1"]] = "w10-002.reranker.v1"
RERANKER_MODEL_ID: Final[Literal["enterprise-ai/deterministic-token-overlap"]] = (
    "enterprise-ai/deterministic-token-overlap"
)
RERANKER_REVISION: Final[Literal["w10-002.v1"]] = "w10-002.v1"
_TOKEN_PATTERN = re.compile(r"[a-z0-9]+", flags=re.ASCII)


class RerankerIdentity(StrictModel):
    """Immutable identity proving that reranking is local and dependency-free."""

    schema_version: Literal["w10-002.reranker.v1"] = RERANKER_SCHEMA_VERSION
    provider: Literal["local"] = "local"
    model_id: Literal["enterprise-ai/deterministic-token-overlap"] = RERANKER_MODEL_ID
    revision: Literal["w10-002.v1"] = RERANKER_REVISION
    algorithm: Literal["query-token-overlap-v1"] = "query-token-overlap-v1"
    network_required: Literal[False] = False
    model_download_required: Literal[False] = False
    provenance: Literal["repository-source-only"] = "repository-source-only"


APPROVED_RERANKER_IDENTITY = RerankerIdentity()


class RerankingPolicy(StrictModel):
    """Exact W10-002 budgets and adoption thresholds."""

    schema_version: Literal["w10-002.reranker.v1"] = RERANKER_SCHEMA_VERSION
    maximum_candidates: Literal[20] = 20
    maximum_top_k: Literal[20] = 20
    maximum_query_tokens: Literal[256] = 256
    maximum_candidate_tokens: Literal[384] = 384
    maximum_total_tokens: Literal[8192] = 8192
    timeout_seconds: float = Field(default=0.25, ge=0.25, le=0.25)
    maximum_concurrent_calls: Literal[4] = 4
    queue_capacity: Literal[0] = 0
    retry_attempts: Literal[0] = 0
    minimum_recall_at_5: float = Field(default=0.85, ge=0.85, le=0.85)
    minimum_mrr_gain: float = Field(default=0.05, ge=0.05, le=0.05)
    required_citation_precision: float = Field(default=1.0, ge=1.0, le=1.0)
    maximum_authorization_violations: Literal[0] = 0
    maximum_incremental_p95_ms: float = Field(default=100.0, ge=100.0, le=100.0)
    maximum_total_retrieval_p99_ms: float = Field(default=750.0, ge=750.0, le=750.0)

    def identity_sha256(self) -> str:
        return _canonical_sha256(self.model_dump(mode="json"))


def _canonical_sha256(value: object) -> str:
    canonical = json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


APPROVED_RERANKING_POLICY = RerankingPolicy()
APPROVED_RERANKING_POLICY_SHA256 = APPROVED_RERANKING_POLICY.identity_sha256()


APPROVED_RETRIEVAL_CONFIGURATION_SHA256 = _canonical_sha256(
    {
        "hybrid": APPROVED_HYBRID_POLICY.model_dump(mode="json"),
        "reranking": APPROVED_RERANKING_POLICY.model_dump(mode="json"),
    }
)


def tokenize(text: str, maximum_tokens: int) -> tuple[str, ...]:
    """Return deterministic lowercase ASCII tokens truncated to an approved budget."""

    if isinstance(maximum_tokens, bool) or maximum_tokens < 1:
        raise RerankerValidationError
    return tuple(_TOKEN_PATTERN.findall(text.casefold())[:maximum_tokens])


class RerankCandidate(StrictModel):
    """One authorized candidate represented without tenant or ACL metadata."""

    chunk_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    baseline_rank: int = Field(ge=0, lt=20)
    tokens: tuple[str, ...] = Field(max_length=384)


class RerankRequest(StrictModel):
    """Bounded local reranking request."""

    query_tokens: tuple[str, ...] = Field(max_length=256)
    candidates: tuple[RerankCandidate, ...] = Field(min_length=1, max_length=20)
    requested_top_k: int = Field(ge=1, le=20)

    @model_validator(mode="after")
    def require_unique_contiguous_candidates(self) -> RerankRequest:
        identifiers = tuple(candidate.chunk_id for candidate in self.candidates)
        ranks = tuple(candidate.baseline_rank for candidate in self.candidates)
        if len(set(identifiers)) != len(identifiers):
            raise ValueError("reranker candidate identities must be unique")
        if ranks != tuple(range(len(self.candidates))):
            raise ValueError("reranker baseline ranks must be contiguous")
        if self.requested_top_k > len(self.candidates):
            raise ValueError("reranker top_k cannot exceed candidate count")
        token_count = len(self.query_tokens) + sum(
            len(candidate.tokens) for candidate in self.candidates
        )
        if token_count > APPROVED_RERANKING_POLICY.maximum_total_tokens:
            raise ValueError("reranker request exceeds the total token budget")
        return self


class RerankScore(StrictModel):
    """One provider-neutral reranking score."""

    chunk_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    score: float = Field(ge=0.0, le=1.0)


class RerankResponse(StrictModel):
    """Complete ordered result returned by a reranker."""

    identity: RerankerIdentity
    results: tuple[RerankScore, ...] = Field(min_length=1, max_length=20)

    @model_validator(mode="after")
    def require_unique_results(self) -> RerankResponse:
        identifiers = tuple(result.chunk_id for result in self.results)
        if len(set(identifiers)) != len(identifiers):
            raise ValueError("reranker result identities must be unique")
        return self


class Reranker(Protocol):
    """Minimal async boundary supported by local and test rerankers."""

    @property
    def identity(self) -> RerankerIdentity: ...

    async def rerank(
        self,
        request: RerankRequest,
        *,
        timeout_seconds: float,
    ) -> RerankResponse: ...


class DeterministicTokenOverlapReranker:
    """Local deterministic reference reranker with no network or model artifact."""

    @property
    def identity(self) -> RerankerIdentity:
        return APPROVED_RERANKER_IDENTITY

    async def rerank(
        self,
        request: RerankRequest,
        *,
        timeout_seconds: float,
    ) -> RerankResponse:
        if timeout_seconds != APPROVED_RERANKING_POLICY.timeout_seconds:
            raise RerankerValidationError
        query_tokens = frozenset(request.query_tokens)
        denominator = max(1, len(query_tokens))
        ranked = []
        for candidate in request.candidates:
            score = len(query_tokens.intersection(candidate.tokens)) / denominator
            ranked.append((score, candidate.baseline_rank, candidate.chunk_id))
        ranked.sort(key=lambda item: (-item[0], item[1], item[2]))
        return RerankResponse(
            identity=self.identity,
            results=tuple(
                RerankScore(chunk_id=chunk_id, score=score) for score, _, chunk_id in ranked
            ),
        )


class EvidenceScope(StrEnum):
    SYNTHETIC = "synthetic"
    REPRESENTATIVE_OWNER_APPROVED = "representative_owner_approved"


class AdoptionDecision(StrEnum):
    ADOPTED = "ADOPTED"
    NOT_ADOPTED = "NOT_ADOPTED"
    INDETERMINATE = "INDETERMINATE"


class QualityMetrics(StrictModel):
    recall_at_5: float = Field(ge=0.0, le=1.0)
    precision_at_5: float = Field(ge=0.0, le=1.0)
    mrr: float = Field(ge=0.0, le=1.0)
    citation_precision: float = Field(ge=0.0, le=1.0)


class RuntimeCostMetrics(StrictModel):
    incremental_p95_ms: float = Field(ge=0.0)
    total_retrieval_p99_ms: float = Field(ge=0.0)
    request_count: int = Field(ge=1)
    saturation_count: int = Field(ge=0)
    degraded_count: int = Field(ge=0)
    provider_calls: int = Field(ge=0)
    estimated_total_paid_cost: float | None = Field(default=None, ge=0.0)
    estimated_incremental_paid_cost: float | None = Field(default=None, ge=0.0)
    local_cpu_ms: float = Field(ge=0.0)


class RerankingComparison(StrictModel):
    """Auditable baseline-versus-candidate evidence without adopting it implicitly."""

    scope: EvidenceScope
    baseline_quality: QualityMetrics
    candidate_quality: QualityMetrics
    runtime_cost: RuntimeCostMetrics
    authorization_violations: int = Field(ge=0)
    known_backend_differences: tuple[str, ...] = Field(min_length=1, max_length=10)


def evaluate_adoption(comparison: RerankingComparison) -> AdoptionDecision:
    """Apply the approved quality, security, latency and cost adoption gates."""

    metrics = comparison.runtime_cost
    if (
        comparison.scope is not EvidenceScope.REPRESENTATIVE_OWNER_APPROVED
        or metrics.estimated_total_paid_cost is None
        or metrics.estimated_incremental_paid_cost is None
    ):
        return AdoptionDecision.INDETERMINATE
    quality = comparison.candidate_quality
    baseline = comparison.baseline_quality
    passes = (
        quality.recall_at_5 >= APPROVED_RERANKING_POLICY.minimum_recall_at_5
        and quality.recall_at_5 >= baseline.recall_at_5
        and quality.precision_at_5 >= baseline.precision_at_5
        and quality.mrr - baseline.mrr >= APPROVED_RERANKING_POLICY.minimum_mrr_gain
        and quality.citation_precision == APPROVED_RERANKING_POLICY.required_citation_precision
        and comparison.authorization_violations
        == APPROVED_RERANKING_POLICY.maximum_authorization_violations
        and metrics.incremental_p95_ms <= APPROVED_RERANKING_POLICY.maximum_incremental_p95_ms
        and metrics.total_retrieval_p99_ms
        <= APPROVED_RERANKING_POLICY.maximum_total_retrieval_p99_ms
        and metrics.estimated_incremental_paid_cost == 0.0
        and metrics.provider_calls == 0
    )
    return AdoptionDecision.ADOPTED if passes else AdoptionDecision.NOT_ADOPTED


def build_rerank_request(
    query_text: str,
    candidates: tuple[tuple[str, str], ...],
    requested_top_k: int,
) -> RerankRequest:
    """Build a strictly bounded request from already-authorized chunk text."""

    policy = APPROVED_RERANKING_POLICY
    if len(candidates) > policy.maximum_candidates or requested_top_k > policy.maximum_top_k:
        raise RerankerInputLimitError
    return RerankRequest(
        query_tokens=tokenize(query_text, policy.maximum_query_tokens),
        candidates=tuple(
            RerankCandidate(
                chunk_id=chunk_id,
                baseline_rank=rank,
                tokens=tokenize(text, policy.maximum_candidate_tokens),
            )
            for rank, (chunk_id, text) in enumerate(candidates)
        ),
        requested_top_k=requested_top_k,
    )
