"""Provider-neutral identities and deterministic hybrid retrieval fusion."""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from typing import Final, Literal

from pydantic import Field, model_validator

from enterprise_ai_platform.config import RetrievalMode as RetrievalMode

from .errors import VectorStoreValidationError
from .models import Chunk, CollectionSpec, RetrievedChunk, StrictModel

HYBRID_RETRIEVAL_SCHEMA_VERSION: Final[Literal["w10-001.hybrid-retrieval.v1"]] = (
    "w10-001.hybrid-retrieval.v1"
)
STANDARD_LEXICAL_ANALYZER: Final[Literal["standard"]] = "standard"


class BackendCapabilities(StrictModel):
    """Explicit provider capability declaration without fallback behavior."""

    backend: Literal["in_memory", "qdrant", "opensearch"]
    retrieval_modes: frozenset[RetrievalMode] = Field(min_length=1, max_length=2)

    def require(self, mode: RetrievalMode) -> None:
        if not isinstance(mode, RetrievalMode) or mode not in self.retrieval_modes:
            raise VectorStoreValidationError


IN_MEMORY_CAPABILITIES = BackendCapabilities(
    backend="in_memory",
    retrieval_modes=frozenset({RetrievalMode.VECTOR}),
)
QDRANT_CAPABILITIES = BackendCapabilities(
    backend="qdrant",
    retrieval_modes=frozenset({RetrievalMode.VECTOR}),
)
OPENSEARCH_CAPABILITIES = BackendCapabilities(
    backend="opensearch",
    retrieval_modes=frozenset({RetrievalMode.VECTOR, RetrievalMode.HYBRID}),
)


class HybridRetrievalPolicy(StrictModel):
    """Immutable normalization, fusion and candidate-budget contract."""

    schema_version: Literal["w10-001.hybrid-retrieval.v1"] = HYBRID_RETRIEVAL_SCHEMA_VERSION
    lexical_analyzer: Literal["standard"] = STANDARD_LEXICAL_ANALYZER
    lexical_similarity: Literal["BM25"] = "BM25"
    vector_weight: float = Field(default=0.5, ge=0.0, le=1.0)
    lexical_weight: float = Field(default=0.5, ge=0.0, le=1.0)
    candidate_multiplier: Literal[4] = 4
    minimum_candidates: Literal[20] = 20
    maximum_candidates: Literal[100] = 100
    maximum_concurrent_channels: Literal[2] = 2

    @model_validator(mode="after")
    def require_exact_weights(self) -> HybridRetrievalPolicy:
        if not math.isclose(
            self.vector_weight + self.lexical_weight,
            1.0,
            rel_tol=0.0,
            abs_tol=1e-12,
        ):
            raise ValueError("hybrid retrieval weights must sum to one")
        return self

    def candidate_limit(self, top_k: int) -> int:
        if isinstance(top_k, bool) or not 1 <= top_k <= 100:
            raise VectorStoreValidationError
        return min(
            max(self.candidate_multiplier * top_k, self.minimum_candidates),
            self.maximum_candidates,
        )

    def identity_sha256(self) -> str:
        canonical = json.dumps(
            self.model_dump(mode="json"),
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()


APPROVED_HYBRID_POLICY = HybridRetrievalPolicy()
APPROVED_HYBRID_POLICY_SHA256 = APPROVED_HYBRID_POLICY.identity_sha256()


class RetrievalIdentity(StrictModel):
    """Exact collection, embedding, analyzer and retrieval-policy identity."""

    collection: CollectionSpec
    mode: RetrievalMode
    lexical_analyzer: Literal["standard"] | None
    policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


def build_retrieval_identity(
    collection: CollectionSpec,
    mode: RetrievalMode,
    policy: HybridRetrievalPolicy = APPROVED_HYBRID_POLICY,
) -> RetrievalIdentity:
    """Bind an index mapping to its exact retrieval and embedding contract."""

    OPENSEARCH_CAPABILITIES.require(mode)
    return RetrievalIdentity(
        collection=collection,
        mode=mode,
        lexical_analyzer=(policy.lexical_analyzer if mode is RetrievalMode.HYBRID else None),
        policy_sha256=policy.identity_sha256(),
    )


@dataclass(frozen=True, slots=True)
class RankedCandidate:
    """One validated provider result before normalization."""

    chunk: Chunk
    raw_score: float

    def __post_init__(self) -> None:
        if isinstance(self.raw_score, bool) or not math.isfinite(self.raw_score):
            raise VectorStoreValidationError


def _deduplicate(candidates: tuple[RankedCandidate, ...]) -> dict[str, RankedCandidate]:
    deduplicated: dict[str, RankedCandidate] = {}
    for candidate in candidates:
        chunk_id = candidate.chunk.chunk_id
        existing = deduplicated.get(chunk_id)
        if existing is not None and existing.chunk != candidate.chunk:
            raise VectorStoreValidationError
        if existing is None or candidate.raw_score > existing.raw_score:
            deduplicated[chunk_id] = candidate
    return deduplicated


def normalize_channel_scores(
    candidates: tuple[RankedCandidate, ...],
) -> tuple[dict[str, RankedCandidate], dict[str, float]]:
    """Return deduplicated candidates and deterministic min-max scores."""

    deduplicated = _deduplicate(candidates)
    if not deduplicated:
        return deduplicated, {}
    scores = tuple(candidate.raw_score for candidate in deduplicated.values())
    minimum = min(scores)
    maximum = max(scores)
    if math.isclose(minimum, maximum, rel_tol=0.0, abs_tol=0.0):
        return deduplicated, {chunk_id: 1.0 for chunk_id in deduplicated}
    span = maximum - minimum
    return deduplicated, {
        chunk_id: (candidate.raw_score - minimum) / span
        for chunk_id, candidate in deduplicated.items()
    }


def fuse_ranked_candidates(
    *,
    vector_candidates: tuple[RankedCandidate, ...],
    lexical_candidates: tuple[RankedCandidate, ...],
    top_k: int,
    min_score: float,
    policy: HybridRetrievalPolicy = APPROVED_HYBRID_POLICY,
) -> tuple[RetrievedChunk, ...]:
    """Fuse two authorized channels into stable provider-neutral results."""

    policy.candidate_limit(top_k)
    if isinstance(min_score, bool) or not math.isfinite(min_score) or not -1.0 <= min_score <= 1.0:
        raise VectorStoreValidationError
    vectors, vector_scores = normalize_channel_scores(vector_candidates)
    lexicals, lexical_scores = normalize_channel_scores(lexical_candidates)
    shared_ids = vectors.keys() & lexicals.keys()
    for chunk_id in shared_ids:
        if vectors[chunk_id].chunk != lexicals[chunk_id].chunk:
            raise VectorStoreValidationError

    ranked: list[tuple[float, float, float, str, Chunk]] = []
    for chunk_id in vectors.keys() | lexicals.keys():
        vector_score = vector_scores.get(chunk_id, 0.0)
        lexical_score = lexical_scores.get(chunk_id, 0.0)
        fused_score = policy.vector_weight * vector_score + policy.lexical_weight * lexical_score
        if fused_score < min_score:
            continue
        source = vectors.get(chunk_id) or lexicals[chunk_id]
        ranked.append((fused_score, lexical_score, vector_score, chunk_id, source.chunk))

    ranked.sort(key=lambda row: (-row[0], -row[1], -row[2], row[3]))
    return tuple(
        RetrievedChunk(**chunk.model_dump(), score=fused_score)
        for fused_score, _lexical, _vector, _chunk_id, chunk in ranked[:top_k]
    )
