"""Provider-neutral contracts for authorized enterprise retrieval."""

from .hybrid import (
    APPROVED_HYBRID_POLICY,
    BackendCapabilities,
    HybridRetrievalPolicy,
    RetrievalIdentity,
    RetrievalMode,
)
from .models import (
    Answer,
    AuthContext,
    Chunk,
    Citation,
    CollectionSpec,
    Document,
    Query,
    RetrievedChunk,
)
from .reranking import (
    APPROVED_RERANKER_IDENTITY,
    APPROVED_RERANKING_POLICY,
    AdoptionDecision,
    DeterministicTokenOverlapReranker,
    EvidenceScope,
    Reranker,
    RerankerIdentity,
    RerankingComparison,
    RerankingPolicy,
)
from .service import RetrievalService
from .vector_store import VectorStore

__all__ = [
    "Answer",
    "APPROVED_HYBRID_POLICY",
    "APPROVED_RERANKER_IDENTITY",
    "APPROVED_RERANKING_POLICY",
    "AdoptionDecision",
    "AuthContext",
    "BackendCapabilities",
    "Chunk",
    "Citation",
    "CollectionSpec",
    "Document",
    "DeterministicTokenOverlapReranker",
    "EvidenceScope",
    "HybridRetrievalPolicy",
    "Query",
    "Reranker",
    "RerankerIdentity",
    "RerankingComparison",
    "RerankingPolicy",
    "RetrievalService",
    "RetrievalIdentity",
    "RetrievalMode",
    "RetrievedChunk",
    "VectorStore",
]
