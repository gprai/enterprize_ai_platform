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
from .service import RetrievalService
from .vector_store import VectorStore

__all__ = [
    "Answer",
    "APPROVED_HYBRID_POLICY",
    "AuthContext",
    "BackendCapabilities",
    "Chunk",
    "Citation",
    "CollectionSpec",
    "Document",
    "HybridRetrievalPolicy",
    "Query",
    "RetrievalService",
    "RetrievalIdentity",
    "RetrievalMode",
    "RetrievedChunk",
    "VectorStore",
]
