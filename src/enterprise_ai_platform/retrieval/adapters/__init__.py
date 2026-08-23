"""Vector-store adapters that keep vendor objects behind the common contract."""

from .fake import InMemoryVectorStore
from .opensearch import OpenSearchVectorStore
from .qdrant import QdrantVectorStore

__all__ = ["InMemoryVectorStore", "OpenSearchVectorStore", "QdrantVectorStore"]
