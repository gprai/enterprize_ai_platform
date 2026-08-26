"""Stable, content-free errors for the cited-RAG boundary."""

from __future__ import annotations

from enum import StrEnum


class RAGErrorCode(StrEnum):
    CONFIGURATION = "rag_configuration_invalid"
    OUTPUT_VALIDATION = "rag_output_invalid"


class RAGError(Exception):
    code: RAGErrorCode
    public_message: str

    def __init__(self) -> None:
        super().__init__(self.public_message)


class RAGConfigurationError(RAGError):
    code = RAGErrorCode.CONFIGURATION
    public_message = "The RAG policy configuration is invalid."


class RAGOutputValidationError(RAGError):
    code = RAGErrorCode.OUTPUT_VALIDATION
    public_message = "The generated RAG output is invalid."
