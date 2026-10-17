"""Public contract tests for provider-neutral W10-002 reranking."""

from __future__ import annotations

import enterprise_ai_platform.retrieval as retrieval
from enterprise_ai_platform.retrieval.errors import (
    RerankerErrorCode,
    RerankerInputLimitError,
    RerankerMalformedResponseError,
    RerankerSaturatedError,
    RerankerTimeoutError,
    RerankerUnavailableError,
)
from enterprise_ai_platform.retrieval.reranking import (
    APPROVED_RERANKER_IDENTITY,
    APPROVED_RERANKING_POLICY,
    APPROVED_RERANKING_POLICY_SHA256,
    APPROVED_RETRIEVAL_CONFIGURATION_SHA256,
)


def test_public_contract_exports_exact_local_identity_and_budgets() -> None:
    assert retrieval.APPROVED_RERANKER_IDENTITY == APPROVED_RERANKER_IDENTITY
    assert retrieval.APPROVED_RERANKING_POLICY == APPROVED_RERANKING_POLICY
    assert APPROVED_RERANKER_IDENTITY.network_required is False
    assert APPROVED_RERANKER_IDENTITY.model_download_required is False
    assert APPROVED_RERANKING_POLICY.maximum_candidates == 20
    assert APPROVED_RERANKING_POLICY.maximum_concurrent_calls == 4
    assert APPROVED_RERANKING_POLICY.queue_capacity == 0
    assert APPROVED_RERANKING_POLICY.retry_attempts == 0
    assert len(APPROVED_RERANKING_POLICY_SHA256) == 64
    assert len(APPROVED_RETRIEVAL_CONFIGURATION_SHA256) == 64


def test_failures_have_stable_non_retrying_safe_codes() -> None:
    expected = {
        RerankerInputLimitError: RerankerErrorCode.INPUT_LIMIT,
        RerankerTimeoutError: RerankerErrorCode.TIMEOUT,
        RerankerUnavailableError: RerankerErrorCode.UNAVAILABLE,
        RerankerSaturatedError: RerankerErrorCode.SATURATED,
        RerankerMalformedResponseError: RerankerErrorCode.MALFORMED_RESPONSE,
    }
    for error_type, code in expected.items():
        error = error_type()
        assert error.code is code
        assert error.retryable is False
        assert "query" not in str(error).casefold()
