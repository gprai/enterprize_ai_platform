"""Public and CLI contracts for W10-003 evaluation governance."""

from __future__ import annotations

import enterprise_ai_platform.evaluation as evaluation
from enterprise_ai_platform.evaluation.rag_safety import (
    DATASET_ID,
    POLICY_ID,
    REPORT_SCHEMA_VERSION,
    load_rag_safety_policy,
)
from enterprise_ai_platform.evaluation.rag_safety_runner import build_parser
from enterprise_ai_platform.llm.bedrock import (
    MAX_APPLICATION_ATTEMPTS,
    OUTER_TIMEOUT_SECONDS,
)
from enterprise_ai_platform.llm.provider import PROCESS_WIDE_PROVIDER_CALL_GATE
from tests.fakes.w10_003_rag_evaluation import POLICY_PATH


def test_public_contract_exports_versioned_safety_types() -> None:
    assert evaluation.RAGSafetyPolicy is not None
    assert evaluation.RAGSafetyReport is not None
    assert DATASET_ID == "w10-003.rag-safety-golden-set.v1"
    assert POLICY_ID == "w10-003.rag-evaluation-policy.v2"
    assert REPORT_SCHEMA_VERSION == "w10-003.rag-evaluation-report.v1"


def test_policy_preserves_provider_and_evaluation_retry_ownership() -> None:
    policy, _sha = load_rag_safety_policy(POLICY_PATH)

    assert policy.runtime.concurrency == 1
    assert policy.runtime.evaluation_retries == 0
    assert policy.runtime.provider_max_attempts == 2
    assert policy.runtime.process_provider_call_limit == 4
    assert policy.runtime.per_call_timeout_seconds == 30
    assert policy.runtime.total_evaluation_timeout_seconds == 900
    assert MAX_APPLICATION_ATTEMPTS == policy.runtime.provider_max_attempts
    assert OUTER_TIMEOUT_SECONDS == policy.runtime.per_call_timeout_seconds
    assert (
        PROCESS_WIDE_PROVIDER_CALL_GATE.max_active_calls
        == policy.runtime.process_provider_call_limit
    )


def test_cli_separates_local_validation_paid_execution_and_comparison() -> None:
    parser = build_parser()
    help_text = parser.format_help()

    assert "validate" in help_text
    assert "candidate" in help_text
    assert "compare" in help_text
