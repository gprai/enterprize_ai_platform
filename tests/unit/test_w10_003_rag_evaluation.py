"""Unit coverage for W10-003 canonical safety evaluation."""

from __future__ import annotations

from pathlib import Path

import pytest

from enterprise_ai_platform.evaluation.rag_safety import (
    EXPECTED_CASE_IDS,
    SafetyObservation,
    canonical_safety_dataset_bytes,
    evaluate_safety_cases,
    load_rag_safety_policy,
    load_safety_dataset,
)
from enterprise_ai_platform.json_contracts import strict_json_loads, unwrap_single_json_fence
from tests.fakes.w10_003_rag_evaluation import (
    DATASET_PATH,
    POLICY_PATH,
    configuration,
    passing_observations,
    report,
)


def test_dataset_and_policy_have_exact_owner_approved_contract() -> None:
    dataset = load_safety_dataset(DATASET_PATH)
    policy, policy_sha = load_rag_safety_policy(POLICY_PATH)

    assert tuple(case.case_id for case in dataset.cases) == EXPECTED_CASE_IDS
    assert len(canonical_safety_dataset_bytes(dataset.cases)) > 0
    assert len(dataset.checksum_sha256) == 64
    assert len(policy_sha) == 64
    assert policy.aws.profile == "enterprise-ai-platform-w6-004"
    assert policy.runtime.maximum_provider_requests_per_run == 30
    assert policy.policy_id == "w10-003.rag-evaluation-policy.v2"
    assert policy.base_dataset_path == "configs/eval/golden-w10-003-v2.jsonl"


def test_historical_v1_policy_remains_readable() -> None:
    policy, _sha = load_rag_safety_policy(Path("configs/eval/rag-safety-regression-policy.yaml"))

    assert policy.policy_id == "w10-003.rag-evaluation-policy.v1"
    assert policy.base_dataset_path == "configs/eval/golden.jsonl"


@pytest.mark.parametrize(
    "response_text",
    [
        '{"abstain":true}',
        '```json\n{"abstain":true}\n```',
    ],
)
def test_safety_abstention_accepts_bare_or_one_exact_json_fence(
    response_text: str,
) -> None:
    parsed = strict_json_loads(unwrap_single_json_fence(response_text))

    assert parsed == {"abstain": True}


@pytest.mark.parametrize(
    "response_text",
    [
        '```\n{"abstain":true}\n```',
        '```JSON\n{"abstain":true}\n```',
        'prefix\n```json\n{"abstain":true}\n```',
        '```json\n{"abstain":true}\n```\nsuffix',
        '```json\n```json\n{"abstain":true}\n```\n```',
    ],
)
def test_safety_abstention_rejects_ambiguous_json_envelopes(
    response_text: str,
) -> None:
    with pytest.raises(ValueError):
        strict_json_loads(unwrap_single_json_fence(response_text))


def test_all_exact_observations_pass_non_compensable_safety_gates() -> None:
    dataset = load_safety_dataset(DATASET_PATH)
    results, metrics = evaluate_safety_cases(dataset, passing_observations())

    assert all(result.passed for result in results)
    assert metrics.passed_cases == 12
    assert metrics.leakage_violations == 0
    assert metrics.configuration_drift == 0


def test_configuration_identity_changes_with_advanced_retrieval() -> None:
    control = configuration("CONTROL")
    candidate = configuration("CANDIDATE")

    assert control.checksum_sha256 != candidate.checksum_sha256
    assert control.prompt_version == "w10-003.extractive.v2"
    assert candidate.prompt_version == "w10-003.extractive.v2"
    assert control.retrieval_mode == "VECTOR"
    assert candidate.retrieval_mode == "HYBRID"
    assert candidate.reranker_enabled is True


def test_repeatability_digest_excludes_runtime_variability() -> None:
    observations = list(passing_observations())
    changed = observations[0].model_dump(mode="python")
    changed.update(
        input_tokens=11,
        output_tokens=3,
        duration_ms=999,
        raw_response_sha256="b" * 64,
    )
    observations[0] = SafetyObservation.model_validate(changed, strict=True)

    original = report("CONTROL")
    repeated = report("CONTROL", observations=observations)

    assert repeated.repeatability_payload_sha256 == original.repeatability_payload_sha256
    assert repeated.deterministic_payload_sha256 != original.deterministic_payload_sha256
