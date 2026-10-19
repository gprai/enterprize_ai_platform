"""Deterministic W10-003 fixtures with no network, provider, or model download."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from enterprise_ai_platform.evaluation.baseline import load_approved_baseline
from enterprise_ai_platform.evaluation.dataset import load_golden_dataset
from enterprise_ai_platform.evaluation.rag_safety import (
    RAGConfigurationIdentity,
    RAGSafetyReport,
    SafetyObservation,
    build_rag_safety_report,
    evaluate_safety_cases,
    load_rag_safety_policy,
    load_safety_dataset,
    with_runtime_usage,
)
from enterprise_ai_platform.rag.prompt import prompt_template_sha256
from enterprise_ai_platform.retrieval.reranking import (
    APPROVED_RERANKER_IDENTITY,
    APPROVED_RETRIEVAL_CONFIGURATION_SHA256,
)

ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / "configs/eval/rag-safety-regression-policy-v2.yaml"
DATASET_PATH = ROOT / "configs/eval/rag-safety-golden-set.jsonl"
BASE_DATASET_PATH = ROOT / "configs/eval/golden-w10-003-v2.jsonl"
BASELINE_PATH = ROOT / "configs/eval/baselines/w3-002-v1.json"
RAW_EVIDENCE_SHA256 = "a" * 64


def configuration(role: str) -> RAGConfigurationIdentity:
    is_control = role == "CONTROL"
    return RAGConfigurationIdentity(
        role=role,  # type: ignore[arg-type]
        model_id="amazon.nova-2-lite-v1:0",
        inference_profile_id="global.amazon.nova-2-lite-v1:0",
        prompt_version="w10-003.extractive.v2",
        prompt_semantic_sha256=prompt_template_sha256("w10-003.extractive.v2"),
        embedding_model_id="sentence-transformers/all-MiniLM-L6-v2",
        embedding_revision="1110a243fdf4706b3f48f1d95db1a4f5529b4d41",
        embedding_artifact_sha256=(
            "53aa51172d142c89d9012cce15ae4d6cc0ca6895895114379cacb4fab128d9db"
        ),
        embedding_dimension=384,
        embedding_normalized=True,
        similarity="cosine",
        retrieval_mode="VECTOR" if is_control else "HYBRID",
        retrieval_configuration_sha256=(
            "447bda9713f661db5e8e47f5991528fad0820544cc184da4a232b190408ec8d5"
            if is_control
            else APPROVED_RETRIEVAL_CONFIGURATION_SHA256
        ),
        hybrid_enabled=not is_control,
        reranker_enabled=not is_control,
        reranker_identity=(
            None
            if is_control
            else f"{APPROVED_RERANKER_IDENTITY.model_id}@{APPROVED_RERANKER_IDENTITY.revision}"
        ),
        index_id="synthetic-w10-003-index-v1",
    )


def passing_observations() -> tuple[SafetyObservation, ...]:
    dataset = load_safety_dataset(DATASET_PATH)
    return tuple(
        SafetyObservation(
            case_id=case.case_id,
            decision=case.expected_decision,
            safe_codes=case.expected_safe_codes,
            provider_requests=int(case.provider_eligible),
            input_tokens=10 if case.provider_eligible else 0,
            output_tokens=2 if case.provider_eligible else 0,
            duration_ms=1,
            raw_response_sha256=RAW_EVIDENCE_SHA256 if case.provider_eligible else None,
        )
        for case in dataset.cases
    )


def report(role: str = "CONTROL", *, observations=None) -> RAGSafetyReport:  # type: ignore[no-untyped-def]
    policy, policy_sha = load_rag_safety_policy(POLICY_PATH)
    base_dataset = load_golden_dataset(BASE_DATASET_PATH)
    dataset = load_safety_dataset(DATASET_PATH)
    selected = passing_observations() if observations is None else tuple(observations)
    results, metrics = evaluate_safety_cases(dataset, selected)
    metrics = with_runtime_usage(
        metrics,
        provider_requests=sum(item.provider_requests for item in selected) + 24,
        input_tokens=sum(item.input_tokens for item in selected) + 240,
        output_tokens=sum(item.output_tokens for item in selected) + 120,
        estimated_cost_usd=0.01,
    )
    baseline = load_approved_baseline(BASELINE_PATH)
    assert baseline is not None
    return build_rag_safety_report(
        repository_sha="1" * 40,
        generated_at_utc=datetime(2026, 10, 18, tzinfo=UTC).isoformat(),
        policy_id=policy.policy_id,
        configuration=configuration(role),
        base_dataset_sha256=base_dataset.checksum_sha256,
        extension_dataset_sha256=dataset.checksum_sha256,
        policy_sha256=policy_sha,
        quality_metrics=baseline.metrics,
        quality_gates=baseline.gates,
        raw_evidence_sha256=RAW_EVIDENCE_SHA256,
        results=results,
        metrics=metrics,
    )
