"""Security and privacy regression coverage for W10-003."""

from __future__ import annotations

import json

import pytest

from enterprise_ai_platform.evaluation.errors import (
    RAGSafetyDatasetError,
    RAGSafetyEvidenceError,
)
from enterprise_ai_platform.evaluation.rag_safety import (
    SafetyObservation,
    canonical_json_bytes,
    evaluate_safety_cases,
    load_rag_safety_report,
    load_safety_dataset,
    write_exclusive_json,
)
from tests.fakes.w10_003_rag_evaluation import (
    DATASET_PATH,
    passing_observations,
    report,
)


def test_duplicate_keys_and_personal_data_fail_closed(tmp_path) -> None:  # type: ignore[no-untyped-def]
    first = DATASET_PATH.read_text(encoding="utf-8").splitlines()[0]
    duplicate = first.replace('{"case_id":', '{"case_id":"S01","case_id":', 1)
    duplicate_path = tmp_path / "duplicate.jsonl"
    duplicate_path.write_text("\n".join([duplicate] * 12) + "\n", encoding="utf-8")
    with pytest.raises(RAGSafetyDatasetError):
        load_safety_dataset(duplicate_path)

    records = DATASET_PATH.read_text(encoding="utf-8").splitlines()
    payload = json.loads(records[0])
    payload["question"] = "Send the result to synthetic.user@example.com"
    records[0] = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    pii_path = tmp_path / "pii.jsonl"
    pii_path.write_text("\n".join(records) + "\n", encoding="utf-8")
    with pytest.raises(RAGSafetyDatasetError):
        load_safety_dataset(pii_path)


def test_leaked_marker_is_a_non_compensable_failure() -> None:
    dataset = load_safety_dataset(DATASET_PATH)
    observations = list(passing_observations())
    original = observations[0]
    payload = original.model_dump(mode="python")
    payload["observed_markers"] = (dataset.cases[0].forbidden_markers[0],)
    observations[0] = SafetyObservation.model_validate(
        payload,
        strict=True,
    )

    results, metrics = evaluate_safety_cases(dataset, observations)

    assert results[0].passed is False
    assert metrics.injection_violations == 1
    assert metrics.leakage_violations == 1


def test_canonical_report_contains_no_raw_synthetic_content() -> None:
    payload = canonical_json_bytes(report("CANDIDATE").model_dump(mode="json"))
    assert b"W10_SENTINEL" not in payload
    assert b"BEGIN_UNTRUSTED" not in payload


def test_full_report_hash_rejects_raw_evidence_identity_tampering(
    tmp_path,  # type: ignore[no-untyped-def]
) -> None:
    path = tmp_path / "report.json"
    value = report("CANDIDATE").model_dump(mode="json")
    value["raw_evidence_sha256"] = "b" * 64
    write_exclusive_json(path, value)

    with pytest.raises(RAGSafetyEvidenceError):
        load_rag_safety_report(path)
