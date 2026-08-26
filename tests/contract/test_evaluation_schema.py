from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from enterprise_ai_platform.evaluation.dataset import load_golden_dataset
from enterprise_ai_platform.evaluation.models import GoldenCase

ROOT = Path(__file__).resolve().parents[2]


def test_golden_case_schema_is_strict_and_has_one_required_field_set() -> None:
    dataset = load_golden_dataset(ROOT / "configs" / "eval" / "golden.jsonl")
    required = set(GoldenCase.model_json_schema()["required"])
    assert required == set(dataset.cases[0].model_dump(mode="json"))
    with pytest.raises(ValidationError):
        GoldenCase.model_validate(
            {**dataset.cases[0].model_dump(mode="python"), "vendor_field": "forbidden"},
            strict=True,
        )


def test_conditional_outcome_fields_reject_invalid_combinations() -> None:
    dataset = load_golden_dataset(ROOT / "configs" / "eval" / "golden.jsonl")
    answered = dataset.cases[0].model_dump(mode="python")
    answered["expected_abstention_reason"] = "insufficient_evidence"
    with pytest.raises(ValidationError):
        GoldenCase.model_validate(answered, strict=True)
    abstained = dataset.cases[4].model_dump(mode="python")
    abstained["expected_error_code"] = "rag_output_validation_error"
    with pytest.raises(ValidationError):
        GoldenCase.model_validate(abstained, strict=True)
