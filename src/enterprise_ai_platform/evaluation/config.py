"""Strict owner-approved W3-002 configuration loading."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Literal

from pydantic import Field, ValidationError, model_validator

from enterprise_ai_platform.json_contracts import strict_json_loads

from .errors import EvaluationConfigurationError
from .models import StrictEvaluationModel

RETRIEVAL_ELIGIBLE_CASE_IDS = (
    "Q1",
    "Q2",
    "Q3",
    "Q4",
    "Q6",
    "Q7",
    "Q8",
    "Q9",
    "Q10",
    "Q11",
    "Q12",
    "Q13",
    "Q14",
    "Q15",
    "Q16",
    "Q17",
    "Q18",
    "Q19",
    "Q20",
    "Q21",
    "Q22",
    "Q23",
    "Q29",
    "Q39",
)


class AbsoluteThresholds(StrictEvaluationModel):
    recall_at_5: float = Field(ge=0.0, le=1.0)
    citation_precision: float = Field(ge=0.0, le=1.0)
    answered_correctness: float = Field(ge=0.0, le=1.0)
    abstention_correctness: float = Field(ge=0.0, le=1.0)
    combined_correctness: float = Field(ge=0.0, le=1.0)
    expected_error_correctness: float = Field(ge=0.0, le=1.0)
    maximum_security_violations: Literal[0]
    maximum_exposed_invalid_citations: Literal[0]


class RegressionTolerances(StrictEvaluationModel):
    recall_at_5: float = Field(ge=0.0, le=1.0)
    citation_precision: float = Field(ge=0.0, le=1.0)
    answered_correctness: float = Field(ge=0.0, le=1.0)
    abstention_correctness: float = Field(ge=0.0, le=1.0)
    combined_correctness: float = Field(ge=0.0, le=1.0)
    expected_error_correctness: float = Field(ge=0.0, le=1.0)
    security_violations: Literal[0]
    exposed_invalid_citations: Literal[0]


class EvaluationConfig(StrictEvaluationModel):
    schema_version: Literal["w3-002.v1"]
    evaluator_version: Literal["w3-002.v1"]
    metric_version: Literal["w3-002.metrics.v1"]
    dataset_version: Literal["w3-002.v1"]
    retrieval_eligible_case_ids: tuple[str, ...]
    thresholds: AbsoluteThresholds
    regression_tolerances: RegressionTolerances
    informational_metrics: tuple[Literal["mrr", "runtime_duration_ms", "tokens", "cost"], ...]
    report_paths: tuple[Literal["reports/eval.json", "reports/eval-repeat.json"], ...]
    approved_baseline_path: Literal["configs/eval/baselines/w3-002-v1.json"]
    external_retention_days: Literal[180]

    @model_validator(mode="after")
    def require_owner_values(self) -> EvaluationConfig:
        if self.retrieval_eligible_case_ids != RETRIEVAL_ELIGIBLE_CASE_IDS:
            raise ValueError("retrieval eligibility differs from owner approval")
        expected_thresholds = (0.85, 1.0, 0.95, 0.95, 0.95, 1.0, 0, 0)
        actual_thresholds = tuple(self.thresholds.model_dump(mode="python").values())
        if actual_thresholds != expected_thresholds:
            raise ValueError("absolute thresholds differ from owner approval")
        expected_tolerances = (0.05, 0.0, 0.0, 0.0, 0.0, 0.0, 0, 0)
        actual_tolerances = tuple(self.regression_tolerances.model_dump(mode="python").values())
        if actual_tolerances != expected_tolerances:
            raise ValueError("regression tolerances differ from owner approval")
        if self.informational_metrics != ("mrr", "runtime_duration_ms", "tokens", "cost"):
            raise ValueError("informational metrics differ from owner approval")
        if self.report_paths != ("reports/eval.json", "reports/eval-repeat.json"):
            raise ValueError("report paths differ from owner approval")
        return self


def load_evaluation_config(path: Path) -> tuple[EvaluationConfig, str]:
    """Load strict JSON-compatible YAML and return its exact byte checksum."""

    try:
        raw_bytes = path.read_bytes()
        raw_text = raw_bytes.decode("utf-8", errors="strict")
        strict_json_loads(raw_text)
        config = EvaluationConfig.model_validate_json(raw_text, strict=True)
    except (OSError, UnicodeError, TypeError, ValueError, ValidationError):
        raise EvaluationConfigurationError from None
    return config, hashlib.sha256(raw_bytes).hexdigest()
