"""Strict golden-dataset loading, privacy checks, and canonical identity."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from pathlib import Path

from pydantic import ValidationError

from enterprise_ai_platform.json_contracts import strict_json_loads

from .config import RETRIEVAL_ELIGIBLE_CASE_IDS
from .errors import DuplicateEvaluationCaseError, EvaluationDatasetError
from .models import GoldenCase, GoldenDataset

_EXPECTED_CASE_IDS = tuple(f"Q{index}" for index in range(1, 40))
_PROHIBITED_PATTERNS = (
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    re.compile(r"(?i)\b(?:password|secret|token)\s*[:=]\s*[^\s]+"),
)


def _contains_prohibited_data(values: Iterable[str]) -> bool:
    return any(pattern.search(value) for value in values for pattern in _PROHIBITED_PATTERNS)


def canonical_dataset_bytes(cases: tuple[GoldenCase, ...]) -> bytes:
    """Return the exact owner-approved canonical parsed JSONL representation."""

    records = (
        json.dumps(
            case.model_dump(mode="json"),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        for case in cases
    )
    return ("\n".join(records) + "\n").encode("utf-8")


def load_golden_dataset(path: Path) -> GoldenDataset:
    """Load exactly Q1-Q39 without coercion, duplicate keys, or prohibited data."""

    try:
        text = path.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeError):
        raise EvaluationDatasetError from None
    raw_lines = text.splitlines()
    if len(raw_lines) != 39 or any(not line.strip() for line in raw_lines):
        raise EvaluationDatasetError
    cases: list[GoldenCase] = []
    try:
        for line in raw_lines:
            strict_json_loads(line)
            cases.append(GoldenCase.model_validate_json(line, strict=True))
    except (TypeError, ValueError, ValidationError):
        raise EvaluationDatasetError from None
    case_ids = tuple(case.case_id for case in cases)
    if len(case_ids) != len(set(case_ids)):
        raise DuplicateEvaluationCaseError
    if case_ids != _EXPECTED_CASE_IDS:
        raise EvaluationDatasetError
    outcomes = tuple(case.expected_outcome for case in cases)
    if (outcomes.count("ANSWERED"), outcomes.count("ABSTAINED"), outcomes.count("ERROR")) != (
        24,
        12,
        3,
    ):
        raise EvaluationDatasetError
    eligible = tuple(case.case_id for case in cases if case.retrieval_metric_eligible)
    if eligible != RETRIEVAL_ELIGIBLE_CASE_IDS:
        raise EvaluationDatasetError
    sensitive_values = tuple(
        value for case in cases for value in (case.question, *case.expected_facts)
    )
    if _contains_prohibited_data(sensitive_values):
        raise EvaluationDatasetError
    frozen_cases = tuple(cases)
    checksum = hashlib.sha256(canonical_dataset_bytes(frozen_cases)).hexdigest()
    return GoldenDataset(version="w3-002.v1", checksum_sha256=checksum, cases=frozen_cases)
