from __future__ import annotations

import json
from pathlib import Path

import pytest

from enterprise_ai_platform.evaluation.config import (
    RETRIEVAL_ELIGIBLE_CASE_IDS,
    load_evaluation_config,
)
from enterprise_ai_platform.evaluation.dataset import (
    canonical_dataset_bytes,
    load_golden_dataset,
)
from enterprise_ai_platform.evaluation.errors import (
    EvaluationConfigurationError,
    EvaluationDatasetError,
)

ROOT = Path(__file__).resolve().parents[2]
DATASET = ROOT / "configs" / "eval" / "golden.jsonl"
CONFIG = ROOT / "configs" / "eval" / "cited-rag-evaluation-policy.yaml"


def test_golden_dataset_has_exact_owner_inventory() -> None:
    dataset = load_golden_dataset(DATASET)
    assert [case.case_id for case in dataset.cases] == [f"Q{index}" for index in range(1, 40)]
    outcomes = [case.expected_outcome for case in dataset.cases]
    assert outcomes.count("ANSWERED") == 24
    assert outcomes.count("ABSTAINED") == 12
    assert outcomes.count("ERROR") == 3
    assert (
        tuple(case.case_id for case in dataset.cases if case.retrieval_metric_eligible)
        == RETRIEVAL_ELIGIBLE_CASE_IDS
    )


def test_canonical_checksum_ignores_object_key_order(tmp_path: Path) -> None:
    dataset = load_golden_dataset(DATASET)
    objects = [json.loads(line) for line in DATASET.read_text(encoding="utf-8").splitlines()]
    reordered = tmp_path / "reordered.jsonl"
    reordered.write_text(
        "\n".join(json.dumps(dict(reversed(tuple(item.items())))) for item in objects) + "\n",
        encoding="utf-8",
    )
    loaded = load_golden_dataset(reordered)
    assert loaded.checksum_sha256 == dataset.checksum_sha256
    assert canonical_dataset_bytes(loaded.cases) == canonical_dataset_bytes(dataset.cases)


@pytest.mark.parametrize(
    "mutation",
    (
        lambda lines: [*lines[:1], lines[0], *lines[1:]],
        lambda lines: list(reversed(lines)),
        lambda lines: [lines[0].replace('"question":', '"unknown":1,"question":', 1), *lines[1:]],
        lambda lines: [
            lines[0].replace(
                '"expected_provider_calls":1',
                '"expected_provider_calls":"1"',
            ),
            *lines[1:],
        ],
        lambda lines: [
            lines[0].replace(
                '"case_id":"Q1"',
                '"case_id":"Q1","case_id":"Q1"',
            ),
            *lines[1:],
        ],
    ),
)
def test_invalid_duplicate_reordered_unknown_or_coerced_data_fails(
    tmp_path: Path,
    mutation: object,
) -> None:
    lines = DATASET.read_text(encoding="utf-8").splitlines()
    invalid = tmp_path / "invalid.jsonl"
    invalid.write_text(
        "\n".join(mutation(lines)) + "\n",  # type: ignore[operator]
        encoding="utf-8",
    )
    with pytest.raises(EvaluationDatasetError):
        load_golden_dataset(invalid)


def test_secret_or_pii_pattern_fails(tmp_path: Path) -> None:
    lines = DATASET.read_text(encoding="utf-8").splitlines()
    lines[0] = lines[0].replace("Which vector", "owner@example.com Which vector")
    invalid = tmp_path / "sensitive.jsonl"
    invalid.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(EvaluationDatasetError):
        load_golden_dataset(invalid)


def test_missing_required_dataset_field_fails(tmp_path: Path) -> None:
    objects = [json.loads(line) for line in DATASET.read_text(encoding="utf-8").splitlines()]
    objects[0].pop("question")
    invalid = tmp_path / "missing.jsonl"
    invalid.write_text(
        "\n".join(json.dumps(item, separators=(",", ":")) for item in objects) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(EvaluationDatasetError):
        load_golden_dataset(invalid)


def test_config_is_exact_and_strict() -> None:
    config, checksum = load_evaluation_config(CONFIG)
    assert config.thresholds.recall_at_5 == 0.85
    assert config.thresholds.citation_precision == 1.0
    assert config.regression_tolerances.recall_at_5 == 0.05
    assert config.report_paths == ("reports/eval.json", "reports/eval-repeat.json")
    assert len(checksum) == 64


@pytest.mark.parametrize("mutation", ("missing", "unknown", "boolean", "nan"))
def test_invalid_configuration_shape_or_number_fails(
    tmp_path: Path,
    mutation: str,
) -> None:
    raw = json.loads(CONFIG.read_text(encoding="utf-8"))
    if mutation == "missing":
        raw.pop("thresholds")
    elif mutation == "unknown":
        raw["unapproved"] = True
    elif mutation == "boolean":
        raw["thresholds"]["recall_at_5"] = True
    else:
        raw["thresholds"]["recall_at_5"] = float("nan")
    invalid = tmp_path / "invalid-config.yaml"
    invalid.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(EvaluationConfigurationError, match="invalid_configuration"):
        load_evaluation_config(invalid)


def test_duplicate_configuration_key_fails(tmp_path: Path) -> None:
    original = CONFIG.read_text(encoding="utf-8")
    invalid = tmp_path / "duplicate-config.yaml"
    invalid.write_text(
        original.replace(
            "{",
            '{"schema_version":"w3-002.v1",',
            1,
        ),
        encoding="utf-8",
    )
    with pytest.raises(EvaluationConfigurationError, match="invalid_configuration"):
        load_evaluation_config(invalid)
