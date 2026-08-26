"""Checksum-bound, separately approved immutable baseline promotion command."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path

from .config import load_evaluation_config
from .dataset import load_golden_dataset
from .errors import (
    EvaluationError,
    EvaluationReportExistsError,
    EvaluationReportWriteError,
    PromotionChecksumError,
    PromotionTargetExistsError,
)
from .models import ApprovedBaseline
from .report import _atomic_write_no_overwrite, load_evaluation_report

_APPROVED_TARGET = Path("configs/eval/baselines/w3-002-v1.json")
_APPROVED_DATASET = Path("configs/eval/golden.jsonl")
_APPROVED_CONFIG = Path("configs/eval/w3-002.yaml")
_APPROVED_CANDIDATE = Path("reports/eval.json")
_APPROVED_REPEAT = Path("reports/eval-repeat.json")


def _sha256(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        raise PromotionChecksumError from None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Promote one approved W3-002 candidate")
    parser.add_argument("--repository-sha", required=True)
    parser.add_argument("--dataset", required=True, type=Path)
    parser.add_argument("--dataset-sha256", required=True)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--candidate-sha256", required=True)
    parser.add_argument("--repeat-report", required=True, type=Path)
    parser.add_argument("--repeat-sha256", required=True)
    parser.add_argument("--reviewer", required=True)
    parser.add_argument("--decision", required=True, choices=("APPROVED",))
    parser.add_argument("--approved-at", required=True)
    parser.add_argument("--target", required=True, type=Path)
    return parser


def promote(arguments: argparse.Namespace) -> ApprovedBaseline:
    """Validate supplied identities and atomically create only the approved target."""

    if (
        arguments.target.as_posix() != _APPROVED_TARGET.as_posix()
        or arguments.dataset.as_posix() != _APPROVED_DATASET.as_posix()
        or arguments.config.as_posix() != _APPROVED_CONFIG.as_posix()
        or arguments.candidate.as_posix() != _APPROVED_CANDIDATE.as_posix()
        or arguments.repeat_report.as_posix() != _APPROVED_REPEAT.as_posix()
        or arguments.reviewer != "Gyan Prakash Rai"
        or arguments.decision != "APPROVED"
        or re.fullmatch(r"[0-9a-f]{40}", arguments.repository_sha) is None
    ):
        raise PromotionChecksumError
    if arguments.target.exists():
        raise PromotionTargetExistsError
    try:
        approved_at = datetime.fromisoformat(arguments.approved_at)
    except ValueError:
        raise PromotionChecksumError from None
    if approved_at.tzinfo is None or approved_at.utcoffset() is None:
        raise PromotionChecksumError
    dataset = load_golden_dataset(arguments.dataset)
    config, configuration_checksum = load_evaluation_config(arguments.config)
    if dataset.checksum_sha256 != arguments.dataset_sha256:
        raise PromotionChecksumError
    if _sha256(arguments.candidate) != arguments.candidate_sha256:
        raise PromotionChecksumError
    if _sha256(arguments.repeat_report) != arguments.repeat_sha256:
        raise PromotionChecksumError
    candidate = load_evaluation_report(arguments.candidate)
    repeat = load_evaluation_report(arguments.repeat_report)
    candidate_cases_match = all(
        (
            result.case_id == case.case_id
            and result.expected_outcome == case.expected_outcome
            and result.release_blocking == case.release_blocking
            and result.provider_calls == case.expected_provider_calls
            and (result.usage is not None) == case.expected_usage_retained
        )
        for case, result in zip(dataset.cases, candidate.cases, strict=True)
    )
    repeat_cases_match = all(
        (
            result.case_id == case.case_id
            and result.expected_outcome == case.expected_outcome
            and result.release_blocking == case.release_blocking
            and result.provider_calls == case.expected_provider_calls
            and (result.usage is not None) == case.expected_usage_retained
        )
        for case, result in zip(dataset.cases, repeat.cases, strict=True)
    )
    if (
        not candidate_cases_match
        or not repeat_cases_match
        or (
            candidate.deterministic_payload_sha256
            != repeat.deterministic_payload_sha256
        )
        or candidate.dataset_checksum_sha256 != dataset.checksum_sha256
        or candidate.configuration_checksum_sha256 != configuration_checksum
        or candidate.gates.absolute_gate_status != "PASS"
        or repeat.gates.absolute_gate_status != "PASS"
        or candidate.baseline_comparison_status != "NO_APPROVED_BASELINE"
        or repeat.baseline_comparison_status != "NO_APPROVED_BASELINE"
        or candidate.metrics.release_blocking_failures != 0
        or candidate.metrics.security_violations != 0
        or candidate.metrics.exposed_invalid_citations != 0
    ):
        raise PromotionChecksumError
    baseline = ApprovedBaseline(
        schema_version="w3-002.baseline.v1",
        repository_sha=arguments.repository_sha,
        dataset_version=config.dataset_version,
        dataset_checksum_sha256=dataset.checksum_sha256,
        evaluator_version=config.evaluator_version,
        metric_version=config.metric_version,
        configuration_checksum_sha256=configuration_checksum,
        candidate_sha256=arguments.candidate_sha256,
        repeat_report_sha256=arguments.repeat_sha256,
        deterministic_payload_sha256=candidate.deterministic_payload_sha256,
        reviewer=arguments.reviewer,
        decision="APPROVED",
        approved_at=approved_at.isoformat(),
        metrics=candidate.metrics,
        gates=candidate.gates,
    )
    payload = (
        json.dumps(
            baseline.model_dump(mode="json"),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")
    try:
        _atomic_write_no_overwrite(arguments.target, payload)
    except (EvaluationReportExistsError, EvaluationReportWriteError):
        raise PromotionTargetExistsError from None
    return baseline


def main(argv: Sequence[str] | None = None) -> int:
    try:
        promote(build_parser().parse_args(argv))
    except EvaluationError as exc:
        print(json.dumps({"status": "ERROR", "error_code": exc.code}))
        return 1
    except Exception:
        print(json.dumps({"status": "ERROR", "error_code": "evaluation_error"}))
        return 1
    print(json.dumps({"status": "PROMOTED", "target": _APPROVED_TARGET.as_posix()}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
