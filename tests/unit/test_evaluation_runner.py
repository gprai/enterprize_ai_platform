from __future__ import annotations

import hashlib
import os
import subprocess  # noqa: S404 - isolated launcher subprocess is the contract under test
import sys
from pathlib import Path

import pytest

from enterprise_ai_platform.evaluation.errors import (
    EvaluationReportExistsError,
    MissingApprovedBaselineError,
)
from enterprise_ai_platform.evaluation.models import (
    CaseAssessment,
    CaseExecution,
    EvaluationMetrics,
    GateResults,
    MetricValue,
    Provenance,
)
from enterprise_ai_platform.evaluation.report import build_report, write_candidate_report
from enterprise_ai_platform.evaluation.runner import build_parser, require_release_baseline

ROOT = Path(__file__).resolve().parents[2]


def _repository_path_inventory() -> frozenset[Path]:
    inventory: set[Path] = set()
    for path in ROOT.rglob("*"):
        relative = path.relative_to(ROOT)
        if relative.parts and relative.parts[0] != ".git":
            inventory.add(relative)
    return frozenset(inventory)


def _metric(numerator: int = 1, denominator: int = 1) -> MetricValue:
    return MetricValue(
        numerator=numerator,
        denominator=denominator,
        value=numerator / denominator,
        display=f"{numerator / denominator:.6f}",
    )


def _report() -> object:
    answered_ids = {
        "Q1",
        "Q2",
        "Q3",
        "Q4",
        *(f"Q{index}" for index in range(6, 24)),
        "Q29",
        "Q39",
    }
    error_ids = {"Q36", "Q37", "Q38"}
    citation = Provenance(
        source_id="DOC-SYNTHETIC",
        document_id="a" * 64,
        document_version="b" * 64,
        chunk_id="c" * 64,
    )
    executions: list[CaseExecution] = []
    assessments: list[CaseAssessment] = []
    for index in range(1, 40):
        case_id = f"Q{index}"
        expected_outcome = (
            "ANSWERED"
            if case_id in answered_ids
            else "ERROR"
            if case_id in error_ids
            else "ABSTAINED"
        )
        executions.append(
            CaseExecution(
                case_id=case_id,
                expected_outcome=expected_outcome,
                release_blocking=False,
                actual_outcome=expected_outcome,
                answer_text="internal only" if expected_outcome == "ANSWERED" else None,
                abstention_reason=(
                    "insufficient_evidence"
                    if expected_outcome == "ABSTAINED"
                    else None
                ),
                error_code=(
                    "rag_output_validation_error"
                    if expected_outcome == "ERROR"
                    else None
                ),
                citations=(citation,) if expected_outcome == "ANSWERED" else (),
                provider_calls=0,
            )
        )
        eligible = expected_outcome == "ANSWERED"
        assessments.append(
            CaseAssessment(
                case_id=case_id,
                outcome_correct=True,
                provider_calls_correct=True,
                usage_correct=True,
                facts_correct=eligible,
                citations_valid=eligible,
                abstention_correct=expected_outcome == "ABSTAINED",
                error_correct=expected_outcome == "ERROR",
                retrieval_recall_numerator=int(eligible),
                retrieval_recall_denominator=int(eligible),
                reciprocal_rank=1.0 if eligible else 0.0,
                returned_citations=int(eligible),
                valid_citations=int(eligible),
                security_violations=0,
                exposed_invalid_citations=0,
                passed=True,
            )
        )
    metrics = EvaluationMetrics(
        recall_at_5=_metric(),
        mrr=_metric(),
        citation_precision=_metric(),
        answered_correctness=_metric(24, 24),
        abstention_correctness=_metric(12, 12),
        combined_correctness=_metric(36, 36),
        expected_error_correctness=_metric(3, 3),
        release_blocking_failures=0,
        security_violations=0,
        exposed_invalid_citations=0,
    )
    gates = GateResults(
        recall_at_5="PASS",
        citation_precision="PASS",
        answered_correctness="PASS",
        abstention_correctness="PASS",
        combined_correctness="PASS",
        expected_error_correctness="PASS",
        release_blocking_cases="PASS",
        security="PASS",
        absolute_gate_status="PASS",
    )
    return build_report(
        executions=tuple(executions),
        assessments=tuple(assessments),
        metrics=metrics,
        gates=gates,
        dataset_checksum="a" * 64,
        configuration_checksum="b" * 64,
        baseline_status="NO_APPROVED_BASELINE",
        generated_at_utc="2026-08-26T00:00:00+00:00",
        runtime_duration_ms=1,
    )


def test_runner_parser_supports_canonical_owner_interface() -> None:
    arguments = build_parser().parse_args(
        [
            "--config", "configs/eval/w3-002.yaml",
            "--dataset", "configs/eval/golden.jsonl",
            "--baseline", "configs/eval/baselines/w3-002-v1.json",
            "--out", "reports/eval.json",
        ]
    )
    assert arguments.out == Path("reports/eval.json")
    assert not arguments.enforce_release


def test_launcher_dispatches_both_commands_without_pythonpath_or_residue() -> None:
    environment = {
        key: value
        for key, value in os.environ.items()
        if key.casefold() != "pythonpath"
    }
    candidate_report = ROOT / "reports" / "eval.json"
    repeat_report = ROOT / "reports" / "eval-repeat.json"
    baseline = ROOT / "configs" / "eval" / "baselines" / "w3-002-v1.json"

    def report_hash(path: Path) -> str | None:
        if not path.exists():
            return None
        return hashlib.sha256(path.read_bytes()).hexdigest()

    report_hashes_before = {
        candidate_report: report_hash(candidate_report),
        repeat_report: report_hash(repeat_report),
    }
    inventory_before = _repository_path_inventory()

    for subcommand, parser_description in (
        ("candidate", "Run deterministic offline RAG evaluation"),
        ("promotion", "Promote one approved W3-002 candidate"),
    ):
        completed = subprocess.run(  # noqa: S603 - fixed local interpreter and script
            [
                sys.executable,
                "-B",
                "tools/evaluationctl.py",
                subcommand,
                "--help",
            ],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        output = completed.stdout + completed.stderr
        assert completed.returncode == 0
        assert parser_description in completed.stdout
        assert "ModuleNotFoundError" not in output

    assert _repository_path_inventory() == inventory_before
    assert report_hashes_before == {
        candidate_report: report_hash(candidate_report),
        repeat_report: report_hash(repeat_report),
    }
    assert baseline.exists()
    assert hashlib.sha256(baseline.read_bytes()).hexdigest() == (
        "4bbc8f24af911ba09356196e9285d261549926c713110f9549929e1e4ac9086f"
    )


def test_release_enforcement_requires_an_approved_baseline() -> None:
    with pytest.raises(MissingApprovedBaselineError):
        require_release_baseline(True, "NO_APPROVED_BASELINE")
    require_release_baseline(False, "NO_APPROVED_BASELINE")
    require_release_baseline(True, "PASS")


def test_report_write_is_no_overwrite_and_removes_temporary_sibling(
    tmp_path: Path,
) -> None:
    target = tmp_path / "eval.json"
    report = _report()
    write_candidate_report(target, report)  # type: ignore[arg-type]
    with pytest.raises(EvaluationReportExistsError):
        write_candidate_report(target, report)  # type: ignore[arg-type]
    assert list(tmp_path.glob(".eval.json.*.tmp")) == []
