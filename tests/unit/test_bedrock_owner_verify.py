"""Deterministic unit tests for the W5-001 owner verifier."""

from __future__ import annotations

import asyncio
import copy
import json
from collections.abc import Mapping
from pathlib import Path
from typing import cast

import pytest
import tools.bedrock_owner_verify as verifier
from tools.bedrock_owner_verify import (
    RunEvidence,
    SafeVerificationError,
    _smoke,
    _validate_owner_review,
    account_read_only_summary,
    dry_run_summary,
    load_contract,
    paid_summary,
)

from enterprise_ai_platform.evaluation.dataset import load_golden_dataset
from enterprise_ai_platform.evaluation.models import GoldenCase

ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = ROOT / "configs/verification/bedrock-owner-test.json"


class ExactSts:
    def get_caller_identity(self) -> dict[str, object]:
        return {
            "Account": "526338061652",
            "Arn": "arn:aws:iam::526338061652:user/finopsinfra",
        }


class ExactQuotas:
    _values = {
        "L-D5F39C2F": (
            "Global cross-region model inference requests per minute for Amazon Nova 2 Lite",
            200,
        ),
        "L-71C69B70": (
            "Global cross-region model inference tokens per minute for Amazon Nova 2 Lite",
            8_000_000,
        ),
        "L-AD940EDE": (
            "Global cross-region model inference tokens per day for Amazon Nova 2 Lite",
            432_000_000,
        ),
    }

    def get_service_quota(self, *, ServiceCode: str, QuotaCode: str) -> dict[str, object]:
        assert ServiceCode == "bedrock"
        name, value = self._values[QuotaCode]
        return {
            "Quota": {
                "ServiceCode": ServiceCode,
                "QuotaCode": QuotaCode,
                "QuotaName": name,
                "Unit": "None",
                "Value": value,
            }
        }


class ExactBedrock:
    def get_inference_profile(self, *, inferenceProfileIdentifier: str) -> dict[str, object]:
        return {"inferenceProfileId": inferenceProfileIdentifier}

    def get_foundation_model(self, *, modelIdentifier: str) -> dict[str, object]:
        return {
            "modelDetails": {
                "modelId": modelIdentifier,
                "modelLifecycle": {"status": "ACTIVE"},
            }
        }


class ExactRuntime:
    def __init__(self) -> None:
        self.calls = 0
        self.arguments: list[dict[str, object]] = []

    def converse(self, **kwargs: object) -> dict[str, object]:
        self.calls += 1
        self.arguments.append(dict(kwargs))
        assert kwargs["modelId"] == "global.amazon.nova-2-lite-v1:0"
        expected_inference: dict[str, object] = {
            "maxTokens": 512,
            "temperature": 0.0,
            "topP": 1.0,
        }
        messages = kwargs["messages"]
        assert isinstance(messages, list)
        assert all(message.get("role") != "assistant" for message in messages)
        assert kwargs["inferenceConfig"] == expected_inference
        assert "toolConfig" not in kwargs
        assert "outputConfig" not in kwargs
        return {
            "output": {"message": {"content": [{"text": "READY"}]}},
            "usage": {"inputTokens": 8, "outputTokens": 1, "totalTokens": 9},
            "stopReason": "end_turn",
        }


def _case_structured_input(case: GoldenCase) -> dict[str, object]:
    def value_at(values: tuple[str, ...], index: int) -> str:
        return values[index] if len(values) > 1 else values[0]

    citations = [
        {
            "source_id": value_at(case.expected_source_ids, index),
            "document_id": value_at(case.expected_document_ids, index),
            "document_version": value_at(case.expected_document_versions, index),
            "chunk_id": chunk_id,
        }
        for index, chunk_id in enumerate(case.expected_chunk_ids)
    ]
    return {
        "answer": " ".join(case.expected_facts),
        "citations": citations,
    }


class SuccessfulEvaluationRuntime:
    def __init__(self) -> None:
        contract = load_contract(CONTRACT_PATH)
        evaluation = contract.get("evaluation")
        assert isinstance(evaluation, dict)
        raw_eligible = evaluation.get("provider_eligible_case_ids")
        assert isinstance(raw_eligible, list)
        eligible = frozenset(cast(list[str], raw_eligible))
        dataset = load_golden_dataset(ROOT / "configs/eval/golden.jsonl")
        self._structured_inputs = [
            _case_structured_input(case) for case in dataset.cases if case.case_id in eligible
        ]
        self.calls = 0
        self.arguments: list[dict[str, object]] = []

    @property
    def remaining_structured_inputs(self) -> int:
        return len(self._structured_inputs)

    def converse(self, **kwargs: object) -> dict[str, object]:
        self.calls += 1
        self.arguments.append(dict(kwargs))
        assert kwargs["modelId"] == "global.amazon.nova-2-lite-v1:0"
        assert kwargs["inferenceConfig"] == {
            "maxTokens": 512,
            "temperature": 0.0,
            "topP": 1.0,
        }
        messages = kwargs["messages"]
        assert isinstance(messages, list)
        assert all(message.get("role") != "assistant" for message in messages)
        assert "outputConfig" not in kwargs
        if self.calls == 1:
            assert "toolConfig" not in kwargs
            content: list[dict[str, object]] = [{"text": "READY"}]
            stop_reason = "end_turn"
        else:
            system = kwargs.get("system")
            assert isinstance(system, list) and len(system) == 2
            assert system[-1] == {"text": verifier.STRUCTURED_GROUNDING_INSTRUCTION}
            tool_config = kwargs.get("toolConfig")
            assert isinstance(tool_config, dict)
            assert tool_config.get("toolChoice") == {"tool": {"name": "return_cited_answer"}}
            tools = tool_config.get("tools")
            assert isinstance(tools, list) and len(tools) == 1
            tool = tools[0]
            assert isinstance(tool, dict)
            tool_spec = tool.get("toolSpec")
            assert isinstance(tool_spec, dict)
            assert tool_spec.get("name") == "return_cited_answer"
            structured_input = self._structured_inputs.pop(0)
            content = [
                {
                    "toolUse": {
                        "toolUseId": f"tooluse-{self.calls}",
                        "name": "return_cited_answer",
                        "input": structured_input,
                    }
                }
            ]
            stop_reason = "tool_use"
        return {
            "output": {"message": {"content": content}},
            "usage": {"inputTokens": 8, "outputTokens": 1, "totalTokens": 9},
            "stopReason": stop_reason,
        }


class ParaphrasingEvaluationRuntime(SuccessfulEvaluationRuntime):
    def __init__(self) -> None:
        super().__init__()
        first = self._structured_inputs[0]
        first["answer"] = (
            "For local development the platform uses Qdrant, while its AWS vector target "
            "is OpenSearch."
        )


class WeakModalEvaluationRuntime(SuccessfulEvaluationRuntime):
    def __init__(self) -> None:
        super().__init__()
        contract = load_contract(CONTRACT_PATH)
        evaluation = contract["evaluation"]
        assert isinstance(evaluation, dict)
        case_ids = evaluation["provider_eligible_case_ids"]
        assert isinstance(case_ids, list)
        weakened_answers = {
            "Q15": (
                "The platform should apply bounded retries and a deadline, then use only "
                "an approved fallback or return a controlled error."
            ),
            "Q18": (
                "The platform should recover by rolling back the application, prompt, "
                "model, graph or index to the last known-good version as applicable."
            ),
            "Q19": (
                "Apply the reviewed last-known-good Terraform version; destroy should not "
                "be used as an ordinary rollback."
            ),
        }
        for case_id, structured_input in zip(
            case_ids,
            self._structured_inputs,
            strict=True,
        ):
            if case_id in weakened_answers:
                structured_input["answer"] = weakened_answers[case_id]


def _synthetic_aws_access_key() -> str:
    return "".join(("AKIA", "0000000000000000"))


class FailingAfterSmokeRuntime(ExactRuntime):
    def converse(self, **kwargs: object) -> dict[str, object]:
        if self.calls == 0:
            return super().converse(**kwargs)
        self.calls += 1
        raise RuntimeError(_synthetic_aws_access_key() + " secret provider envelope")


def test_exact_canonical_contract_loads_and_dry_run_performs_no_network() -> None:
    contract = load_contract(CONTRACT_PATH)
    summary = dry_run_summary(contract)

    assert summary.mode == "dry-run"
    assert summary.network_activity is False
    assert summary.provider_requests == 0
    assert summary.overall_status == "NOT RUN"
    assert [item.status for item in summary.checks].count("PASS") == 1
    assert contract["schema_version"] == "w5-001.bedrock-owner-verification.v6"
    assert contract["structured_response"] == {
        "mode": "forced_client_side_tool_schema",
        "tool_name": "return_cited_answer",
        "external_tool_execution": False,
        "grounding_instruction": verifier.STRUCTURED_GROUNDING_INSTRUCTION,
        "required_fields": ["answer", "citations"],
        "required_citation_fields": [
            "source_id",
            "document_id",
            "document_version",
            "chunk_id",
        ],
    }
    assert contract["runtime_evidence"] == {
        "record_synthetic_questions": True,
        "record_synthetic_answers": True,
        "record_citations": True,
        "record_provider_envelopes": False,
        "record_credentials": False,
        "owner_review_scope": "all_live_answers",
    }


def test_modified_reordered_or_noncanonical_contract_fails_closed(tmp_path: Path) -> None:
    exact = CONTRACT_PATH.read_text(encoding="utf-8")
    variants = (
        exact.replace('"profile":"default"', '"profile":"other"'),
        exact.replace(
            '"schema_version":"w5-001.bedrock-owner-verification.v6","prompt_id"',
            '"prompt_id":"W5-001","schema_version"',
        ),
        exact[:-1] + " \n",
    )
    for index, value in enumerate(variants):
        target = tmp_path / f"modified-{index}.json"
        target.write_text(value, encoding="utf-8")
        with pytest.raises(SafeVerificationError):
            load_contract(target)


def test_read_only_checks_exact_identity_model_and_three_quotas() -> None:
    summary = account_read_only_summary(
        load_contract(CONTRACT_PATH),
        sts_client=ExactSts(),
        quotas_client=ExactQuotas(),
        bedrock_client=ExactBedrock(),
    )

    by_name = {item.name: item for item in summary.checks}
    assert by_name["caller_identity"].status == "PASS"
    assert by_name["model_configuration"].status == "PASS"
    assert by_name["service_quotas"].status == "PASS"
    assert by_name["model_access"].status == "INDETERMINATE"
    assert summary.provider_requests == 0


def test_bounded_smoke_uses_exact_converse_settings_and_cost() -> None:
    runtime = ExactRuntime()
    response = asyncio.run(_smoke(load_contract(CONTRACT_PATH), runtime))

    assert runtime.calls == 1
    assert response.usage is not None
    assert response.usage.total_tokens == 9
    assert response.usage.estimated_cost_usd is not None


def test_paid_evaluation_structured_responses_pass_every_quality_gate() -> None:
    captured_report: dict[str, object] = {}

    def capture_report(payload: Mapping[str, object]) -> None:
        captured_report.update(payload)

    runtime = SuccessfulEvaluationRuntime()
    summary = paid_summary(
        load_contract(CONTRACT_PATH),
        mode="paid-evaluation",
        sts_client=ExactSts(),
        quotas_client=ExactQuotas(),
        bedrock_client=ExactBedrock(),
        runtime_client=runtime,
        pricing_confirmed=True,
        result_consumer=capture_report,
    )

    assert runtime.calls == 25
    assert runtime.remaining_structured_inputs == 0
    assert "toolConfig" not in runtime.arguments[0]
    assert all("toolConfig" in item for item in runtime.arguments[1:])
    assert all("outputConfig" not in item for item in runtime.arguments)
    assert summary.provider_requests == 25
    assert summary.input_tokens == 200
    assert summary.output_tokens == 25
    assert summary.estimated_cost_usd == pytest.approx(0.0000243, abs=1e-15)
    assert summary.overall_status == "INDETERMINATE"
    assert summary.report_written is False
    assert captured_report["provider_requests"] == 25
    assert captured_report["schema_version"] == "w5-001.bedrock-owner-result.v4"
    assert captured_report["status"] == "INDETERMINATE"
    evaluation = captured_report["evaluation"]
    assert isinstance(evaluation, dict)
    assert evaluation["live_quality_status"] == "INDETERMINATE"
    assert evaluation["live_hard_gate_status"] == "PASS"
    assert evaluation["grounding_policy"] == {
        "scope": "structured_live_evaluation_only",
        "owner_review_scope": "all_live_answers",
        "control_preservation_mode": "verbatim_operative_clauses",
        "automatic_weak_modal_gate": True,
        "instruction_sha256": ("117855656e1144a7ab242bfc63133e5c9d95382369fe9651a6532ae79258971b"),
        "question_is_evidence": False,
        "expected_facts_injected": False,
        "normative_strength_review_required": True,
    }
    assert evaluation["automatic_control_strength"] == {
        "status": "PASS",
        "failure_case_ids": [],
    }
    assert evaluation["semantic_review"] == {
        "status": "PENDING_OWNER_REVIEW",
        "required_case_ids": [
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
        ],
        "criteria": [
            "factual_equivalence",
            "completeness",
            "grounding",
            "no_contradiction",
            "control_strength",
            "safety",
        ],
    }
    assert evaluation["absolute_gate_status"] == "PASS"
    assert evaluation["baseline_comparison_status"] == "PASS"
    gates = evaluation["gates"]
    assert isinstance(gates, dict)
    assert set(gates.values()) == {"PASS"}
    cases = evaluation["cases"]
    assert isinstance(cases, list) and len(cases) == 39
    assert all(
        isinstance(case, dict) and case.get("automatic_exact_match_status") == "PASS"
        for case in cases
    )
    assert sum(case.get("execution_source") == "LIVE_BEDROCK" for case in cases) == 24
    assert sum(case.get("semantic_review_status") == "PENDING_OWNER_REVIEW" for case in cases) == 24
    assert sum(case.get("automatic_control_strength_status") == "PASS" for case in cases) == 24
    assert (
        sum(case.get("automatic_control_strength_status") == "NOT_APPLICABLE" for case in cases)
        == 15
    )
    required_case_ids = evaluation["semantic_review"]["required_case_ids"]
    assert {"Q15", "Q17", "Q18", "Q19"} <= set(required_case_ids)
    metrics = evaluation["metrics"]
    assert isinstance(metrics, dict)
    assert metrics["citation_precision"] == {
        "numerator": 28,
        "denominator": 28,
        "value": 1.0,
        "display": "1.000000",
    }
    usage = captured_report["usage"]
    assert isinstance(usage, dict)
    assert usage == {
        "input_tokens": 200,
        "output_tokens": 25,
        "total_tokens": 225,
        "estimated_cost_usd": pytest.approx(0.0000243, abs=1e-15),
    }


def test_paid_evaluation_failure_retains_content_free_partial_runtime_evidence() -> None:
    runtime = FailingAfterSmokeRuntime()

    with pytest.raises(SafeVerificationError) as error:
        paid_summary(
            load_contract(CONTRACT_PATH),
            mode="paid-evaluation",
            sts_client=ExactSts(),
            quotas_client=ExactQuotas(),
            bedrock_client=ExactBedrock(),
            runtime_client=runtime,
            pricing_confirmed=True,
        )

    assert runtime.calls == 2
    assert error.value.safe_code == "provider_invocation_failed"
    assert error.value.runtime_evidence == {
        "provider_requests_attempted": 2,
        "provider_responses_with_usage": 1,
        "recorded_input_tokens": 8,
        "recorded_output_tokens": 1,
        "recorded_total_tokens": 9,
        "recorded_estimated_cost_usd": pytest.approx(0.000000972, abs=1e-15),
        "recorded_cost_status": "PARTIAL",
        "report_written": False,
    }
    assert "AKIA" not in str(error.value)


def test_live_paraphrase_requires_owner_review_without_weakening_hard_gates() -> None:
    captured_report: dict[str, object] = {}
    summary = paid_summary(
        load_contract(CONTRACT_PATH),
        mode="paid-evaluation",
        sts_client=ExactSts(),
        quotas_client=ExactQuotas(),
        bedrock_client=ExactBedrock(),
        runtime_client=ParaphrasingEvaluationRuntime(),
        pricing_confirmed=True,
        result_consumer=captured_report.update,
    )

    assert summary.overall_status == "INDETERMINATE"
    evaluation = captured_report["evaluation"]
    assert isinstance(evaluation, dict)
    assert evaluation["live_quality_status"] == "INDETERMINATE"
    assert evaluation["live_hard_gate_status"] == "PASS"
    assert evaluation["baseline_comparison_status"] == "FAIL"
    semantic = evaluation["semantic_review"]
    assert isinstance(semantic, dict)
    assert semantic["required_case_ids"] == [
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
    ]
    cases = evaluation["cases"]
    assert isinstance(cases, list)
    first = cases[0]
    assert isinstance(first, dict)
    assert first["execution_source"] == "LIVE_BEDROCK"
    assert first["automatic_exact_match_status"] == "FAIL"
    assert first["hard_gate_status"] == "PASS"
    assert first["semantic_review_status"] == "PENDING_OWNER_REVIEW"
    assert first["question"] == (
        "Which vector database is selected for local development and which is the AWS target?"
    )
    assert first["answer"] == (
        "For local development the platform uses Qdrant, while its AWS vector target is OpenSearch."
    )
    assert first["returned_citations"] == first["expected_citations"]


def test_automatic_control_strength_gate_blocks_unsupported_weak_modals() -> None:
    captured_report: dict[str, object] = {}
    summary = paid_summary(
        load_contract(CONTRACT_PATH),
        mode="paid-evaluation",
        sts_client=ExactSts(),
        quotas_client=ExactQuotas(),
        bedrock_client=ExactBedrock(),
        runtime_client=WeakModalEvaluationRuntime(),
        pricing_confirmed=True,
        result_consumer=captured_report.update,
    )

    assert summary.overall_status == "FAIL"
    evaluation = captured_report["evaluation"]
    assert isinstance(evaluation, dict)
    assert evaluation["live_hard_gate_status"] == "FAIL"
    assert evaluation["live_hard_gate_failure_case_ids"] == ["Q15", "Q18", "Q19"]
    assert evaluation["automatic_control_strength"] == {
        "status": "FAIL",
        "failure_case_ids": ["Q15", "Q18", "Q19"],
    }
    semantic = evaluation["semantic_review"]
    assert isinstance(semantic, dict)
    assert len(semantic["required_case_ids"]) == 24
    cases = evaluation["cases"]
    assert isinstance(cases, list)
    by_id = {case["case_id"]: case for case in cases if isinstance(case, dict)}
    assert by_id["Q15"]["automatic_control_strength_failure_reasons"] == [
        "unsupported_weak_modal_should"
    ]
    assert by_id["Q18"]["automatic_control_strength_failure_reasons"] == [
        "unsupported_weak_modal_should"
    ]
    assert by_id["Q19"]["automatic_control_strength_failure_reasons"] == [
        "unsupported_weak_modal_should",
        "required_prohibition_marker_missing",
    ]
    assert all(
        by_id[case_id]["semantic_review_status"] == "PENDING_OWNER_REVIEW"
        for case_id in ("Q15", "Q18", "Q19")
    )


def test_run_evidence_records_runtime_events_result_and_integrity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    contract = copy.deepcopy(load_contract(CONTRACT_PATH))
    source_files = (
        "configs/verification/bedrock-owner-test.json",
        "configs/eval/golden.jsonl",
        "configs/eval/w3-002.yaml",
        "configs/eval/baselines/w3-002-v1.json",
        "configs/rag.yaml",
        "requirements.txt",
        "pyproject.toml",
        "tools/bedrock_owner_verify.py",
    )
    for relative in source_files:
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(f"synthetic {relative}\n", encoding="utf-8")
    monkeypatch.setattr(verifier, "__file__", str(tmp_path / "tools/bedrock_owner_verify.py"))
    monkeypatch.setattr(
        verifier,
        "_git_metadata",
        lambda _root: {
            "head_sha": "a" * 40,
            "branch": "main",
            "state": "DIRTY",
            "status_sha256": "b" * 64,
        },
    )
    evidence = RunEvidence.start(
        contract,
        contract_path=tmp_path / "configs/verification/bedrock-owner-test.json",
        run_id="W5-001-20260904-01",
        mode="dry-run",
        command_argv=("python", "tools/bedrock_owner_verify.py", "--mode", "dry-run"),
        repository_root=tmp_path,
    )
    evidence.event("synthetic_check", {"status": "PASS"})
    evidence.finish({"schema_version": "test.v1", "overall_status": "NOT RUN"})

    manifest = json.loads(evidence.manifest_path.read_text(encoding="utf-8"))
    result = json.loads(evidence.result_path.read_text(encoding="utf-8"))
    integrity = json.loads(evidence.integrity_path.read_text(encoding="utf-8"))
    events = [json.loads(line) for line in evidence.events_path.read_text().splitlines()]
    assert manifest["runtime"]["python_version"]
    assert manifest["repository"]["head_sha"] == "a" * 40
    assert manifest["source_files"]["verifier"]["sha256"]
    assert manifest["grounding_policy"] == {
        "scope": "structured_live_evaluation_only",
        "owner_review_scope": "all_live_answers",
        "control_preservation_mode": "verbatim_operative_clauses",
        "automatic_weak_modal_gate": True,
        "instruction_sha256": ("117855656e1144a7ab242bfc63133e5c9d95382369fe9651a6532ae79258971b"),
        "question_is_evidence": False,
        "expected_facts_injected": False,
        "normative_strength_review_required": True,
    }
    assert result["run_id"] == "W5-001-20260904-01"
    assert result["completed_at_utc"].endswith("Z")
    assert [item["event_type"] for item in events] == [
        "run_started",
        "synthetic_check",
        "run_completed",
    ]
    assert set(integrity["files"]) == {"manifest.json", "events.jsonl", "result.json"}
    with pytest.raises(SafeVerificationError, match="run_id_already_exists"):
        RunEvidence.start(
            contract,
            contract_path=tmp_path / "configs/verification/bedrock-owner-test.json",
            run_id="W5-001-20260904-01",
            mode="dry-run",
            command_argv=("python",),
            repository_root=tmp_path,
        )


def test_complete_owner_review_can_close_all_required_live_semantic_cases() -> None:
    contract = load_contract(CONTRACT_PATH)
    contract_evaluation = contract["evaluation"]
    assert isinstance(contract_evaluation, dict)
    required_case_ids = contract_evaluation["provider_eligible_case_ids"]
    assert isinstance(required_case_ids, list)
    case_records = [
        {
            "case_id": case_id,
            "execution_source": "LIVE_BEDROCK",
            "actual_outcome": "ANSWERED",
        }
        for case_id in required_case_ids
    ]
    result = {
        "evaluation": {
            "live_hard_gate_status": "PASS",
            "semantic_review": {"required_case_ids": required_case_ids},
            "cases": case_records,
        }
    }
    review = {
        "schema_version": "w5-001.owner-semantic-review.v2",
        "prompt_id": "W5-001",
        "run_id": "W5-001-20260904-01",
        "reviewer": "Gyan Prakash Rai",
        "reviewer_role": "Project Owner and Final Approval Reviewer",
        "reviewed_at": "2026-09-04T12:00:00+08:00",
        "decisions": [
            {
                "case_id": case_id,
                "factual_equivalence": "PASS",
                "completeness": "PASS",
                "grounding": "PASS",
                "no_contradiction": "PASS",
                "control_strength": "PASS",
                "safety": "PASS",
                "status": "PASS",
                "reason": "The synthetic answer is factually equivalent and fully grounded.",
            }
            for case_id in required_case_ids
        ],
    }

    status, decisions = _validate_owner_review(
        contract,
        run_id="W5-001-20260904-01",
        result=result,
        review=review,
    )

    assert status == "PASS"
    assert decisions == review["decisions"]
