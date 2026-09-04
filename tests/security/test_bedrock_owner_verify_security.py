"""Security and privacy controls for the W5-001 owner verifier."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
from tools.bedrock_owner_verify import (
    STRUCTURED_GROUNDING_INSTRUCTION,
    ConverseProvider,
    RuntimeLedger,
    SafeVerificationError,
    _automatic_control_strength_failures,
    _error_public_mapping,
    _redacted_argv,
    _safe_synthetic_text,
    _smoke,
    _validate_owner_review,
    _verify_identity,
    _with_runtime_ledger,
    build_parser,
    load_contract,
)

from enterprise_ai_platform.llm.models import ChatMessage, ChatRequest, ChatRole

ROOT = Path(__file__).resolve().parents[2]
CONTRACT = ROOT / "configs/verification/bedrock-owner-test.json"


class WrongIdentity:
    def get_caller_identity(self) -> dict[str, object]:
        return {"Account": "000000000000", "Arn": "arn:aws:iam::000000000000:user/wrong"}


def _synthetic_aws_access_key() -> str:
    return "".join(("AKIA", "0000000000000000"))


class FailingIdentity:
    def get_caller_identity(self) -> dict[str, object]:
        raise RuntimeError(_synthetic_aws_access_key() + " secret provider envelope")


class ProviderFailure(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(_synthetic_aws_access_key() + " secret provider envelope")
        self.response: dict[str, object] = {
            "Error": {
                "Code": code,
                "Message": _synthetic_aws_access_key() + " secret provider envelope",
            }
        }


class FailingRuntime:
    def __init__(self, code: str) -> None:
        self.code = code

    def converse(self, **_kwargs: object) -> dict[str, object]:
        raise ProviderFailure(self.code)


class RecordingRuntime:
    def __init__(self) -> None:
        self.arguments: dict[str, object] = {}

    def converse(self, **kwargs: object) -> dict[str, object]:
        self.arguments = dict(kwargs)
        return {
            "output": {
                "message": {
                    "content": [
                        {
                            "toolUse": {
                                "toolUseId": "tooluse-synthetic",
                                "name": "return_cited_answer",
                                "input": {
                                    "answer": "Synthetic grounded answer.",
                                    "citations": [
                                        {
                                            "source_id": "SOURCE",
                                            "document_id": "document-id",
                                            "document_version": "document-version",
                                            "chunk_id": "chunk-id",
                                        }
                                    ],
                                },
                            }
                        }
                    ]
                }
            },
            "usage": {"inputTokens": 1, "outputTokens": 1, "totalTokens": 2},
            "stopReason": "tool_use",
        }


class StaticRuntime:
    def __init__(self, content: list[dict[str, object]], stop_reason: str) -> None:
        self._content = content
        self._stop_reason = stop_reason

    def converse(self, **_kwargs: object) -> dict[str, object]:
        return {
            "output": {"message": {"content": self._content}},
            "usage": {"inputTokens": 1, "outputTokens": 1, "totalTokens": 2},
            "stopReason": self._stop_reason,
        }


class ProhibitedDownstreamClient:
    def __getattr__(self, _name: str) -> object:
        raise AssertionError("identity mismatch must stop all downstream clients")


def test_identity_mismatch_is_content_free_and_fails() -> None:
    result = _verify_identity(load_contract(CONTRACT), WrongIdentity())

    assert result.status == "FAIL"
    assert result.safe_code == "identity_mismatch"
    assert "000000000000" not in json.dumps(result.safe_code)


def test_identity_mismatch_stops_before_model_and_quota_calls() -> None:
    from tools.bedrock_owner_verify import account_read_only_summary

    blocked = ProhibitedDownstreamClient()
    summary = account_read_only_summary(
        load_contract(CONTRACT),
        sts_client=WrongIdentity(),
        quotas_client=blocked,  # type: ignore[arg-type]
        bedrock_client=blocked,  # type: ignore[arg-type]
    )

    assert summary.overall_status == "FAIL"
    assert {item.name: item.status for item in summary.checks}["service_quotas"] == "NOT RUN"


def test_provider_exception_is_replaced_with_safe_code() -> None:
    with pytest.raises(SafeVerificationError) as error:
        _verify_identity(load_contract(CONTRACT), FailingIdentity())

    assert error.value.safe_code == "identity_provider_error"
    assert "AKIA" not in str(error.value)


@pytest.mark.parametrize(
    ("provider_code", "safe_code"),
    (
        ("AccessDeniedException", "provider_access_denied"),
        ("ExpiredTokenException", "provider_authentication_failed"),
        ("UnrecognizedClientException", "provider_authentication_failed"),
        ("ValidationException", "provider_validation_failed"),
        ("ResourceNotFoundException", "provider_resource_not_found"),
        ("ThrottlingException", "provider_throttled"),
        ("ServiceQuotaExceededException", "provider_quota_exceeded"),
        ("ModelNotReadyException", "provider_model_not_ready"),
        ("ModelTimeoutException", "provider_model_timeout"),
        ("ModelErrorException", "provider_model_error"),
        ("InternalServerException", "provider_internal_error"),
        ("ServiceUnavailableException", "provider_service_unavailable"),
        ("UnknownProviderException", "provider_invocation_failed"),
    ),
)
def test_runtime_provider_failures_use_only_allowlisted_content_free_codes(
    provider_code: str,
    safe_code: str,
) -> None:
    with pytest.raises(SafeVerificationError) as error:
        asyncio.run(_smoke(load_contract(CONTRACT), FailingRuntime(provider_code)))

    assert error.value.safe_code == safe_code
    assert "AKIA" not in str(error.value)
    assert "secret provider envelope" not in str(error.value)


def test_partial_runtime_evidence_contains_only_safe_numeric_metadata() -> None:
    ledger = RuntimeLedger()
    with pytest.raises(SafeVerificationError) as error:
        asyncio.run(
            _smoke(
                load_contract(CONTRACT),
                FailingRuntime("AccessDeniedException"),
                ledger=ledger,
            )
        )

    payload = _error_public_mapping(_with_runtime_ledger(error.value, ledger))
    encoded = json.dumps(payload, separators=(",", ":"))
    assert payload["safe_code"] == "provider_access_denied"
    assert payload["runtime_evidence"] == {
        "provider_requests_attempted": 1,
        "provider_responses_with_usage": 0,
        "recorded_input_tokens": 0,
        "recorded_output_tokens": 0,
        "recorded_total_tokens": 0,
        "recorded_estimated_cost_usd": 0.0,
        "recorded_cost_status": "PARTIAL",
        "report_written": False,
    }
    assert "AKIA" not in encoded
    assert "secret provider envelope" not in encoded


def _synthetic_structured_request() -> ChatRequest:
    return ChatRequest(
        messages=(
            ChatMessage(role=ChatRole.SYSTEM, content="Synthetic system instruction."),
            ChatMessage(role=ChatRole.USER, content="Synthetic question."),
        ),
        max_output_tokens=512,
    )


def test_forced_tool_schema_is_translated_without_executing_a_tool() -> None:
    runtime = RecordingRuntime()
    provider = ConverseProvider(
        runtime,
        load_contract(CONTRACT),
        structured_response=True,
    )
    response = asyncio.run(provider.chat(_synthetic_structured_request()))

    messages = runtime.arguments["messages"]
    assert isinstance(messages, list)
    assert all(message.get("role") != "assistant" for message in messages)
    system = runtime.arguments["system"]
    assert isinstance(system, list) and system == [
        {"text": "Synthetic system instruction."},
        {"text": STRUCTURED_GROUNDING_INSTRUCTION},
    ]
    assert "Synthetic question." not in STRUCTURED_GROUNDING_INSTRUCTION
    assert runtime.arguments["inferenceConfig"] == {
        "maxTokens": 512,
        "temperature": 0.0,
        "topP": 1.0,
    }
    tool_config = runtime.arguments["toolConfig"]
    assert isinstance(tool_config, dict)
    assert tool_config["toolChoice"] == {"tool": {"name": "return_cited_answer"}}
    tools = tool_config["tools"]
    assert isinstance(tools, list) and len(tools) == 1
    tool = tools[0]
    assert isinstance(tool, dict)
    tool_spec = tool["toolSpec"]
    assert isinstance(tool_spec, dict)
    schema = tool_spec["inputSchema"]
    assert isinstance(schema, dict)
    assert schema["json"] == {
        "type": "object",
        "properties": {
            "answer": {
                "type": "string",
                "description": STRUCTURED_GROUNDING_INSTRUCTION,
            },
            "citations": {
                "type": "array",
                "description": "One or more exact supplied evidence citations.",
                "items": {
                    "type": "object",
                    "properties": {
                        "source_id": {
                            "type": "string",
                            "description": (
                                "Copy the exact source_id from one supplied evidence header."
                            ),
                        },
                        "document_id": {
                            "type": "string",
                            "description": (
                                "Copy the exact document_id from one supplied evidence header."
                            ),
                        },
                        "document_version": {
                            "type": "string",
                            "description": (
                                "Copy the exact document_version from one supplied evidence header."
                            ),
                        },
                        "chunk_id": {
                            "type": "string",
                            "description": (
                                "Copy the exact chunk_id from one supplied evidence header."
                            ),
                        },
                    },
                    "required": [
                        "source_id",
                        "document_id",
                        "document_version",
                        "chunk_id",
                    ],
                },
            },
        },
        "required": ["answer", "citations"],
    }
    assert "outputConfig" not in runtime.arguments
    assert response.stop_reason == "tool_use"
    assert response.tool_calls == ()
    assert json.loads(response.text) == {
        "answer": "Synthetic grounded answer.",
        "citations": [
            {
                "source_id": "SOURCE",
                "document_id": "document-id",
                "document_version": "document-version",
                "chunk_id": "chunk-id",
            }
        ],
    }


@pytest.mark.parametrize(
    ("content", "stop_reason"),
    (
        ([{"text": "secret provider response"}], "tool_use"),
        (
            [
                {
                    "toolUse": {
                        "toolUseId": "tooluse-synthetic",
                        "name": "return_cited_answer",
                        "input": {"answer": "Synthetic", "citations": []},
                    }
                }
            ],
            "tool_use",
        ),
        (
            [
                {
                    "toolUse": {
                        "toolUseId": "tooluse-synthetic",
                        "name": "wrong_tool",
                        "input": {"answer": "Synthetic", "citations": []},
                    }
                }
            ],
            "tool_use",
        ),
        (
            [
                {
                    "toolUse": {
                        "toolUseId": "tooluse-synthetic",
                        "name": "return_cited_answer",
                        "input": {"answer": "Synthetic"},
                    }
                }
            ],
            "tool_use",
        ),
        (
            [
                {
                    "toolUse": {
                        "toolUseId": "tooluse-synthetic",
                        "name": "return_cited_answer",
                        "input": {
                            "answer": "Synthetic",
                            "citations": [
                                {
                                    "source_id": "SOURCE",
                                    "document_id": "document-id",
                                    "document_version": "document-version",
                                    "chunk_id": "chunk-id",
                                    "unexpected": "secret provider response",
                                }
                            ],
                        },
                    }
                }
            ],
            "tool_use",
        ),
        (
            [
                {
                    "toolUse": {
                        "toolUseId": "tooluse-synthetic",
                        "name": "return_cited_answer",
                        "input": {
                            "answer": "Synthetic",
                            "citations": [
                                {
                                    "source_id": "SOURCE",
                                    "document_id": "document-id",
                                    "document_version": "document-version",
                                    "chunk_id": "chunk-id",
                                }
                            ],
                        },
                    }
                }
            ],
            "end_turn",
        ),
    ),
)
def test_structured_response_mismatch_fails_closed_without_content_leakage(
    content: list[dict[str, object]],
    stop_reason: str,
) -> None:
    provider = ConverseProvider(
        StaticRuntime(content, stop_reason),
        load_contract(CONTRACT),
        structured_response=True,
    )

    with pytest.raises(SafeVerificationError) as error:
        asyncio.run(provider.chat(_synthetic_structured_request()))

    assert error.value.safe_code == "provider_structured_response_invalid"
    assert "secret provider response" not in str(error.value)


def test_network_and_paid_modes_are_never_defaults() -> None:
    arguments = build_parser().parse_args([])

    assert arguments.mode == "dry-run"
    assert arguments.owner_authorized_network is False
    assert arguments.owner_authorized_paid is False
    assert arguments.owner_confirmed_pricing is False
    assert arguments.run_id is None


def test_contract_contains_no_secret_value_fields_or_fallback() -> None:
    source = CONTRACT.read_text(encoding="utf-8")
    contract = load_contract(CONTRACT)

    for prohibited in ("access_key", "secret_key", "session_token", "password", "private_key"):
        assert prohibited not in source.casefold()
    assert contract["aws"]["fallback_region"] is None
    assert contract["bedrock"]["fallback_policy"] is None
    structured_response = contract["structured_response"]
    assert isinstance(structured_response, dict)
    assert structured_response["external_tool_execution"] is False
    assert structured_response["grounding_instruction"] == STRUCTURED_GROUNDING_INSTRUCTION
    for case_specific_text in (
        "Q15",
        "Q17",
        "Q18",
        "Q19",
        "Q20",
        "bounded retries",
        "stop the workflow",
        "roll back",
        "destroy",
        "teardown",
        "dependency remains",
        "residual resource",
    ):
        assert case_specific_text.casefold() not in STRUCTURED_GROUNDING_INSTRUCTION.casefold()
    evidence = contract["runtime_evidence"]
    assert isinstance(evidence, dict)
    assert evidence == {
        "record_synthetic_questions": True,
        "record_synthetic_answers": True,
        "record_citations": True,
        "record_provider_envelopes": False,
        "record_credentials": False,
        "owner_review_scope": "all_live_answers",
    }
    assert "Preserve the normative strength" in STRUCTURED_GROUNDING_INSTRUCTION
    assert "must not be weakened" in STRUCTURED_GROUNDING_INSTRUCTION
    assert "copy each operative requirement or prohibition verbatim" in (
        STRUCTURED_GROUNDING_INSTRUCTION
    )
    assert "unless that exact term appears in the supplied evidence" in (
        STRUCTURED_GROUNDING_INSTRUCTION
    )


def test_automatic_control_strength_gate_is_conservative_and_evidence_derived() -> None:
    assert _automatic_control_strength_failures(
        ("Apply bounded retries and a deadline.",),
        "The platform should apply bounded retries and a deadline.",
    ) == ("unsupported_weak_modal_should",)
    assert _automatic_control_strength_failures(
        ("Roll back to the last known-good version.",),
        "The platform should recover by rolling back to the last known-good version.",
    ) == ("unsupported_weak_modal_should",)
    assert _automatic_control_strength_failures(
        ("Do not use destroy as an ordinary rollback.",),
        "Destroy should not be used as an ordinary rollback.",
    ) == (
        "unsupported_weak_modal_should",
        "required_prohibition_marker_missing",
    )
    assert (
        _automatic_control_strength_failures(
            ("Stop the workflow safely and record the reason.",),
            "The agent must stop the workflow safely and record the reason.",
        )
        == ()
    )
    assert (
        _automatic_control_strength_failures(
            ("Sensitive information may be redacted.",),
            "Sensitive information may be redacted.",
        )
        == ()
    )
    assert _automatic_control_strength_failures(
        ("The platform must deny the request.",),
        "The platform denies the request.",
    ) == ("required_mandatory_marker_missing",)


def test_runtime_command_redaction_and_synthetic_evidence_reject_credentials() -> None:
    assert _redacted_argv(("--api-token", "secret-value", "--mode=dry-run")) == [
        "--api-token",
        "[REDACTED]",
        "--mode=dry-run",
    ]
    with pytest.raises(SafeVerificationError) as error:
        _safe_synthetic_text("Synthetic answer " + _synthetic_aws_access_key())
    assert error.value.safe_code == "synthetic_evidence_prohibited_content"
    assert "AKIA" not in str(error.value)


def test_owner_review_must_cover_every_live_case_and_cannot_override_hard_failure() -> None:
    contract = load_contract(CONTRACT)
    evaluation = contract["evaluation"]
    assert isinstance(evaluation, dict)
    required_case_ids = evaluation["provider_eligible_case_ids"]
    assert isinstance(required_case_ids, list)
    case_records = [
        {
            "case_id": case_id,
            "execution_source": "LIVE_BEDROCK",
            "actual_outcome": "ANSWERED",
        }
        for case_id in required_case_ids
    ]
    incomplete = {
        "schema_version": "w5-001.owner-semantic-review.v2",
        "prompt_id": "W5-001",
        "run_id": "W5-001-20260904-01",
        "reviewer": "Gyan Prakash Rai",
        "reviewer_role": "Project Owner and Final Approval Reviewer",
        "reviewed_at": "2026-09-04T12:00:00+08:00",
        "decisions": [],
    }
    prior_partial_scope_result = {
        "evaluation": {
            "live_hard_gate_status": "PASS",
            "semantic_review": {"required_case_ids": ["Q1"]},
            "cases": case_records,
        }
    }
    with pytest.raises(SafeVerificationError) as error:
        _validate_owner_review(
            contract,
            run_id="W5-001-20260904-01",
            result=prior_partial_scope_result,
            review=incomplete,
        )
    assert error.value.safe_code == "owner_review_scope_invalid"

    result = {
        "evaluation": {
            "live_hard_gate_status": "PASS",
            "semantic_review": {"required_case_ids": required_case_ids},
            "cases": case_records,
        }
    }
    with pytest.raises(SafeVerificationError) as error:
        _validate_owner_review(
            contract,
            run_id="W5-001-20260904-01",
            result=result,
            review=incomplete,
        )
    assert error.value.safe_code == "owner_review_incomplete"

    complete_decisions = [
        {
            "case_id": case_id,
            "factual_equivalence": "PASS",
            "completeness": "PASS",
            "grounding": "PASS",
            "no_contradiction": "PASS",
            "control_strength": "PASS",
            "safety": "PASS",
            "status": "PASS",
            "reason": "Synthetic evidence passes every approved review criterion.",
        }
        for case_id in required_case_ids
    ]
    incomplete["decisions"] = complete_decisions
    hard_failure = {
        "evaluation": {
            "live_hard_gate_status": "FAIL",
            "semantic_review": {"required_case_ids": required_case_ids},
            "cases": case_records,
        }
    }
    status, _decisions = _validate_owner_review(
        contract,
        run_id="W5-001-20260904-01",
        result=hard_failure,
        review=incomplete,
    )
    assert status == "FAIL"

    unanswered_case_records = [
        {
            **case_record,
            "actual_outcome": (
                "ERROR" if case_record["case_id"] == required_case_ids[-1] else "ANSWERED"
            ),
        }
        for case_record in case_records
    ]
    answered_case_ids = required_case_ids[:-1]
    unanswered_result = {
        "evaluation": {
            "live_hard_gate_status": "FAIL",
            "semantic_review": {"required_case_ids": answered_case_ids},
            "cases": unanswered_case_records,
        }
    }
    unanswered_review = {
        **incomplete,
        "decisions": complete_decisions[:-1],
    }
    status, _decisions = _validate_owner_review(
        contract,
        run_id="W5-001-20260904-01",
        result=unanswered_result,
        review=unanswered_review,
    )
    assert status == "FAIL"
