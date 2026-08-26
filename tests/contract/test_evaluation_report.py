from __future__ import annotations

import json

from enterprise_ai_platform.evaluation.models import EvaluationReport


def test_report_schema_forbids_raw_content_fields() -> None:
    schema = json.dumps(EvaluationReport.model_json_schema(), sort_keys=True)
    for forbidden in (
        '"question"',
        '"expected_facts"',
        '"answer_text"',
        '"citations"',
        '"prompt"',
        '"provider_response"',
    ):
        assert forbidden not in schema


def test_only_two_report_runtime_fields_are_nondeterministic() -> None:
    fields = set(EvaluationReport.model_fields)
    assert {"generated_at_utc", "runtime_duration_ms"}.issubset(fields)
    assert "deterministic_payload_sha256" in fields
