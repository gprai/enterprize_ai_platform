"""Smoke checks for the read-only W11-001 CLI."""

from __future__ import annotations

import json
from pathlib import Path

from tools.ai_reliabilityctl import main

from enterprise_ai_platform.telemetry.ai_reliability import load_ai_reliability_policy
from tests.fakes.w11_001_ai_reliability import passing_batch


def test_validate_reports_source_contract_without_live_claim(capsys) -> None:
    assert main(["validate"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload == {
        "classification": "source-contract-not-live-evidence",
        "prompt_id": "W11-001",
        "schema_version": "w11-001.ai-reliability.v1",
        "sli_count": 17,
        "status": "VALID",
    }


def test_evaluate_returns_copyable_json_and_no_output_file(
    tmp_path: Path,
    capsys,
) -> None:
    policy = load_ai_reliability_policy()
    input_path = tmp_path / "evidence.json"
    input_path.write_text(passing_batch(policy).model_dump_json(), encoding="utf-8")
    before = set(tmp_path.iterdir())
    assert main(["evaluate", "--input", str(input_path)]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["decision"]["status"] == "PASS"
    assert payload["decision"]["release_allowed"] is True
    assert set(tmp_path.iterdir()) == before
