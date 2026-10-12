"""Smoke test for the stdout-only evidence recorder entry point."""

from __future__ import annotations

import json

from tools.record_test_evidence import main

from tests.fakes import FixedClock


def test_cli_prints_one_json_record_without_creating_a_file(
    capsys: object,
) -> None:
    return_code = main(
        [
            "--command",
            "python -B -m pytest",
            "--git-sha",
            "UNCOMMITTED",
            "--git-state",
            "UNCOMMITTED",
            "--environment",
            "sandbox",
            "--result",
            "PASS",
            "--report-path",
            "docs/test-evidence/W1/W1-003.md",
        ],
        clock=FixedClock(),
    )
    output = capsys.readouterr().out  # type: ignore[attr-defined]
    payload = json.loads(output)

    assert return_code == 0
    assert payload["git_sha"] == "UNCOMMITTED"
    assert payload["report_path"] == "docs/test-evidence/W1/W1-003.md"
