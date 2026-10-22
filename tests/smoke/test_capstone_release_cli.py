"""Owner CLI surface remains bounded and redacted."""

from __future__ import annotations

import json

import pytest
import tools.capstone_release as release


def test_trigger_stdout_redacted(monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    result = {
        "record_id": "record-id",
        "revision": 1,
        "record_sha256": "a" * 64,
        "workflow_run_id": 42,
        "run_url": "https://api.github.com/run/42",
        "html_url": "https://github.com/run/42",
        "status": "DISPATCHED",
    }
    monkeypatch.setattr(release, "_trigger", lambda _args: result)
    assert (
        release.main(
            [
                "trigger",
                "--record",
                "record",
                "--sha256-file",
                "sidecar",
                "--commit",
                "a" * 40,
                "--opa-receipt",
                "receipt",
                "--opa-receipt-sha256-file",
                "receipt-sidecar",
            ]
        )
        == 0
    )
    output = capsys.readouterr().out
    assert json.loads(output) == result
    assert list(json.loads(output)) == [
        "record_id",
        "revision",
        "record_sha256",
        "workflow_run_id",
        "run_url",
        "html_url",
        "status",
    ]
    assert "record_b64url" not in output and "opa_receipt_b64url" not in output


def test_hcp_approval_target_is_not_exposed() -> None:
    with pytest.raises(SystemExit):
        release._parser().parse_args(
            [
                "approve",
                "--target",
                "hcp",
                "--record",
                "ready.json",
                "--sha256-file",
                "ready.sha256",
                "--run-id",
                "7",
                "--environment-id",
                "42",
                "--ready-artifact-id",
                "9",
            ]
        )
