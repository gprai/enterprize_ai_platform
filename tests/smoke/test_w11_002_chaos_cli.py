"""W11-002 CLI is local-only and emits canonical content-free JSON."""

import json
import subprocess  # noqa: S404 - isolated local CLI invocation is the test contract
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / "tools/chaosctl.py"
CONFIG = "configs/chaos/controlled-dependency-chaos.yaml"


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed interpreter and local test CLI
        [sys.executable, "-B", str(CLI), *args],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_validate_reports_source_contract_not_live_evidence() -> None:
    result = _run("validate", "--config", CONFIG)
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "VALID"
    assert payload["live_status"] == "NOT RUN"
    assert payload["scenario_count"] == 13
    assert result.stdout.strip() == json.dumps(payload, sort_keys=True, separators=(",", ":"))


def test_rehearse_telemetry_loss_preserves_indeterminate_sli() -> None:
    result = _run("rehearse", "--config", CONFIG, "--scenario", "telemetry_loss")
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["local_control_status"] == "PASS"
    assert payload["sli_status"] == "INDETERMINATE"
    assert payload["live_status"] == "NOT RUN"
    assert payload["residue_status"] == "PASS"


def test_cli_has_no_live_execution_verb() -> None:
    result = _run("start-experiment")
    assert result.returncode != 0
    assert "start-experiment" not in result.stdout


def test_unknown_scenario_fails_without_raw_exception() -> None:
    result = _run("rehearse", "--config", CONFIG, "--scenario", "production-node-delete")
    assert result.returncode == 2
    assert result.stdout == ""
    assert result.stderr.strip() == "W11-002 validation failed"
