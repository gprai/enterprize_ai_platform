"""W11-003 CLI emits canonical, content-free, local-only JSON."""

import json
import subprocess  # noqa: S404 - isolated local CLI invocation is the test contract
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / "tools/recoveryctl.py"
CONFIG = "configs/recovery/disaster-recovery.yaml"


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed interpreter and local test CLI
        [sys.executable, "-B", str(CLI), *args],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_validate_reports_targets_without_readiness() -> None:
    result = _run("validate", "--config", CONFIG)
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["feature_ids"] == ["DR-001", "RPO-001"]
    assert payload["live_status"] == "NOT RUN"
    assert payload["multi_region_readiness"] == "NOT_ESTABLISHED"
    assert result.stdout.strip() == json.dumps(payload, sort_keys=True, separators=(",", ":"))


def test_rehearse_index_rebuild_remains_local_only() -> None:
    result = _run(
        "rehearse",
        "--config",
        CONFIG,
        "--operation",
        "INDEX_REBUILD",
        "--scope",
        "OPENSEARCH_INDEX",
    )
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["local_contract_status"] == "PASS"
    assert payload["live_status"] == "NOT RUN"
    assert payload["multi_region_readiness"] == "NOT_ESTABLISHED"


def test_cli_has_no_live_restore_or_cutover_verb() -> None:
    for command in ("restore-live", "cutover", "failover", "terraform-apply"):
        result = _run(command)
        assert result.returncode != 0
        assert command not in result.stdout


def test_invalid_operation_scope_fails_without_raw_exception() -> None:
    result = _run(
        "rehearse",
        "--config",
        CONFIG,
        "--operation",
        "INDEX_REBUILD",
        "--scope",
        "MODEL_REGISTRY",
    )
    assert result.returncode == 2
    assert result.stdout == ""
    assert result.stderr.strip() == "W11-003 validation failed"
