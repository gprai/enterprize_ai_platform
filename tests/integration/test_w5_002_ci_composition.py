"""Composition tests for W5-002 config, helper, workflows, and consumers."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from tools import w5_002_ci
from tools.platformctl.validate import EXPECTED_GHA_FEATURE

ROOT = Path(__file__).resolve().parents[2]


def test_config_helper_makefile_and_feature_matrix_share_one_contract() -> None:
    config = w5_002_ci.validate_config(w5_002_ci.load_json(ROOT / "configs/ci/w5-002.json"))
    matrix = json.loads((ROOT / "feature-matrix.yaml").read_text(encoding="utf-8"))
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")

    assert matrix["features"][-1] == EXPECTED_GHA_FEATURE
    assert config["reports"] == list(w5_002_ci.REPORT_PATHS)
    for target in (
        "w5-002-validate-config",
        "w5-002-static",
        "w5-002-workflow-contract",
        "w5-002-build",
        "w5-002-scan",
        "w5-002-sbom",
        "w5-002-reconcile",
        "w5-002-clean",
        "w5-002-verify-clean",
    ):
        assert f"{target}:" in makefile
    assert "W5_002_OCI_LAYOUT = $(W5_002_RAW_DIR)/oci-layout" in makefile
    assert "tar.exe -xf '$(W5_002_OCI)' -C '$(W5_002_OCI_LAYOUT)'" in makefile
    assert "image --input '$(W5_002_OCI_LAYOUT)'" in makefile
    assert "$(TRIVY) image --input $(W5_002_OCI)" not in makefile
    assert "Remove-Item -LiteralPath '$(W5_002_OCI_LAYOUT)'" in makefile


def test_all_five_owner_generated_lock_consumers_are_wired() -> None:
    expected = (
        ROOT / "requirements-runtime.lock",
        ROOT / "requirements-ci.lock",
        ROOT / "requirements-checkov.lock",
        ROOT / "infra/bootstrap/.terraform.lock.hcl",
        ROOT / "infra/environments/sandbox/.terraform.lock.hcl",
    )
    assert all(path.is_file() for path in expected)
    dockerfile = (ROOT / "docker/application.Dockerfile").read_text(encoding="utf-8")
    workflows = "\n".join(
        path.read_text(encoding="utf-8") for path in (ROOT / ".github/workflows").glob("*.yml")
    )
    assert "requirements-runtime.lock" in dockerfile
    assert (
        "ENTERPRISE_AI_AGENT_STORE_PATH=/var/lib/enterprise-ai-platform/"
        "w4-002/agent-control-v1.sqlite3"
    ) in dockerfile
    assert "chown 10001:10001 /var/lib/enterprise-ai-platform/w4-002" in dockerfile
    assert "requirements-ci.lock" in workflows
    assert "requirements-checkov.lock" in workflows
    assert workflows.count("-lockfile=readonly") >= 3


def test_partial_or_unknown_report_set_fails_closed(tmp_path: Path) -> None:
    reports = tmp_path / "reports"
    reports.mkdir()
    (reports / "image-identity.json").write_text("{}\n", encoding="utf-8")

    with pytest.raises(w5_002_ci.ContractError, match="missing, partial, or contains"):
        w5_002_ci.validate_report_set(reports, "supply-chain")


def test_helper_source_has_no_external_process_or_network_client() -> None:
    source = (ROOT / "tools/w5_002_ci.py").read_text(encoding="utf-8")
    prohibited = ("subprocess", "socket", "requests", "urllib.request", "boto3", "docker.from_env")

    assert not any(token in source for token in prohibited)
