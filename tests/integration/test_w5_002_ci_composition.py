"""Composition tests for W5-002 Python 3.13 config, workflows, and consumers."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from tools import w5_002_ci
from tools.platformctl.validate import EXPECTED_GHA_FEATURE

ROOT = Path(__file__).resolve().parents[2]


def test_config_helper_makefile_and_feature_matrix_share_one_v2_contract() -> None:
    config = w5_002_ci.validate_config(w5_002_ci.load_json(ROOT / "configs/ci/w5-002.json"))
    matrix = json.loads((ROOT / "feature-matrix.yaml").read_text(encoding="utf-8"))
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")

    assert (
        next(item for item in matrix["features"] if item["id"] == "GHA-001") == EXPECTED_GHA_FEATURE
    )
    assert config["reports"] == list(w5_002_ci.REPORT_PATHS)
    assert config["schema_version"] == w5_002_ci.CONFIG_SCHEMA
    for target in (
        "w5-002-validate-config",
        "w5-002-validate-locks",
        "w5-002-static",
        "w5-002-workflow-contract",
        "w5-002-build",
        "w5-002-scan",
        "w5-002-sbom",
        "w5-002-clean-runtime",
        "w5-002-reconcile",
        "w5-002-rollback-identity",
        "w5-002-clean",
        "w5-002-verify-clean",
    ):
        assert f"{target}:" in makefile
    assert "W5_002_BUILDER = enterprise-ai-platform-w5-002-py313" in makefile
    assert "owner-must-supply-exact-external-w5-002-py313-candidate.oci" in makefile
    assert "write-cleanup-retention" in makefile
    assert "reconcile-supply-chain --reports-dir $(W5_002_REPORTS)" in makefile


def test_all_five_owner_generated_lock_consumers_remain_wired() -> None:
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
    assert "requirements-ci.lock" in workflows
    assert "requirements-checkov.lock" in workflows
    assert workflows.count("-lockfile=readonly") >= 3


def test_dockerfile_uses_one_qualified_wolfi_pair_and_minimal_runtime() -> None:
    dockerfile = (ROOT / "docker/application.Dockerfile").read_text(encoding="utf-8")
    runtime_stage = dockerfile.split(
        f"FROM {w5_002_ci.RUNTIME_IMAGE}",
        maxsplit=1,
    )[1]

    assert dockerfile.count("FROM ") == 2
    assert f"FROM {w5_002_ci.BUILDER_IMAGE} AS builder" in dockerfile
    assert f"FROM {w5_002_ci.RUNTIME_IMAGE}" in dockerfile
    assert "/venv/bin/python -m pip install --require-hashes --no-deps" in dockerfile
    assert "COPY --from=builder --chown=65532:65532 /venv /venv" in dockerfile
    assert "USER 65532:65532" in runtime_stage
    assert 'ENTRYPOINT ["/venv/bin/python", "-m", "uvicorn"]' in runtime_stage
    assert "apt-get" not in dockerfile
    assert "apk add" not in dockerfile
    assert "RUN " not in runtime_stage
    assert (
        "ENTERPRISE_AI_AGENT_STORE_PATH=/var/lib/enterprise-ai-platform/"
        "w4-002/agent-control-v1.sqlite3"
    ) in runtime_stage


def test_source_composition_is_post_edit_content_not_baseline_commit_identity() -> None:
    composition = w5_002_ci.source_composition_sha256(ROOT)

    assert composition.startswith("sha256:")
    assert len(composition) == 71
    assert composition != w5_002_ci.BASELINE_SOURCE_COMPOSITION


def test_partial_or_unknown_report_set_fails_closed(tmp_path: Path) -> None:
    reports = tmp_path / "reports"
    reports.mkdir()
    (reports / "image-identity.json").write_text("{}\n", encoding="utf-8")

    with pytest.raises(w5_002_ci.ContractError, match="missing, partial, or contains"):
        w5_002_ci.validate_report_set(reports, "supply-chain")


def test_helper_source_has_no_external_process_or_network_client() -> None:
    source = (ROOT / "tools/w5_002_ci.py").read_text(encoding="utf-8")
    prohibited = ("subprocess", "socket", "urllib.request", "boto3", "docker.from_env")

    assert not any(token in source for token in prohibited)


def test_w6_001_ci_extension_is_offline_and_source_template_only() -> None:
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

    assert "-m tools.w6_001_k8s validate-template --template-root deploy/k8s" in workflow
    assert "deploy/k8s --framework kubernetes" in workflow
    assert "policies/opa/kubernetes.rego policies/opa/kubernetes_test.rego" in workflow
    assert "policies/opa/exceptions.json --verbose" in workflow
    for prohibited in ("bind-release", "kubectl", "aws eks", "aws ecr", "docker push"):
        assert prohibited not in workflow


def test_supply_chain_remediation_policy_is_composed_without_new_waivers() -> None:
    import json

    config = json.loads((ROOT / "configs/ci/w5-002.json").read_text(encoding="utf-8"))
    remediation = config["remediation"]
    assert remediation["waivers"] == {
        "expiry_required": True,
        "new_waivers_allowed": False,
    }
    assert remediation["zero_critical_required"] is True


def test_w6_003_ci_extension_validates_only_the_local_readiness_contract() -> None:
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

    assert (
        "-m tools.w6_003_readiness validate-config --root . --config "
        "configs/readiness/local-integrated-readiness.yaml" in workflow
    )
    assert (
        "-m tools.platformctl w6-004-validate-source --config configs/lifecycle/w6-004.json"
        in workflow
    )
    for prohibited in (
        "validate-evidence",
        "w6-004-readiness-manifest.json",
        "kubectl",
        "aws eks",
        "aws ecr",
        "docker push",
    ):
        assert prohibited not in workflow
