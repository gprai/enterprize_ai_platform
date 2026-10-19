"""Exact W9-004 policy and registry-binding contracts."""

import os
import subprocess
import sys
from pathlib import Path

from enterprise_ai_platform.model_supply_chain import load_supply_chain_policy
from tests.fakes.w9_004_model_supply_chain import make_eligibility

ROOT = Path(__file__).resolve().parents[2]
ELIGIBILITY_PATH = "${{ runner.temp }}/w9-004/eligibility.json"


def test_direct_cli_bootstraps_source_without_ambient_pythonpath() -> None:
    environment = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    environment.pop("PYTHONPATH", None)

    completed = subprocess.run(  # noqa: S603 -- fixed local interpreter and script
        [sys.executable, "-B", str(ROOT / "tools/w9_004_supply_chain.py"), "--help"],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )

    assert completed.returncode == 0, completed.stderr
    assert "usage:" in completed.stdout


def test_policy_preserves_owner_approved_limits() -> None:
    policy = load_supply_chain_policy()
    assert policy.feature_ids == ("SUPPLY-002", "GHA-002")
    assert policy.region == "ap-southeast-1"
    assert policy.limits.maximum_artifact_bytes == 10_737_418_240
    assert policy.limits.evidence_freshness_hours == 24
    assert policy.limits.automatic_retry_attempts == 0
    assert policy.limits.concurrent_candidates == 1
    assert policy.security.allowed_weight_extensions == (".safetensors",)
    assert policy.github.environment == "sandbox"
    assert policy.network_access == "OWNER_APPROVED_WORKFLOW_ONLY"
    assert policy.deployment_approval == "NOT_AUTHORIZED"


def test_eligibility_is_bound_to_exact_candidate_and_policy() -> None:
    evidence = make_eligibility()
    assert evidence.inventory.artifact_sha256 == evidence.candidate.artifact_sha256
    assert evidence.opa_decision.policy_sha256 == evidence.policy_sha256
    assert tuple(item.scanner for item in evidence.scanners) == (
        "checkov",
        "grype",
        "model-format",
        "trivy",
    )


def test_workflow_scopes_transient_path_to_each_consumer_step() -> None:
    workflow = (ROOT / ".github/workflows/model-supply-chain.yml").read_text(encoding="utf-8")

    def step(name: str) -> str:
        return workflow.split(f"      - name: {name}\n", 1)[1].split("      - name:", 1)[0]

    validation = step("Validate non-secret dispatch identities")
    fetch = step("Fetch the exact versioned eligibility record")
    enforcement = step("Enforce schema and OPA admission policy")
    upload = step("Upload transient non-secret gate evidence")
    cleanup = step("Remove the downloaded evidence")

    assert "ELIGIBILITY_PATH:" not in validation
    assert f"ELIGIBILITY_PATH: {ELIGIBILITY_PATH}" in fetch
    assert f"ELIGIBILITY_PATH: {ELIGIBILITY_PATH}" in enforcement
    assert f"path: {ELIGIBILITY_PATH}" in upload
    assert f"ELIGIBILITY_PATH: {ELIGIBILITY_PATH}" in cleanup
