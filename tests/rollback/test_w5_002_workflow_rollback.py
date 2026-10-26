"""Rollback boundary for W5-002 workflow-only Phase A changes."""

from __future__ import annotations

from pathlib import Path

from tools import w5_002_ci

ROOT = Path(__file__).resolve().parents[2]


def test_phase_a_rollback_is_workflow_disable_or_candidate_rejection_only() -> None:
    workflows = (ROOT / ".github/workflows/security-scan.yml").read_text(encoding="utf-8")
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")

    for prohibited in (
        "terraform apply",
        "terraform destroy",
        "docker push",
        "kubectl",
        "aws ecr",
    ):
        assert prohibited not in workflows.casefold()
        assert prohibited not in makefile.casefold()
    assert "eligible_for_owner_approval" in (ROOT / "tools/w5_002_ci.py").read_text(
        encoding="utf-8"
    )


def test_v2_rollback_identity_is_bound_to_the_exact_candidate() -> None:
    helper = (ROOT / "tools/w5_002_ci.py").read_text(encoding="utf-8")
    config = w5_002_ci.load_json(ROOT / "configs/ci/w5-002.json")

    assert w5_002_ci.ROLLBACK_SCHEMA in helper
    assert "application_manifest_digest" in helper
    assert "source_composition_sha256" in helper
    assert "deployment_status" in helper
    assert config["historical"] == {
        "config_schema": "w5-002.ci-config.v1",
        "python": "3.11.16",
        "status": "RETAINED EVIDENCE ONLY",
        "w5_002_formal_status": "FAIL",
    }


def test_rollback_does_not_claim_deployment_or_replace_historical_evidence() -> None:
    helper = (ROOT / "tools/w5_002_ci.py").read_text(encoding="utf-8")
    workflow = (ROOT / ".github/workflows/security-scan.yml").read_text(encoding="utf-8")

    assert '"deployment_status": "NOT RUN"' in helper
    assert '"rollback_status": "IDENTITY_RECORDED"' in helper
    assert '"formal_w5_002_status": "FAIL"' in helper
    assert "reports/verification" not in workflow
    assert "docker push" not in workflow.casefold()


def test_cancellation_is_bounded_to_duplicate_task_work() -> None:
    ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    plan = (ROOT / ".github/workflows/plan-sandbox.yml").read_text(encoding="utf-8")
    supply = (ROOT / ".github/workflows/security-scan.yml").read_text(encoding="utf-8")

    assert "w5-002-pr-${{ github.event.pull_request.number }}" in ci
    assert "group: w5-002-plan-sandbox" in plan
    assert "w5-002-py313-supply-chain-${{ github.sha }}" in supply
    assert all("cancel-in-progress: true" in text for text in (ci, plan, supply))


def test_migration_cleanup_runs_on_success_failure_and_cancellation() -> None:
    supply = (ROOT / ".github/workflows/security-scan.yml").read_text(encoding="utf-8")
    cleanup = supply.split("Remove only migration-created runtime resources", maxsplit=1)[1]

    assert "if: always()" in cleanup
    assert "write-cleanup-retention" in cleanup
    assert "docker buildx rm" in cleanup
    assert cleanup.index("docker buildx rm") < cleanup.index('rm -rf -- "$DOCKER_CONFIG"')
    assert 'test ! -e "$SUPPLY_CHAIN_DOWNLOADS"' in cleanup
    assert 'test ! -e "$SUPPLY_CHAIN_TOOLS_DIR"' in cleanup
    assert "w5-002.cleanup-retention.v2" in (ROOT / "tools/w5_002_ci.py").read_text(
        encoding="utf-8"
    )


def test_supply_chain_disagreement_remains_fail_closed() -> None:
    import json

    config = json.loads((ROOT / "configs/ci/w5-002.json").read_text(encoding="utf-8"))
    assert config["security"]["scanner_disagreement_blocks"] is True
    assert config["remediation"]["freshness"]["stale_status"] == "INDETERMINATE"
