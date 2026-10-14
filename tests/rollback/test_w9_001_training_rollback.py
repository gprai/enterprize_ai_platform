"""Rollback contracts for failed or indeterminate W9-001 training."""

from tests.fakes.w9_001_training import make_request

from enterprise_ai_platform.training import CleanupPlan, fingerprint, load_training_policy


def test_cleanup_plan_is_exact_owner_controlled_and_retains_evidence() -> None:
    request = make_request()
    cleanup = CleanupPlan(request_identity_sha256=fingerprint(request))

    assert cleanup.exact_job_name is None
    assert cleanup.retain_logs_and_evidence is True
    assert cleanup.delete_shared_resources is False
    assert cleanup.owner_approval_required is True
    assert cleanup.status == "NOT_RUN"


def test_unknown_submission_cannot_be_retried_by_policy() -> None:
    policy = load_training_policy()

    assert policy.limits.automatic_retry_attempts == 0
    assert policy.live_execution == "NOT_AUTHORIZED"
