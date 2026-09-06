"""Security contracts for the W5-002 trust and artifact boundaries."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from tools import w5_002_ci

ROOT = Path(__file__).resolve().parents[2]


def _contains_github_secret_authority(text: str) -> bool:
    expression = re.search(r"\$\{\{[^}]*\bsecrets\s*(?:\.|\[)", text)
    mapping = re.search(r"(?m)^[ \t]*secrets[ \t]*:", text)
    return expression is not None or mapping is not None


def test_untrusted_pr_workflow_has_zero_cloud_authority() -> None:
    text = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

    for forbidden in (
        "pull_request_target",
        "id-token: write",
        "configure-aws-credentials",
        "aws-access-key-id",
        "environment: sandbox",
    ):
        assert forbidden not in text
    assert not _contains_github_secret_authority(text)
    assert "permissions: {}" in text
    assert "contents: read" in text


def test_secret_authority_matcher_distinguishes_baseline_from_github_secrets() -> None:
    assert not _contains_github_secret_authority("detect-secrets scan --baseline .secrets.baseline")
    assert not _contains_github_secret_authority("# secrets: inherit")
    assert _contains_github_secret_authority("value: ${{ secrets.AWS_ACCESS_KEY_ID }}")
    assert _contains_github_secret_authority("value: ${{ secrets['AWS_SECRET_ACCESS_KEY'] }}")
    assert _contains_github_secret_authority("secrets: inherit")


def test_trusted_workflow_denies_wrong_identity_before_oidc() -> None:
    text = (ROOT / ".github/workflows/plan-sandbox.yml").read_text(encoding="utf-8")
    denial = text.index("Reject an unapproved repository, ref, source, or environment")
    oidc = text.index("Assume only the approved sandbox role through OIDC")

    assert denial < oidc
    assert "gprai/enterprize_ai_platform" in text
    assert "refs/heads/main" in text
    assert "role-duration-seconds: 900" in text
    assert "audience: sts.amazonaws.com" in text


def test_artifact_uploads_are_exact_bounded_and_exclude_raw_outputs() -> None:
    plan = (ROOT / ".github/workflows/plan-sandbox.yml").read_text(encoding="utf-8")
    supply = (ROOT / ".github/workflows/security-scan.yml").read_text(encoding="utf-8")

    assert "reports/w5-002/terraform-plan-summary.json" in plan
    assert "w5-002-sandbox.tfplan" not in plan.split("Upload only the redacted plan summary")[-1]
    upload = supply.split("Upload only the bounded allowlisted reports")[-1]
    assert "w5-002-candidate.oci" not in upload
    assert "w5-002-oci-layout" not in upload
    assert plan.count("retention-days: 7") == 1
    assert supply.count("retention-days: 7") == 1


def test_secret_shaped_runtime_fragments_are_rejected_and_not_echoed() -> None:
    field = "session" + "_token"
    value = "test-fragment-" + "never-print"
    with pytest.raises(w5_002_ci.ContractError) as raised:
        w5_002_ci.assert_content_safe({field: value})
    assert value not in str(raised.value)


def test_symlink_output_is_rejected(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    target.write_text("{}\n", encoding="utf-8")
    link = tmp_path / "link.json"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlink creation is unavailable to this owner-controlled test process")
    with pytest.raises(w5_002_ci.ContractError, match="symlink"):
        w5_002_ci.write_json(link, {})
