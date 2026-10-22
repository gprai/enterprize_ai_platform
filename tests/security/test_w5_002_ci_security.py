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
    assert "cgr.dev/vayunetrix.com" not in text
    assert "setup-chainctl" not in text


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


def test_chainguard_oidc_is_bounded_to_the_trusted_supply_chain_workflow() -> None:
    supply = (ROOT / ".github/workflows/security-scan.yml").read_text(encoding="utf-8")

    assert "permissions: {}" in supply
    assert "id-token: write" in supply
    assert "github.event_name == 'workflow_dispatch'" in supply
    assert "github.ref == 'refs/heads/main'" in supply
    assert "github.repository == 'gprai/enterprize_ai_platform'" in supply
    assert "environment: sandbox" in supply
    assert "Require the configured Chainguard pull identity" in supply
    assert '[[ -z "$CHAINGUARD_PULL_IDENTITY" ]]' in supply
    assert "chainguard-dev/setup-chainctl@9014a6ef4f9783eef6414ed71e92fcecf152dfe7" in supply
    assert "identity: ${{ vars.CHAINGUARD_PULL_IDENTITY }}" in supply
    assert "secrets." not in supply
    assert "docker login" not in supply.casefold()
    assert "--password" not in supply.casefold()


def test_qualified_images_are_immutable_and_exact() -> None:
    supply = (ROOT / ".github/workflows/security-scan.yml").read_text(encoding="utf-8")
    dockerfile = (ROOT / "docker/application.Dockerfile").read_text(encoding="utf-8")

    for reference in (w5_002_ci.BUILDER_IMAGE, w5_002_ci.RUNTIME_IMAGE):
        assert reference in supply
        assert reference in dockerfile
        assert reference.count("@sha256:") == 1


def test_zero_critical_gate_covers_both_bases_and_composed_image() -> None:
    supply = (ROOT / ".github/workflows/security-scan.yml").read_text(encoding="utf-8")

    assert supply.count("--severity CRITICAL --exit-code 1") >= 2
    assert supply.count("--fail-on critical") >= 3
    assert "reconcile-supply-chain" in supply
    assert "trivy-base-builder.json" in supply
    assert "trivy-base-runtime.json" in supply
    assert "grype-base-builder.json" in supply
    assert "grype-base-runtime.json" in supply
    for prohibited in ("--ignorefile", "--ignore-policy", "--only-fixed", "--exclude-wont-fix"):
        assert prohibited not in supply


def test_runtime_image_is_non_root_shell_free_and_package_manager_free() -> None:
    dockerfile = (ROOT / "docker/application.Dockerfile").read_text(encoding="utf-8")
    runtime = dockerfile.split(f"FROM {w5_002_ci.RUNTIME_IMAGE}", maxsplit=1)[1]

    assert "USER 65532:65532" in runtime
    assert 'ENTRYPOINT ["/venv/bin/python"' in runtime
    assert "RUN " not in runtime
    assert "/bin/sh" not in runtime
    assert "apk " not in runtime
    assert "apt-get" not in runtime


def test_security_config_preserves_accepted_findings_without_overclaim() -> None:
    config = w5_002_ci.load_json(ROOT / "configs/ci/w5-002.json")
    w5_002_ci.validate_config(config)
    qualification = config["base_qualification"]

    assert qualification["vulnerability_free_claim"] is False
    assert qualification["builder"]["trivy_purl_skips"] == 147
    assert qualification["runtime"]["trivy_purl_skips"] == 48
    assert [finding["severity"] for finding in qualification["accepted_findings"]] == [
        "Medium",
        "Medium",
        "Medium",
        "Low",
    ]


def test_artifact_uploads_are_exact_bounded_and_exclude_raw_outputs() -> None:
    plan = (ROOT / ".github/workflows/plan-sandbox.yml").read_text(encoding="utf-8")
    supply = (ROOT / ".github/workflows/security-scan.yml").read_text(encoding="utf-8")

    assert "reports/w5-002/terraform-plan-summary.json" in plan
    assert "w5-002-sandbox.tfplan" not in plan.split("Upload only the redacted plan summary")[-1]
    upload = supply.split("Upload only the bounded allowlisted v2 reports", maxsplit=1)[1]
    assert "w5-002-py313-candidate.oci" not in upload
    assert "w5-002-py313-oci-layout" not in upload
    assert "w5-002-py313-raw" not in upload
    assert "trivy-base-builder.json" not in upload
    assert "trivy-base-runtime.json" not in upload
    assert "grype-base-builder.json" not in upload
    assert "grype-base-runtime.json" not in upload
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


def test_normalization_policy_cannot_suppress_vulnerabilities() -> None:
    config = w5_002_ci.load_json(ROOT / "configs/ci/w5-002.json")
    remediation = config["remediation"]
    assert remediation["purl"]["normalization_reason_required"] is True
    assert remediation["scanner_reconciliation"]["disagreement_status"] == "INDETERMINATE"
    assert config["security"]["vulnerability_free_claim"] is False
