"""Static contracts for the three W5-002 GitHub workflows."""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_ROOT = ROOT / ".github/workflows"
PINS = {
    "actions/checkout": "9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
    "actions/setup-python": "5fda3b95a4ea91299a34e894583c3862153e4b97",
    "actions/upload-artifact": "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
    "hashicorp/setup-terraform": "dfe3c3f87815947d99a8997f908cb6525fc44e9e",
    "aws-actions/configure-aws-credentials": "e6de054238d6b7531b4efff3b6587d9aade6a06c",
    "docker/setup-buildx-action": "d7f5e7f509e45cec5c76c4d5afdd7de93d0b3df5",
    "chainguard-dev/setup-chainctl": "be0acd273acf04bfdf91f51198327e719f6af978",
}


def _text(name: str) -> str:
    return (WORKFLOW_ROOT / name).read_text(encoding="utf-8")


def _yaml(name: str) -> dict[str, object]:
    value = yaml.safe_load(_text(name))
    assert isinstance(value, dict)
    if True in value:
        assert "on" not in value
        value["on"] = value.pop(True)
    return value


def test_all_workflows_are_yaml_and_use_only_exact_action_commits() -> None:
    combined = "\n".join(
        _text(name) for name in ("ci.yml", "plan-sandbox.yml", "security-scan.yml")
    )
    for name in ("ci.yml", "plan-sandbox.yml", "security-scan.yml"):
        assert _yaml(name)["permissions"] == {}
    for action, commit in PINS.items():
        references = [line.strip() for line in combined.splitlines() if f"uses: {action}@" in line]
        assert references
        assert all(reference == f"uses: {action}@{commit}" for reference in references)


def test_untrusted_pull_request_has_no_registry_cloud_or_oidc_authority() -> None:
    workflow = _yaml("ci.yml")
    text = _text("ci.yml")

    assert workflow["on"] == {
        "pull_request": {
            "branches": ["main"],
            "types": ["opened", "synchronize", "reopened", "ready_for_review"],
        }
    }
    for forbidden in (
        "pull_request_target",
        "id-token: write",
        "configure-aws-credentials",
        "environment:",
        "uses: ./.github/workflows/security-scan.yml",
        "cgr.dev/",
        "CHAINGUARD_PULL_IDENTITY",
        "setup-chainctl",
    ):
        assert forbidden not in text
    assert 'python-version: "3.13.15"' in text
    assert "w5-002-pr-${{ github.event.pull_request.number }}" in text


def test_trusted_plan_is_manual_python_313_and_never_applies_or_destroys() -> None:
    workflow = _yaml("plan-sandbox.yml")
    text = _text("plan-sandbox.yml")

    assert set(workflow["on"]) == {"workflow_dispatch"}
    assert 'python-version: "3.13.15"' in text
    assert "environment: sandbox" in text
    assert "id-token: write" in text
    assert "arn:aws:iam::526338061652:role/enterprise-ai-platform-sandbox-github-oidc" in text
    assert "role-duration-seconds: 900" in text
    assert "-backend=false" in text
    assert "-refresh=false" in text
    assert not any(f"terraform {command}" in text for command in ("apply", "destroy", "import"))
    assert "w5-002-plan-summary" in text and "retention-days: 7" in text


def test_private_supply_chain_runs_only_for_trusted_main_or_manual_events() -> None:
    workflow = _yaml("security-scan.yml")
    text = _text("security-scan.yml")

    assert workflow["on"] == {"push": {"branches": ["main"]}, "workflow_dispatch": None}
    assert "workflow_call" not in text
    assert "pull_request" not in text
    assert "github.repository == 'gprai/enterprize_ai_platform'" in text
    assert "github.ref == 'refs/heads/main'" in text
    assert "id-token: write" in text
    assert "contents: read" in text
    assert "${{ vars.CHAINGUARD_PULL_IDENTITY }}" in text
    assert "${{ secrets." not in text
    assert "secrets:" not in text
    assert 'version: "0.2.346"' in text
    assert 'python-version: "3.13.15"' in text


def test_supply_chain_uses_exact_images_one_oci_and_no_push_or_load() -> None:
    text = _text("security-scan.yml")

    assert (
        "cgr.dev/vayunetrix.com/python:3.13.15-dev@sha256:"
        "023795336613750af2cd86cf06503b5b74370c6a561d2a22219a2e80c6fe4811"
    ) in text
    assert (
        "cgr.dev/vayunetrix.com/python:3.13.15@sha256:"
        "f7cc453a5d7ac0cf86f585e22b6e404eaa10f69db5d00da50f9940e2806358fa"
    ) in text
    assert '--output "type=oci,dest=$OCI_ARCHIVE"' in text
    assert 'tar -xf "$OCI_ARCHIVE" -C "$OCI_LAYOUT"' in text
    assert 'test -f "$OCI_LAYOUT/index.json"' in text
    assert 'test -f "$OCI_LAYOUT/oci-layout"' in text
    assert 'trivy image --cache-dir "$TRIVY_CACHE"' in text
    assert 'grype "oci-archive:$OCI_ARCHIVE"' in text
    assert "--load" not in text and "--push" not in text
    assert "docker push" not in text


def test_four_base_scan_paths_and_independent_composed_scanners_are_required() -> None:
    text = _text("security-scan.yml")

    assert text.count("--severity CRITICAL --exit-code 1 --format json") == 2
    assert '--output "$RAW_DIR/trivy-base-builder.json" "$BUILDER_IMAGE"' in text
    assert '--output "$RAW_DIR/trivy-base-runtime.json" "$RUNTIME_IMAGE"' in text
    assert 'grype "$BUILDER_IMAGE" --fail-on critical' in text
    assert 'grype "$RUNTIME_IMAGE" --fail-on critical' in text
    assert 'grype "oci-archive:$OCI_ARCHIVE"' in text
    assert "--scanner-database-identity" in text


def test_artifact_allowlist_contains_every_v2_report_and_no_raw_artifact() -> None:
    text = _text("security-scan.yml")
    upload = text.split("Upload only the bounded allowlisted v2 reports")[-1]

    for name in (
        "image-identity.json",
        "trivy-filesystem.json",
        "trivy-image.json",
        "grype-image.json",
        "sbom.spdx.json",
        "sbom.cyclonedx.json",
        "provenance.json",
        "eligibility.json",
        "rollback-identity.json",
        "cleanup-retention.json",
    ):
        assert f"reports/w5-002/{name}" in upload
    for forbidden in ("w5-002-py313-candidate.oci", "w5-002-py313-raw", "oci-layout"):
        assert forbidden not in upload
    assert "retention-days: 7" in upload


def test_all_dependency_installations_are_hash_locked_and_non_resolving() -> None:
    combined = "\n".join(
        _text(name) for name in ("ci.yml", "plan-sandbox.yml", "security-scan.yml")
    )
    install_lines = [line for line in combined.splitlines() if "pip install" in line]

    assert install_lines
    assert all("--require-hashes --no-deps" in line for line in install_lines)
    assert combined.count("tools/w5_002_ci.py validate-locks") == 4
    for name in ("ci.yml", "plan-sandbox.yml", "security-scan.yml"):
        text = _text(name)
        assert text.index("tools/w5_002_ci.py validate-locks") < text.index("pip install")
    assert "requirements-dev.txt" not in combined
    assert "requirements-checkov.txt" not in combined


def test_policy_tools_are_downloaded_from_exact_hash_verified_releases() -> None:
    action = (ROOT / ".github/actions/setup-policy-tools/action.yml").read_text(encoding="utf-8")
    workflow = _text("ci.yml")

    expected = {
        "v0.60.0/tflint_linux_amd64.zip": "".join(
            (
                "3476ceed",
                "cf0c4f9f",
                "2bed35e9",
                "2988e141",
                "1bec2caa",
                "543c9387",
                "bffaa720",
                "df9efaf7",
            )
        ),
        "v0.48.0/tflint-ruleset-aws_linux_amd64.zip": "".join(
            (
                "531444ac",
                "5dd989ce",
                "3117b2ab",
                "695d52e5",
                "2599020a",
                "41df8b2a",
                "8811add2",
                "f6764164",
            )
        ),
        "v1.20.0/opa_linux_amd64_static": "".join(
            (
                "4e4c65be",
                "08ed27e7",
                "375d816d",
                "446a444e",
                "65ba1018",
                "06014c7a",
                "51b2a765",
                "2c2a942a",
            )
        ),
        "v1.7.12/actionlint_1.7.12_linux_amd64.tar.gz": "".join(
            (
                "8aca8db9",
                "6f1b9477",
                "0f1b0d72",
                "b6dddcb1",
                "ebb8123c",
                "b3712530",
                "b08cc387",
                "b349a3d8",
            )
        ),
    }
    for release, digest in expected.items():
        assert release in action
        assert digest in action
    assert action.count("sha256sum --check --strict") == 4
    assert "uses: ./.github/actions/setup-policy-tools" in workflow
    assert 'tflint --config="$(realpath .tflint.hcl)"' in workflow
