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


def test_untrusted_pull_request_has_no_privileged_trigger_or_identity() -> None:
    workflow = _yaml("ci.yml")
    text = _text("ci.yml")

    assert workflow["on"] == {
        "pull_request": {
            "branches": ["main"],
            "types": ["opened", "synchronize", "reopened", "ready_for_review"],
        }
    }
    assert "pull_request_target" not in text
    assert "id-token: write" not in text
    assert "configure-aws-credentials" not in text
    assert "environment:" not in text
    assert "w5-002-pr-${{ github.event.pull_request.number }}" in text


def test_trusted_plan_is_manual_exact_and_never_applies_or_destroys() -> None:
    workflow = _yaml("plan-sandbox.yml")
    text = _text("plan-sandbox.yml")

    assert set(workflow["on"]) == {"workflow_dispatch"}
    assert "environment: sandbox" in text
    assert "id-token: write" in text
    assert "repo:gprai/enterprize_ai_platform:environment:sandbox" not in text
    assert "arn:aws:iam::526338061652:role/enterprise-ai-platform-sandbox-github-oidc" in text
    assert "role-duration-seconds: 900" in text
    assert "-backend=false" in text
    assert "-refresh=false" in text
    assert not any(f"terraform {command}" in text for command in ("apply", "destroy", "import"))
    assert "w5-002-plan-summary" in text and "retention-days: 7" in text


def test_supply_chain_uses_one_oci_and_no_registry_or_cloud_authority() -> None:
    text = _text("security-scan.yml")

    assert "workflow_call:" in text
    assert "w5-002-supply-chain-${{ github.sha }}" in text
    assert "timeout-minutes: 30" in text
    assert text.count("OCI_ARCHIVE: ${{ runner.temp }}/w5-002-candidate.oci") == 3
    assert '--output "type=oci,dest=$OCI_ARCHIVE"' in text
    assert "OCI_LAYOUT: ${{ runner.temp }}/w5-002-oci-layout" in text
    assert 'tar -xf "$OCI_ARCHIVE" -C "$OCI_LAYOUT"' in text
    assert 'test -f "$OCI_LAYOUT/index.json"' in text
    assert 'test -f "$OCI_LAYOUT/oci-layout"' in text
    assert 'trivy image --input "$OCI_LAYOUT"' in text
    assert 'trivy image --input "$OCI_ARCHIVE"' not in text
    assert "oci-archive:$OCI_ARCHIVE" in text
    assert 'rm -rf -- "$OCI_LAYOUT"' in text
    assert "--load" not in text and "--push" not in text
    assert "id-token" not in text and "configure-aws-credentials" not in text
    assert "w5-002-supply-chain" in text and "retention-days: 7" in text


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
