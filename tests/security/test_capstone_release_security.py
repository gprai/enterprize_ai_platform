"""Fail-closed W12 record, receipt, privilege and log controls."""

from __future__ import annotations

import base64
import hashlib
from copy import deepcopy
from pathlib import Path

import pytest
from tools.capstone_release import (
    BOOTSTRAP_JSON,
    BOOTSTRAP_SHA,
    ReleaseError,
    _make_zip,
    _release_publication_key,
    _zip_files,
    make_future_lineage_zip,
    make_primary_source_bundle,
    validate_future_lineage_zip,
    validate_opa_receipt,
    validate_primary_source_bundle,
    validate_record,
)
from tools.platformctl.aws_inventory import validate_w12_binding_coverage
from tools.platformctl.contracts import ContractError
from tools.platformctl.lifecycle_models import (
    W12ProtectedObject,
    W12PublishedObject,
    W12RetentionBinding,
)

from tests.fakes.capstone_release import (
    canonical,
    opa_receipt,
    render_input_fixture,
    requested_record,
    sidecar,
    verified_release_chain,
)

ROOT = Path(__file__).resolve().parents[2]


def test_opa_receipt_substitution_rejected() -> None:
    record = requested_record()
    raw = canonical(record)
    receipt = opa_receipt(record, raw)
    receipt["hcp"]["plan_json_sha256"] = "9" * 64
    substituted = canonical(receipt)
    with pytest.raises(ReleaseError):
        validate_opa_receipt(
            substituted,
            b"0" * 64 + b"\n",
            record=record,
            record_sha256=hashlib.sha256(raw).hexdigest(),
        )
    receipt = opa_receipt(record, raw)
    receipt["opa"]["override_used"] = True
    substituted = canonical(receipt)
    with pytest.raises(ReleaseError):
        validate_opa_receipt(
            substituted,
            sidecar(substituted),
            record=record,
            record_sha256=hashlib.sha256(raw).hexdigest(),
        )


def test_secret_bearing_requested_record_rejected() -> None:
    record = requested_record()
    changed = deepcopy(record)
    changed["credentials"] = "synthetic-secret"
    raw = canonical(changed)
    with pytest.raises(ReleaseError):
        validate_record(raw, sidecar(raw), requested=True)
    changed = deepcopy(record)
    changed["evidence"] = [{"kind": "raw_state", "uri": "secret-token", "sha256": "a" * 64}]
    raw = canonical(changed)
    with pytest.raises(ReleaseError):
        validate_record(raw, sidecar(raw), requested=True)


def test_preflight_log_and_privilege_boundary() -> None:
    workflow = (ROOT / ".github/workflows/capstone-release.yml").read_text(encoding="utf-8")
    preflight = workflow.split("  preflight:", 1)[1].split("  receipt_validation_gate:", 1)[0]
    assert "id-token: write" not in preflight
    assert "configure-aws-credentials" not in preflight
    assert "TFC_TOKEN" not in preflight
    assert "echo $W12_RECORD_B64URL" not in workflow
    assert "echo $W12_OPA_RECEIPT_B64URL" not in workflow
    assert preflight.index("Validate dispatch and checked-out source") < preflight.index(
        "Upload validated current-run record"
    )
    build = workflow.split("  build_scan_attest:", 1)[1].split("  prepare_ready_record:", 1)[0]
    assert "TFC_TOKEN:" not in build
    protected = workflow.split("  github_release_apply:", 1)[1].split("  codebuild_deploy:", 1)[0]
    assert "environment: sandbox" in protected
    assert "TFC_TOKEN: ${{ secrets.TFC_TOKEN }}" in protected


def test_state_lineage_fallback_never_forwards_token_or_persists_raw_state() -> None:
    source = (ROOT / "tools/capstone_release.py").read_text(encoding="utf-8")
    helper = source.split("def _hcp_state_identity(", 1)[1].split("\ndef _hcp_token()", 1)[0]
    assert '{"app.terraform.io", "archivist.terraform.io"}' in helper
    assert 'headers={"Accept": "application/json"}' in helper
    assert 'if target.hostname == "app.terraform.io":' in helper
    assert 'request_headers["Authorization"] = f"Bearer {token}"' in helper
    redirect = helper.split("class NoCredentialRedirect", 1)[1].split("request_headers =", 1)[0]
    assert '"Authorization"' not in redirect
    assert "write_bytes" not in helper
    assert "write_text" not in helper
    assert "print(" not in helper


def test_final_zero_change_run_review_stays_fail_closed() -> None:
    source = (ROOT / "tools/capstone_release.py").read_text(encoding="utf-8")
    review = source.split("def _review_plan(", 1)[1].split("\ndef _workflow_requested", 1)[0]
    assert '"planned_and_finished"' in review
    assert "_hcp_plan_is_zero_change(plan_json)" in review
    assert 'ReleaseError("HCP_FINAL_RUN_NOT_ZERO_CHANGE")' in review
    assert 'allow_unreachable=run_status == "planned_and_finished"' in review
    helper = source.split("def _hcp_plan_is_zero_change(", 1)[1].split("\ndef _review_plan", 1)[0]
    for guarded_field in (
        "resource_changes",
        "resource_drift",
        "output_changes",
        "deferred_changes",
        "action_invocations",
    ):
        assert guarded_field in helper
    apply_guard = source.split("def _hcp_apply_not_started(", 1)[1].split(
        "\ndef _hcp_plan_is_zero_change", 1
    )[0]
    assert '{"pending", "unreachable"} if allow_unreachable else {"pending"}' in apply_guard
    assert 'timestamps.get("queued-at") is not None' in apply_guard
    assert 'timestamps.get("started-at") is not None' in apply_guard


def test_final_zero_change_state_fallback_requires_exact_finalized_current_state() -> None:
    source = (ROOT / "tools/capstone_release.py").read_text(encoding="utf-8")
    helper = source.split("def _hcp_final_zero_change_state_identity(", 1)[1].split(
        "\ndef _review_plan", 1
    )[0]
    assert "_hcp_plan_is_zero_change(plan)" in helper
    assert 'f"/workspaces/{workspace_id}/current-state-version"' in helper
    assert 'current.get("id") != expected_id' in helper
    assert 'current.get("attributes", {}).get("status") != "finalized"' in helper
    assert "lineage != expected_lineage" in helper
    assert "serial != expected_serial" in helper
    review = source.split("def _review_plan(", 1)[1].split("\ndef _workflow_requested", 1)[0]
    assert 'run_status != "planned_and_finished"' in review
    assert "_hcp_final_zero_change_state_identity(" in review


def test_codebuild_role_cannot_read_kubernetes_secret() -> None:
    policy = (ROOT / "infra/modules/iam/main.tf").read_text(encoding="utf-8")
    role = policy.split('data "aws_iam_policy_document" "capstone_codebuild"', 1)[1]
    role = role.split('resource "aws_iam_role_policy" "capstone_codebuild"', 1)[0]
    assert "secretsmanager:GetSecretValue" not in role
    assert "eks:DescribeCluster" in role
    rbac = (ROOT / "deploy/capstone/tokenreview-rbac.yaml").read_text(encoding="utf-8")
    assert "secrets" not in rbac.lower()


def test_lineage_derivative_substitution_rejected() -> None:
    chain = verified_release_chain()
    raw = make_future_lineage_zip(chain)
    assert (
        validate_future_lineage_zip(raw, raws=chain)["record_id"] == requested_record()["record_id"]
    )
    changed = chain.copy()
    changed[3] = chain[2]
    with pytest.raises(ReleaseError):
        validate_future_lineage_zip(raw, raws=changed)


def test_only_lineage_zip_uses_derivative_coverage() -> None:
    record_id = requested_record()["record_id"]
    bucket = "w12-evidence-example"
    version = "synthetic-version-1"
    stamp = "2026-01-01T00:00:00Z"
    record_key = _release_publication_key(record_id, "verified_record")
    sidecar_key = _release_publication_key(record_id, "verified_sidecar")
    lineage_key = _release_publication_key(record_id, "future_lineage")
    protected = tuple(
        sorted(
            (
                W12ProtectedObject(
                    bucket,
                    record_key,
                    version,
                    "a" * 64,
                    "verified_record",
                    "VERIFIED_SELF_PUBLICATION",
                ),
                W12ProtectedObject(
                    bucket,
                    sidecar_key,
                    version,
                    "b" * 64,
                    "verified_sidecar",
                    "VERIFIED_SELF_PUBLICATION",
                ),
                W12ProtectedObject(
                    bucket,
                    lineage_key,
                    version,
                    "c" * 64,
                    "future_lineage",
                    "VERIFIED_LINEAGE_DERIVATIVE",
                ),
            ),
            key=lambda item: (item.bucket, item.key, item.version_id),
        )
    )
    binding = W12RetentionBinding(
        record_id=record_id,
        operation="deploy",
        verified_record_sha256="a" * 64,
        verified_created_at_utc=stamp,
        verified_record_object=W12PublishedObject(bucket, record_key, version, "a" * 64, stamp),
        verified_sidecar_object=W12PublishedObject(bucket, sidecar_key, version, "b" * 64, stamp),
        publication_anchor_utc=stamp,
        retain_until_utc="2026-06-30T00:00:00Z",
        kms_key_arn="arn:aws:kms:ap-southeast-1:123456789012:key/synthetic",
        protected_objects=protected,
    )
    validate_w12_binding_coverage(binding)
    bad = tuple(
        W12ProtectedObject(
            item.bucket,
            item.key,
            item.version_id,
            item.sha256,
            item.evidence_kind,
            "VERIFIED_LINEAGE_DERIVATIVE" if item.key == record_key else item.coverage,
        )
        for item in protected
    )
    with pytest.raises(ContractError):
        validate_w12_binding_coverage(
            W12RetentionBinding(**{**binding.__dict__, "protected_objects": bad})
        )


def test_terraform_manifest_rejects_worktree_substitution(monkeypatch: pytest.MonkeyPatch) -> None:
    import json

    import tools.capstone_release as release

    committed = {"infra/environments/sandbox/main.tf": b'output "id" { value = "committed" }\n'}
    monkeypatch.setattr(release, "_tracked_regular_files", lambda _commit, _tree: committed)
    manifest = json.loads(release.terraform_configuration_manifest("a" * 40, "b" * 40))
    assert (
        manifest["files"][0]["sha256"]
        == hashlib.sha256(committed["infra/environments/sandbox/main.tf"]).hexdigest()
    )
    changed_worktree = b'output "id" { value = "uncommitted" }\n'
    assert manifest["files"][0]["sha256"] != hashlib.sha256(changed_worktree).hexdigest()


def _source_security_fixture() -> tuple[dict[str, bytes], str, str]:
    archive, manifest_sha, w6_sha = make_primary_source_bundle(
        {
            "deploy/k8s/deployment.yaml": b"kind: Deployment\n",
            "tools/capstone_release.py": b"synthetic\n",
        },
        commit="a" * 40,
        tree="b" * 40,
    )
    return _zip_files(archive), manifest_sha, w6_sha


def _validate_source_members(
    members: dict[str, bytes], manifest_sha: str, w6_sha: str
) -> dict[str, bytes]:
    archive = _make_zip(members)
    return validate_primary_source_bundle(
        archive,
        archive_sha256=hashlib.sha256(archive).hexdigest(),
        manifest_sha256=manifest_sha,
        w6_sha256=w6_sha,
        commit="a" * 40,
        tree="b" * 40,
    )


def test_source_manifest_self_listing_rejected() -> None:
    import json

    members, _, w6_sha = _source_security_fixture()
    manifest = json.loads(members[BOOTSTRAP_JSON])
    manifest["files"].append({"path": BOOTSTRAP_JSON, "size": 1, "sha256": "a" * 64})
    manifest["files"].sort(key=lambda item: item["path"])
    changed = canonical(manifest)
    members[BOOTSTRAP_JSON] = changed
    members[BOOTSTRAP_SHA] = sidecar(changed)
    with pytest.raises(ReleaseError):
        _validate_source_members(members, hashlib.sha256(changed).hexdigest(), w6_sha)


def test_source_manifest_entry_identity_fail_closed() -> None:
    members, _, w6_sha = _source_security_fixture()
    with pytest.raises(ReleaseError, match="SOURCE_BOOTSTRAP_DIGEST_MISMATCH"):
        _validate_source_members(members, "0" * 64, w6_sha)


def test_source_manifest_sidecar_identity_fail_closed() -> None:
    members, manifest_sha, w6_sha = _source_security_fixture()
    members[BOOTSTRAP_SHA] = b"0" * 64 + b"\n"
    with pytest.raises(ReleaseError, match="SOURCE_BOOTSTRAP_DIGEST_MISMATCH"):
        _validate_source_members(members, manifest_sha, w6_sha)


def test_source_manifest_sidecar_locator_rejected() -> None:
    from tools.capstone_release import encode_s3v_locator

    chain = verified_release_chain()
    ready = __import__("json").loads(chain[1])
    source = ready["source"]
    with pytest.raises(ReleaseError, match="BOOTSTRAP_SIDECAR_LOCATOR"):
        encode_s3v_locator(
            source["s3_bucket"], source["s3_key"], source["s3_version_id"], entry=BOOTSTRAP_SHA
        )
    valid_uri = encode_s3v_locator(
        source["s3_bucket"], source["s3_key"], source["s3_version_id"], entry=BOOTSTRAP_JSON
    )
    sidecar_selector = base64.urlsafe_b64encode(BOOTSTRAP_SHA.encode()).decode().rstrip("=")
    forged_uri = valid_uri.rsplit("/", 1)[0] + "/" + sidecar_selector
    ready["evidence"] = [
        {
            "kind": "w12_source_manifest",
            "uri": forged_uri,
            "sha256": "f" * 64,
        }
    ]
    with pytest.raises(ReleaseError, match="BOOTSTRAP_SIDECAR_LOCATOR"):
        validate_record(canonical(ready), sidecar(canonical(ready)), previous=chain[0])


def test_source_manifest_unlisted_or_missing_payload_rejected() -> None:
    members, manifest_sha, w6_sha = _source_security_fixture()
    members.pop("tools/capstone_release.py")
    with pytest.raises(ReleaseError, match="SOURCE_PAYLOAD_SET_MISMATCH"):
        _validate_source_members(members, manifest_sha, w6_sha)
    members, manifest_sha, w6_sha = _source_security_fixture()
    members["extra.txt"] = b"not in manifest\n"
    with pytest.raises(ReleaseError, match="SOURCE_PAYLOAD_SET_MISMATCH"):
        _validate_source_members(members, manifest_sha, w6_sha)


def test_github_approval_evidence_rejects_invented_event_fields() -> None:
    import json

    config = json.loads((ROOT / "configs/ci/capstone-release.json").read_text())
    fields = config["approval_github_fields"]
    assert "approval_event_id" not in fields
    assert "approval_event_timestamp" not in fields
    assert "client_observed_at_utc" in fields
    assert "approver_id" in fields


def test_hcp_account_resource_must_match_approved_team(monkeypatch: pytest.MonkeyPatch) -> None:
    import tools.capstone_release as release

    monkeypatch.setenv("W12_HCP_OWNER_TEAM_ID", "team-approved")
    monkeypatch.setenv("W12_HCP_SERVICE_USER_ID", "user-service")
    account = {
        "data": {
            "type": "users",
            "id": "user-service",
            "attributes": {"username": "service", "is-service-account": True},
            "relationships": {
                "authenticated-resource": {"data": {"type": "teams", "id": "team-foreign"}}
            },
        }
    }
    monkeypatch.setattr(release, "_hcp_request", lambda *_args: (200, account))
    with pytest.raises(ReleaseError, match="HCP_AUTOMATION_IDENTITY_MISMATCH"):
        release._hcp_automation_identity("synthetic-token")
    account["data"]["relationships"]["authenticated-resource"]["data"]["id"] = "team-approved"
    assert release._hcp_automation_identity("synthetic-token")["resource_id"] == "team-approved"


def test_hcp_organization_token_cannot_apply(monkeypatch: pytest.MonkeyPatch) -> None:
    import tools.capstone_release as release

    monkeypatch.setenv("W12_HCP_OWNER_TEAM_ID", "team-approved")
    monkeypatch.setenv("W12_HCP_SERVICE_USER_ID", "user-service")
    account = {
        "data": {
            "type": "users",
            "id": "user-service",
            "attributes": {"username": "service", "is-service-account": True},
            "relationships": {
                "authenticated-resource": {"data": {"type": "organizations", "id": "org-foreign"}}
            },
        }
    }
    monkeypatch.setattr(release, "_hcp_request", lambda *_args: (200, account))
    with pytest.raises(ReleaseError, match="HCP_AUTOMATION_IDENTITY_MISMATCH"):
        release._hcp_automation_identity("synthetic-token")


def test_ambiguous_hcp_apply_never_creates_approved() -> None:
    source = (ROOT / "tools/capstone_release.py").read_text()
    apply = source.split("def workflow_apply_wait(", 1)[1].split(
        "def workflow_cleanup_transitions(", 1
    )[0]
    ambiguity = apply.index('raise ReleaseError("HCP_APPLY_POST_AMBIGUOUS"')
    approved = apply.index('"APPROVED"')
    assert ambiguity < approved
    assert apply.count('"POST", path, token, request_body') == 1


def _validate_render_fixture(raw: bytes, fixture):
    import tools.capstone_release as release

    ready, approved, applied, _ = fixture
    return release.validate_render_inputs(
        raw,
        sidecar(raw),
        ready=ready,
        ready_sha256=hashlib.sha256(canonical(ready)).hexdigest(),
        approved=approved,
        approved_sha256=hashlib.sha256(canonical(approved)).hexdigest(),
        applied=applied,
    )


def test_render_input_substitution_rejected() -> None:
    import json

    fixture = render_input_fixture()
    _, _, _, raw = fixture
    changed = json.loads(raw)
    changed["source_archive_sha256"] = "0" * 64
    with pytest.raises(ReleaseError, match="RENDER_INPUT_RELEASE_BINDING"):
        _validate_render_fixture(canonical(changed), fixture)


def test_mutable_application_image_rejected() -> None:
    from tools.capstone_release import application_image_from_ready

    ready, _, _, _ = render_input_fixture()
    ready["artifacts"]["image_digest"] = "latest"
    with pytest.raises(ReleaseError):
        application_image_from_ready(ready)


def test_application_image_substitution_rejected() -> None:
    import json

    fixture = render_input_fixture()
    _, _, _, raw = fixture
    changed = json.loads(raw)
    changed["application_image"] = changed["otel_collector_image"]
    with pytest.raises(ReleaseError, match="RENDER_INPUT_RELEASE_BINDING"):
        _validate_render_fixture(canonical(changed), fixture)


def test_application_and_collector_images_not_interchangeable() -> None:
    import json

    fixture = render_input_fixture()
    _, _, _, raw = fixture
    changed = json.loads(raw)
    changed["application_image"], changed["otel_collector_image"] = (
        changed["otel_collector_image"],
        changed["application_image"],
    )
    with pytest.raises(ReleaseError):
        _validate_render_fixture(canonical(changed), fixture)


def test_adapter_rejects_application_collector_swap() -> None:
    import json

    fixture = render_input_fixture()
    _, _, _, raw = fixture
    changed = json.loads(raw)
    changed["application_image"], changed["otel_collector_image"] = (
        changed["otel_collector_image"],
        changed["application_image"],
    )
    with pytest.raises(ReleaseError):
        _validate_render_fixture(canonical(changed), fixture)


def test_adapter_rejects_equal_application_and_collector_references() -> None:
    import json

    fixture = render_input_fixture()
    _, _, _, raw = fixture
    changed = json.loads(raw)
    changed["otel_collector_image"] = changed["application_image"]
    with pytest.raises(ReleaseError):
        _validate_render_fixture(canonical(changed), fixture)


def test_deployment_boundary_rejects_untrusted_render_bindings() -> None:
    import json

    fixture = render_input_fixture()
    _, _, _, raw = fixture
    changed = json.loads(raw)
    changed["aws_account_id"] = "000000000000"
    with pytest.raises(ReleaseError, match="RENDER_INPUT_RELEASE_BINDING"):
        _validate_render_fixture(canonical(changed), fixture)


def test_w6_v2_binding_cannot_substitute_w12_bindings() -> None:
    from tools.w6_001_k8s import W6001Error, render_w12_release

    with pytest.raises(W6001Error, match="W12 render bindings"):
        render_w12_release(source_root=ROOT / "deploy/k8s", bindings={})


def test_w12_renderer_binding_validation() -> None:
    from dataclasses import replace

    from tools.w6_001_k8s import W12RenderBindings, W6001Error, render_w12_release

    bindings = W12RenderBindings(
        application_image="example.invalid/api@sha256:" + "a" * 64,
        otel_collector_image="example.invalid/collector@sha256:" + "b" * 64,
        opensearch_https_endpoint="http://example.invalid",
        bedrock_inference_profile_arn=(
            "arn:aws:bedrock:ap-southeast-1:123456789012:inference-profile/test"
        ),
        release_record_sha256="c" * 64,
        render_inputs_sha256="d" * 64,
        w6_release_hashes_sha256="e" * 64,
    )
    with pytest.raises(W6001Error, match="OpenSearch HTTPS"):
        render_w12_release(source_root=ROOT / "deploy/k8s", bindings=bindings)
    with pytest.raises(W6001Error):
        render_w12_release(
            source_root=ROOT / "deploy/k8s",
            bindings=replace(
                bindings,
                application_image="latest",
                opensearch_https_endpoint="https://example.invalid",
            ),
        )


def test_unresolved_image_placeholder_rejected() -> None:
    from dataclasses import replace

    from tools.w6_001_k8s import W12RenderBindings, W6001Error, render_w12_release

    bindings = W12RenderBindings(
        application_image="example.invalid/api@sha256:" + "a" * 64,
        otel_collector_image="example.invalid/collector@sha256:" + "b" * 64,
        opensearch_https_endpoint="https://example.invalid",
        bedrock_inference_profile_arn=(
            "arn:aws:bedrock:ap-southeast-1:123456789012:inference-profile/test"
        ),
        release_record_sha256="c" * 64,
        render_inputs_sha256="d" * 64,
        w6_release_hashes_sha256="e" * 64,
    )
    with pytest.raises(W6001Error):
        render_w12_release(
            source_root=ROOT / "deploy/k8s",
            bindings=replace(bindings, application_image="OWNER_BINDING_REQUIRED"),
        )


def test_w12_annotation_override_rejected(tmp_path: Path) -> None:
    import yaml
    from tools.w6_001_k8s import TEMPLATE_FILES, W6001Error, render_w12_release

    from tests.unit.test_capstone_release import _render_w12_fixture

    _, bindings, _ = _render_w12_fixture()
    for name in TEMPLATE_FILES:
        (tmp_path / name).write_bytes((ROOT / "deploy/k8s" / name).read_bytes())
    deployment = yaml.safe_load((tmp_path / "deployment.yaml").read_bytes())
    deployment["metadata"].setdefault("annotations", {})["enterprise.ai/release-record-sha256"] = (
        "0" * 64
    )
    (tmp_path / "deployment.yaml").write_text(yaml.safe_dump(deployment))
    with pytest.raises(W6001Error):
        render_w12_release(source_root=tmp_path, bindings=bindings)


def test_unresolved_or_unknown_render_placeholder_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import tools.w6_001_k8s as renderer
    from tools.w6_001_k8s import W6001Error, render_w12_release

    from tests.unit.test_capstone_release import _render_w12_fixture

    _, bindings, _ = _render_w12_fixture()
    original = renderer._substitute_release_templates

    def substituted(*args):
        files, documents = original(*args)
        files["configmap.yaml"] = files["configmap.yaml"].replace(
            b"enterprise_ai_sandbox", b"__UNRESOLVED_W12__"
        )
        return files, documents

    monkeypatch.setattr(renderer, "_substitute_release_templates", substituted)
    with pytest.raises(W6001Error, match="unresolved"):
        render_w12_release(source_root=ROOT / "deploy/k8s", bindings=bindings)


def test_w12_renderer_unsafe_output_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    import tools.w6_001_k8s as renderer
    from tools.w6_001_k8s import W6001Error, render_w12_release

    from tests.unit.test_capstone_release import _render_w12_fixture

    _, bindings, _ = _render_w12_fixture()
    original = renderer._substitute_release_templates

    def substituted(*args):
        files, documents = original(*args)
        files["configmap.yaml"] = files["configmap.yaml"].replace(
            b"enterprise_ai_sandbox", b"{{unbound}}"
        )
        return files, documents

    monkeypatch.setattr(renderer, "_substitute_release_templates", substituted)
    with pytest.raises(W6001Error):
        render_w12_release(source_root=ROOT / "deploy/k8s", bindings=bindings)


def test_render_inputs_are_non_sensitive_and_redacted() -> None:
    import json

    _, _, _, raw = render_input_fixture()
    document = json.loads(raw)
    assert not {"password", "token", "private_key", "raw_plan", "raw_state"} & set(document)
    assert "model_prompt" not in raw.decode() and "model_response" not in raw.decode()


def test_proof_root_rejects_unapproved_files(tmp_path: Path) -> None:
    from datetime import UTC, datetime

    from tools.capstone_release import validate_publication_proof

    (tmp_path / "unapproved.txt").write_text("synthetic")
    with pytest.raises(ReleaseError, match="PUBLICATION_PROOF_INVENTORY"):
        validate_publication_proof(
            tmp_path,
            client=object(),
            kms_key_arn="synthetic",
            now=datetime(2026, 1, 1, tzinfo=UTC),
        )


def test_verified_pair_substitution_rejected() -> None:
    import json

    from tools.capstone_release import validate_publication_selector

    chain = verified_release_chain()
    verified = json.loads(chain[4])
    record_id = verified["record_id"]
    record_sha = hashlib.sha256(chain[4]).hexdigest()
    lineage_sha = hashlib.sha256(make_future_lineage_zip(chain)).hexdigest()

    def identity(key: str, digest: str) -> dict[str, str]:
        return {
            "bucket": verified["source"]["s3_bucket"],
            "key": key,
            "version_id": "synthetic-version-1",
            "sha256": digest,
            "last_modified_utc": verified["created_at_utc"],
            "kms_key_arn": "arn:aws:kms:ap-southeast-1:123456789012:key/synthetic",
        }

    selector = {
        "schema_version": "w12-001.publication-selector.v1",
        "record_id": record_id,
        "operation": "deploy",
        "account_id": "123456789012",
        "region": "ap-southeast-1",
        "verified_record_sha256": record_sha,
        "record_object": identity(_release_publication_key(record_id, "verified_record"), "0" * 64),
        "sidecar_object": identity(
            _release_publication_key(record_id, "verified_sidecar"),
            hashlib.sha256(sidecar(chain[4])).hexdigest(),
        ),
        "lineage_object": identity(
            _release_publication_key(record_id, "future_lineage"), lineage_sha
        ),
    }
    with pytest.raises(ReleaseError, match="PUBLICATION_SELECTOR_OBJECT_IDENTITY"):
        validate_publication_selector(
            canonical(selector),
            verified=verified,
            verified_sha256=record_sha,
            lineage_sha256=lineage_sha,
        )


def test_separate_canonical_object_requires_r5_locator() -> None:
    import json

    chain = verified_release_chain()
    verified = json.loads(chain[4])
    verified["evidence"] = [item for item in verified["evidence"] if item["kind"] != "opa_receipt"]
    with pytest.raises(ReleaseError, match="VERIFIED_CANONICAL_OBJECT_COVERAGE"):
        validate_record(canonical(verified), sidecar(canonical(verified)), previous=chain[3])


def test_post_verified_canonical_object_is_indeterminate() -> None:
    source = (ROOT / "tools/capstone_release.py").read_text()
    proof = source.split("def validate_publication_proof(", 1)[1].split(
        "def load_prior_rollback_lineage(", 1
    )[0]
    assert 'for evidence in verified["evidence"]' in proof
    assert "PUBLICATION_DUPLICATE_PROTECTED_OBJECT" in proof
    assert '"VERIFIED_LINEAGE_DERIVATIVE"' in proof


def test_rollback_lineage_substitution_rejected() -> None:
    from tools.capstone_release import validate_future_lineage_zip

    chain = verified_release_chain()
    files = _zip_files(make_future_lineage_zip(chain))
    files["rollback/parent/release-record.json"] = b"{}\n"
    with pytest.raises(ReleaseError, match="FUTURE_LINEAGE_RECORD_BYTES"):
        validate_future_lineage_zip(_make_zip(files), raws=chain)


def test_rollback_record_path_escape_rejected() -> None:
    from tools.capstone_release import _safe_bundle_path

    for path in (
        "../release-record.json",
        "/release-record.json",
        "rollback/../../release-record.json",
    ):
        with pytest.raises(ReleaseError):
            _safe_bundle_path(path)


def test_codebuild_lineage_read_is_versioned_and_bounded() -> None:
    source = (ROOT / "tools/capstone_deploy.py").read_text()
    preflight = source.split("def _source(", 1)[1].split("def _record(", 1)[0]
    assert "load_prior_rollback_lineage(" in preflight
    assert "kms_key_arn=observed_kms" in preflight
    release = (ROOT / "tools/capstone_release.py").read_text()
    loader = release.split("def load_prior_rollback_lineage(", 1)[1].split(
        "def application_image_from_ready(", 1
    )[0]
    assert "_s3_read_exact(" in loader
    assert "decode_s3v_locator(" in loader


def test_codebuild_source_requires_exact_approved_kms_key() -> None:
    source = (ROOT / "tools/capstone_deploy.py").read_text()
    preflight = source.split("def _source(", 1)[1].split("def _record(", 1)[0]
    assert 'observed_kms != _required_env("W12_RELEASE_KMS_KEY_ARN")' in preflight
    assert 'control_head.get("SSEKMSKeyId") != observed_kms' in preflight


def test_control_bundle_inventory_not_trusted_before_bootstrap() -> None:
    source = (ROOT / "tools/capstone_deploy.py").read_text()
    function = source.split("def _source(", 1)[1].split("def _record(", 1)[0]
    assert function.index("if set(control_files) != expected_control:") < function.index(
        'listed = handoff["files"]'
    )
    assert '"codebuild-handoff.sha256"' in function


def test_control_bundle_unlisted_or_missing_entry_rejected() -> None:
    source = (ROOT / "tools/capstone_deploy.py").read_text()
    function = source.split("def _source(", 1)[1].split("def _record(", 1)[0]
    assert "set(control_files) != expected_control" in function
    assert "listed != _file_inventory(payload)" in function


def test_only_verified_pair_uses_self_publication_exception() -> None:
    from dataclasses import replace

    from tests.unit.test_platformctl import _w12_coverage_binding

    binding = _w12_coverage_binding()
    changed = tuple(
        replace(item, coverage="VERIFIED_SELF_PUBLICATION")
        if item.evidence_kind == "future_lineage"
        else item
        for item in binding.protected_objects
    )
    with pytest.raises(ContractError):
        validate_w12_binding_coverage(replace(binding, protected_objects=changed))


def test_expires_at_does_not_override_w12_retention() -> None:
    from datetime import UTC, datetime

    from tools.capstone_release import retention_anchor_from_publication

    anchor, retain_until = retention_anchor_from_publication(
        "2026-01-01T00:00:00Z",
        "2026-01-01T00:00:01Z",
        "2026-01-01T00:00:02Z",
        "2026-01-01T00:00:03Z",
        now=datetime(2026, 1, 1, 0, 0, 4, tzinfo=UTC),
    )
    assert retain_until > anchor
    assert retain_until == datetime(2026, 6, 30, 0, 0, 3, tzinfo=UTC)


def test_release_version_not_superseded_before_terminal_record() -> None:
    source = (ROOT / "tools/capstone_release.py").read_text()
    verification = source.split("def workflow_verify(", 1)[1].split("def workflow_publish(", 1)[0]
    assert verification.index('"VERIFIED"') < verification.index(
        "publish_verified_pair_and_lineage("
    )


def test_deployment_cannot_substitute_rendered_archive() -> None:
    source = (ROOT / "tools/capstone_deploy.py").read_text()
    reader = source.split("def _read_verified_archive(", 1)[1].split("def preflight(", 1)[0]
    assert "_s3_version(" in reader
    assert "validate_rendered_release(" in reader
    assert "RENDERED_ARCHIVE_IDENTITY" in reader or "RENDERED_ARCHIVE" in reader


def test_invalid_rollback_evidence_rejected() -> None:
    from tools.capstone_release import encode_s3v_locator

    record = requested_record()
    record["operation"] = "rollback"
    record["recovery"]["previous_good_record_sha256"] = "a" * 64
    prior_id = "4e116df3-a624-4f19-9ab4-8311c1a7ecf7"
    record["recovery"]["rollback_ref"] = encode_s3v_locator(
        "synthetic-bucket",
        _release_publication_key(prior_id, "future_lineage"),
        "synthetic-version-1",
        entry="rollback/rollback-lineage-manifest.json",
    )
    raw = canonical(record)
    with pytest.raises(ReleaseError, match="ROLLBACK_EVIDENCE_CARRIAGE"):
        validate_record(raw, sidecar(raw), requested=True)


def test_prepare_ready_never_receives_hcp_apply_credential() -> None:
    workflow = (ROOT / ".github/workflows/capstone-release.yml").read_text()
    ready = workflow.split("  prepare_ready_record:", 1)[1].split("  github_release_apply:", 1)[0]
    protected = workflow.split("  github_release_apply:", 1)[1].split("  codebuild_deploy:", 1)[0]
    assert "TFC_READ_TOKEN: ${{ secrets.TFC_READ_TOKEN }}" in ready
    assert "TFC_TOKEN: ${{ secrets.TFC_TOKEN }}" not in ready
    assert "TFC_TOKEN: ${{ secrets.TFC_TOKEN }}" in protected
    function = (
        (ROOT / "tools/capstone_release.py")
        .read_text()
        .split("def workflow_prepare_ready(", 1)[1]
        .split("def workflow_cleanup_ready(", 1)[0]
    )
    assert 'os.environ.get("TFC_READ_TOKEN", "")' in function
    assert "_hcp_token()" not in function


def test_result_version_substitution_prevents_verified() -> None:
    from tools.capstone_release import _s3_result_version

    class Client:
        def list_object_versions(self, **_kwargs):
            return {
                "Versions": [
                    {"Key": "w12-001/results/result.json", "VersionId": "expected-version"}
                ]
            }

        def head_object(self, **_kwargs):
            return {
                "VersionId": "foreign-version",
                "ServerSideEncryption": "aws:kms",
                "SSEKMSKeyId": "synthetic-key",
            }

    with pytest.raises(ReleaseError, match="RESULT_KMS_OR_VERSION_CHANGED"):
        _s3_result_version(
            Client(),
            bucket="synthetic-bucket",
            key="w12-001/results/result.json",
            expected_metadata={},
            kms_key_arn="synthetic-key",
        )


def test_ambiguous_result_upload_is_indeterminate() -> None:
    producer = (
        (ROOT / "tools/capstone_deploy.py")
        .read_text()
        .split("def publish_result(", 1)[1]
        .split("def main(", 1)[0]
    )
    assert 'IfNoneMatch="*"' in producer
    assert '"CODEBUILD_RESULT_UPLOAD_AMBIGUOUS", "INDETERMINATE"' in producer
    assert producer.count(".put_object(") == 1
