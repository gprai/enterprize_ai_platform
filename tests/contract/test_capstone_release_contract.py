"""W12 source-level contracts for GitHub and immutable handoffs."""

from __future__ import annotations

import ast
import hashlib
from pathlib import Path

import yaml
from tools.capstone_release import (
    BOOTSTRAP_JSON,
    BOOTSTRAP_SHA,
    W6_HASHES_JSON,
    W6_HASHES_SHA,
    _zip_files,
    encode_s3v_locator,
    make_future_lineage_zip,
    make_primary_source_bundle,
    validate_publication_selector,
    validate_record,
)

from tests.fakes.capstone_release import (
    canonical,
    render_input_fixture,
    sidecar,
    verified_release_chain,
)

ROOT = Path(__file__).resolve().parents[2]


def _source(name: str) -> str:
    return (ROOT / name).read_text(encoding="utf-8")


def test_dispatch_request_shape() -> None:
    workflow = _source(".github/workflows/capstone-release.yml")
    owner = _source("tools/capstone_release.py")
    inputs = (
        "record_b64url",
        "record_sha256",
        "opa_receipt_b64url",
        "opa_receipt_sha256",
        "operation",
        "source_commit",
    )
    block = workflow.split("workflow_dispatch:", 1)[1].split("permissions:", 1)[0]
    assert [
        line.strip().removesuffix(":")
        for line in block.splitlines()
        if line.startswith("      ") and not line.startswith("        ")
    ] == list(inputs)
    assert '"ref": "main"' in owner
    assert '"inputs": {' in owner
    assert "return_run_details" not in owner + workflow
    assert "record_artifact_id:" not in block


def test_github_api_version_is_pinned() -> None:
    config = _source("configs/ci/capstone-release.json")
    client = _source("tools/capstone_release.py")
    workflow = _source(".github/workflows/capstone-release.yml")
    assert '"github_api_version": "2026-03-10"' in config
    assert '"X-GitHub-Api-Version": _config()["github_api_version"]' in client
    assert '"X-GitHub-Api-Version":"2026-03-10"' in workflow
    assert "2022-11-28" not in workflow + client


def test_build_step_can_revalidate_the_current_run_artifact() -> None:
    """Step-local credentials must reach the artifact reader inside workflow_build."""
    job = yaml.safe_load(_source(".github/workflows/capstone-release.yml"))["jobs"][
        "build_scan_attest"
    ]
    build = next(step for step in job["steps"] if step.get("id") == "build")
    assert "workflow_build()" in build["run"]
    assert build["env"]["GH_TOKEN"] == "${{ github.token }}"
    assert job["permissions"] == {
        "contents": "read",
        "actions": "read",
        "id-token": "write",
    }


def test_workflow_helpers_are_defined_and_no_unapproved_owner_command() -> None:
    source = _source("tools/capstone_release.py")
    module = ast.parse(source)
    defined = {
        node.name
        for node in module.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    workflow = _source(".github/workflows/capstone-release.yml")
    invoked = {name for name in defined if f"import {name}; {name}()" in workflow}
    assert invoked >= {
        "workflow_preflight",
        "workflow_conflict_check",
        "workflow_receipt_validation_gate",
        "workflow_build",
        "workflow_prepare_ready",
        "workflow_apply_wait",
        "workflow_codebuild",
    }
    assert '"fetch-ready"' not in source
    assert 'choices=("github",)' in source


def test_immutable_source_control_and_result_paths() -> None:
    owner = _source("tools/capstone_release.py")
    deploy = _source("tools/capstone_deploy.py")
    buildspec = _source("deploy/codebuild/capstone-deploy.buildspec.yml")
    assert "SOURCE_KEY =" in owner and "CONTROL_KEY =" in owner
    assert "validate_primary_source_bundle" in owner + deploy
    assert "validate_rendered_release" in owner + deploy
    assert "secondarySourcesVersionOverride" in owner
    assert "CODEBUILD_SOURCE_VERSION_W12_CONTROL" in buildspec
    assert "publish-result" in buildspec


def test_future_lineage_zip_exact_six_entries() -> None:
    chain = verified_release_chain()
    files = _zip_files(make_future_lineage_zip(chain))
    assert set(files) == {
        "rollback/rollback-lineage-manifest.json",
        "rollback/rollback-lineage-manifest.sha256",
        "rollback/verified/release-record.json",
        "rollback/verified/release-record.sha256",
        "rollback/parent/release-record.json",
        "rollback/parent/release-record.sha256",
    }
    assert files["rollback/verified/release-record.json"] == chain[4]
    assert files["rollback/parent/release-record.json"] == chain[3]


def test_publication_selector_includes_lineage_object() -> None:
    import json

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
            "kms_key_arn": (
                "arn:aws:kms:ap-southeast-1:123456789012:key/123e4567-e89b-42d3-a456-426614174000"
            ),
        }

    selector = {
        "schema_version": "w12-001.publication-selector.v1",
        "record_id": record_id,
        "operation": "deploy",
        "account_id": "123456789012",
        "region": "ap-southeast-1",
        "verified_record_sha256": record_sha,
        "record_object": identity(
            f"w12-001/releases/{record_id}/records/r5/release-record.json", record_sha
        ),
        "sidecar_object": identity(
            f"w12-001/releases/{record_id}/records/r5/release-record.sha256",
            hashlib.sha256(sidecar(chain[4])).hexdigest(),
        ),
        "lineage_object": identity(
            f"w12-001/releases/{record_id}/lineage/verified-lineage.zip", lineage_sha
        ),
    }
    assert (
        validate_publication_selector(
            canonical(selector),
            verified=verified,
            verified_sha256=record_sha,
            lineage_sha256=lineage_sha,
        )
        == selector
    )


def test_handoff_v2_inventory_counts() -> None:
    import re

    release = _source("tools/capstone_release.py")
    deploy = _source("tools/capstone_deploy.py")
    assert '"schema_version": "w12-001.codebuild-handoff.v2"' in release
    assert 'len(control_files) != (24 if applied["operation"] == "rollback" else 18)' in release
    compact_deploy = re.sub(r"\s+", "", deploy)
    assert 'len(payload)!=(22ifapplied["operation"]=="rollback"else16)' in compact_deploy


def test_hcp_configuration_binding_is_not_archive_hash(monkeypatch) -> None:
    import pytest
    import tools.capstone_release as release

    record = verified_release_chain()[0]
    import json

    parsed = json.loads(record)
    manifest = b'{"schema_version":"w12-001.terraform-configuration-manifest.v1"}\n'
    monkeypatch.setattr(
        release, "terraform_configuration_manifest", lambda _commit, _tree: manifest
    )
    parsed["terraform"]["configuration_sha256"] = hashlib.sha256(manifest).hexdigest()
    parsed["terraform"]["configuration_version_id"] = "cv-synthetic-opaque-id"
    assert (
        release.validate_terraform_configuration_binding(parsed)
        == hashlib.sha256(manifest).hexdigest()
    )
    parsed["terraform"]["configuration_sha256"] = "f" * 64
    with pytest.raises(release.ReleaseError, match="TERRAFORM_CONFIGURATION_MANIFEST_MISMATCH"):
        release.validate_terraform_configuration_binding(parsed)


def test_source_manifest_bootstrap_pair_excluded_from_payload_files() -> None:
    import json

    archive, _, _ = make_primary_source_bundle(
        {"deploy/k8s/deployment.yaml": b"kind: Deployment\n"},
        commit="a" * 40,
        tree="b" * 40,
    )
    members = _zip_files(archive)
    manifest = json.loads(members[BOOTSTRAP_JSON])
    listed = {item["path"] for item in manifest["files"]}
    assert BOOTSTRAP_JSON not in listed and BOOTSTRAP_SHA not in listed
    assert listed == set(members) - {BOOTSTRAP_JSON, BOOTSTRAP_SHA}
    assert {W6_HASHES_JSON, W6_HASHES_SHA} <= listed


def test_source_manifest_bootstrap_locator_accepts_self_exclusion() -> None:
    import json

    chain = verified_release_chain()
    ready = json.loads(chain[1])
    source = ready["source"]
    ready["evidence"] = [
        {
            "kind": "w12_source_manifest",
            "uri": encode_s3v_locator(
                source["s3_bucket"], source["s3_key"], source["s3_version_id"], entry=BOOTSTRAP_JSON
            ),
            "sha256": "f" * 64,
        }
    ]
    assert (
        validate_record(canonical(ready), sidecar(canonical(ready)), previous=chain[0])["evidence"][
            0
        ]["kind"]
        == "w12_source_manifest"
    )


def test_source_manifest_exact_payload_coverage() -> None:
    archive, manifest_sha, w6_sha = make_primary_source_bundle(
        {
            "deploy/k8s/deployment.yaml": b"kind: Deployment\n",
            "tools/capstone_release.py": b"synthetic\n",
        },
        commit="a" * 40,
        tree="b" * 40,
    )
    from tools.capstone_release import validate_primary_source_bundle

    members = validate_primary_source_bundle(
        archive,
        archive_sha256=hashlib.sha256(archive).hexdigest(),
        manifest_sha256=manifest_sha,
        w6_sha256=w6_sha,
        commit="a" * 40,
        tree="b" * 40,
    )
    assert set(members) == {
        "deploy/k8s/deployment.yaml",
        "tools/capstone_release.py",
        BOOTSTRAP_JSON,
        BOOTSTRAP_SHA,
        W6_HASHES_JSON,
        W6_HASHES_SHA,
    }


def test_non_manifest_locator_requires_manifest_entry() -> None:
    archive, _, _ = make_primary_source_bundle(
        {"deploy/k8s/deployment.yaml": b"kind: Deployment\n"},
        commit="a" * 40,
        tree="b" * 40,
    )
    members = _zip_files(archive)
    assert BOOTSTRAP_JSON in members
    assert W6_HASHES_JSON in members
    assert members[BOOTSTRAP_SHA] == sidecar(members[BOOTSTRAP_JSON])


def test_github_approval_uses_only_documented_fields() -> None:
    import json

    source = _source("tools/capstone_release.py")
    contract = json.loads(_source("configs/ci/capstone-release.json"))
    assert contract["approval_github_fields"] == [
        "repository",
        "workflow_run_id",
        "run_attempt",
        "environment_id",
        "environment_name",
        "state",
        "comment_sha256",
        "approver_id",
        "approver_login",
        "approver_node_id",
        "approver_type",
        "canonical_subset_sha256",
        "client_observed_at_utc",
    ]
    approval = source.split("def _github_approval_subset(", 1)[1].split(
        "def workflow_verify_github_approval(", 1
    )[0]
    assert 'item.get("comment")' in approval
    assert 'user.get("id")' in approval
    assert 'env.get("node_id")' in approval
    assert "approval_event_id" not in approval
    assert "approved_at" not in approval


def test_approved_transition_evidence_contract() -> None:
    import json

    config = json.loads(_source("configs/ci/capstone-release.json"))
    assert config["approval_evidence_fields"] == [
        "schema_version",
        "transition",
        "record_id",
        "from_revision",
        "to_revision",
        "parent_record_sha256",
        "github_approval",
        "hcp_authenticated_resource",
        "hcp_apply",
        "observed_at_utc",
    ]
    assert config["approval_hcp_apply_fields"][-3:] == [
        "post_run_subset_sha256",
        "client_requested_at_utc",
        "client_observed_at_utc",
    ]
    source = _source("tools/capstone_release.py")
    assert '"transition": "READY_FOR_OWNER_TO_APPROVED"' in source
    assert '"response_status": 202' in source


def test_render_input_contract() -> None:
    import json

    from tools.capstone_release import validate_render_inputs

    config = json.loads(_source("configs/ci/capstone-release.json"))
    ready, approved, applied, raw = render_input_fixture()
    document = json.loads(raw)
    assert list(document) == config["render_input_fields"]
    assert (
        validate_render_inputs(
            raw,
            sidecar(raw),
            ready=ready,
            ready_sha256=hashlib.sha256(canonical(ready)).hexdigest(),
            approved=approved,
            approved_sha256=hashlib.sha256(canonical(approved)).hexdigest(),
            applied=applied,
        )["schema_version"]
        == config["render_input_schema_version"]
    )


def test_w12_does_not_require_w6_v2_rendered_package() -> None:
    source = _source("tools/capstone_deploy.py")
    assert "render_w12_release" in source
    assert "validate_release(" not in source
    assert "release-binding.json" not in source


def test_week6_renderer_w12_interface() -> None:
    source = _source("tools/w6_001_k8s.py")
    assert "class W12RenderBindings:" in source
    assert "def render_w12_release(" in source
    assert "_substitute_release_templates(" in source


def test_week6_v2_renderer_interface_is_preserved() -> None:
    source = _source("tools/w6_001_k8s.py")
    for name in (
        "load_documents",
        "load_template",
        "template_identity",
        "validate_documents",
        "validate_template",
        "validate_release_binding",
        "build_release_files",
        "bind_release",
        "validate_release",
        "main",
    ):
        assert f"def {name}(" in source
    for command in ("validate-template", "bind-release", "validate-release"):
        assert command in source


def test_renderer_is_not_release_provenance_boundary() -> None:
    source = _source("tools/capstone_deploy.py")
    assert "validate_render_inputs(" in source
    assert "validate_primary_source_bundle(" in source
    assert "render_w12_release(" in source
    assert source.index("validate_primary_source_bundle(") < source.index("render_w12_release(")


def test_rendered_release_exact_file_coverage() -> None:
    import tools.capstone_release as release

    files = {name: b"synthetic\n" for name in release.W12_RENDERED_FILE_NAMES}
    document = {
        "schema_version": "w12-001.rendered-release.v1",
        "ready_record_sha256": "a" * 64,
        "approved_record_sha256": "b" * 64,
        "applied_record_sha256": "c" * 64,
        "source_archive_sha256": "d" * 64,
        "w6_release_hashes_sha256": "e" * 64,
        "render_inputs_sha256": "f" * 64,
        "renderer_path": "tools/w6_001_k8s.py",
        "renderer_sha256": "1" * 64,
        "created_at_utc": "2026-01-01T00:00:00Z",
        "files": release._file_inventory(files),
    }
    raw = release._canonical_bytes(document)
    binding = dict(
        ready_sha256="a" * 64,
        approved_sha256="b" * 64,
        applied_sha256="c" * 64,
        source_sha256="d" * 64,
        w6_sha256="e" * 64,
        render_inputs_sha256="f" * 64,
        renderer_sha256="1" * 64,
    )
    assert (
        release.validate_rendered_release(raw, sidecar(raw), archive_files=files, **binding)
        == document
    )
    files.pop("service.yaml")
    import pytest

    with pytest.raises(release.ReleaseError, match="RENDERED_RELEASE_FILE_SET"):
        release.validate_rendered_release(raw, sidecar(raw), archive_files=files, **binding)


def test_purge_inventory_v3_schema_version() -> None:
    from tools.platformctl.lifecycle_models import PURGE_INVENTORY_V3_SCHEMA_VERSION

    assert PURGE_INVENTORY_V3_SCHEMA_VERSION == "platformctl.purge-inventory.v3"


def test_w12_publication_key_templates() -> None:
    import tools.capstone_release as release

    record_id = "123e4567-e89b-42d3-a456-426614174000"
    assert release._release_publication_key(record_id, "verified_record") == (
        f"w12-001/releases/{record_id}/records/r5/release-record.json"
    )
    assert release._release_publication_key(record_id, "verified_sidecar") == (
        f"w12-001/releases/{record_id}/records/r5/release-record.sha256"
    )
    assert release._release_publication_key(record_id, "future_lineage") == (
        f"w12-001/releases/{record_id}/lineage/verified-lineage.zip"
    )


def test_publication_selector_schema() -> None:
    import json

    config = json.loads(_source("configs/ci/capstone-release.json"))
    assert config["publication_selector_schema_version"] == "w12-001.publication-selector.v1"
    source = _source("tools/capstone_release.py")
    selector = source.split("def validate_publication_selector(", 1)[1].split(
        "def _read_selected_object(", 1
    )[0]
    assert '"lineage_object"' in selector
    assert '"last_modified_utc"' in selector


def test_zip_manifest_transitive_coverage() -> None:
    source = _source("tools/capstone_release.py")
    proof = source.split("def validate_publication_proof(", 1)[1].split(
        "def load_prior_rollback_lineage(", 1
    )[0]
    assert "validate_primary_source_bundle(" in proof
    assert "validate_current_control_bundle(" in proof
    assert "validate_rendered_release(" in proof


def test_retention_proof_root_cli_contract() -> None:
    from tools.platformctl.cli import build_parser

    parser = build_parser()
    help_text = parser.format_help()
    assert "verify-clean" in help_text
    source = _source("tools/platformctl/cli.py")
    assert source.count('"--w12-retention-proof-root"') >= 3
    assert 'action="append"' in source


def test_purge_inventory_v3_retention_binding_order() -> None:
    from dataclasses import fields

    from tools.platformctl.lifecycle_models import (
        PurgeInventoryV2,
        PurgeInventoryV3,
        W12RetentionBinding,
    )

    v2 = [field.name for field in fields(PurgeInventoryV2)]
    v3 = [field.name for field in fields(PurgeInventoryV3)]
    assert v3 == [*v2, "w12_retention_bindings"]
    assert [field.name for field in fields(W12RetentionBinding)] == [
        "record_id",
        "operation",
        "verified_record_sha256",
        "verified_created_at_utc",
        "verified_record_object",
        "verified_sidecar_object",
        "publication_anchor_utc",
        "retain_until_utc",
        "kms_key_arn",
        "protected_objects",
    ]


def test_w12_retention_matches_canonical_evidence_policy() -> None:
    from datetime import UTC, datetime, timedelta

    from tools.capstone_release import retention_anchor_from_publication

    anchor, retain_until = retention_anchor_from_publication(
        "2026-01-01T00:00:00Z",
        "2026-01-01T00:00:01Z",
        "2026-01-01T00:00:02Z",
        "2026-01-01T00:00:03Z",
        now=datetime(2026, 1, 1, 0, 0, 4, tzinfo=UTC),
    )
    assert retain_until == anchor + timedelta(days=180)
    sandbox = _source("infra/environments/sandbox/main.tf")
    assert "noncurrent_version_retention_days = 180" in sandbox


def test_codebuild_handoff_v2_field_order() -> None:
    source = _source("tools/capstone_release.py")
    handoff = source.split('"schema_version": "w12-001.codebuild-handoff.v2"', 1)[1]
    assert handoff.index('"created_at_utc"') < handoff.index('"files"')
    assert '"schema_version","record_id","operation","workflow_run_id"' in "".join(source.split())


def test_deploy_control_bundle_exact_file_set() -> None:
    source = _source("tools/capstone_release.py")
    function = source.split("def validate_current_control_bundle(", 1)[1].split(
        "def make_primary_source_bundle(", 1
    )[0]
    assert 'len(files)!=(24ifrecords[4]["operation"]=="rollback"else18)' in "".join(
        function.split()
    )
    assert "payload_names |= FUTURE_LINEAGE_PATHS" in function
    assert '"w12-render-inputs.json","w12-render-inputs.sha256"' in "".join(function.split())


def test_rollback_control_bundle_exact_file_set() -> None:
    source = _source("tools/capstone_release.py")
    function = source.split("def validate_current_control_bundle(", 1)[1].split(
        "def make_primary_source_bundle(", 1
    )[0]
    assert 'if records[4]["operation"] == "rollback":' in function
    assert "payload_names |= FUTURE_LINEAGE_PATHS" in function
    assert "_file_inventory(payload)" in function


def test_verified_release_lineage_bundle_contract() -> None:
    from tools.capstone_release import validate_future_lineage_zip

    chain = verified_release_chain()
    bundle = make_future_lineage_zip(chain)
    members = _zip_files(bundle)
    assert set(members) == {
        "rollback/rollback-lineage-manifest.json",
        "rollback/rollback-lineage-manifest.sha256",
        "rollback/verified/release-record.json",
        "rollback/verified/release-record.sha256",
        "rollback/parent/release-record.json",
        "rollback/parent/release-record.sha256",
    }
    assert validate_future_lineage_zip(bundle, raws=chain)["schema_version"] == (
        "w12-001.rollback-lineage.v1"
    )


def test_rollback_locator_and_digest_scopes_are_separate() -> None:
    from tools.capstone_release import _release_publication_key, decode_s3v_locator

    record_id = "123e4567-e89b-42d3-a456-426614174000"
    locator = encode_s3v_locator(
        "synthetic-bucket",
        _release_publication_key(record_id, "future_lineage"),
        "synthetic-version-1",
        entry="rollback/rollback-lineage-manifest.json",
    )
    selected = decode_s3v_locator(locator)
    assert selected["entry"] == "rollback/rollback-lineage-manifest.json"
    archive = make_future_lineage_zip(verified_release_chain())
    assert (
        hashlib.sha256(archive).hexdigest()
        != hashlib.sha256(_zip_files(archive)[selected["entry"]]).hexdigest()
    )


def test_rollback_evidence_revision_contract() -> None:
    source = _source("tools/capstone_release.py")
    validator = source.split("def validate_record(", 1)[1].split("def decode_record_b64url(", 1)[0]
    assert "ifrev>=2else" in "".join(validator.split())
    assert '"rollback-lineage-archive", "rollback-lineage-manifest"' in validator
    assert '"rollback-verified-record","rollback-parent-record"' in "".join(validator.split())


def test_codebuild_rollback_path_variables_are_populated() -> None:
    source = _source("tools/capstone_deploy.py")
    preflight = source.split("def _source(", 1)[1].split("def _record(", 1)[0]
    assert 'control / f"records/r{revision}"' in preflight
    assert '"rollback/verified/release-record.json"' in preflight
    assert '"rollback/parent/release-record.json"' in preflight
    assert "W12_PREVIOUS_GOOD_RECORD_PATH" not in preflight


def test_primary_source_precedes_ready_and_excludes_release_records() -> None:
    source = _source("tools/capstone_release.py")
    build = source.split("def workflow_build(", 1)[1].split("def _write_workflow_pair(", 1)[0]
    ready = source.split("def workflow_prepare_ready(", 1)[1].split(
        "def workflow_cleanup_ready(", 1
    )[0]
    assert "make_primary_source_bundle(" in build
    assert ready.index("validate_primary_source_bundle(") < ready.index(
        '_write_workflow_pair(directory, "release-record", raw)'
    )
    assert "release-record.json" not in _zip_files(
        make_primary_source_bundle(
            {"deploy/k8s/namespace.yaml": b"kind: Namespace\n"},
            commit="a" * 40,
            tree="b" * 40,
        )[0]
    )


def test_w6_release_hashes_cover_exact_tracked_manifest_set() -> None:
    import json

    tracked = {
        "deploy/k8s/namespace.yaml": b"kind: Namespace\n",
        "deploy/k8s/service.yaml": b"kind: Service\n",
        "tools/capstone_release.py": b"synthetic source\n",
    }
    archive, _, _ = make_primary_source_bundle(tracked, commit="a" * 40, tree="b" * 40)
    members = _zip_files(archive)
    manifest = json.loads(members[W6_HASHES_JSON])
    assert {item["path"] for item in manifest["files"]} == {
        "deploy/k8s/namespace.yaml",
        "deploy/k8s/service.yaml",
    }


def test_source_manifest_binds_commit_tree_and_w6_hashes() -> None:
    import json

    archive, manifest_sha, w6_sha = make_primary_source_bundle(
        {"deploy/k8s/namespace.yaml": b"kind: Namespace\n"},
        commit="a" * 40,
        tree="b" * 40,
    )
    members = _zip_files(archive)
    manifest = json.loads(members[BOOTSTRAP_JSON])
    assert (manifest["commit"], manifest["tree"], manifest["w6_release_hashes_sha256"]) == (
        "a" * 40,
        "b" * 40,
        w6_sha,
    )
    assert hashlib.sha256(members[BOOTSTRAP_JSON]).hexdigest() == manifest_sha


def test_applied_preserves_ready_source_identity() -> None:
    import json

    chain = verified_release_chain()
    ready, approved, applied = (json.loads(chain[index]) for index in (1, 2, 3))
    assert ready["source"] == approved["source"] == applied["source"]


def test_control_bundle_contains_exact_r1_to_r4_chain() -> None:
    source = _source("tools/capstone_release.py")
    producer = source.split("def workflow_codebuild(", 1)[1].split("def workflow_verify(", 1)[0]
    consumer = (
        _source("tools/capstone_deploy.py").split("def _source(", 1)[1].split("def _record(", 1)[0]
    )
    assert '"release-record.json": raws[3]' in producer
    assert 'control_files[f"records/r{revision}/{name}"]' in producer
    assert 'len(control_files) != (24 if applied["operation"] == "rollback" else 18)' in producer
    assert "CONTROL_ARCHIVE_FILE_SET" in consumer


def test_control_bundle_binds_ready_source_and_applied_record() -> None:
    source = _source("tools/capstone_release.py")
    producer = source.split("def workflow_codebuild(", 1)[1].split("def workflow_verify(", 1)[0]
    assert '"primary_source": {' in producer
    assert '"object_sha256": applied["source"]["archive_sha256"]' in producer
    assert '"release-record.json": raws[3]' in producer
    proof = source.split("def validate_current_control_bundle(", 1)[1].split(
        "def make_primary_source_bundle(", 1
    )[0]
    assert "CONTROL_PROOF_RECORD_BINDING" in proof
    assert "CONTROL_PROOF_HCP_OR_ARTIFACT_CHANGED" in proof
    assert "CONTROL_PROOF_OUTPUT_STATE_CHANGED" in proof


def test_control_bundle_has_no_self_referential_object_digest() -> None:
    source = _source("tools/capstone_release.py")
    producer = source.split("def workflow_codebuild(", 1)[1].split("def workflow_verify(", 1)[0]
    before = producer.split("handoff_raw = _canonical_bytes(handoff)", 1)[0]
    assert '"control_archive_sha256"' not in before
    assert 'handoff["files"] = _file_inventory(control_files)' in before


def test_codebuild_project_has_primary_and_secondary_s3_sources() -> None:
    terraform = _source("infra/environments/sandbox/main.tf")
    assert 'resource "aws_codebuild_project"' in terraform
    assert "secondary_sources" in terraform
    assert "W12_CONTROL" in terraform


def test_buildspec_uses_primary_w6_and_secondary_applied_record() -> None:
    buildspec = _source("deploy/codebuild/capstone-deploy.buildspec.yml")
    deploy = _source("tools/capstone_deploy.py")
    assert "CODEBUILD_SRC_DIR_W12_CONTROL" in buildspec
    assert "CODEBUILD_SOURCE_VERSION_W12_CONTROL" in buildspec
    assert 'raw, sidecar = _pair(folder, "release-record")' in deploy
    assert "source_files != _tree_files(primary)" in deploy


def test_s3_source_version_variables_are_used() -> None:
    buildspec = _source("deploy/codebuild/capstone-deploy.buildspec.yml")
    assert '$CODEBUILD_SOURCE_VERSION" = "$W12_SOURCE_VERSION_ID' in buildspec
    assert '$CODEBUILD_SOURCE_VERSION_W12_CONTROL" = "$W12_CONTROL_VERSION_ID' in buildspec


def test_resolved_source_version_is_not_used_for_s3() -> None:
    deploy = _source("tools/capstone_deploy.py")
    workflow = _source("tools/capstone_release.py")
    assert "CODEBUILD_RESOLVED_SOURCE_VERSION" not in deploy + workflow


def test_codebuild_result_key_is_derived_from_record_and_build() -> None:
    producer = _source("tools/capstone_deploy.py").split("def publish_result(", 1)[1]
    assert (
        "w12-001/results/{applied['record_id']}/r4/{_build_uuid()}/codebuild-result.json"
        in producer
    )
    assert 'build_id = _required_env("CODEBUILD_BUILD_ID")' in producer
    assert '"record-revision": "4"' in producer


def test_codebuild_result_upload_requires_checksum_and_kms() -> None:
    producer = _source("tools/capstone_deploy.py").split("def publish_result(", 1)[1]
    assert 'ServerSideEncryption="aws:kms"' in producer
    assert 'SSEKMSKeyId=_required_env("W12_RESULT_KMS_KEY_ARN")' in producer
    assert "ChecksumSHA256=base64.b64encode(hashlib.sha256(raw).digest())" in producer
    assert 'IfNoneMatch="*"' in producer


def test_codebuild_role_write_is_limited_to_result_prefix() -> None:
    iam = _source("infra/bootstrap/modules/platform-iam/main.tf")
    role = iam.split('data "aws_iam_policy_document" "capstone_codebuild"', 1)[1].split(
        'resource "aws_iam_role_policy" "capstone_codebuild"', 1
    )[0]
    assert 'actions   = ["s3:PutObject"]' in role
    assert '"${local.platform_bucket_arn}/w12-001/results/*"' in role


def test_codebuild_role_cannot_modify_source_or_control_objects() -> None:
    iam = _source("infra/bootstrap/modules/platform-iam/main.tf")
    role = iam.split('data "aws_iam_policy_document" "capstone_codebuild"', 1)[1].split(
        'resource "aws_iam_role_policy" "capstone_codebuild"', 1
    )[0]
    assert '"s3:DeleteObject"' not in role
    assert '"s3:DeleteObjectVersion"' not in role
    write = role.split('sid       = "WriteRedactedBuildResult"', 1)[1].split("}", 1)[0]
    assert "w12-001/source" not in write and "w12-001/control" not in write


def test_batch_get_builds_returns_exact_result_identities() -> None:
    source = _source("tools/capstone_release.py")
    watch = source.split("def workflow_codebuild(", 1)[1].split("def workflow_verify(", 1)[0]
    assert "client.batch_get_builds(ids=[build_id])" in watch
    assert 'build.get("id") != build_id' in watch
    assert 'build.get("sourceVersion") != request["sourceVersion"]' in watch
    assert 'secondary != request["secondarySourcesVersionOverride"]' in watch


def test_missing_result_identity_prevents_verified() -> None:
    source = _source("tools/capstone_release.py")
    verify = source.split("def workflow_verify(", 1)[1].split("def workflow_publish(", 1)[0]
    assert "W12_RESULT_LOCATOR" in verify
    assert "W12_RESULT_SHA256" in verify
    assert "validate_codebuild_result(" in verify
    assert verify.index("validate_codebuild_result(") < verify.index(
        '_transition_record(applied, raws[3], "VERIFIED")'
    )


def test_verified_binds_exact_result_object_version_and_digest() -> None:
    source = _source("tools/capstone_release.py")
    verify = source.split("def workflow_verify(", 1)[1].split("def workflow_publish(", 1)[0]
    compact = "".join(verify.split())
    assert '"kind":"codebuild_result","uri":os.environ["W12_RESULT_LOCATOR"]' in compact
    assert '"sha256":os.environ["W12_RESULT_SHA256"]' in compact


def test_fetch_ready_is_not_added_without_prior_approval() -> None:
    from tools.capstone_release import _parser

    parser = _parser()
    assert "fetch-ready" not in parser.format_help()
    assert "fetch-ready" not in _source("tools/capstone_release.py")
