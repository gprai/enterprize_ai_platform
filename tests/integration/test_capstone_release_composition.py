"""Offline composition of the two immutable W12 source boundaries."""

from __future__ import annotations

import hashlib

import pytest
import tools.capstone_release as release
from tools.capstone_release import (
    BOOTSTRAP_JSON,
    BOOTSTRAP_SHA,
    ReleaseError,
    _make_zip,
    _zip_files,
    make_primary_source_bundle,
    validate_primary_source_bundle,
)

from tests.fakes.capstone_release import verified_release_chain


def _source() -> dict[str, bytes]:
    return {
        "deploy/k8s/namespace.yaml": b"apiVersion: v1\nkind: Namespace\n",
        "tools/w6_001_k8s.py": b"# exact renderer blob\n",
        "Dockerfile": b"FROM scratch\n",
    }


def test_source_manifest_bootstrap_and_exact_archive_payload() -> None:
    archive, manifest_sha, w6_sha = make_primary_source_bundle(
        _source(), commit="a" * 40, tree="b" * 40
    )
    files = validate_primary_source_bundle(
        archive,
        archive_sha256=hashlib.sha256(archive).hexdigest(),
        manifest_sha256=manifest_sha,
        w6_sha256=w6_sha,
        commit="a" * 40,
        tree="b" * 40,
    )
    assert BOOTSTRAP_JSON in files and BOOTSTRAP_SHA in files
    assert files["deploy/k8s/namespace.yaml"] == _source()["deploy/k8s/namespace.yaml"]


def test_source_manifest_self_exclusion_and_payload_substitution() -> None:
    archive, manifest_sha, w6_sha = make_primary_source_bundle(
        _source(), commit="a" * 40, tree="b" * 40
    )
    files = _zip_files(archive)
    files["Dockerfile"] = b"FROM substituted\n"
    changed = _make_zip(files)
    with pytest.raises(ReleaseError):
        validate_primary_source_bundle(
            changed,
            archive_sha256=hashlib.sha256(changed).hexdigest(),
            manifest_sha256=manifest_sha,
            w6_sha256=w6_sha,
            commit="a" * 40,
            tree="b" * 40,
        )


def test_current_run_record_and_opa_receipt_chain() -> None:
    from pathlib import Path

    workflow = (
        Path(__file__).resolve().parents[2] / ".github/workflows/capstone-release.yml"
    ).read_text()
    assert workflow.count("artifact-ids: ${{ needs.preflight.outputs.record_artifact_id }}") >= 2
    assert "run-id: ${{ github.run_id }}" in workflow
    assert "opa-receipt.sha256" in workflow
    assert "retention-days: 7" in workflow
    assert "actions/download-artifact@" in workflow


def test_future_lineage_publication_follows_verified_pair(monkeypatch: pytest.MonkeyPatch) -> None:
    chain = verified_release_chain()
    order: list[str] = []
    objects: dict[str, bytes] = {}

    def fake_publish(
        _client,
        *,
        key: str,
        raw: bytes,
        bucket: str,
        kms_key: str,
        record_id: str,
        revision: int,
        content_type: str,
    ) -> dict[str, str]:
        del record_id, revision, content_type
        order.append(key)
        objects[key] = raw
        return {
            "bucket": bucket,
            "key": key,
            "version_id": "synthetic-version-1",
            "sha256": hashlib.sha256(raw).hexdigest(),
            "last_modified_utc": "2026-01-01T00:00:00Z",
            "kms_key_arn": kms_key,
        }

    def fake_read(_client, bucket: str, key: str, version: str, digest: str) -> bytes:
        del bucket, version
        assert hashlib.sha256(objects[key]).hexdigest() == digest
        return objects[key]

    monkeypatch.setattr(release, "_publish_bound_object", fake_publish)
    monkeypatch.setattr(release, "_s3_read_exact", fake_read)
    published_pair, lineage, archive = release.publish_verified_pair_and_lineage(
        object(),
        bucket="w12-evidence-example",
        kms_key="arn:aws:kms:ap-southeast-1:123456789012:key/123e4567-e89b-42d3-a456-426614174000",
        chain_raws=chain,
    )
    assert order == [
        published_pair["verified_record"]["key"],
        published_pair["verified_sidecar"]["key"],
        lineage["key"],
    ]
    assert lineage["sha256"] == hashlib.sha256(archive).hexdigest()


def test_protected_github_job_is_only_hcp_apply_job() -> None:
    from pathlib import Path

    workflow = (
        Path(__file__).resolve().parents[2] / ".github/workflows/capstone-release.yml"
    ).read_text()
    protected = workflow.split("  github_release_apply:", 1)[1].split("  codebuild_deploy:", 1)[0]
    assert workflow.count("environment: sandbox") == 1
    assert "TFC_TOKEN: ${{ secrets.TFC_TOKEN }}" in protected
    assert "workflow_apply_wait" in protected
    assert "  hcp_apply_wait:" not in workflow


def test_codebuild_requires_applied_record() -> None:
    from pathlib import Path

    workflow = (
        Path(__file__).resolve().parents[2] / ".github/workflows/capstone-release.yml"
    ).read_text()
    deploy = workflow.split("  codebuild_deploy:", 1)[1].split("  verify:", 1)[0]
    assert "github_release_apply" in deploy.split("steps:", 1)[0]
    assert "applied_artifact_id" in deploy
    assert "workflow_codebuild" in deploy


def test_source_bundle_validation_precedes_ready_revision() -> None:
    source = (release.ROOT / "tools/capstone_release.py").read_text()
    section = source.split("def workflow_prepare_ready(", 1)[1].split(
        "def workflow_cleanup_ready(", 1
    )[0]
    assert section.index("validate_primary_source_bundle") < section.index(
        '_write_workflow_pair(directory, "release-record", raw)'
    )


def test_ready_uses_exact_versioned_source_entry_locators() -> None:
    from tools.capstone_release import (
        SOURCE_KEY,
        W6_HASHES_JSON,
        decode_s3v_locator,
        encode_s3v_locator,
    )

    bucket, version = "synthetic-bucket", "synthetic-version-1"
    manifest = encode_s3v_locator(bucket, SOURCE_KEY, version, entry=BOOTSTRAP_JSON)
    w6 = encode_s3v_locator(bucket, SOURCE_KEY, version, entry=W6_HASHES_JSON)
    for locator, entry in ((manifest, BOOTSTRAP_JSON), (w6, W6_HASHES_JSON)):
        selected = decode_s3v_locator(locator)
        assert (selected["bucket"], selected["key"], selected["version_id"], selected["entry"]) == (
            bucket,
            SOURCE_KEY,
            version,
            entry,
        )


def test_w6_release_hashes_manifest_and_locator_binding() -> None:
    from tools.capstone_release import W6_HASHES_JSON, W6_HASHES_SHA

    archive, manifest_sha, w6_sha = make_primary_source_bundle(
        _source(),
        commit="a" * 40,
        tree="b" * 40,
    )
    members = validate_primary_source_bundle(
        archive,
        archive_sha256=hashlib.sha256(archive).hexdigest(),
        manifest_sha256=manifest_sha,
        w6_sha256=w6_sha,
        commit="a" * 40,
        tree="b" * 40,
    )
    assert members[W6_HASHES_SHA] == (w6_sha + "\n").encode("ascii")
    assert hashlib.sha256(members[W6_HASHES_JSON]).hexdigest() == w6_sha


def test_protected_approval_follows_ready_bundle_validation() -> None:
    workflow = (release.ROOT / ".github/workflows/capstone-release.yml").read_text()
    ready = workflow.split("  prepare_ready_record:", 1)[1].split("  github_release_apply:", 1)[0]
    protected = workflow.split("  github_release_apply:", 1)[1].split("  codebuild_deploy:", 1)[0]
    assert "workflow_prepare_ready" in ready
    assert "prepare_ready_record" in protected.split("steps:", 1)[0]


def test_codebuild_revalidates_source_bootstrap_pair() -> None:
    deploy = (release.ROOT / "tools/capstone_deploy.py").read_text()
    source = deploy.split("def _source(", 1)[1].split("def _record_chain(", 1)[0]
    assert "validate_primary_source_bundle" in source
    assert "_s3_version(bucket,SOURCE_KEY,source_version" in "".join(source.split())
    assert "SOURCE_MANIFEST_RECORD_BINDING" in source


def test_capstone_deploy_uses_w12_renderer_interface() -> None:
    source = (release.ROOT / "tools/capstone_deploy.py").read_text()
    adapter = source.split("def _render_bundle(", 1)[1].split("def _pki_ready(", 1)[0]
    assert "W12RenderBindings(" in adapter
    assert "render_w12_release(source_root=source_root, bindings=bindings)" in adapter
    assert "bind_release(" not in adapter


def test_capstone_deploy_passes_ready_application_image() -> None:
    source = (release.ROOT / "tools/capstone_deploy.py").read_text()
    adapter = source.split("def _render_bundle(", 1)[1].split("def _pki_ready(", 1)[0]
    assert "application = application_image_from_ready(ready)" in adapter
    assert "application_image=application" in adapter
    assert 'collector = ready["artifacts"]["otel_collector_image"]' in adapter


def test_codebuild_reaches_renderer_only_through_validated_adapter() -> None:
    source = (release.ROOT / "tools/capstone_deploy.py").read_text()
    actual_source = source.split("def _source(", 1)[1].split("def _render_bundle(", 1)[0]
    adapter = source.split("def _render_bundle(", 1)[1].split("def _pki_ready(", 1)[0]
    assert "validate_primary_source_bundle(" in actual_source
    assert "validate_render_inputs(" in actual_source
    assert "render_w12_release(" in adapter
    assert "CODEBUILD_EXECUTABLE_BLOB_SUBSTITUTION" in actual_source


def test_opensearch_render_input_uses_exact_applied_state() -> None:
    source = (release.ROOT / "tools/capstone_release.py").read_text()
    function = source.split("def workflow_apply_wait(", 1)[1].split(
        "def workflow_cleanup_transitions(", 1
    )[0]
    assert '"opensearch_https_endpoint"' in function
    assert '"applied_state_version_id"' in function
    assert '"state_lineage"' in function


def test_bedrock_render_input_uses_exact_applied_state() -> None:
    source = (release.ROOT / "tools/capstone_release.py").read_text()
    function = source.split("def workflow_apply_wait(", 1)[1].split(
        "def workflow_cleanup_transitions(", 1
    )[0]
    assert '"bedrock_inference_profile_arn"' in function
    assert '"state_serial"' in function


def test_rendered_archive_binding_precedes_kubernetes_mutation() -> None:
    deploy = (release.ROOT / "tools/capstone_deploy.py").read_text()
    preflight = deploy.split("def preflight(", 1)[1].split("def _bootstrap_ready(", 1)[0]
    runtime = deploy.split("def deploy(", 1)[1].split("def withdraw_service(", 1)[0]
    assert "_render_bundle(" in preflight
    assert "_apply_documents(" in runtime
    assert runtime.index("_read_verified_archive(") < runtime.index("_apply_documents(")


def test_verified_record_binds_rendered_release() -> None:
    source = (release.ROOT / "tools/capstone_release.py").read_text()
    section = source.split("def workflow_verify(", 1)[1].split("def workflow_publish(", 1)[0]
    assert '"rendered_release_archive"' in section
    assert '"derivative_manifest_sha256"' in section
    assert "validate_codebuild_result(" in section


def test_publication_selector_after_verified_pair_readback() -> None:
    source = (release.ROOT / "tools/capstone_release.py").read_text()
    section = source.split("def workflow_verify(", 1)[1].split("def workflow_publish(", 1)[0]
    assert section.index("publish_verified_pair_and_lineage(") < section.index(
        '"lineage_object": published_lineage'
    )
    producer = source.split("def publish_verified_pair_and_lineage(", 1)[1].split(
        "def _publication_timestamp(", 1
    )[0]
    assert producer.index('"verified_sidecar"') < producer.index("make_future_lineage_zip")
    assert "_s3_read_exact(" in producer


def test_verified_pair_exact_version_readback() -> None:
    source = (release.ROOT / "tools/capstone_release.py").read_text()
    producer = source.split("def _publish_bound_object(", 1)[1].split(
        "def publish_verified_pair_and_lineage(", 1
    )[0]
    assert "_s3_read_exact(" in producer
    assert "version_id" in producer


def test_rollback_lineage_enters_control_bundle() -> None:
    source = (release.ROOT / "tools/capstone_release.py").read_text()
    section = source.split("def workflow_codebuild(", 1)[1].split("def workflow_verify(", 1)[0]
    assert "control_files.update(prior_files)" in section
    assert 'if applied["operation"] == "rollback"' in section


def test_verified_publication_requires_lineage_readback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    chain = verified_release_chain()

    def fake_publish(
        _client, *, raw: bytes, key: str, bucket: str, kms_key: str, **_kwargs
    ) -> dict[str, str]:
        return {
            "bucket": bucket,
            "key": key,
            "version_id": "synthetic-version-1",
            "sha256": hashlib.sha256(raw).hexdigest(),
            "last_modified_utc": "2026-01-01T00:00:00Z",
            "kms_key_arn": kms_key,
        }

    monkeypatch.setattr(release, "_publish_bound_object", fake_publish)
    monkeypatch.setattr(release, "_s3_read_exact", lambda *_args: b"wrong bytes")
    with pytest.raises(ReleaseError):
        release.publish_verified_pair_and_lineage(
            object(),
            bucket="synthetic-bucket",
            kms_key="arn:aws:kms:ap-southeast-1:123456789012:key/synthetic",
            chain_raws=chain,
        )


def test_codebuild_rechecks_lineage_before_kubernetes() -> None:
    source = (release.ROOT / "tools/capstone_deploy.py").read_text()
    read = source.split("def _source(", 1)[1].split("def _record(", 1)[0]
    runtime = source.split("def deploy(", 1)[1].split("def withdraw_service(", 1)[0]
    assert "load_prior_rollback_lineage(" in read
    assert '"ROLLBACK_PRE_KUBERNETES_IDENTITY_CHANGED"' in read
    assert runtime.index("_source(args)") < runtime.index("_apply_documents(")


def test_codebuild_reconciles_original_and_carried_rollback_records() -> None:
    source = (release.ROOT / "tools/capstone_deploy.py").read_text()
    read = source.split("def _source(", 1)[1].split("def _record(", 1)[0]
    assert "prior_files, prior_records" in read
    assert "control_files[name] != contents" in read
    assert "ROLLBACK_CONTROL_LINEAGE_SUBSTITUTION" in read


def test_ready_binds_exact_source_s3_version_and_digests() -> None:
    source = (release.ROOT / "tools/capstone_release.py").read_text()
    ready = source.split("def workflow_prepare_ready(", 1)[1].split(
        "def workflow_cleanup_ready(", 1
    )[0]
    assert "_s3_read_exact(source_client, bucket, SOURCE_KEY, version, archive_sha)" in ready
    assert "validate_primary_source_bundle(" in ready
    assert '"s3_version_id": version' in ready


def test_start_build_uses_exact_primary_and_secondary_versions() -> None:
    source = (release.ROOT / "tools/capstone_release.py").read_text()
    start = source.split("def workflow_codebuild(", 1)[1].split("def workflow_verify(", 1)[0]
    assert '"sourceVersion": applied["source"]["s3_version_id"]' in start
    assert '"sourceIdentifier": "W12_CONTROL", "sourceVersion": version' in start
    assert '"W12_CONTROL_ARCHIVE_SHA256": control_sha' in start
    assert '"W12_RELEASE_KMS_KEY_ARN": kms_key' in start


def test_start_build_rejects_source_and_buildspec_overrides() -> None:
    source = (release.ROOT / "tools/capstone_release.py").read_text()
    start = source.split("def workflow_codebuild(", 1)[1].split("def workflow_verify(", 1)[0]
    request = start.split("request = {", 1)[1].split("client = boto3.client", 1)[0]
    assert '"sourceVersion"' in request
    assert '"secondarySourcesVersionOverride"' in request
    assert '"sourceTypeOverride"' not in request
    assert '"buildspecOverride"' not in request


def test_source_version_substitution_fails_closed() -> None:
    source = (release.ROOT / "tools/capstone_deploy.py").read_text()
    function = source.split("def _source(", 1)[1].split("def _record(", 1)[0]
    assert 'os.environ.get("CODEBUILD_SOURCE_VERSION") != source_version' in function
    assert '"CODEBUILD_SOURCE_VERSION_MISMATCH"' in function


def test_control_version_substitution_fails_closed() -> None:
    source = (release.ROOT / "tools/capstone_deploy.py").read_text()
    function = source.split("def _source(", 1)[1].split("def _record(", 1)[0]
    assert 'os.environ.get("CODEBUILD_SOURCE_VERSION_W12_CONTROL") != control_version' in function
    assert '"CONTROL_KMS_OR_VERSION_CHANGED"' in function


def _ambiguous_bundle_upload(key: str) -> None:
    class Pages:
        def paginate(self, **_kwargs):
            return iter(({"Versions": []},))

    class Client:
        def get_bucket_versioning(self, **_kwargs):
            return {"Status": "Enabled"}

        def get_paginator(self, _name: str):
            return Pages()

        def put_object(self, **_kwargs):
            raise TimeoutError("synthetic ambiguous response")

    with pytest.raises(ReleaseError) as error:
        release._s3_upload_exact(
            Client(),
            bucket="synthetic-bucket",
            key=key,
            raw=b"synthetic",
            kms_key="arn:aws:kms:ap-southeast-1:123456789012:key/synthetic",
            metadata={"record-id": "synthetic", "record-revision": "4"},
        )
    assert error.value.classification == "INDETERMINATE"


def test_ambiguous_source_upload_is_indeterminate() -> None:
    _ambiguous_bundle_upload(release.SOURCE_KEY)


def test_ambiguous_control_upload_is_indeterminate() -> None:
    _ambiguous_bundle_upload(release.CONTROL_KEY)


def test_verified_record_binds_control_bundle_and_build() -> None:
    import json

    verified = json.loads(verified_release_chain()[4])
    kinds = {item["kind"] for item in verified["evidence"]}
    assert {"codebuild-control-bundle", "codebuild_result"} <= kinds


def test_source_and_control_versions_are_retained_and_classified() -> None:
    source = (release.ROOT / "tools/capstone_release.py").read_text()
    proof = source.split("def validate_publication_proof(", 1)[1].split(
        "def load_prior_rollback_lineage(", 1
    )[0]
    assert 'evidence["kind"] == "source_bundle"' in proof
    assert 'evidence["kind"] == "codebuild-control-bundle"' in proof
    assert '"coverage": "R5_LOCATOR"' in proof
