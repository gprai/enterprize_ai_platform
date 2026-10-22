"""Owner-local release record, receipt, transport and dispatch behavior."""

from __future__ import annotations

import argparse
import base64
import hashlib
from copy import deepcopy

import pytest
import tools.capstone_release as release

from tests.fakes.capstone_release import (
    canonical,
    codebuild_result_fixture,
    opa_receipt,
    render_input_fixture,
    requested_record,
    sidecar,
    verified_release_chain,
)


def _pair() -> tuple[dict, bytes, dict, bytes]:
    record = requested_record()
    raw = canonical(record)
    receipt = opa_receipt(record, raw)
    return record, raw, receipt, canonical(receipt)


def test_canonical_record_round_trip_and_transport_rejections() -> None:
    record, raw, _, _ = _pair()
    encoded = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    assert release.validate_record(raw, sidecar(raw), requested=True) == record
    assert release.decode_record_b64url(encoded, hashlib.sha256(raw).hexdigest()) == raw
    for changed in (encoded + "=", encoded + " ", encoded[:-1] + "+", encoded[:-1]):
        with pytest.raises(release.ReleaseError):
            release.decode_record_b64url(changed, hashlib.sha256(raw).hexdigest())
    with pytest.raises(release.ReleaseError):
        release.decode_record_b64url(encoded, "0" * 64)


def test_record_byte_schema_and_digest_fail_closed() -> None:
    _, raw, _, _ = _pair()
    for changed in (
        raw[:-1],
        b"\xef\xbb\xbf" + raw,
        b"\xff" + raw,
        raw.replace(b'"revision":1', b'"revision":1,"revision":1'),
        raw.replace(b'"revision":1', b'"unexpected":1,"revision":1'),
        raw.replace(b'"status":"REQUESTED"', b'"status":"APPLIED"'),
        raw.replace(b'"revision":1', b'"revision": 1'),
    ):
        with pytest.raises(release.ReleaseError):
            release.validate_record(changed, sidecar(changed), requested=True)
    with pytest.raises(release.ReleaseError):
        release.validate_record(raw, b"0" * 64 + b"\n", requested=True)


def test_valid_opa_receipt_and_expiry() -> None:
    record, raw, receipt, receipt_raw = _pair()
    assert (
        release.validate_opa_receipt(
            receipt_raw,
            sidecar(receipt_raw),
            record=record,
            record_sha256=hashlib.sha256(raw).hexdigest(),
        )
        == receipt
    )
    with pytest.raises(release.ReleaseError):
        release.validate_opa_receipt(
            receipt_raw,
            b"0" * 64 + b"\n",
            record=record,
            record_sha256=hashlib.sha256(raw).hexdigest(),
        )
    expired = deepcopy(receipt)
    expired["expires_at_utc"] = expired["created_at_utc"]
    changed = canonical(expired)
    with pytest.raises(release.ReleaseError):
        release.validate_opa_receipt(
            changed, sidecar(changed), record=record, record_sha256=hashlib.sha256(raw).hexdigest()
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("record_sha256", "0" * 64),
        ("source.repository", "foreign/repository"),
        ("source.commit", "0" * 40),
        ("hcp.run_id", "run-other"),
        ("hcp.plan_id", "plan-other"),
        ("hcp.state_lineage", "other"),
        ("hcp.state_serial", 5),
        ("opa.result", "DENY"),
        ("opa.waiver_used", True),
        ("infracost.status", "FAIL"),
    ],
)
def test_opa_receipt_dispatch_binding(field: str, value: object) -> None:
    record, raw, receipt, _ = _pair()
    changed = deepcopy(receipt)
    target = changed
    names = field.split(".")
    for name in names[:-1]:
        target = target[name]
    target[names[-1]] = value
    payload = canonical(changed)
    with pytest.raises(release.ReleaseError):
        release.validate_opa_receipt(
            payload, sidecar(payload), record=record, record_sha256=hashlib.sha256(raw).hexdigest()
        )


def test_trigger_requires_opa_receipt_pair() -> None:
    parser = release._parser()
    with pytest.raises(SystemExit):
        parser.parse_args(
            [
                "trigger",
                "--record",
                "record.json",
                "--sha256-file",
                "record.sha256",
                "--commit",
                "a" * 40,
            ]
        )


def test_dispatch_payload_boundaries() -> None:
    _, raw, _, receipt_raw = _pair()
    digest = hashlib.sha256(raw).hexdigest()
    receipt_digest = hashlib.sha256(receipt_raw).hexdigest()
    assert (
        release._strict_transport(
            base64.urlsafe_b64encode(raw).decode().rstrip("="), digest, receipt=False
        )
        == raw
    )
    assert (
        release._strict_transport(
            base64.urlsafe_b64encode(receipt_raw).decode().rstrip("="), receipt_digest, receipt=True
        )
        == receipt_raw
    )
    with pytest.raises(release.ReleaseError):
        release._strict_transport("A" * 43_692, digest, receipt=False)
    with pytest.raises(release.ReleaseError):
        release._strict_transport("A" * 10_924, receipt_digest, receipt=True)


def test_ambiguous_dispatch_not_retried(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    record, raw, _, receipt_raw = _pair()
    record_path = tmp_path / "record.json"
    record_path.write_bytes(raw)
    sidecar_path = tmp_path / "record.sha256"
    sidecar_path.write_bytes(sidecar(raw))
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_bytes(receipt_raw)
    receipt_sidecar = tmp_path / "receipt.sha256"
    receipt_sidecar.write_bytes(sidecar(receipt_raw))
    monkeypatch.setenv("GH_TOKEN", "offline-synthetic")
    monkeypatch.setattr(release, "_lookup_existing", lambda *_a, **_k: None)
    monkeypatch.setattr(
        release, "validate_terraform_configuration_binding", lambda _record: "c" * 64
    )
    posts = []

    def fake_request(method, path, token, body=None):
        del path, token
        if method == "GET":
            return 200, {"object": {"sha": record["source"]["commit"]}}
        posts.append(body)
        return 204, None

    monkeypatch.setattr(release, "_github_request", fake_request)
    args = argparse.Namespace(
        record=record_path,
        sha256_file=sidecar_path,
        previous_record=None,
        opa_receipt=receipt_path,
        opa_receipt_sha256_file=receipt_sidecar,
        commit=record["source"]["commit"],
    )
    with pytest.raises(release.ReleaseError) as error:
        release._trigger(args)
    assert error.value.classification == "INDETERMINATE"
    assert len(posts) == 1
    assert list(posts[0]["inputs"]) == [
        "record_b64url",
        "record_sha256",
        "opa_receipt_b64url",
        "opa_receipt_sha256",
        "operation",
        "source_commit",
    ]


def test_lineage_manifest_binds_verified_and_parent() -> None:
    import json

    chain = verified_release_chain()
    archive = release.make_future_lineage_zip(chain)
    manifest = release.validate_future_lineage_zip(archive, raws=chain)
    assert manifest["schema_version"] == "w12-001.rollback-lineage.v1"
    assert manifest["verified_record_sha256"] == hashlib.sha256(chain[4]).hexdigest()
    assert manifest["parent_record_sha256"] == json.loads(chain[4])["previous_record_sha256"]
    assert [item["path"] for item in manifest["files"]] == sorted(
        release.FUTURE_LINEAGE_RECORD_PATHS
    )
    changed = list(chain)
    changed[3] += b" "
    with pytest.raises(release.ReleaseError):
        release.validate_future_lineage_zip(archive, raws=changed)


def test_terraform_configuration_manifest() -> None:
    import json

    commit, tree = "a" * 40, "b" * 40
    tracked = {
        "infra/environments/sandbox/main.tf": (
            b'module "network" {\n  source = "../../modules/network"\n}\n'
        ),
        "infra/environments/sandbox/.terraform.lock.hcl": b'provider "example" {}\n',
        "infra/modules/network/main.tf": b'output "id" { value = "synthetic" }\n',
    }
    raw = release.terraform_configuration_manifest(commit, tree, tracked_files=tracked)
    manifest = json.loads(raw)
    assert raw.endswith(b"\n")
    assert list(manifest) == [
        "schema_version",
        "repository",
        "commit",
        "root",
        "module_roots",
        "files",
    ]
    assert manifest["module_roots"] == ["infra/modules/network"]
    assert [item["path"] for item in manifest["files"]] == sorted(tracked)
    assert manifest["files"][0]["size"] == len(tracked[manifest["files"][0]["path"]])


def test_terraform_manifest_includes_local_module_closure() -> None:
    import json

    tracked = {
        "infra/environments/sandbox/main.tf": (
            b'module "outer" {\n  source = "../../modules/network"\n}\n'
        ),
        "infra/modules/network/main.tf": b'module "inner" {\n  source = "../iam"\n}\n',
        "infra/modules/iam/main.tf": b'output "id" { value = "synthetic" }\n',
    }
    manifest = json.loads(
        release.terraform_configuration_manifest(
            "a" * 40,
            "b" * 40,
            tracked_files=tracked,
        )
    )
    assert manifest["module_roots"] == ["infra/modules/iam", "infra/modules/network"]
    assert [item["path"] for item in manifest["files"]] == sorted(tracked)
    tracked["infra/modules/network/main.tf"] = (
        b'module "inner" {\n  source = "../../../../outside"\n}\n'
    )
    with pytest.raises(release.ReleaseError):
        release.terraform_configuration_manifest("a" * 40, "b" * 40, tracked_files=tracked)


def _source_bundle_fixture() -> tuple[bytes, str, str]:
    tracked = {
        "deploy/k8s/deployment.yaml": b"kind: Deployment\n",
        "tools/capstone_release.py": b"# synthetic committed source\n",
    }
    return release.make_primary_source_bundle(
        tracked,
        commit="a" * 40,
        tree="b" * 40,
    )


def test_source_bundle_digest_binding() -> None:
    archive, manifest_sha, w6_sha = _source_bundle_fixture()
    files = release.validate_primary_source_bundle(
        archive,
        archive_sha256=hashlib.sha256(archive).hexdigest(),
        manifest_sha256=manifest_sha,
        w6_sha256=w6_sha,
        commit="a" * 40,
        tree="b" * 40,
    )
    assert files["deploy/k8s/deployment.yaml"] == b"kind: Deployment\n"
    with pytest.raises(release.ReleaseError, match="SOURCE_ARCHIVE_DIGEST_MISMATCH"):
        release.validate_primary_source_bundle(
            archive,
            archive_sha256="0" * 64,
            manifest_sha256=manifest_sha,
            w6_sha256=w6_sha,
            commit="a" * 40,
            tree="b" * 40,
        )


def test_source_manifest_sidecar_matches_manifest_digest() -> None:
    archive, manifest_sha, _ = _source_bundle_fixture()
    files = release._zip_files(archive)
    assert files[release.BOOTSTRAP_SHA] == (manifest_sha + "\n").encode("ascii")
    assert hashlib.sha256(files[release.BOOTSTRAP_JSON]).hexdigest() == manifest_sha


def test_requested_validation_does_not_require_source_bundle() -> None:
    record = requested_record()
    assert record["source"]["archive_sha256"] is None
    assert (
        release.validate_record(canonical(record), sidecar(canonical(record)), requested=True)
        == record
    )


def test_github_approval_comment_binds_ready_digest(monkeypatch: pytest.MonkeyPatch) -> None:
    chain = verified_release_chain()
    ready = __import__("json").loads(chain[1])
    ready["gates"]["github_environment_id"] = 42
    raw = canonical(ready)
    digest = hashlib.sha256(raw).hexdigest()
    expected = (
        f"W12-001 APPROVE record={ready['record_id']} revision=2 ready_sha256={digest} run_id=7"
    )
    monkeypatch.setenv("GITHUB_RUN_ID", "7")
    monkeypatch.setenv("GITHUB_ACTOR_ID", "101")
    monkeypatch.setenv("W12_GITHUB_ENVIRONMENT_ID", "42")
    monkeypatch.setenv("W12_APPROVED_REVIEWER_IDS", "102")
    monkeypatch.setenv("W12_ALLOW_SELF_REVIEW", "false")
    monkeypatch.setattr(release, "_github_token", lambda: "synthetic")
    monkeypatch.setattr(release, "_valid_run", lambda *_args: None)

    def response(_method, path, _token, _body=None):
        if path.endswith("/approvals"):
            return 200, [
                {
                    "state": "approved",
                    "comment": expected,
                    "environments": [{"id": 42, "node_id": "env-node", "name": "sandbox"}],
                    "user": {
                        "id": 102,
                        "login": "reviewer",
                        "node_id": "user-node",
                        "type": "User",
                    },
                }
            ]
        return 200, {"run_attempt": 1}

    monkeypatch.setattr(release, "_github_request", response)
    subset = release._github_approval_subset(ready, raw)
    assert subset["comment_sha256"] == hashlib.sha256(expected.encode()).hexdigest()
    assert subset["approver_id"] == 102
    assert "comment" not in subset and "approval_event_id" not in subset


def _render_w12_fixture():
    from pathlib import Path

    from tools.w6_001_k8s import W12RenderBindings, render_w12_release

    bindings = W12RenderBindings(
        application_image="123456789012.dkr.ecr.ap-southeast-1.amazonaws.com/api@sha256:"
        + "a" * 64,
        otel_collector_image="public.ecr.aws/aws-observability/collector@sha256:" + "b" * 64,
        opensearch_https_endpoint="https://example.ap-southeast-1.es.amazonaws.com",
        bedrock_inference_profile_arn=(
            "arn:aws:bedrock:ap-southeast-1:123456789012:inference-profile/test"
        ),
        release_record_sha256="c" * 64,
        render_inputs_sha256="d" * 64,
        w6_release_hashes_sha256="e" * 64,
    )
    root = Path(__file__).resolve().parents[2] / "deploy/k8s"
    return root, bindings, render_w12_release


def test_w12_renderer_does_not_require_w6_v2_binding() -> None:
    root, bindings, render = _render_w12_fixture()
    files = render(source_root=root, bindings=bindings)
    assert "deployment.yaml" in files
    assert "release-binding.json" not in files


def test_w12_renderer_injects_release_annotations() -> None:
    import yaml

    root, bindings, render = _render_w12_fixture()
    deployment = yaml.safe_load(render(source_root=root, bindings=bindings)["deployment.yaml"])
    annotations = deployment["metadata"]["annotations"]
    assert annotations["enterprise.ai/release-record-sha256"] == "c" * 64
    assert annotations["enterprise.ai/render-inputs-sha256"] == "d" * 64
    assert annotations["enterprise.ai/w6-release-hashes-sha256"] == "e" * 64


def test_w12_renderer_injects_pod_template_annotations() -> None:
    import yaml

    root, bindings, render = _render_w12_fixture()
    deployment = yaml.safe_load(render(source_root=root, bindings=bindings)["deployment.yaml"])
    annotations = deployment["spec"]["template"]["metadata"]["annotations"]
    assert annotations["enterprise.ai/release-record-sha256"] == "c" * 64
    assert annotations["enterprise.ai/render-inputs-sha256"] == "d" * 64


def test_w12_renderer_output_is_deterministic() -> None:
    root, bindings, render = _render_w12_fixture()
    assert render(source_root=root, bindings=bindings) == render(
        source_root=root, bindings=bindings
    )


def test_w12_renderer_requires_application_image() -> None:
    from dataclasses import replace

    from tools.w6_001_k8s import W6001Error

    root, bindings, render = _render_w12_fixture()
    with pytest.raises(W6001Error):
        render(source_root=root, bindings=replace(bindings, application_image="latest"))


def test_w12_renderer_maps_named_images_to_fixed_placeholders() -> None:
    import yaml

    root, bindings, render = _render_w12_fixture()
    deployment = yaml.safe_load(render(source_root=root, bindings=bindings)["deployment.yaml"])
    images = {
        item["name"]: item["image"] for item in deployment["spec"]["template"]["spec"]["containers"]
    }
    assert images["api"] == bindings.application_image
    assert images["otel-collector"] == bindings.otel_collector_image


def test_w12_renderer_resolves_application_and_collector_images() -> None:
    root, bindings, render = _render_w12_fixture()
    combined = b"".join(render(source_root=root, bindings=bindings).values())
    assert bindings.application_image.encode() in combined
    assert bindings.otel_collector_image.encode() in combined
    assert b"OWNER_BINDING_REQUIRED" not in combined


def test_ready_requires_immutable_otel_image() -> None:
    ready, _, _, _ = render_input_fixture()
    assert ready["artifacts"]["otel_collector_image"].count("@sha256:") == 1
    ready["artifacts"]["otel_collector_image"] = "mutable:latest"
    from tools.capstone_release import validate_render_inputs

    _, approved, applied, raw = render_input_fixture()
    with pytest.raises(release.ReleaseError):
        validate_render_inputs(
            raw,
            sidecar(raw),
            ready=ready,
            ready_sha256=hashlib.sha256(canonical(ready)).hexdigest(),
            approved=approved,
            approved_sha256=hashlib.sha256(canonical(approved)).hexdigest(),
            applied=applied,
        )


def test_render_inputs_bind_release_and_applied_state() -> None:
    ready, approved, applied, raw = render_input_fixture()
    document = release.validate_render_inputs(
        raw,
        sidecar(raw),
        ready=ready,
        ready_sha256=hashlib.sha256(canonical(ready)).hexdigest(),
        approved=approved,
        approved_sha256=hashlib.sha256(canonical(approved)).hexdigest(),
        applied=applied,
    )
    assert document["applied_state_version_id"] == "sv-output-synthetic"
    changed = deepcopy(applied)
    changed["deployment"]["render_inputs_sha256"] = "0" * 64
    with pytest.raises(release.ReleaseError, match="APPLIED_RENDER_INPUT_MISMATCH"):
        release.validate_render_inputs(
            raw,
            sidecar(raw),
            ready=ready,
            ready_sha256=hashlib.sha256(canonical(ready)).hexdigest(),
            approved=approved,
            approved_sha256=hashlib.sha256(canonical(approved)).hexdigest(),
            applied=changed,
        )


def test_render_input_application_image_is_derived_from_ready() -> None:
    ready, _, _, raw = render_input_fixture()
    import json

    assert json.loads(raw)["application_image"] == release.application_image_from_ready(ready)


def test_render_input_images_derived_from_ready_roles() -> None:
    ready, _, _, raw = render_input_fixture()
    import json

    document = json.loads(raw)
    assert document["application_image"] == release.application_image_from_ready(ready)
    assert document["otel_collector_image"] == ready["artifacts"]["otel_collector_image"]
    assert document["application_image"] != document["otel_collector_image"]


def test_renderer_is_deterministic_for_bound_inputs() -> None:
    root, bindings, render = _render_w12_fixture()
    first = render(source_root=root, bindings=bindings)
    second = render(source_root=root, bindings=bindings)
    assert release._file_inventory(first) == release._file_inventory(second)


def test_release_record_uses_archive_level_evidence() -> None:
    import json

    verified = json.loads(verified_release_chain()[4])
    kinds = {item["kind"] for item in verified["evidence"]}
    assert "source_bundle" in kinds
    assert "codebuild-control-bundle" in kinds
    assert "rendered_release_archive" in kinds
    assert "source_bundle_entry" not in kinds
    assert "control_bundle_entry" not in kinds


def test_requested_rollback_digest_carriage() -> None:
    request = requested_record()
    request["operation"] = "rollback"
    prior_id = "4e116df3-a624-4f19-9ab4-8311c1a7ecf7"
    locator = release.encode_s3v_locator(
        "synthetic-bucket",
        release._release_publication_key(prior_id, "future_lineage"),
        "synthetic-version-1",
        entry="rollback/rollback-lineage-manifest.json",
    )
    request["recovery"]["previous_good_record_sha256"] = "a" * 64
    request["recovery"]["rollback_ref"] = locator
    request["evidence"] = [
        {"kind": "rollback-lineage-archive", "uri": locator, "sha256": "b" * 64},
        {"kind": "rollback-lineage-manifest", "uri": locator, "sha256": "c" * 64},
    ]
    raw = canonical(request)
    assert release.validate_record(raw, sidecar(raw), requested=True)["operation"] == "rollback"
    request["recovery"]["previous_good_record_sha256"] = None
    changed = canonical(request)
    with pytest.raises(release.ReleaseError, match="ROLLBACK_RECOVERY_IDENTITY"):
        release.validate_record(changed, sidecar(changed), requested=True)


def test_rollback_ref_binds_verified_and_parent_records() -> None:
    chain = verified_release_chain()
    members = release._zip_files(release.make_future_lineage_zip(chain))
    assert members["rollback/verified/release-record.json"] == chain[4]
    assert members["rollback/parent/release-record.json"] == chain[3]
    assert (
        hashlib.sha256(chain[3]).hexdigest()
        == __import__("json").loads(chain[4])["previous_record_sha256"]
    )


def test_deploy_rejects_rollback_lineage_inputs() -> None:
    record = requested_record()
    record["recovery"]["rollback_ref"] = "w12-s3v://synthetic/foreign"
    raw = canonical(record)
    with pytest.raises(release.ReleaseError, match="DEPLOY_ROLLBACK_LINEAGE_PROHIBITED"):
        release.validate_record(raw, sidecar(raw), requested=True)


def test_deploy_rejects_rollback_control_files() -> None:
    source = (release.ROOT / "tools/capstone_release.py").read_text()
    validator = source.split("def validate_current_control_bundle(", 1)[1].split(
        "def make_primary_source_bundle(", 1
    )[0]
    assert 'if records[4]["operation"] == "rollback":' in validator
    assert "set(files) != payload_names |" in validator


def test_trigger_idempotency_outcomes(monkeypatch: pytest.MonkeyPatch) -> None:
    record, raw, _, receipt_raw = _pair()
    digest = hashlib.sha256(raw).hexdigest()
    receipt_digest = hashlib.sha256(receipt_raw).hexdigest()
    listing = {"total_count": 0, "workflow_runs": []}

    def github_request(_method: str, path: str, _token: str, **_kwargs):
        if path.endswith("/runs?per_page=100"):
            return 200, listing
        return 200, {
            "total_count": 1,
            "artifacts": [
                {
                    "name": f"w12-001-requested-{record['record_id']}-r1",
                    "id": 9,
                    "expired": False,
                    "workflow_run": {"id": int(path.split("/")[3])},
                }
            ],
        }

    monkeypatch.setattr(release, "_github_request", github_request)
    assert release._lookup_existing(record, digest, receipt_digest, "synthetic") is None
    listing.update(total_count=1, workflow_runs=[{"id": 7, "status": "completed"}])
    files = {
        "release-record.json": raw,
        "release-record.sha256": sidecar(raw),
        "opa-receipt.json": receipt_raw,
        "opa-receipt.sha256": sidecar(receipt_raw),
    }
    monkeypatch.setattr(release, "_github_artifact_files", lambda *_args: (files, {}))
    monkeypatch.setattr(release, "_valid_run", lambda *_args: (7, "api-url", "html-url"))
    assert release._lookup_existing(record, digest, receipt_digest, "synthetic") == (
        7,
        "api-url",
        "html-url",
    )
    with pytest.raises(release.ReleaseError, match="CONFLICTING_DUPLICATE"):
        release._lookup_existing(record, "0" * 64, receipt_digest, "synthetic")
    listing.update(
        total_count=2,
        workflow_runs=[
            {"id": 7, "status": "completed"},
            {"id": 8, "status": "completed"},
        ],
    )
    with pytest.raises(release.ReleaseError, match="MULTIPLE_MATCHING_RUNS"):
        release._lookup_existing(record, digest, receipt_digest, "synthetic")


def test_w12_s3v_object_locator_round_trip() -> None:
    locator = release.encode_s3v_locator(
        "synthetic-bucket",
        "w12-001/results/result.json",
        "version+one",
    )
    assert locator.endswith("/object")
    assert release.decode_s3v_locator(locator) == {
        "bucket": "synthetic-bucket",
        "key": "w12-001/results/result.json",
        "version_id": "version+one",
        "entry": None,
    }


def test_w12_s3v_zip_entry_locator_round_trip() -> None:
    locator = release.encode_s3v_locator(
        "synthetic-bucket",
        release.SOURCE_KEY,
        "synthetic-version-1",
        entry=release.BOOTSTRAP_JSON,
    )
    assert "/entry/" in locator and "entry:" not in locator
    assert release.decode_s3v_locator(locator)["entry"] == release.BOOTSTRAP_JSON


def test_w12_s3v_locator_rejects_query_fragment_userinfo_and_padding() -> None:
    locator = release.encode_s3v_locator(
        "synthetic-bucket",
        release.SOURCE_KEY,
        "synthetic-version-1",
    )
    for malformed in (
        locator + "?versionId=other",
        locator + "#part",
        locator + "@owner",
        locator.replace("/object", "=/object"),
    ):
        with pytest.raises(release.ReleaseError):
            release.decode_s3v_locator(malformed)


def test_w12_s3v_locator_rejects_bucket_version_and_entry_mismatch() -> None:
    import json

    locator = release.encode_s3v_locator(
        "synthetic-bucket",
        release.SOURCE_KEY,
        "synthetic-version-1",
        entry=release.BOOTSTRAP_JSON,
    )
    selected = release.decode_s3v_locator(locator)
    assert selected["entry"] == release.BOOTSTRAP_JSON
    with pytest.raises(release.ReleaseError):
        release.decode_s3v_locator(locator.replace("/entry/", "/entry:guest/"))
    chain = verified_release_chain()
    for changed_uri in (
        release.encode_s3v_locator(
            "foreign-bucket",
            release.SOURCE_KEY,
            "synthetic-version-1",
            entry=release.BOOTSTRAP_JSON,
        ),
        release.encode_s3v_locator(
            "w12-evidence-example",
            release.SOURCE_KEY,
            "other-version",
            entry=release.BOOTSTRAP_JSON,
        ),
        release.encode_s3v_locator(
            "w12-evidence-example",
            release.SOURCE_KEY,
            "synthetic-version-1",
            entry=release.W6_HASHES_JSON,
        ),
    ):
        ready = json.loads(chain[1])
        ready["evidence"].append(
            {"kind": "w12_source_manifest", "uri": changed_uri, "sha256": "f" * 64}
        )
        ready["evidence"].sort(key=lambda item: (item["kind"], item["uri"]))
        raw = canonical(ready)
        with pytest.raises(release.ReleaseError):
            release.validate_record(raw, sidecar(raw), previous=chain[0])


def test_codebuild_result_schema_and_canonical_bytes() -> None:
    import json

    applied_raw = verified_release_chain()[3]
    applied = json.loads(applied_raw)
    result = codebuild_result_fixture(applied, applied_raw)
    raw = canonical(result)
    assert (
        release.validate_codebuild_result(
            raw,
            applied=applied,
            applied_sha256=hashlib.sha256(applied_raw).hexdigest(),
            build_id=result["build"]["build_id"],
            source_version=applied["source"]["s3_version_id"],
            control_version="synthetic-control-version",
            control_sha256="a" * 64,
            handoff_sha256="c" * 64,
        )
        == result
    )
    with pytest.raises(release.ReleaseError):
        release.validate_codebuild_result(
            raw.replace(b'"status":"PASS"', b'"status": "PASS"'),
            applied=applied,
            applied_sha256=hashlib.sha256(applied_raw).hexdigest(),
            build_id=result["build"]["build_id"],
            source_version=applied["source"]["s3_version_id"],
            control_version="synthetic-control-version",
            control_sha256="a" * 64,
            handoff_sha256="c" * 64,
        )
