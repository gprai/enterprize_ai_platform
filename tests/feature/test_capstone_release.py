"""W12 release behavior from owner intent to immutable deployment inputs."""

from __future__ import annotations

from copy import deepcopy

import pytest
from tools.capstone_release import ReleaseError, application_image_from_ready

from tests.fakes.capstone_release import requested_record


def test_ready_application_image_is_derived_from_repository_and_digest() -> None:
    ready = requested_record()
    ready["revision"] = 2
    ready["status"] = "READY_FOR_OWNER"
    ready["artifacts"]["container_repository"] = (
        "123456789012.dkr.ecr.ap-southeast-1.amazonaws.com/api"
    )
    ready["artifacts"]["image_digest"] = "sha256:" + "a" * 64
    expected = "123456789012.dkr.ecr.ap-southeast-1.amazonaws.com/api@sha256:" + "a" * 64
    assert application_image_from_ready(ready) == expected
    changed = deepcopy(ready)
    changed["artifacts"]["image_digest"] = "latest"
    with pytest.raises(ReleaseError):
        application_image_from_ready(changed)


def test_renderer_role_provenance_is_checked_by_deploy_adapter() -> None:
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    adapter = (root / "tools/capstone_deploy.py").read_text(encoding="utf-8")
    renderer = (root / "tools/w6_001_k8s.py").read_text(encoding="utf-8")
    assert "application_image_from_ready(ready)" in adapter
    assert 'collector = ready["artifacts"]["otel_collector_image"]' in adapter
    assert 'render["application_image"] != application' in adapter
    assert 'render["otel_collector_image"] != collector' in adapter
    assert "def render_w12_release(" in renderer
    assert "_substitute_release_templates(" in renderer


def test_w12_renderer_maps_distinct_images_to_distinct_containers() -> None:
    from pathlib import Path

    import yaml
    from tools.w6_001_k8s import W12RenderBindings, render_w12_release

    application = "123456789012.dkr.ecr.ap-southeast-1.amazonaws.com/api@sha256:" + "a" * 64
    collector = "public.ecr.aws/aws-observability/collector@sha256:" + "b" * 64
    bindings = W12RenderBindings(
        application_image=application,
        otel_collector_image=collector,
        opensearch_https_endpoint="https://example.ap-southeast-1.es.amazonaws.com",
        bedrock_inference_profile_arn="arn:aws:bedrock:ap-southeast-1:123456789012:inference-profile/test",
        release_record_sha256="c" * 64,
        render_inputs_sha256="d" * 64,
        w6_release_hashes_sha256="e" * 64,
    )
    files = render_w12_release(
        source_root=Path(__file__).resolve().parents[2] / "deploy/k8s",
        bindings=bindings,
    )
    deployment = yaml.safe_load(files["deployment.yaml"])
    containers = {
        item["name"]: item["image"] for item in deployment["spec"]["template"]["spec"]["containers"]
    }
    assert containers["api"] == application
    assert containers["otel-collector"] == collector


def test_tls_pods_without_ready_condition_do_not_count(monkeypatch: pytest.MonkeyPatch) -> None:
    import json

    import tools.capstone_deploy as deploy

    record = {
        "previous_record_sha256": "c" * 64,
        "deployment": {"render_inputs_sha256": "d" * 64},
        "artifacts": {
            "container_repository": "example.invalid/api",
            "image_digest": "sha256:" + "a" * 64,
            "otel_collector_image": "example.invalid/collector@sha256:" + "b" * 64,
        },
    }
    pods = {
        "items": [
            {
                "metadata": {
                    "annotations": {
                        "enterprise.ai/release-record-sha256": "c" * 64,
                        "enterprise.ai/render-inputs-sha256": "d" * 64,
                    }
                },
                "spec": {
                    "containers": [
                        {"name": "api", "image": "example.invalid/api@sha256:" + "a" * 64},
                        {
                            "name": "otel-collector",
                            "image": "example.invalid/collector@sha256:" + "b" * 64,
                        },
                    ]
                },
                "status": {"conditions": []},
            }
        ]
    }
    monkeypatch.setattr(
        deploy, "_kubectl", lambda *args, **_kwargs: json.dumps(pods) if args[0] == "get" else ""
    )
    with pytest.raises(ReleaseError, match="TWO_TLS_PODS_NOT_READY"):
        deploy._tls_pods_ready(record)


def test_github_approved_apply_revalidates_exact_hcp_candidate() -> None:
    from tools import capstone_release as release

    source = (release.ROOT / "tools/capstone_release.py").read_text()
    apply = source.split("def workflow_apply_wait(", 1)[1].split(
        "def workflow_cleanup_transitions(", 1
    )[0]
    post = apply.index('"POST", path, token, request_body')
    for check in (
        "_github_approval_subset(ready, ready_raw)",
        "validate_opa_receipt(",
        "_hcp_automation_identity(token)",
        "_hcp_preapply(ready, receipt, token)",
    ):
        assert apply.index(check) < post
    preapply = source.split("def _hcp_preapply(", 1)[1].split("def _hcp_relationships_match(", 1)[0]
    assert "HCP_INPUT_STATE_CHANGED" in preapply
    assert "HCP_PLAN_JSON_CHANGED" in preapply
    assert "INFRACOST_RESULT_CHANGED" in preapply


def test_approved_requires_apply_202_and_exact_run_transition() -> None:
    from tools import capstone_release as release

    source = (release.ROOT / "tools/capstone_release.py").read_text()
    apply = source.split("def workflow_apply_wait(", 1)[1].split(
        "def workflow_cleanup_transitions(", 1
    )[0]
    assert apply.index("if status != 202") < apply.index('"APPROVED"')
    assert apply.index("_hcp_relationships_match(pre, post)") < apply.index('"APPROVED"')
    assert apply.count('"POST", path, token, request_body') == 1
    assert "HCP_APPLY_POST_AMBIGUOUS" in apply


def test_ready_not_created_until_source_bundle_validation_passes() -> None:
    from tools import capstone_release as release

    source = (release.ROOT / "tools/capstone_release.py").read_text()
    ready = source.split("def workflow_prepare_ready(", 1)[1].split(
        "def workflow_cleanup_ready(", 1
    )[0]
    assert ready.index("validate_primary_source_bundle(") < ready.index(
        '_write_workflow_pair(directory, "release-record", raw)'
    )


def test_render_failure_blocks_kubernetes_mutation() -> None:
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    buildspec = (root / "deploy/codebuild/capstone-deploy.buildspec.yml").read_text()
    assert buildspec.index("tools.capstone_deploy preflight") < buildspec.index(
        "aws eks update-kubeconfig"
    )
    assert buildspec.index("tools.capstone_deploy preflight") < buildspec.index(
        "tools.capstone_deploy deploy"
    )


def test_renderer_failure_blocks_kubernetes_mutation() -> None:
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    buildspec = (root / "deploy/codebuild/capstone-deploy.buildspec.yml").read_text()
    assert buildspec.index("tools.capstone_deploy preflight") < buildspec.index(
        "tools.capstone_deploy deploy"
    )
    adapter = (root / "tools/capstone_deploy.py").read_text()
    preflight = adapter.split("def preflight(", 1)[1].split("def _bootstrap_ready(", 1)[0]
    assert "_render_bundle(" in preflight


def test_application_image_mismatch_blocks_deployment() -> None:
    from pathlib import Path

    source = (Path(__file__).resolve().parents[2] / "tools/capstone_deploy.py").read_text()
    adapter = source.split("def _render_bundle(", 1)[1].split("def _pki_ready(", 1)[0]
    assert adapter.index("IMAGE_ROLE_SUBSTITUTION") < adapter.index("render_w12_release(")
