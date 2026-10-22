"""Secret-free canonical W12 fixtures for owner-executed offline tests."""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from typing import Any

from tools.capstone_release import (
    CONTROL_KEY,
    SOURCE_KEY,
    _config,
    _release_publication_key,
    encode_s3v_locator,
)


def canonical(value: dict[str, Any]) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()
        + b"\n"
    )


def sidecar(raw: bytes) -> bytes:
    return (hashlib.sha256(raw).hexdigest() + "\n").encode("ascii")


def codebuild_result_fixture(applied: dict[str, Any], applied_raw: bytes) -> dict[str, Any]:
    """Offline result bound to an APPLIED fixture, with no provider assertion."""
    build_id = "enterprise-ai-capstone-deploy:123e4567-e89b-42d3-a456-426614174000"
    return {
        "schema_version": "w12-001.codebuild-result.v1",
        "record_id": applied["record_id"],
        "record_revision": 4,
        "operation": applied["operation"],
        "observed_at_utc": "2026-01-01T00:00:00Z",
        "build": {
            "project_name": "enterprise-ai-capstone-deploy",
            "build_id": build_id,
            "build_arn": "arn:aws:codebuild:ap-southeast-1:123456789012:build/" + build_id,
            "build_number": 1,
        },
        "inputs": {
            "primary_source_version_id": applied["source"]["s3_version_id"],
            "control_source_version_id": "synthetic-control-version",
            "source_archive_sha256": applied["source"]["archive_sha256"],
            "control_archive_sha256": "a" * 64,
            "applied_record_sha256": hashlib.sha256(applied_raw).hexdigest(),
            "source_manifest_sha256": "b" * 64,
            "codebuild_handoff_sha256": "c" * 64,
            "image_digest": applied["artifacts"]["image_digest"],
            "hcp_run_id": applied["terraform"]["run_id"],
        },
        "deployment": {
            "namespace": "enterprise-ai-sandbox",
            "workload": "enterprise-ai-api",
            "derivative_manifest_sha256": "d" * 64,
            "rollout_status": "PASS",
        },
        "probe": {
            "job_name": "enterprise-ai-capstone-probe",
            "status": "PASS",
            "evidence_sha256": "e" * 64,
        },
        "cleanup": {"job_deleted": True, "pod_absent": True},
        "status": "PASS",
    }


def requested_record() -> dict[str, Any]:
    cfg = _config()
    now = datetime.now(UTC).replace(microsecond=0)
    source = dict.fromkeys(cfg["source_fields"])
    source.update(repository=cfg["repository"], commit="a" * 40, tree="b" * 40)
    terraform = dict.fromkeys(cfg["terraform_fields"])
    terraform.update(
        organization=cfg["hcp_organization"],
        project=cfg["hcp_project"],
        workspace=cfg["hcp_sandbox_workspace"],
        configuration_version_id="cv-123",
        run_id="run-123",
        plan_id="plan-123",
        input_state_version_id="sv-123",
        state_lineage="lineage-123",
        input_state_serial=4,
        configuration_sha256="c" * 64,
    )
    gates = dict.fromkeys(cfg["gate_fields"])
    gates.update(
        opa_status="NOT_RUN",
        run_task_status="PASS",
        run_task_result_id="task-123",
        scan_status="NOT_RUN",
        github_approval_status="NOT_RUN",
        hcp_approval_status="NOT_RUN",
    )
    deployment = dict.fromkeys(cfg["deployment_fields"])
    deployment.update(region=cfg["aws_region"], environment=cfg["deployment_environment"])
    return {
        "schema_version": cfg["schema_version"],
        "record_id": "123e4567-e89b-42d3-a456-426614174000",
        "revision": 1,
        "previous_record_sha256": None,
        "status": "REQUESTED",
        "operation": "deploy",
        "created_at_utc": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at_utc": (now + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": source,
        "artifacts": dict.fromkeys(cfg["artifact_fields"]),
        "terraform": terraform,
        "gates": gates,
        "deployment": deployment,
        "recovery": dict.fromkeys(cfg["recovery_fields"]),
        "evidence": [],
    }


def opa_receipt(record: dict[str, Any], record_raw: bytes) -> dict[str, Any]:
    cfg = _config()
    now = datetime.now(UTC).replace(microsecond=0)
    tf = record["terraform"]
    hcp = {
        "organization": tf["organization"],
        "project": tf["project"],
        "workspace": tf["workspace"],
        "configuration_version_id": tf["configuration_version_id"],
        "run_id": tf["run_id"],
        "plan_id": tf["plan_id"],
        "input_state_version_id": tf["input_state_version_id"],
        "state_lineage": tf["state_lineage"],
        "state_serial": tf["input_state_serial"],
        "plan_json_sha256": "d" * 64,
    }
    return {
        "schema_version": cfg["opa_receipt_schema_version"],
        "receipt_id": "123e4567-e89b-42d3-a456-426614174001",
        "revision": 1,
        "created_at_utc": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at_utc": (now + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "record_sha256": hashlib.sha256(record_raw).hexdigest(),
        "source": {
            "repository": cfg["repository"],
            "commit": record["source"]["commit"],
            "operation": record["operation"],
        },
        "hcp": hcp,
        "opa": {
            "executable_version": "1.20.0",
            "executable_sha256": "e" * 64,
            "package": "enterprise_ai.terraform.plan",
            "decision_entrypoint": "data.enterprise_ai.terraform.plan.decision",
            "policy_sha256": "f" * 64,
            "exceptions_sha256": "1" * 64,
            "result": "PASS",
            "violation_count": 0,
            "waiver_used": False,
            "override_used": False,
        },
        "infracost": {
            "result_id": record["gates"]["run_task_result_id"],
            "status": "PASS",
            "waiver_used": False,
            "override_used": False,
        },
        "evidence": {
            "normalized_plan_sha256": "2" * 64,
            "opa_output_sha256": "3" * 64,
            "infracost_result_sha256": "4" * 64,
        },
        "decision": "PASS",
    }


def verified_release_chain() -> list[bytes]:
    """Complete synthetic r1-r5 chain for offline lineage and retention tests."""
    first = requested_record()
    raws = [canonical(first)]
    prior = first
    bucket = "w12-evidence-example"
    version = "synthetic-version-1"
    for revision, status in enumerate(
        ("READY_FOR_OWNER", "APPROVED", "APPLIED", "VERIFIED"), start=2
    ):
        current = deepcopy(prior)
        current["revision"] = revision
        current["status"] = status
        current["previous_record_sha256"] = hashlib.sha256(raws[-1]).hexdigest()
        if revision == 2:
            current["source"].update(
                {
                    "archive_sha256": "a" * 64,
                    "s3_bucket": bucket,
                    "s3_key": SOURCE_KEY,
                    "s3_version_id": version,
                }
            )
            current["artifacts"].update(
                {
                    "container_repository": (
                        "123456789012.dkr.ecr.ap-southeast-1.amazonaws.com/enterprise-ai/api"
                    ),
                    "image_digest": "sha256:" + "b" * 64,
                    "otel_collector_image": (
                        "123456789012.dkr.ecr.ap-southeast-1.amazonaws.com/"
                        "enterprise-ai/collector@sha256:" + "c" * 64
                    ),
                    "sbom_sha256": "d" * 64,
                    "provenance_sha256": "e" * 64,
                    "signature_ref": "urn:synthetic-signature:1",
                }
            )
            current["gates"].update(
                {
                    "opa_status": "PASS",
                    "opa_evidence_sha256": "f" * 64,
                    "run_task_status": "PASS",
                    "scan_status": "PASS",
                }
            )
            current["deployment"].update(
                {
                    "account_id": "123456789012",
                    "render_contract": "w12-001.render.v1",
                    "w6_release_hashes_sha256": "1" * 64,
                    "root_fingerprint_sha256": "2" * 64,
                    "trust_bundle_sha256": "3" * 64,
                }
            )
        if revision == 4:
            current["deployment"]["render_inputs_sha256"] = "4" * 64
        if revision == 5:
            current["deployment"]["derivative_manifest_sha256"] = "5" * 64
            evidence = [
                {
                    "kind": "source_bundle",
                    "uri": encode_s3v_locator(bucket, SOURCE_KEY, version),
                    "sha256": "a" * 64,
                },
                {
                    "kind": "codebuild-control-bundle",
                    "uri": encode_s3v_locator(
                        bucket, CONTROL_KEY, version, entry="codebuild-handoff.json"
                    ),
                    "sha256": "6" * 64,
                },
                {
                    "kind": "codebuild_result",
                    "uri": encode_s3v_locator(
                        bucket,
                        f"w12-001/results/{first['record_id']}/r4/123e4567-e89b-42d3-a456-426614174002/codebuild-result.json",
                        version,
                    ),
                    "sha256": "7" * 64,
                },
                {
                    "kind": "rendered_release_archive",
                    "uri": encode_s3v_locator(
                        bucket,
                        f"w12-001/results/{first['record_id']}/r4/123e4567-e89b-42d3-a456-426614174002/w12-rendered-release.zip",
                        version,
                    ),
                    "sha256": "8" * 64,
                },
            ]
            for kind, digest in (
                ("verified_transition", "9" * 64),
                ("verified_transition_sidecar", "0" * 64),
                ("opa_receipt", "a" * 64),
                ("opa_receipt_sidecar", "b" * 64),
            ):
                evidence.append(
                    {
                        "kind": kind,
                        "uri": encode_s3v_locator(
                            bucket, _release_publication_key(first["record_id"], kind), version
                        ),
                        "sha256": digest,
                    }
                )
            current["evidence"] = sorted(evidence, key=lambda item: (item["kind"], item["uri"]))
        raws.append(canonical(current))
        prior = current
    return raws


def render_input_fixture() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], bytes]:
    """Synthetic READY/APPROVED/APPLIED identities and canonical W12 render input."""
    from tools.capstone_release import application_image_from_ready

    chain = verified_release_chain()
    ready, approved, applied = (json.loads(chain[index]) for index in (1, 2, 3))
    now = datetime.now(UTC).replace(microsecond=0)
    document = {
        "schema_version": "w12-001.render-inputs.v1",
        "ready_record_sha256": hashlib.sha256(chain[1]).hexdigest(),
        "approved_record_sha256": hashlib.sha256(chain[2]).hexdigest(),
        "source_archive_sha256": ready["source"]["archive_sha256"],
        "w6_release_hashes_sha256": ready["deployment"]["w6_release_hashes_sha256"],
        "hcp_organization": ready["terraform"]["organization"],
        "hcp_workspace": ready["terraform"]["workspace"],
        "hcp_run_id": ready["terraform"]["run_id"],
        "hcp_plan_id": ready["terraform"]["plan_id"],
        "applied_state_version_id": "sv-output-synthetic",
        "state_lineage": ready["terraform"]["state_lineage"],
        "state_serial": 5,
        "aws_account_id": ready["deployment"]["account_id"],
        "aws_region": ready["deployment"]["region"],
        "environment": ready["deployment"]["environment"],
        "application_image": application_image_from_ready(ready),
        "otel_collector_image": ready["artifacts"]["otel_collector_image"],
        "opensearch_domain_arn": ("arn:aws:es:ap-southeast-1:123456789012:domain/synthetic"),
        "opensearch_https_endpoint": "https://synthetic.ap-southeast-1.es.amazonaws.com",
        "bedrock_inference_profile_arn": (
            "arn:aws:bedrock:ap-southeast-1:123456789012:inference-profile/synthetic"
        ),
        "release_binding_sha256": hashlib.sha256(chain[2]).hexdigest(),
        "created_at_utc": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at_utc": (now + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    raw = canonical(document)
    applied["deployment"]["render_inputs_sha256"] = hashlib.sha256(raw).hexdigest()
    return ready, approved, applied, raw
