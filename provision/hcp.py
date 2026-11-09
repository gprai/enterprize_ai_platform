"""HCP-only plan/review/apply orchestration with write-ahead mutation checkpoints."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

from tools import capstone_release as release
from tools.platformctl.policy_runner import (
    capstone_source_commit,
    normalize_plan,
    parse_production_decision,
)

from provision import iam_handoff
from provision.services import ServiceError, Services, relationship

TERMINAL = {"applied", "planned_and_finished", "errored", "canceled", "force_canceled", "discarded"}
STAGES = {
    "identity-seed": (False, False, False),
    "bootstrap-bind-seed": (False, False, False),
    "network-seed": (False, False, False),
    "bootstrap-bind-complete": (False, False, False),
    "base": (False, False, False),
    "foundation": (True, False, False),
    "pki-access": (True, False, True),
    "pki-disable": (True, False, False),
    "activation": (True, True, False),
    "release-plan": (True, True, False),
    "teardown": None,
    "bootstrap-teardown": None,
}


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
    ).encode()


def requested(
    context: dict[str, Any],
    state: dict[str, Any],
    config_id: str,
    otel_image: str,
    *,
    operation: str = "deploy",
) -> dict[str, Any]:
    cfg = release._config()
    record: dict[str, Any] = {
        "schema_version": cfg["schema_version"],
        "record_id": str(uuid.uuid4()),
        "revision": 1,
        "previous_record_sha256": None,
        "status": "REQUESTED",
        "operation": operation,
        "created_at_utc": datetime.now(UTC).strftime(release.UTC_FORMAT),
        "expires_at_utc": context["expires_at"],
    }
    for section, fields in (
        ("source", "source_fields"),
        ("artifacts", "artifact_fields"),
        ("terraform", "terraform_fields"),
        ("gates", "gate_fields"),
        ("deployment", "deployment_fields"),
        ("recovery", "recovery_fields"),
    ):
        record[section] = dict.fromkeys(cfg[fields])
    record["source"].update(repository=cfg["repository"], **context["source"])
    record["artifacts"]["otel_collector_image"] = otel_image
    record["terraform"].update(
        organization=cfg["hcp_organization"],
        project=cfg["hcp_project"],
        workspace=cfg["hcp_sandbox_workspace"],
        configuration_version_id=config_id,
        input_state_version_id=state["id"],
        state_lineage=state["lineage"],
        input_state_serial=state["serial"],
    )
    for key in record["gates"]:
        if key.endswith("status"):
            record["gates"][key] = "NOT_RUN"
    record["deployment"].update(
        account_id="526338061652", region="ap-southeast-1", environment="sandbox"
    )
    record["evidence"] = []
    raw = canonical(record)
    release.validate_record(raw, (digest(raw) + "\n").encode(), requested=True)
    release.validate_terraform_configuration_binding(record)
    return record


def save_pair(directory: Path, name: str, raw: bytes) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    pair = (directory / f"{name}.json", directory / f"{name}.sha256")
    if pair[0].exists():
        if pair[0].read_bytes() != raw or pair[1].read_text().strip() != digest(raw):
            raise ServiceError("EVIDENCE_ALREADY_EXISTS_DIFFERENT_BYTES")
        return
    release._write_new_pair(pair[0], pair[1], raw)


def wait_run(
    services: Services, run_id: str, statuses: set[str], *, seconds: int = 3600
) -> dict[str, Any]:
    deadline, previous = time.monotonic() + seconds, ""
    while time.monotonic() < deadline:
        run = services.hcp(f"/runs/{run_id}")["data"]
        status = run.get("attributes", {}).get("status")
        if status != previous:
            print(f"HCP run {run_id}: {status}", flush=True)
            previous = status
        if status in statuses:
            return cast(dict[str, Any], run)
        if status in TERMINAL:
            raise ServiceError("HCP_RUN_" + str(status).upper())
        time.sleep(10)
    raise ServiceError("HCP_WAIT_DEADLINE_RESUME_EXISTING_RUN", "INDETERMINATE")


def active_runs(services: Services, workspace: str) -> list[dict[str, Any]]:
    return [
        r
        for r in services.hcp_pages(f"/workspaces/{workspace}/runs?page[size]=100")
        if r["attributes"]["status"] not in TERMINAL
    ]


def assert_run(run: dict[str, Any], step: dict[str, Any], workspace: str) -> None:
    attrs = run.get("attributes", {})
    if (
        run.get("id") != step["run_id"]
        or relationship(run, "workspace") != workspace
        or relationship(run, "configuration-version") != step["configuration_id"]
        or attrs.get("auto-apply") is not False
        or attrs.get("plan-only") is not False
        or attrs.get("message") != step["message"]
    ):
        raise ServiceError("EXACT_HCP_RUN_BINDING_MISMATCH")
    if attrs.get("is-destroy", False) != step.get("destroy", False):
        raise ServiceError("EXACT_RUN_DESTROY_FLAG_MISMATCH")


def infracost(services: Services, workspace: str, run_id: str) -> str:
    stages = services.hcp_pages(f"/runs/{run_id}/task-stages")
    stages = [s for s in stages if s["attributes"].get("stage") == "post_plan"]
    if len(stages) != 1 or stages[0]["attributes"].get("status") != "passed":
        raise ServiceError("INFRACOST_POST_PLAN_NOT_PASSED")
    refs = stages[0].get("relationships", {}).get("task-results", {}).get("data", [])
    matches = []
    for ref in refs:
        item = services.hcp(f"/task-results/{ref['id']}")["data"]
        attrs = item["attributes"]
        if attrs.get("task-name") == "Infracost":
            if attrs.get("status") != "passed" or attrs.get("is-speculative") is not False:
                raise ServiceError("INFRACOST_RESULT_FAILED")
            release._hcp_infracost_binding(workspace, item, services.hcp_token)
            matches.append(item["id"])
    if len(matches) != 1:
        raise ServiceError("INFRACOST_RESULT_AMBIGUOUS")
    return str(matches[0])


def review(
    services: Services,
    context: dict[str, Any],
    step: dict[str, Any],
    inputs: dict[str, Any],
    run: dict[str, Any],
) -> dict[str, Any]:
    workspace = context["bindings"]["workspaces"][step["target"]]
    assert_run(run, step, workspace)
    if services.current_state(workspace) != step["input_state"]:
        raise ServiceError("INPUT_STATE_CHANGED")
    direct = relationship(run, "input-state-version")
    if direct and direct != step["input_state"]["id"]:
        raise ServiceError("INPUT_STATE_RELATIONSHIP_MISMATCH")
    # Without a direct relationship, the exclusive current run and unchanged finalized
    # state are the pre-apply binding. Never describe this as a direct HCP input-state ID.
    if not direct and run["attributes"]["status"] != "planned_and_finished":
        ws = services.hcp(f"/workspaces/{workspace}")["data"]
        if relationship(ws, "current-run") != run["id"]:
            raise ServiceError("EXCLUSIVE_CURRENT_RUN_BINDING_REQUIRED")
    plan_id = relationship(run, "plan")
    if not plan_id:
        raise ServiceError("PLAN_ID_MISSING")
    raw = release._hcp_plan_json_bytes(plan_id, services.hcp_token)
    plan = json.loads(raw)
    for key, value in stage_variables(inputs, step["stage"], context).items():
        if plan.get("variables", {}).get(key, {}).get("value") != value:
            raise ServiceError("PLAN_VARIABLE_BINDING_MISMATCH_" + key)
    changes = [
        r
        for r in plan.get("resource_changes", [])
        if r.get("mode") == "managed" and r["change"]["actions"] != ["no-op"]
    ]
    if run["attributes"][
        "status"
    ] == "planned_and_finished" and not release._hcp_plan_is_zero_change(plan):
        raise ServiceError("FINAL_RUN_NOT_ZERO_CHANGE")
    if step["stage"] == "release-plan" and changes:
        raise ServiceError("RELEASE_REQUIRES_CONVERGED_INFRASTRUCTURE")
    if step["stage"] in iam_handoff.TARGETS:
        iam_handoff.validate_seed(plan, step["stage"])
    if step["stage"] in iam_handoff.BOOTSTRAP_STAGES:
        proof = context["bindings"]["iam_handoffs"][step["stage"]]
        iam_handoff.assert_source(services, context, proof)
        iam_handoff.validate_delta(services.root, plan, proof)
        policy_sha = iam_handoff.review_policy(services.root, inputs, plan, context, step)
        task = infracost(services, workspace, run["id"])
        return {
            "plan_id": plan_id,
            "plan_sha256": digest(raw),
            "opa": "PASS",
            "infracost": "PASS",
            "infracost_result_id": task,
            "policy_sha256": policy_sha,
            "input_state_binding": "DIRECT" if direct else "EXCLUSIVE_RUN_CURRENT_STATE",
            "sandbox_source_state": proof["source_state"],
            "changes": [
                {"address": c["address"], "actions": c["change"]["actions"]} for c in changes
            ],
        }
    if step.get("destroy"):
        from provision.cleanup import validate_destroy

        validate_destroy(plan, step)
    if step["stage"] == "pki-disable":
        expected = {
            "module.eks[0].aws_eks_access_entry.capstone_pki_bootstrap[0]",
            "module.eks[0].aws_eks_access_policy_association.capstone_pki_bootstrap[0]",
        }
        if changes and (
            {c["address"] for c in changes} != expected
            or any(c["change"]["actions"] != ["delete"] for c in changes)
        ):
            raise ServiceError("PKI_DISABLE_REQUIRES_ONLY_TWO_TEMPORARY_ACCESS_DELETIONS")
    executable = Path(inputs["opa"]["path"]).resolve(strict=True)
    if digest(executable.read_bytes()) != inputs["opa"]["sha256"]:
        raise ServiceError("OPA_EXECUTABLE_DIGEST_MISMATCH")
    version = subprocess.run(  # noqa: S603 -- owner-bound executable, fixed arguments
        [str(executable), "version"], capture_output=True, timeout=30, check=False
    )
    if version.returncode or version.stdout.splitlines()[:1] != [b"Version: 1.20.0"]:
        raise ServiceError("OPA_VERSION_MISMATCH")
    policy = services.root / "policies/opa/terraform_plan.rego"
    exceptions = services.root / "policies/opa/exceptions.json"
    policy_sha, exceptions_sha = digest(policy.read_bytes()), digest(exceptions.read_bytes())
    if json.loads(exceptions.read_bytes()) != {
        "schema_version": "w5-003.policy-exceptions.v1",
        "exceptions": [],
    }:
        raise ServiceError("OPA_WAIVER_OR_OVERRIDE_PROHIBITED")
    with capstone_source_commit(context["source"]["commit"], context["source"]["tree"]):
        normalized = normalize_plan(
            plan, evaluation_time=datetime.now(UTC).strftime(release.UTC_FORMAT)
        )
    evaluation = normalized["evaluation_context"]
    if not isinstance(evaluation, dict):
        raise ServiceError("OPA_CONTEXT_INVALID")
    evaluation["operation"] = {
        "schema_version": "w12-001.plan-review.v1",
        "action": "PLAN_REVIEW",
        "profile": "FINAL_ZERO_CHANGE_EXISTING_STATE"
        if not changes
        else (
            "RECOVERY_EXISTING_STATE"
            if direct
            else "INITIAL_EMPTY_STATE"
            if step["input_state"]["id"] is None
            else "RECOVERY_EXISTING_STATE"
        ),
        "record_sha256": step["record_sha256"],
        "source_commit": context["source"]["commit"],
        "source_tree": context["source"]["tree"],
        "configuration_version_id": step["configuration_id"],
        "run_id": run["id"],
        "plan_id": plan_id,
        "plan_json_sha256": digest(raw),
        "workspace": release._config()[f"hcp_{step['target']}_workspace"],
        "input_state_version_id": step["input_state"]["id"],
    }
    if step.get("destroy") or (step["stage"] == "pki-disable" and changes):
        expiry = min(
            datetime.fromisoformat(context["expires_at"].replace("Z", "+00:00")),
            datetime.now(UTC) + timedelta(minutes=55),
        )
        evaluation["operation"] = {
            "schema_version": "w5-004.lifecycle.v2",
            "operation_id": context["run_id"],
            "action": "BOOTSTRAP-DESTROY" if step["target"] == "bootstrap" else "PLATFORM-DESTROY",
            "profile": "DESTROY",
            "state_lineage": step["input_state"]["lineage"],
            "state_serial": step["input_state"]["serial"],
            "inventory_sha256": digest(canonical(step.get("inventory", step["input_state"]))),
            "source_sha256": digest(canonical(context["source"])),
            "resource_expires_at": context["expires_at"],
            "expires_at": expiry.strftime(release.UTC_FORMAT),
            "rules": [
                {
                    "address": c["address"],
                    "resource_type": c["type"],
                    "actions": c["change"]["actions"],
                    "update_paths": [],
                    "delta_rule": "NONE",
                }
                for c in cast(list[dict[str, Any]], normalized["resource_changes"])
            ],
        }
    result = subprocess.run(  # noqa: S603 -- verified OPA executable, tracked policy; stdin only
        [
            str(executable),
            "eval",
            "--format=json",
            "--stdin-input",
            "--data",
            str(policy),
            "--data",
            str(exceptions),
            "data.enterprise_ai.terraform.plan.decision",
        ],
        input=canonical(normalized),
        capture_output=True,
        timeout=120,
        check=False,
    )
    if result.returncode or len(result.stdout) > 262144:
        raise ServiceError("OPA_EXECUTION_FAILED")
    decision = parse_production_decision(result.stdout)
    if decision["allow"] is not True or decision["findings"]:
        raise ServiceError("OPA_DENIED")
    if (policy_sha, exceptions_sha) != (
        digest(policy.read_bytes()),
        digest(exceptions.read_bytes()),
    ):
        raise ServiceError("OPA_POLICY_CHANGED")
    task = infracost(services, workspace, run["id"])
    return {
        "plan_id": plan_id,
        "plan_sha256": digest(raw),
        "opa": "PASS",
        "infracost": "PASS",
        "infracost_result_id": task,
        "policy_sha256": policy_sha,
        "exceptions_sha256": exceptions_sha,
        "input_state_binding": "DIRECT" if direct else "EXCLUSIVE_RUN_CURRENT_STATE",
        "changes": [{"address": c["address"], "actions": c["change"]["actions"]} for c in changes],
    }


def execute(
    services: Services,
    context: dict[str, Any],
    inputs: dict[str, Any],
    stage: str,
    directory: Path,
    save: Callable[[], None],
    approve: Callable[[str], None],
    *,
    new_attempt: bool = False,
    plan_only: bool = False,
    before_apply: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    steps = context["results"].setdefault("hcp", {})
    if stage not in STAGES:
        raise ServiceError("UNSUPPORTED_STAGE")
    target = (
        "bootstrap"
        if stage == "bootstrap-teardown" or stage in iam_handoff.BOOTSTRAP_STAGES
        else "sandbox"
    )
    workspace = context["bindings"]["workspaces"][target]
    if stage == "bootstrap-teardown":
        from provision.destroy_source import assert_mode

        if context.get("operation") != "bootstrap-teardown":
            raise ServiceError("SEPARATE_BOOTSTRAP_TEARDOWN_CONTEXT_REQUIRED")
        assert_mode(services.root, "bootstrap-teardown")
    step: dict[str, Any] | None = steps.get(stage)
    if step and step.get("complete"):
        return step
    if step and new_attempt:
        if not step.get("run_id") or services.hcp(f"/runs/{step['run_id']}")["data"]["attributes"][
            "status"
        ] not in {"errored", "canceled", "force_canceled", "discarded"}:
            raise ServiceError("NEW_ATTEMPT_REQUIRES_KNOWN_FAILED_TERMINAL_RUN")
        if stage in iam_handoff.BOOTSTRAP_STAGES:
            old_proof = context["bindings"]["iam_handoffs"][stage]
            iam_handoff.assert_source(services, context, old_proof)
            if active_runs(services, workspace):
                raise ServiceError("OTHER_ACTIVE_HCP_RUN_INSPECT_BEFORE_NEW_RUN")
            current = services.current_state(workspace)
            if current != old_proof["bootstrap_state"]:
                previous_state = old_proof["bootstrap_state"]
                if (
                    not current.get("lineage")
                    or current["lineage"] != previous_state.get("lineage")
                    or current["serial"] <= previous_state["serial"]
                ):
                    raise ServiceError("BOOTSTRAP_RECOVERY_STATE_LINEAGE_OR_SERIAL_CHANGED")
                state_record = services.hcp(f"/state-versions/{current['id']}")["data"]
                if relationship(state_record, "run") != step["run_id"]:
                    raise ServiceError("BOOTSTRAP_RECOVERY_STATE_NOT_FROM_FAILED_RUN")
            fresh = iam_handoff.prepare(services, context, inputs, stage)
            if fresh["bootstrap_state"] != current or any(
                fresh[key] != old_proof[key] for key in ("source_state", "phase", "values")
            ):
                raise ServiceError("BOOTSTRAP_RECOVERY_APPROVED_BINDINGS_CHANGED")
            approve(f"REBIND FAILED BOOTSTRAP ATTEMPT {step['run_id']} {digest(canonical(fresh))}")
            iam_handoff.assert_source(services, context, fresh)
            if services.current_state(workspace) != current or active_runs(services, workspace):
                raise ServiceError("BOOTSTRAP_RECOVERY_STATE_CHANGED_DURING_APPROVAL")
            step["iam_handoff"] = old_proof
            context["bindings"]["iam_handoffs"][stage] = fresh
        context["results"].setdefault("recovery_history", []).append(step)
        del steps[stage]
        step = None
        save()
    if step is None:
        if active_runs(services, workspace):
            raise ServiceError("OTHER_ACTIVE_HCP_RUN_INSPECT_BEFORE_NEW_RUN")
        state = services.current_state(workspace)
        if (
            stage in iam_handoff.BOOTSTRAP_STAGES
            and state != context["bindings"]["iam_handoffs"][stage]["bootstrap_state"]
        ):
            raise ServiceError("BOOTSTRAP_HANDOFF_STATE_CHANGED")
        config_id = services.configuration(workspace, context["source"]["commit"])
        variables = stage_variables(inputs, stage, context)
        flags = STAGES[stage]
        if flags is None or stage in iam_handoff.BOOTSTRAP_STAGES:
            record = {
                "record_id": str(uuid.uuid4()),
                "operation": stage,
                "source": context["source"],
                "input_state": state,
                "configuration_id": config_id,
                "expires_at": context["expires_at"],
            }
        else:
            record = requested(context, state, config_id, inputs["otel_collector_image"])
        raw = canonical(record)
        step = {
            "stage": stage,
            "target": target,
            "destroy": flags is None,
            "record_sha256": digest(raw),
            "record_id": record["record_id"],
            "input_state": state,
            "configuration_id": config_id,
            "variables_sha256": digest(canonical(variables)),
            "run_id": None,
            "post_attempted": False,
            "apply_attempted": False,
        }
        step["message"] = (
            f"lifecycle={context['run_id']}; stage={stage}; record_sha256={digest(raw)}"
        )
        step["directory"] = str(directory / stage / record["record_id"])
        if flags is None:
            from provision.cleanup import destroy_inventory

            step.update(destroy_inventory(services, workspace, bootstrap=target == "bootstrap"))
        if stage in iam_handoff.TARGETS:
            step["targets"] = iam_handoff.TARGETS[stage]
        save_pair(Path(step["directory"]), "release-record", raw)
        steps[stage] = step
        save()
    if not step["run_id"]:
        if step["post_attempted"]:
            candidates = [
                r
                for r in services.hcp_pages(f"/workspaces/{workspace}/runs?page[size]=100")
                if r["attributes"].get("message") == step["message"]
            ]
            if len(candidates) != 1:
                raise ServiceError(
                    "RUN_POST_UNCERTAIN_READ_ONLY_RECONCILIATION_REQUIRED", "INDETERMINATE"
                )
            step["run_id"] = candidates[0]["id"]
            assert_run(candidates[0], step, workspace)
            save()
        else:
            variables = stage_variables(inputs, stage, context)
            if digest(canonical(variables)) != step["variables_sha256"]:
                raise ServiceError("RUN_INPUTS_CHANGED")
            approve(f"CREATE HCP PLAN {stage} {step['record_sha256']}")
            if stage in iam_handoff.BOOTSTRAP_STAGES:
                iam_handoff.assert_source(
                    services, context, context["bindings"]["iam_handoffs"][stage]
                )
            if services.current_state(workspace) != step["input_state"] or active_runs(
                services, workspace
            ):
                raise ServiceError("PRE_POST_STATE_OR_RUN_CHANGED")
            step["post_attempted"] = True
            save()  # Durable before POST, including transport exceptions and process termination.
            attrs: dict[str, Any] = {
                "message": step["message"],
                "auto-apply": False,
                "plan-only": False,
                "variables": [
                    {"key": k, "value": json.dumps(v)} for k, v in sorted(variables.items())
                ],
            }
            if step["destroy"]:
                attrs.update({"is-destroy": True, "target-addrs": step["targets"]})
            elif stage in iam_handoff.TARGETS:
                attrs["target-addrs"] = step["targets"]
            response = services.hcp(
                "/runs",
                "POST",
                {
                    "data": {
                        "type": "runs",
                        "attributes": attrs,
                        "relationships": {
                            "workspace": {"data": {"type": "workspaces", "id": workspace}},
                            "configuration-version": {
                                "data": {
                                    "type": "configuration-versions",
                                    "id": step["configuration_id"],
                                }
                            },
                        },
                    }
                },
            )
            run_id = (response or {}).get("data", {}).get("id")
            if not isinstance(run_id, str) or not run_id.startswith("run-"):
                raise ServiceError("RUN_POST_OUTCOME_UNCERTAIN", "INDETERMINATE")
            step["run_id"] = run_id
            save()
    if step["apply_attempted"]:
        run = wait_run(services, step["run_id"], {"applied"})
        assert_run(run, step, workspace)
    else:
        run = wait_run(services, step["run_id"], {"post_plan_completed", "planned_and_finished"})
        result = review(services, context, step, inputs, run)
        step["review"] = result
        save_pair(Path(step["directory"]), "plan-review", canonical(result))
        save()
        print(json.dumps(result, indent=2), flush=True)
        if stage == "release-plan":
            args = argparse.Namespace(
                record=str(Path(step["directory"]) / "release-record.json"),
                sha256_file=str(Path(step["directory"]) / "release-record.sha256"),
                run_id=step["run_id"],
                opa_bin=inputs["opa"]["path"],
                receipt_output=str(Path(step["directory"]) / "opa-receipt.json"),
                receipt_sha256_file=str(Path(step["directory"]) / "opa-receipt.sha256"),
                previous_record=None,
            )
            os.environ["W12_OPA_EXECUTABLE_SHA256"] = inputs["opa"]["sha256"]
            if not Path(args.receipt_output).exists():
                release._review_plan(args)
            step["complete"] = True
            save()
            return step
        if run["attributes"]["status"] == "planned_and_finished":
            step.update(
                complete=True, final_state=services.current_state(workspace), no_changes=True
            )
            save()
            return step
        if plan_only:
            return step
        approve(f"APPLY HCP EXACT PLAN {step['run_id']} {result['plan_sha256']}")
        if stage in iam_handoff.BOOTSTRAP_STAGES:
            iam_handoff.assert_source(services, context, context["bindings"]["iam_handoffs"][stage])
            iam_handoff.authority(services, inputs, workspace)
        fresh = services.hcp(f"/runs/{step['run_id']}")["data"]
        assert_run(fresh, step, workspace)
        if (
            fresh["attributes"].get("status") != "post_plan_completed"
            or fresh["attributes"].get("actions", {}).get("is-confirmable") is not True
            or relationship(fresh, "plan") != result["plan_id"]
            or services.current_state(workspace) != step["input_state"]
            or digest(release._hcp_plan_json_bytes(result["plan_id"], services.hcp_token))
            != result["plan_sha256"]
        ):
            raise ServiceError("PRE_APPLY_BINDING_CHANGED")
        step["owner_approval"] = {
            "plan_sha256": result["plan_sha256"],
            "at": datetime.now(UTC).strftime(release.UTC_FORMAT),
        }
        if before_apply is not None:
            before_apply(step)
        # Cleanup can take time. Recheck state, expiry (via callback), and exact run after it.
        if services.current_state(workspace) != step["input_state"]:
            raise ServiceError("STATE_CHANGED_DURING_PRE_APPLY_CLEANUP")
        if datetime.now(UTC) >= datetime.fromisoformat(
            context["expires_at"].replace("Z", "+00:00")
        ):
            raise ServiceError("OWNER_APPROVAL_WINDOW_EXPIRED")
        final_run = services.hcp(f"/runs/{step['run_id']}")["data"]
        assert_run(final_run, step, workspace)
        if (
            final_run["attributes"].get("status") != "post_plan_completed"
            or final_run["attributes"].get("actions", {}).get("is-confirmable") is not True
            or relationship(final_run, "plan") != result["plan_id"]
        ):
            raise ServiceError("RUN_CHANGED_DURING_PRE_APPLY_CLEANUP")
        if stage in iam_handoff.BOOTSTRAP_STAGES:
            iam_handoff.assert_source(services, context, context["bindings"]["iam_handoffs"][stage])
        step["apply_attempted"] = True
        save()
        services.hcp(
            f"/runs/{step['run_id']}/actions/apply",
            "POST",
            {"comment": "Owner exact-plan approval"},
        )
        run = wait_run(services, step["run_id"], {"applied"})
        assert_run(run, step, workspace)
    state = services.current_state(workspace)
    item = services.hcp(f"/state-versions/{state['id']}")["data"]
    if (
        relationship(item, "run") != step["run_id"]
        or (
            step["input_state"]["serial"] is not None
            and state["serial"] <= step["input_state"]["serial"]
        )
        or (
            step["input_state"]["lineage"] is not None
            and state["lineage"] != step["input_state"]["lineage"]
        )
    ):
        raise ServiceError("FINAL_STATE_RUN_IDENTITY_MISMATCH")
    step.update(complete=True, final_state=state)
    save_pair(Path(step["directory"]), "apply-proof", canonical(step))
    save()
    return step


def stage_variables(
    inputs: dict[str, Any], stage: str, context: dict[str, Any] | None = None
) -> dict[str, Any]:
    if stage in iam_handoff.BOOTSTRAP_STAGES:
        if context is None:
            raise ServiceError("IAM_HANDOFF_CONTEXT_REQUIRED")
        variables = dict(inputs["stages"][stage].get("variables", {}))
        # Do not inherit sandbox variables or overwrite an owner-declared conflicting binding.
        for key, value in iam_handoff.variables(context, stage).items():
            if key in variables and variables[key] != value:
                raise ServiceError("IAM_HANDOFF_OVERRIDE_CONFLICT_" + key)
            variables[key] = value
        tags = dict(variables.get("mandatory_tags", {}))
        if (
            not tags
            or tags.get("ExpiresAt")
            != context["bindings"]["iam_handoffs"][stage]["values"]["workload_expires_at"]
        ):
            raise ServiceError("BOOTSTRAP_COMPLETE_TAG_MAP_AND_EXPIRY_REQUIRED")
        return variables
    variables = dict(inputs.get("common_variables", {}))
    variables.update(inputs["stages"][stage].get("variables", {}))
    if stage in iam_handoff.TARGETS or stage == "base":
        approved_expiry = inputs.get("iam_handoff", {}).get("workload_expires_at")
        if (
            approved_expiry
            and variables.get("mandatory_tags", {}).get("ExpiresAt") != approved_expiry
        ):
            raise ServiceError("SANDBOX_IAM_EXPIRY_BINDING_MISMATCH")
    if context is not None:
        for key, value in context["bindings"].get("runtime_variables", {}).items():
            if key in variables and variables[key] != value:
                raise ServiceError("APPROVED_DYNAMIC_BINDING_MISMATCH_" + key)
            variables[key] = value
    flags = STAGES[stage]
    if flags is not None:
        for key, value in zip(
            ("w6_004_enabled", "w12_capstone_enabled", "w12_pki_bootstrap_access_enabled"),
            flags,
            strict=True,
        ):
            if key in variables and variables[key] != value:
                raise ServiceError("STAGE_ACTIVATION_FLAG_MISMATCH_" + key)
            variables[key] = value
    return variables
