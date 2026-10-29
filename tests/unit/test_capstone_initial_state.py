"""Initial HCP state and post-plan binding stay explicit and fail closed."""

from __future__ import annotations

import hashlib
import sys
from argparse import Namespace
from copy import deepcopy
from typing import Any

import pytest
from tools import capstone_release as release

from tests.fakes.capstone_release import canonical, opa_receipt, requested_record, sidecar


def _initial_requested() -> dict[str, Any]:
    record = requested_record()
    for key in (
        "configuration_version_id",
        "run_id",
        "plan_id",
        "input_state_version_id",
        "state_lineage",
        "input_state_serial",
        "configuration_sha256",
    ):
        record["terraform"][key] = None
    record["gates"]["run_task_result_id"] = None
    return record


def _observed_receipt(record: dict[str, Any]) -> dict[str, Any]:
    receipt = opa_receipt(record, canonical(record))
    receipt["hcp"].update(
        configuration_version_id="cv-observed",
        run_id="run-observed",
        plan_id="plan-observed",
    )
    receipt["infracost"]["result_id"] = "taskrs-observed"
    return receipt


def test_initial_requested_record_and_bound_receipt() -> None:
    record = _initial_requested()
    raw = canonical(record)
    assert release.validate_record(raw, sidecar(raw), requested=True) == record
    receipt = _observed_receipt(record)
    receipt_raw = canonical(receipt)
    assert (
        release.validate_opa_receipt(
            receipt_raw,
            sidecar(receipt_raw),
            record=record,
            record_sha256=hashlib.sha256(raw).hexdigest(),
        )
        == receipt
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("input_state_version_id", "sv-unexpected"),
        ("state_lineage", "unexpected-lineage"),
        ("input_state_serial", 0),
    ],
)
def test_partial_initial_state_fails_closed(field: str, value: object) -> None:
    record = _initial_requested()
    record["terraform"][field] = value
    raw = canonical(record)
    with pytest.raises(release.ReleaseError):
        release.validate_record(raw, sidecar(raw), requested=True)


def test_receipt_rejects_conflicting_post_plan_identity() -> None:
    record = _initial_requested()
    record["terraform"]["run_id"] = "run-approved"
    receipt = _observed_receipt(record)
    raw = canonical(record)
    receipt_raw = canonical(receipt)
    with pytest.raises(release.ReleaseError):
        release.validate_opa_receipt(
            receipt_raw,
            sidecar(receipt_raw),
            record=record,
            record_sha256=hashlib.sha256(raw).hexdigest(),
        )


def test_receipt_cannot_substitute_existing_state_for_empty_request() -> None:
    record = _initial_requested()
    receipt = _observed_receipt(record)
    receipt["hcp"].update(
        input_state_version_id="sv-unexpected",
        state_lineage="lineage-unexpected",
        state_serial=1,
    )
    raw = canonical(record)
    receipt_raw = canonical(receipt)
    with pytest.raises(release.ReleaseError):
        release.validate_opa_receipt(
            receipt_raw,
            sidecar(receipt_raw),
            record=record,
            record_sha256=hashlib.sha256(raw).hexdigest(),
        )


def test_review_plan_source_selects_recovery_profile_for_existing_state() -> None:
    source = release._review_plan.__code__
    assert "RECOVERY_EXISTING_STATE" in source.co_consts
    assert "OPA_NONINITIAL_PLAN_PROFILE_NOT_APPROVED" not in source.co_consts


def test_ready_receives_verified_plan_binding(monkeypatch: pytest.MonkeyPatch) -> None:
    requested = _initial_requested()
    ready = deepcopy(requested)
    receipt = _observed_receipt(requested)
    monkeypatch.setattr(release, "validate_terraform_configuration_binding", lambda _: "a" * 64)
    release._bind_observed_plan_to_ready(requested, ready, receipt)
    assert ready["terraform"]["configuration_version_id"] == "cv-observed"
    assert ready["terraform"]["run_id"] == "run-observed"
    assert ready["terraform"]["plan_id"] == "plan-observed"
    assert ready["terraform"]["configuration_sha256"] == "a" * 64
    assert all(
        ready["terraform"][key] is None
        for key in ("input_state_version_id", "state_lineage", "input_state_serial")
    )


@pytest.mark.parametrize(
    "state_versions,current_state,allowed",
    [([], None, True), ([{"id": "sv-1"}], None, False), ([], {"id": "sv-1"}, False)],
)
def test_initial_state_uses_metadata_only(
    monkeypatch: pytest.MonkeyPatch,
    state_versions: list[dict[str, Any]],
    current_state: dict[str, Any] | None,
    allowed: bool,
) -> None:
    paths: list[str] = []

    def fake_request(method: str, path: str, token: str) -> tuple[int, dict[str, Any]]:
        assert method == "GET"
        assert token == "test-token"
        paths.append(path)
        if path.startswith("/state-versions?"):
            return 200, {"data": state_versions}
        assert path == "/workspaces/ws-test"
        return 200, {
            "data": {
                "id": "ws-test",
                "relationships": {"current-state-version": {"data": current_state}},
            }
        }

    monkeypatch.setattr(release, "_hcp_request", fake_request)
    if allowed:
        release._hcp_initial_state_empty(_initial_requested(), "ws-test", "test-token")
    else:
        with pytest.raises(release.ReleaseError):
            release._hcp_initial_state_empty(_initial_requested(), "ws-test", "test-token")
    assert all("/state-versions/None" not in path for path in paths)


def test_missing_input_state_relationship_matches_explicit_null() -> None:
    left = {"relationships": {"input-state-version": {"data": None}}}
    right: dict[str, Any] = {"relationships": {}}
    assert release._hcp_relationships_match(left, right)


@pytest.mark.parametrize("state_relationship", [None, {"data": None}])
def test_hcp_run_uses_supported_includes_for_empty_initial_state(
    monkeypatch: pytest.MonkeyPatch,
    state_relationship: dict[str, None] | None,
) -> None:
    record = _initial_requested()
    relationships: dict[str, Any] = {
        "workspace": {"data": {"id": "ws-approved"}},
        "configuration-version": {"data": {"id": "cv-observed"}},
        "plan": {"data": {"id": "plan-observed"}},
    }
    if state_relationship is not None:
        relationships["input-state-version"] = state_relationship

    def fake_request(method: str, path: str, token: str) -> tuple[int, dict[str, Any]]:
        assert (method, path, token) == (
            "GET",
            "/runs/run-observed?include=plan,configuration_version",
            "test-token",
        )
        return 200, {
            "data": {
                "id": "run-observed",
                "attributes": {"plan-only": False, "save-plan": False},
                "relationships": relationships,
            }
        }

    monkeypatch.setattr(release, "_hcp_request", fake_request)
    run = release._hcp_run(record, "run-observed", "test-token")
    assert run["relationships"].get("input-state-version", {}).get("data") is None


@pytest.mark.parametrize(
    "attributes,accepted",
    [
        ({"plan-only": False, "save-plan": False}, True),
        ({"plan-only": False, "save-plan": False, "is-speculative": False}, True),
        ({"plan-only": True, "save-plan": False}, False),
        ({"plan-only": False, "save-plan": True}, False),
        ({"plan-only": False, "save-plan": False, "is-speculative": True}, False),
        ({"plan-only": False, "save-plan": False, "is-speculative": None}, False),
        ({"save-plan": False}, False),
        ({"plan-only": False}, False),
    ],
)
def test_hcp_run_mode_uses_documented_fields_and_rejects_speculation(
    monkeypatch: pytest.MonkeyPatch,
    attributes: dict[str, Any],
    accepted: bool,
) -> None:
    def fake_request(method: str, path: str, token: str) -> tuple[int, dict[str, Any]]:
        assert (method, path, token) == (
            "GET",
            "/runs/run-observed?include=plan,configuration_version",
            "test-token",
        )
        return 200, {
            "data": {
                "id": "run-observed",
                "attributes": attributes,
                "relationships": {"workspace": {"data": {"id": "ws-approved"}}},
            }
        }

    monkeypatch.setattr(release, "_hcp_request", fake_request)
    if accepted:
        release._hcp_run(_initial_requested(), "run-observed", "test-token")
    else:
        with pytest.raises(release.ReleaseError, match="HCP_SPECULATIVE_RUN"):
            release._hcp_run(_initial_requested(), "run-observed", "test-token")


@pytest.mark.parametrize(
    "status,queued,started,allow_unreachable,accepted",
    [
        ("pending", None, None, False, True),
        ("unreachable", None, None, False, False),
        ("unreachable", None, None, True, True),
        ("unreachable", "2026-01-01T00:00:00Z", None, True, False),
        ("finished", None, None, True, False),
        ("queued", "2026-01-01T00:00:00Z", None, False, False),
        ("pending", None, "2026-01-01T00:00:00Z", False, False),
    ],
)
def test_only_unstarted_apply_is_accepted(
    monkeypatch: pytest.MonkeyPatch,
    status: str,
    queued: str | None,
    started: str | None,
    allow_unreachable: bool,
    accepted: bool,
) -> None:
    run = {"relationships": {"apply": {"data": {"id": "apply-test"}}}}

    def fake_request(method: str, path: str, token: str) -> tuple[int, dict[str, Any]]:
        assert (method, path, token) == ("GET", "/applies/apply-test", "test-token")
        return 200, {
            "data": {
                "id": "apply-test",
                "attributes": {
                    "status": status,
                    "status-timestamps": {"queued-at": queued, "started-at": started},
                },
            }
        }

    monkeypatch.setattr(release, "_hcp_request", fake_request)
    if accepted:
        release._hcp_apply_not_started(run, "test-token", allow_unreachable=allow_unreachable)
    else:
        with pytest.raises(release.ReleaseError):
            release._hcp_apply_not_started(run, "test-token", allow_unreachable=allow_unreachable)


def test_infracost_result_must_match_workspace_task(monkeypatch: pytest.MonkeyPatch) -> None:
    result = {
        "attributes": {
            "task-name": "Infracost",
            "task-id": "task-approved",
            "workspace-task-id": "wstask-approved",
        }
    }
    binding: dict[str, Any] = {
        "id": "wstask-approved",
        "attributes": {"stages": ["post_plan"]},
        "relationships": {
            "task": {"data": {"id": "task-approved"}},
            "workspace": {"data": {"id": "ws-approved"}},
        },
    }

    def fake_request(method: str, path: str, token: str) -> tuple[int, dict[str, Any]]:
        assert (method, path, token) == ("GET", "/workspaces/ws-approved/tasks", "test-token")
        return 200, {"data": [binding], "links": {"next": None}}

    monkeypatch.setattr(release, "_hcp_request", fake_request)
    release._hcp_infracost_binding("ws-approved", result, "test-token")
    binding["relationships"]["task"]["data"]["id"] = "task-other"
    with pytest.raises(release.ReleaseError):
        release._hcp_infracost_binding("ws-approved", result, "test-token")


@pytest.mark.parametrize(
    ("run_status", "include_pending_apply", "existing_state_without_relationship"),
    [
        ("post_plan_completed", True, False),
        ("planned_and_finished", False, False),
        ("planned_and_finished", False, True),
    ],
)
def test_review_binds_run_plan_state_and_task_before_opa(
    monkeypatch: pytest.MonkeyPatch,
    run_status: str,
    include_pending_apply: bool,
    existing_state_without_relationship: bool,
) -> None:
    record = requested_record() if existing_state_without_relationship else _initial_requested()
    if existing_state_without_relationship:
        for key in (
            "configuration_version_id",
            "run_id",
            "plan_id",
            "configuration_sha256",
        ):
            record["terraform"][key] = None
        record["gates"]["run_task_result_id"] = None
    run: dict[str, Any] = {
        "id": "run-observed",
        "attributes": {"status": run_status, "auto-apply": False},
        "relationships": {
            "workspace": {"data": {"id": "ws-approved"}},
            "configuration-version": {"data": {"id": "cv-observed"}},
            "plan": {"data": {"id": "plan-observed"}},
        },
    }
    if not existing_state_without_relationship:
        run["relationships"]["input-state-version"] = {"data": None}
    if include_pending_apply:
        run["relationships"]["apply"] = {"data": {"id": "apply-pending"}}
    queried: list[str] = []

    def fake_request(method: str, path: str, token: str) -> tuple[int, dict[str, Any]]:
        assert (method, token) == ("GET", "test-token")
        queried.append(path)
        if path == "/applies/apply-pending":
            return 200, {
                "data": {
                    "id": "apply-pending",
                    "attributes": {
                        "status": "pending",
                        "status-timestamps": {"queued-at": None, "started-at": None},
                    },
                }
            }
        if path.startswith("/state-versions?"):
            return 200, {"data": []}
        if path == "/workspaces/ws-approved":
            return 200, {
                "data": {
                    "id": "ws-approved",
                    "relationships": {
                        "current-state-version": {"data": None},
                    },
                }
            }
        if path == "/workspaces/ws-approved/current-state-version":
            return 200, {
                "data": {
                    "id": "sv-123",
                    "attributes": {
                        "status": "finalized",
                        "lineage": "lineage-123",
                        "serial": 4,
                    },
                }
            }
        if path == "/plans/plan-observed":
            return 200, {"data": {"id": "plan-observed", "attributes": {"status": "finished"}}}
        if path == "/runs/run-observed/task-stages":
            return 200, {
                "data": [
                    {
                        "id": "ts-observed",
                        "attributes": {
                            "stage": "post_plan",
                            "status": "passed",
                        },
                        "relationships": {"task-results": {"data": [{"id": "taskrs-observed"}]}},
                    }
                ]
            }
        if path == "/task-results/taskrs-observed":
            return 200, {
                "data": {
                    "id": "taskrs-observed",
                    "attributes": {
                        "status": "passed",
                        "task-name": "Infracost",
                        "stage": "post_plan",
                        "is-speculative": False,
                        "task-id": "task-approved",
                        "workspace-task-id": "wstask-approved",
                    },
                    "relationships": {"task-stage": {"data": {"id": "ts-observed"}}},
                }
            }
        if path == "/workspaces/ws-approved/tasks":
            return 200, {
                "data": [
                    {
                        "id": "wstask-approved",
                        "attributes": {
                            "stages": ["post_plan"],
                        },
                        "relationships": {
                            "task": {"data": {"id": "task-approved"}},
                            "workspace": {"data": {"id": "ws-approved"}},
                        },
                    }
                ],
                "links": {"next": None},
            }
        raise AssertionError(path)

    monkeypatch.setattr(
        release, "_read_record", lambda *_args, **_kwargs: (b"record", record, "a" * 64)
    )
    monkeypatch.setattr(release, "validate_terraform_configuration_binding", lambda _: "b" * 64)
    monkeypatch.setattr(release, "_hcp_token", lambda: "test-token")
    monkeypatch.setattr(release, "_hcp_run", lambda *_args: run)
    monkeypatch.setattr(release, "_hcp_vcs_binding", lambda *_args: None)
    monkeypatch.setattr(release, "_hcp_request", fake_request)
    monkeypatch.setattr(release, "_hcp_plan_json_bytes", lambda *_args: b'{"resource_changes":[]}')
    monkeypatch.delenv("W12_OPA_EXECUTABLE_SHA256", raising=False)

    with pytest.raises(release.ReleaseError) as failure:
        release._review_plan(Namespace(run_id="run-observed", opa_bin=sys.executable))
    assert failure.value.code == "OPA_EXECUTABLE_IDENTITY_REQUIRED"
    assert ("/applies/apply-pending" in queried) is include_pending_apply
    assert (
        "/workspaces/ws-approved/current-state-version" in queried
    ) is existing_state_without_relationship
    assert "/task-results/taskrs-observed" in queried
    assert all("/state-versions/None" not in path for path in queried)


@pytest.mark.parametrize(
    ("current_id", "current_status", "lineage", "serial", "error_code"),
    [
        ("sv-other", "finalized", "lineage-123", 4, "HCP_FINAL_CURRENT_STATE_MISMATCH"),
        ("sv-123", "pending", "lineage-123", 4, "HCP_FINAL_CURRENT_STATE_MISMATCH"),
        ("sv-123", "finalized", "lineage-other", 4, "HCP_FINAL_STATE_IDENTITY_MISMATCH"),
        ("sv-123", "finalized", "lineage-123", 5, "HCP_FINAL_STATE_IDENTITY_MISMATCH"),
    ],
)
def test_final_zero_change_state_fallback_requires_exact_current_identity(
    monkeypatch: pytest.MonkeyPatch,
    current_id: str,
    current_status: str,
    lineage: str,
    serial: int,
    error_code: str,
) -> None:
    def fake_request(method: str, path: str, token: str) -> tuple[int, dict[str, Any]]:
        assert (method, path, token) == (
            "GET",
            "/workspaces/ws-approved/current-state-version",
            "test-token",
        )
        return 200, {
            "data": {
                "id": current_id,
                "attributes": {
                    "status": current_status,
                    "lineage": lineage,
                    "serial": serial,
                },
            }
        }

    monkeypatch.setattr(release, "_hcp_request", fake_request)
    with pytest.raises(release.ReleaseError) as failure:
        release._hcp_final_zero_change_state_identity(
            requested_record(), "ws-approved", {"resource_changes": []}, "test-token"
        )
    assert failure.value.code == error_code


def test_final_state_fallback_rejects_change_bearing_plan_without_hcp_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        release,
        "_hcp_request",
        lambda *_args: pytest.fail("change-bearing fallback must not contact HCP"),
    )
    with pytest.raises(release.ReleaseError, match="HCP_FINAL_STATE_FALLBACK_UNSAFE"):
        release._hcp_final_zero_change_state_identity(
            requested_record(),
            "ws-approved",
            {
                "resource_changes": [
                    {"address": "terraform_data.example", "change": {"actions": ["update"]}}
                ]
            },
            "test-token",
        )


def _codebuild_default_drift_plan() -> dict[str, Any]:
    identity = {
        "address": "aws_codebuild_project.capstone_deploy[0]",
        "mode": "managed",
        "type": "aws_codebuild_project",
        "provider_name": "registry.terraform.io/hashicorp/aws",
        "module_address": None,
    }
    before_source = {
        "git_clone_depth": None,
        "insecure_ssl": None,
        "report_build_status": None,
        "source_identifier": "W12_CONTROL",
    }
    after_source = {
        "git_clone_depth": 0,
        "insecure_ssl": False,
        "report_build_status": False,
        "source_identifier": "W12_CONTROL",
    }
    return {
        "resource_changes": [
            {**identity, "change": {"actions": ["no-op"]}},
        ],
        "resource_drift": [
            {
                **identity,
                "change": {
                    "actions": ["update"],
                    "before": {"secondary_sources": [before_source]},
                    "after": {"secondary_sources": [after_source]},
                    "after_unknown": {},
                    "before_sensitive": {},
                    "after_sensitive": {},
                    "replace_paths": [],
                },
            }
        ],
    }


def test_zero_change_plan_accepts_exact_codebuild_default_normalization() -> None:
    assert release._hcp_plan_is_zero_change(_codebuild_default_drift_plan())


@pytest.mark.parametrize(
    ("mutation",),
    [
        ("missing_planned_resource",),
        ("planned_update",),
        ("extra_drift_path",),
        ("wrong_default_transition",),
        ("unknown_changed_path",),
        ("sensitive_changed_path",),
        ("replacement",),
    ],
)
def test_zero_change_plan_rejects_near_match_codebuild_drift(mutation: str) -> None:
    plan = _codebuild_default_drift_plan()
    drift_change = plan["resource_drift"][0]["change"]
    if mutation == "missing_planned_resource":
        plan["resource_changes"] = []
    elif mutation == "planned_update":
        plan["resource_changes"][0]["change"]["actions"] = ["update"]
    elif mutation == "extra_drift_path":
        drift_change["after"]["secondary_sources"][0]["location"] = "changed"
    elif mutation == "wrong_default_transition":
        drift_change["after"]["secondary_sources"][0]["git_clone_depth"] = 1
    elif mutation == "unknown_changed_path":
        drift_change["after_unknown"] = {"secondary_sources": [{"git_clone_depth": True}]}
    elif mutation == "sensitive_changed_path":
        drift_change["after_sensitive"] = {"secondary_sources": [{"insecure_ssl": True}]}
    elif mutation == "replacement":
        drift_change["replace_paths"] = [["secondary_sources"]]
    assert not release._hcp_plan_is_zero_change(plan)


@pytest.mark.parametrize(
    ("plan", "expected"),
    [
        ({"resource_changes": []}, True),
        (
            {
                "resource_changes": [
                    {"address": "terraform_data.example", "change": {"actions": ["no-op"]}}
                ]
            },
            True,
        ),
        (
            {
                "resource_changes": [
                    {"address": "terraform_data.example", "change": {"actions": ["create"]}}
                ]
            },
            False,
        ),
        ({"resource_changes": [], "output_changes": {"value": {"actions": ["update"]}}}, False),
        ({"resource_changes": [], "action_invocations": [{"address": "action.example"}]}, False),
        ({"resource_changes": [], "deferred_changes": [{"reason": "unknown"}]}, False),
        ({}, False),
    ],
)
def test_zero_change_plan_classification(plan: dict[str, Any], expected: bool) -> None:
    assert release._hcp_plan_is_zero_change(plan) is expected
