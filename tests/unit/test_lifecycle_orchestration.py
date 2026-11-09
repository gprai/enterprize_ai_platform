from __future__ import annotations

import json
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import provision.lifecycle as lifecycle
import pytest
from provision import hcp
from provision.lifecycle import SCHEMA_VERSION, ContextStore, LifecycleError, _canonical_bytes
from provision.services import ServiceError, Services
from provision.setup import required_variables


def context() -> dict[str, object]:
    now = datetime.now(UTC)
    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": "12345678-1234-4234-9234-123456789abc",
        "operation": "deploy",
        "phase": "PREPARED",
        "classification": "PASS",
        "created_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": (now + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": {"commit": "a" * 40, "tree": "b" * 40},
        "bindings": {},
        "checkpoints": [],
        "results": {},
        "retention": {
            "bootstrap": "RETAIN",
            "bootstrap_owned_iam": "RETAIN",
            "canonical_evidence": "RETAIN",
            "decrypting_kms_access": "RETAIN",
        },
    }


def test_context_is_canonical_and_integrity_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(lifecycle, "REPOSITORY_ROOT", tmp_path / "repository")
    store = ContextStore(tmp_path / "evidence")
    value = context()
    path = store.create(value)

    assert path.read_bytes() == _canonical_bytes(value)
    assert json.loads(path.read_text(encoding="utf-8"))["phase"] == "PREPARED"
    assert store.load(str(value["run_id"])) == value


def test_context_rejects_prohibited_sensitive_field(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(lifecycle, "REPOSITORY_ROOT", tmp_path / "repository")
    store = ContextStore(tmp_path / "evidence")
    value = context()
    value["bindings"] = {"session_token": "forbidden"}

    with pytest.raises(LifecycleError, match="PROHIBITED_CONTEXT_FIELD"):
        store.create(value)


def test_context_rejects_more_than_24_hours(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(lifecycle, "REPOSITORY_ROOT", tmp_path / "repository")
    store = ContextStore(tmp_path / "evidence")
    value = context()
    created = datetime.now(UTC)
    value["created_at"] = created.strftime("%Y-%m-%dT%H:%M:%SZ")
    value["expires_at"] = (created + timedelta(hours=24, seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ")

    with pytest.raises(LifecycleError, match="CONTEXT_LIFETIME_INVALID"):
        store.create(value)


def test_terminal_context_is_archived_while_run_lock_is_held(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(lifecycle, "REPOSITORY_ROOT", tmp_path / "repository")
    store = ContextStore(tmp_path / "evidence")
    value = context()
    run_id = str(value["run_id"])
    store.create(value)

    with store.lock(run_id):
        current = store.load(run_id)
        current["operation"] = "rollback"
        current["phase"] = "ROLLBACK_COMPLETE"
        current["results"] = {"rollback_complete": {"classification": "PASS"}}
        store.save(current)
        summary_path = store.complete(current)

    assert summary_path == store.run_directory(run_id, completed=True) / "context-summary.json"
    assert json.loads(summary_path.read_text(encoding="utf-8"))["phase"] == "ROLLBACK_COMPLETE"
    assert not store.run_directory(run_id).exists()


class FakeHcp:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.hcp_token = "test-only"
        self.calls: list[tuple[str, str]] = []
        self.run: dict[str, Any] | None = None
        self.applied = False
        self.uncertain = False
        self.zero = False
        self.state = {"id": "sv-before", "serial": 1, "lineage": "test-lineage"}

    def current_state(self, workspace: str) -> dict[str, Any]:
        return (
            {"id": "sv-after", "serial": 2, "lineage": "test-lineage"}
            if self.applied
            else deepcopy(self.state)
        )

    def configuration(self, workspace: str, commit: str) -> str:
        return "cv-exact"

    def hcp_pages(self, path: str) -> list[dict[str, Any]]:
        return [self.run] if self.run else []

    def hcp(self, path: str, method: str = "GET", body: Any = None) -> dict[str, Any]:
        self.calls.append((method, path))
        if method == "POST" and path == "/runs":
            attrs = body["data"]["attributes"]
            assert attrs["auto-apply"] is False
            assert attrs["plan-only"] is False
            self.run = {
                "id": "run-exact",
                "attributes": {
                    **attrs,
                    "status": "planned_and_finished" if self.zero else "post_plan_completed",
                    "actions": {"is-confirmable": True},
                },
                "relationships": {
                    **body["data"]["relationships"],
                    "plan": {"data": {"id": "plan-exact"}},
                },
            }
            if self.uncertain:
                raise ServiceError("RESPONSE_LOST", "INDETERMINATE")
            return {"data": self.run}
        if path == "/runs/run-exact/actions/apply":
            assert self.run is not None
            self.run["attributes"]["status"] = "applied"
            self.applied = True
            return {}
        if path.startswith("/runs/"):
            assert self.run is not None
            return {"data": self.run}
        if path == "/state-versions/sv-after":
            return {"data": {"relationships": {"run": {"data": {"id": "run-exact"}}}}}
        raise AssertionError(path)


@pytest.fixture
def orchestration(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    fake = FakeHcp(tmp_path)
    value: dict[str, Any] = context()
    value["bindings"] = {"workspaces": {"sandbox": "ws-exact"}}
    inputs = {"otel_collector_image": "image", "stages": {"base": {"variables": {}}}}
    journal: list[dict[str, Any]] = []
    monkeypatch.setattr(hcp, "requested", lambda *a, **k: {"record_id": "record-test"})
    monkeypatch.setattr(
        hcp,
        "review",
        lambda *a: {
            "plan_id": "plan-exact",
            "plan_sha256": hcp.digest(b"plan"),
            "changes": [],
            "opa": "PASS",
            "infracost": "PASS",
        },
    )
    monkeypatch.setattr(hcp.release, "_hcp_plan_json_bytes", lambda *a: b"plan")

    def execute(approve: Any = lambda text: None, **kwargs: Any) -> dict[str, Any]:
        return hcp.execute(
            fake,
            value,
            inputs,
            "base",
            tmp_path,
            lambda: journal.append(deepcopy(value)),
            approve,
            **kwargs,
        )

    return fake, value, journal, execute


def test_hcp_plan_apply_verifies_new_state_and_journals_before_posts(orchestration: Any) -> None:
    fake, value, journal, execute = orchestration
    result = execute()
    assert result["complete"] and result["final_state"]["serial"] == 2
    assert [(m, p) for m, p in fake.calls if m == "POST"] == [
        ("POST", "/runs"),
        ("POST", "/runs/run-exact/actions/apply"),
    ]
    checkpoints = [j["results"]["hcp"]["base"] for j in journal]
    assert any(s["post_attempted"] and s["run_id"] is None for s in checkpoints)
    assert any(s["apply_attempted"] and not s.get("complete") for s in checkpoints)


def test_uncertain_run_post_resumes_without_second_post(orchestration: Any) -> None:
    fake, value, journal, execute = orchestration
    fake.uncertain = True
    with pytest.raises(ServiceError, match="RESPONSE_LOST"):
        execute()
    assert value["results"]["hcp"]["base"]["post_attempted"]
    result = execute()
    assert result["complete"]
    assert fake.calls.count(("POST", "/runs")) == 1


def test_uncertain_post_without_match_never_reposts(orchestration: Any) -> None:
    fake, value, journal, execute = orchestration
    fake.uncertain = True
    with pytest.raises(ServiceError):
        execute()
    fake.run = None
    with pytest.raises(ServiceError, match="RUN_POST_UNCERTAIN"):
        execute()
    assert fake.calls.count(("POST", "/runs")) == 1


def test_zero_change_final_run_does_not_apply(orchestration: Any) -> None:
    fake, value, journal, execute = orchestration
    fake.zero = True
    result = execute()
    assert result["no_changes"] and result["complete"]
    assert not fake.applied


def test_plan_only_then_resume_reuses_exact_run(orchestration: Any) -> None:
    fake, value, journal, execute = orchestration
    assert not execute(plan_only=True).get("complete")
    assert not fake.applied
    assert execute()["complete"]
    assert fake.calls.count(("POST", "/runs")) == 1


def test_state_change_while_owner_reviews_blocks_apply(orchestration: Any) -> None:
    fake, value, journal, execute = orchestration

    def approve(text: str) -> None:
        if text.startswith("APPLY"):
            fake.state["serial"] = 9

    with pytest.raises(ServiceError, match="PRE_APPLY_BINDING_CHANGED"):
        execute(approve)
    assert not fake.applied


def test_cleanup_runs_only_after_exact_approval(orchestration: Any) -> None:
    fake, value, journal, execute = orchestration
    order = []
    execute(
        lambda text: order.append(
            "apply-approved" if text.startswith("APPLY") else "plan-approved"
        ),
        before_apply=lambda step: order.append("cleanup"),
    )
    assert order == ["plan-approved", "apply-approved", "cleanup"]


def test_new_attempt_cannot_replace_confirmable_run(orchestration: Any) -> None:
    fake, value, journal, execute = orchestration
    execute(plan_only=True)
    with pytest.raises(ServiceError, match="NEW_ATTEMPT_REQUIRES"):
        execute(new_attempt=True)
    assert fake.calls.count(("POST", "/runs")) == 1


def test_required_hcl_variables_handles_nested_validation_and_comments(tmp_path: Path) -> None:
    (tmp_path / "variables.tf").write_text("""
variable "required" { type = map(string)
 validation { condition = length(var.required) > 0 error_message = "default = { fake }" }
}
variable "optional" { default = { x = "}" } }
# variable "commented" { }
""")
    assert required_variables(tmp_path) == {"required"}


def test_resource_inventory_requires_final_processed_state(monkeypatch: pytest.MonkeyPatch) -> None:
    services = object.__new__(Services)
    monkeypatch.setattr(services, "current_state", lambda ws: {"id": "sv-current"})
    monkeypatch.setattr(
        services, "hcp", lambda path: {"data": {"attributes": {"resources-processed": False}}}
    )
    with pytest.raises(ServiceError, match="STATE_RESOURCES_STILL_PROCESSING"):
        services.resources("ws-current")


def test_run_change_during_cleanup_cannot_trigger_apply(orchestration: Any) -> None:
    fake, value, journal, execute = orchestration

    def cleanup(step: Any) -> None:
        fake.run["attributes"]["actions"]["is-confirmable"] = False

    with pytest.raises(ServiceError, match="RUN_CHANGED_DURING_PRE_APPLY_CLEANUP"):
        execute(before_apply=cleanup)
    assert ("POST", "/runs/run-exact/actions/apply") not in fake.calls


def test_image_dispatch_uncertain_response_never_posts_twice(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from provision import bindings

    services = object.__new__(Services)
    calls = []
    monkeypatch.setattr(services, "github", lambda *a: calls.append(a) or {})
    value = context()
    saves = []
    with pytest.raises(ServiceError, match="PUBLICATION_DISPATCH_UNCERTAIN"):
        bindings.images(services, value, lambda: saves.append(deepcopy(value)), lambda t: None)
    assert saves[0]["results"]["images"]["dispatch_attempted"] is True
    with pytest.raises(ServiceError, match="PUBLICATION_DISPATCH_UNCERTAIN"):
        bindings.images(services, value, lambda: None, lambda t: None)
    assert len(calls) == 1


def test_github_binding_reuses_existing_value_without_write(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from provision import bindings

    services = object.__new__(Services)
    monkeypatch.setattr(
        services, "github_pages", lambda *a: [{"name": "APPROVED", "value": "exact"}]
    )
    monkeypatch.setattr(services, "github", lambda *a: pytest.fail("no mutation"))
    bindings.github_binding(
        services, "APPROVED", "exact", lambda t: pytest.fail("no approval needed")
    )


class SetupFixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.profile = "owner"
        self.variables = []
        self.writes = []
        workflows = root / ".github/workflows"
        workflows.mkdir(parents=True)
        for name in ("capstone-release.yml", "w12-prerequisite-images.yml"):
            (workflows / name).write_text("value: ${{ vars.OWNER_BINDING }}")
        for directory in ("infra/bootstrap", "infra/environments/sandbox"):
            (root / directory).mkdir(parents=True)

    def aws(self, *args: Any) -> Any:
        return {"Account": "526338061652"}

    def hcp_pages(self, path: str) -> Any:
        if path.endswith("/vars"):
            return [
                {
                    "attributes": {
                        "key": k,
                        "category": "env",
                        "sensitive": False,
                        "value": "existing",
                    }
                }
                for k in (
                    "TFC_AWS_PROVIDER_AUTH",
                    "TFC_AWS_PLAN_ROLE_ARN",
                    "TFC_AWS_APPLY_ROLE_ARN",
                )
            ]
        if "/tasks" in path:
            return [
                {
                    "attributes": {"enforcement-level": "mandatory", "stages": ["post_plan"]},
                    "relationships": {"task": {"data": {"id": "task-cost"}}},
                }
            ]
        return [{"id": "project", "attributes": {"name": "enterprise-ai-capstone"}}]

    def hcp(self, path: str, *args: Any) -> Any:
        if path == "/account/details":
            return {
                "data": {
                    "id": "user-owner",
                    "type": "users",
                    "attributes": {"is-service-account": False},
                }
            }
        if path == "/tasks/task-cost":
            return {"data": {"attributes": {"name": "Infracost", "enabled": True}}}
        target = "bootstrap" if path.endswith("enterprise-ai-bootstrap") else "sandbox"
        directory = "infra/bootstrap" if target == "bootstrap" else "infra/environments/sandbox"
        return {
            "data": {
                "id": "ws-" + target,
                "attributes": {
                    "auto-apply": False,
                    "execution-mode": "remote",
                    "working-directory": directory,
                    "terraform-version": "1.16.1",
                    "vcs-repo": {"identifier": "gprai/enterprize_ai_platform", "branch": "main"},
                },
                "relationships": {"project": {"data": {"id": "project"}}},
            }
        }

    def github_pages(self, path: str, key: str) -> Any:
        return self.variables if key == "variables" else []

    def github(self, path: str, method: str = "GET", body: Any = None) -> Any:
        if method == "POST":
            self.writes.append((path, body))
            self.variables.append(body)
            return body
        if path == "/branches/main":
            return {"protected": True}
        if path == "/environments/sandbox":
            return {"protection_rules": [{"type": "required_reviewers", "reviewers": [{"id": 1}]}]}
        if path == "/actions/permissions":
            return {"enabled": True}
        if "/actions/variables/" in path:
            return self.variables[0]
        return {"state": "active"}


def test_setup_missing_variables_require_opt_in_and_exact_creation_approval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from provision.setup import ensure_setup

    services = SetupFixture(tmp_path)
    monkeypatch.setattr("provision.iam_handoff.authority", lambda *a: None)
    inputs = {
        "github_variables": {"OWNER_BINDING": {"value": "approved"}},
        "bootstrap_execution": {"plan_role_arn": "tested separately"},
    }
    prompts = []
    missing = ensure_setup(services, inputs, repair=False, approve=prompts.append, login=False)
    assert missing["classification"] == "FAIL" and not services.writes and not prompts
    created = ensure_setup(services, inputs, repair=True, approve=prompts.append, login=False)
    assert created["classification"] == "PASS"
    assert prompts == ["CREATE MISSING GITHUB_VARIABLES_OWNER_BINDING"]
    assert len(services.writes) == 1
    prompts.clear()
    ensure_setup(services, inputs, repair=True, approve=prompts.append, login=False)
    assert len(services.writes) == 1 and not prompts


def test_setup_existing_mismatch_is_reported_not_overwritten(tmp_path: Path) -> None:
    from provision.setup import ensure_setup

    services = SetupFixture(tmp_path)
    services.variables = [{"name": "OWNER_BINDING", "value": "old"}]
    summary = ensure_setup(
        services,
        {"github_variables": {"OWNER_BINDING": {"value": "new"}}},
        repair=True,
        approve=lambda text: pytest.fail("no overwrite approval"),
        login=False,
    )
    assert summary["classification"] == "FAIL" and summary["mismatched"]
    assert not services.writes


@pytest.mark.parametrize("confirmed", [False, True])
def test_eks_binding_waits_for_both_owner_sns_confirmations(
    monkeypatch: pytest.MonkeyPatch, confirmed: bool
) -> None:
    from types import SimpleNamespace

    from provision import bindings

    emails = ["stage@example.invalid", "dev@example.invalid"]
    raw = json.dumps({"variables": {"alert_email_endpoints": {"value": emails}}}).encode()
    topic = "arn:aws:sns:ap-southeast-1:526338061652:enterprise-ai-sandbox-alerts"

    class Aws:
        def client(self, name: str) -> Any:
            return self

        def describe_cluster(self, **kwargs: Any) -> Any:
            return {
                "cluster": {
                    "status": "ACTIVE",
                    "arn": "arn:aws:eks:ap-southeast-1:526338061652:cluster/enterprise-ai-sandbox",
                    "identity": {
                        "oidc": {"issuer": "https://oidc.eks.ap-southeast-1.amazonaws.com/id/ABCD"}
                    },
                }
            }

        def get_paginator(self, name: str) -> Any:
            return self

        def paginate(self, **kwargs: Any) -> Any:
            assert kwargs == {"TopicArn": topic}
            return [
                {
                    "Subscriptions": [
                        {
                            "Protocol": "email",
                            "Endpoint": email,
                            "SubscriptionArn": topic + ":id"
                            if confirmed or index == 0
                            else "PendingConfirmation",
                        }
                        for index, email in enumerate(emails)
                    ]
                }
            ]

    monkeypatch.setattr(bindings, "session", lambda services: Aws())
    monkeypatch.setattr(bindings.release, "_hcp_plan_json_bytes", lambda *args: raw)
    value = {
        "bindings": {"runtime_variables": {"w12_codebuild_image_digest": "reviewed-image"}},
        "results": {
            "hcp": {
                "foundation": {
                    "review": {
                        "plan_id": "plan-test",
                        "plan_sha256": hcp.digest(raw),
                    }
                }
            }
        },
    }
    prompts, saves = [], []
    if confirmed:
        proof = bindings.eks(
            SimpleNamespace(hcp_token="test"), value, lambda: saves.append(True), prompts.append
        )
        assert proof["confirmed_sns_endpoints"] == 2 and len(prompts) == len(saves) == 1
    else:
        with pytest.raises(ServiceError, match="OWNER_SNS_EMAIL_CONFIRMATIONS_REQUIRED"):
            bindings.eks(
                SimpleNamespace(hcp_token="test"), value, lambda: saves.append(True), prompts.append
            )
        assert not prompts and not saves
        assert "w12_owner_approved_eks_issuer" not in value["bindings"]["runtime_variables"]


@pytest.mark.parametrize("status,conclusion", [("waiting", None), ("completed", "failure")])
def test_release_resume_never_redispatches_or_claims_verified_before_success(
    monkeypatch: pytest.MonkeyPatch, status: str, conclusion: str | None
) -> None:
    from types import SimpleNamespace

    value = context()
    value["results"] = {"release": {"workflow_run_id": 123}}
    run = {
        "id": 123,
        "head_sha": "a" * 40,
        "head_branch": "main",
        "url": "https://api.github.com/repos/gprai/enterprize_ai_platform/actions/runs/123",
        "html_url": "https://github.com/gprai/enterprize_ai_platform/actions/runs/123",
        "path": ".github/workflows/capstone-release.yml",
        "status": status,
        "conclusion": conclusion,
    }
    monkeypatch.setattr(
        lifecycle.release_engine, "_trigger", lambda args: pytest.fail("no redispatch")
    )
    monkeypatch.setattr(
        lifecycle, "_collect_publication", lambda *args: pytest.fail("not verified")
    )
    store = SimpleNamespace(save=lambda context: None)
    services = SimpleNamespace(github=lambda path: run)
    arguments = SimpleNamespace(run_id=value["run_id"])
    args = (
        arguments,
        store,
        value,
        services,
        {},
        Path("unused"),
        {},
        b"record",
        b"receipt",
        "release",
    )
    if status == "waiting":
        result = lifecycle._workflow(*args)
        assert result["Result"] == "RELEASE_IN_PROGRESS"
        assert result["Approval"] == "OWNER_USES_GITHUB_PROTECTED_ENVIRONMENT"
    else:
        with pytest.raises(LifecycleError, match="GITHUB_RELEASE_FAILURE"):
            lifecycle._workflow(*args)
    assert value["phase"] != "RELEASE_COMPLETE"
