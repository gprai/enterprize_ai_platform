from __future__ import annotations

import json
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from provision import hcp
from provision import iam_handoff as iam
from provision.services import ServiceError

from tests.unit.test_lifecycle_orchestration import FakeHcp, context

ROOT = Path(__file__).resolve().parents[2]
CAPTURE = json.loads(
    (ROOT / "infra/bootstrap/platform-iam-config/bindings.captured.json").read_bytes()
)


def proof(phase: str = "complete") -> dict[str, Any]:
    now = datetime.now(UTC)
    values = {k: v for k, v in CAPTURE.items() if k != "bootstrap_kms_key_arn"}
    for key in iam.FULL_KEYS:
        # Deliberately different physical IDs: historical IDs must not survive a refresh.
        values[key] = values[key][:-1] + ("a" if values[key][-1] != "a" else "b")
    values["administrator_trust_expires_at"] = (now + timedelta(hours=8)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    values["workload_expires_at"] = (now + timedelta(hours=23)).strftime("%Y-%m-%dT%H:%M:%SZ")
    if phase == "seed":
        for key in iam.FULL_KEYS - iam.SEED_KEYS:
            del values[key]
    return {
        "phase": phase,
        "values": values,
        "previous": CAPTURE,
        "bootstrap_key": CAPTURE["bootstrap_kms_key_arn"],
        "source_state": {"id": "sv-source", "serial": 25, "lineage": "exact"},
        "issued": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


@pytest.mark.parametrize("phase", ["seed", "complete"])
def test_current_complete_binding_maps_pass(phase: str) -> None:
    p = proof(phase)
    iam.validate_bindings(p["values"], phase, p["issued"])


@pytest.mark.parametrize(
    "field,value",
    [
        ("sandbox_vpc_arn", CAPTURE["sandbox_subnet_a_arn"]),
        ("sandbox_kms_key_arn", "*"),
        ("administrator_trust_expires_at", "2020-01-01T00:00:00Z"),
        ("workload_expires_at", "2099-01-01T00:00:00Z"),
        ("bedrock_model_id", "*"),
    ],
)
def test_bad_bindings_fail_before_post(field: str, value: str) -> None:
    p = proof()
    p["values"][field] = value
    with pytest.raises(ServiceError):
        iam.validate_bindings(p["values"], p["phase"], p["issued"])


def test_missing_binding_cannot_fall_back_to_capture() -> None:
    p = proof()
    del p["values"]["sandbox_vpc_arn"]
    with pytest.raises(ServiceError, match="KEYS_MISMATCH"):
        iam.validate_bindings(p["values"], p["phase"], p["issued"])
    source = (ROOT / "infra/bootstrap/platform_iam.tf").read_text()
    assert "bindings.captured.json" not in source


def test_seed_withholds_only_endpoint_parent_authorization_then_restores_exact_bindings() -> None:
    file = "enterprise-ai-capstone-hcp-apply-sandbox-service-recovery-v1.json.tftpl"
    seed = iam.render(ROOT, file, proof("seed"))
    complete = iam.render(ROOT, file, proof())
    assert [s["Sid"] for s in seed["Statement"]] == ["CreateOpenSearchGrantOnExactSandboxKey"]
    endpoints = next(s for s in complete["Statement"] if s["Sid"] == iam.ENDPOINT_SID)
    assert len(endpoints["Resource"]) == 5
    assert all("*" not in r and r not in CAPTURE.values() for r in endpoints["Resource"])


def policy_plan(p: dict[str, Any]) -> dict[str, Any]:
    name = "enterprise-ai-capstone-hcp-apply-sandbox-service-recovery-v1"
    document = iam.render(ROOT, name + ".json.tftpl", p)
    return {
        "terraform_version": "1.16.1",
        "resource_changes": [
            {
                "mode": "managed",
                "address": f'aws_iam_policy.hcp["{name}"]',
                "type": "aws_iam_policy",
                "change": {
                    "actions": ["update"],
                    "before": {"policy": "{}"},
                    "after": {"policy": json.dumps(document)},
                    "after_unknown": {},
                },
            }
        ],
    }


def test_exact_template_delta_passes_but_additional_action_or_unknown_fails() -> None:
    p = proof()
    plan = policy_plan(p)
    iam.validate_delta(ROOT, plan, p)
    bad = deepcopy(plan)
    document = json.loads(bad["resource_changes"][0]["change"]["after"]["policy"])
    document["Statement"][0]["Action"] = "ec2:*"
    bad["resource_changes"][0]["change"]["after"]["policy"] = json.dumps(document)
    with pytest.raises(ServiceError, match="NON_BINDING_DELTA"):
        iam.validate_delta(ROOT, bad, p)
    plan["resource_changes"][0]["change"]["after_unknown"] = {"policy": True}
    with pytest.raises(ServiceError, match="UNKNOWN_AUTHORITY"):
        iam.validate_delta(ROOT, plan, p)


@pytest.mark.parametrize("actions", [["create"], ["delete"], ["delete", "create"]])
def test_refresh_cannot_create_or_destroy_iam(actions: list[str]) -> None:
    p = proof()
    plan = policy_plan(p)
    plan["resource_changes"][0]["change"]["actions"] = actions
    with pytest.raises(ServiceError, match="UNEXPECTED_ADDRESS_OR_ACTION"):
        iam.validate_delta(ROOT, plan, p)


def test_workload_delta_rejects_extra_actions_and_accepts_only_rebinding() -> None:
    p = proof()
    before = {
        "Statement": [{"Action": ["kms:Decrypt"], "Resource": CAPTURE["sandbox_kms_key_arn"]}]
    }
    after = deepcopy(before)
    after["Statement"][0]["Resource"] = p["values"]["sandbox_kms_key_arn"]
    row = {
        "mode": "managed",
        "address": "module.platform_iam.aws_iam_role_policy.runtime",
        "type": "aws_iam_role_policy",
        "change": {
            "actions": ["update"],
            "before": {"policy": json.dumps(before)},
            "after": {"policy": json.dumps(after)},
        },
    }
    iam.validate_delta(ROOT, {"resource_changes": [row]}, p)
    after["Statement"][0]["Action"].append("kms:ScheduleKeyDeletion")
    row["change"]["after"]["policy"] = json.dumps(after)
    with pytest.raises(ServiceError, match="NON_BINDING_DELTA"):
        iam.validate_delta(ROOT, {"resource_changes": [row]}, p)


def test_seed_rejects_dependent_service_or_delete() -> None:
    row = {
        "mode": "managed",
        "address": "module.network.aws_vpc.this",
        "change": {"actions": ["create"]},
    }
    iam.validate_seed({"resource_changes": [row]}, "identity-seed")
    row["address"] = "module.opensearch.aws_opensearch_domain.this"
    with pytest.raises(ServiceError, match="PLAN_SCOPE_CHANGED"):
        iam.validate_seed({"resource_changes": [row]}, "identity-seed")


@pytest.mark.parametrize(
    "stage", ["identity-seed", "network-seed", "bootstrap-bind-seed", "bootstrap-bind-complete"]
)
def test_hcp_stage_journals_and_targets_correct_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stage: str
) -> None:
    fake = FakeHcp(tmp_path)
    c: dict[str, Any] = context()
    p = proof("seed" if stage.endswith("seed") else "complete")
    p["bootstrap_state"] = fake.current_state("ws-bootstrap")
    c["created_at"] = p["issued"]
    c["bindings"] = {
        "workspaces": {"sandbox": "ws-sandbox", "bootstrap": "ws-bootstrap"},
        "iam_handoffs": {stage: p},
    }
    inputs = {
        "stages": {
            stage: {
                "variables": {"mandatory_tags": {"ExpiresAt": p["values"]["workload_expires_at"]}}
            }
        },
        "otel_collector_image": "image",
    }
    monkeypatch.setattr(hcp, "requested", lambda *a, **k: {"record_id": "exact"})
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
    monkeypatch.setattr(iam, "assert_source", lambda *a: None)
    monkeypatch.setattr(iam, "authority", lambda *a: None)
    journal = []
    prompts = []
    result = hcp.execute(
        fake, c, inputs, stage, tmp_path, lambda: journal.append(deepcopy(c)), prompts.append
    )
    assert result["complete"]
    assert len(prompts) == 2 and prompts[1].startswith("APPLY HCP EXACT PLAN")
    assert fake.run["relationships"]["workspace"]["data"]["id"] == (
        "ws-bootstrap" if stage in iam.BOOTSTRAP_STAGES else "ws-sandbox"
    )
    assert fake.run["attributes"].get("target-addrs") == iam.TARGETS.get(stage)
    assert not fake.run["attributes"].get("is-destroy")
    assert any(
        v["results"]["hcp"][stage]["post_attempted"] and not v["results"]["hcp"][stage]["run_id"]
        for v in journal
    )


def test_bootstrap_state_change_rejects_stale_handoff_before_post(tmp_path: Path) -> None:
    fake = FakeHcp(tmp_path)
    c = context()
    c["bindings"] = {
        "workspaces": {"bootstrap": "ws-bootstrap"},
        "iam_handoffs": {"bootstrap-bind-seed": {"bootstrap_state": {"id": "sv-stale"}}},
    }
    with pytest.raises(ServiceError, match="BOOTSTRAP_HANDOFF_STATE_CHANGED"):
        hcp.execute(fake, c, {}, "bootstrap-bind-seed", tmp_path, lambda: None, lambda _: None)
    assert not fake.calls


def test_state_race_or_concurrent_sandbox_run_stops_handoff() -> None:
    class Fake:
        state = proof()["source_state"]
        runs: list[dict[str, Any]] = []

        def current_state(self, _: str) -> Any:
            return self.state

        def hcp_pages(self, _: str) -> Any:
            return self.runs

    fake = Fake()
    p = proof()
    c = {"bindings": {"workspaces": {"sandbox": "ws-sandbox"}}}
    iam.assert_source(fake, c, p)
    fake.runs = [{"attributes": {"status": "applying"}}]
    with pytest.raises(ServiceError, match="CONCURRENT_RUN"):
        iam.assert_source(fake, c, p)
    fake.state = {"id": "sv-other"}
    with pytest.raises(ServiceError, match="STATE_CHANGED"):
        iam.assert_source(fake, c, p)


def authority_fixture() -> tuple[Any, dict[str, Any]]:
    class Fake:
        root = ROOT
        bad_decision = False
        missing_resource = False
        wrong_trust = False

        def hcp_pages(self, _: str) -> Any:
            return [
                {
                    "attributes": {
                        "key": "TFC_AWS_" + phase.upper() + "_ROLE_ARN",
                        "category": "env",
                        "value": f"arn:aws:iam::526338061652:role/bootstrap-{phase}",
                    }
                }
                for phase in ("plan", "apply")
            ]

        def aws(self, *args: str) -> Any:
            if args[1] == "get-role":
                name = args[-1]
                phase = name.removeprefix("bootstrap-")
                subject = (
                    "organization:Enterprise_AI_AWS_Arch:project:enterprise-ai-capstone:workspace:enterprise-ai-bootstrap:run_phase:"
                    + phase
                )
                return {
                    "Role": {
                        "Arn": f"arn:aws:iam::526338061652:role/{name}",
                        "AssumeRolePolicyDocument": {
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": "sts:AssumeRoleWithWebIdentity",
                                    "Principal": {
                                        "Federated": (
                                            "arn:aws:iam::526338061652:"
                                            "oidc-provider/app.terraform.io"
                                        )
                                    },
                                    "Condition": {
                                        "StringEquals": {
                                            "app.terraform.io:aud": "aws.workload.identity",
                                            "app.terraform.io:sub": "*"
                                            if self.wrong_trust
                                            else subject,
                                        }
                                    },
                                }
                            ]
                        },
                    }
                }
            assert args[1] == "simulate-principal-policy"
            index = args.index("--resource-arns")
            resources = args[index + 1 :]
            actions = args[args.index("--action-names") + 1 : index]
            return {
                "EvaluationResults": [
                    {
                        "EvalActionName": a,
                        "EvalDecision": "implicitDeny" if self.bad_decision else "allowed",
                        "ResourceSpecificResults": [
                            {"EvalResourceName": r, "EvalResourceDecision": "allowed"}
                            for r in resources[1 if self.missing_resource else 0 :]
                        ],
                    }
                    for a in actions
                ]
            }

    return Fake(), {
        "bootstrap_execution": {
            phase + "_role_arn": f"arn:aws:iam::526338061652:role/bootstrap-{phase}"
            for phase in ("plan", "apply")
        }
    }


@pytest.mark.parametrize("fault", [None, "bad_decision", "missing_resource", "wrong_trust"])
def test_remote_bootstrap_authority_requires_exact_trust_and_all_permissions(
    fault: str | None,
) -> None:
    services, inputs = authority_fixture()
    if fault is None:
        iam.authority(services, inputs, "ws-bootstrap")
    else:
        setattr(services, fault, True)
        with pytest.raises(ServiceError):
            iam.authority(services, inputs, "ws-bootstrap")


def test_workload_apply_role_cannot_be_used_to_self_administer() -> None:
    services, inputs = authority_fixture()
    inputs["bootstrap_execution"]["plan_role_arn"] = (
        "arn:aws:iam::526338061652:role/enterprise-ai-capstone-hcp-plan"
    )
    with pytest.raises(ServiceError, match="MUST_NOT_SELF_ADMINISTER"):
        iam.authority(services, inputs, "ws-bootstrap")


def test_prepare_handoff_uses_current_outputs_and_never_old_capture_as_future_values() -> None:
    p = proof()

    class Fake:
        root = ROOT

        def current_state(self, workspace: str) -> Any:
            return (
                p["source_state"]
                if workspace == "ws-sandbox"
                else {"id": "sv-bootstrap", "serial": 4}
            )

        def hcp_pages(self, path: str) -> Any:
            if "runs?" in path:
                return []
            if "sv-source" in path:
                return [
                    {
                        "attributes": {
                            "name": "platform_iam_network_bindings",
                            "sensitive": False,
                            "value": {k: p["values"][k] for k in iam.FULL_KEYS},
                        }
                    }
                ]
            return [
                {
                    "attributes": {
                        "name": "state_kms_key_arn",
                        "sensitive": False,
                        "value": p["bootstrap_key"],
                    }
                }
            ]

    c = {
        "created_at": p["issued"],
        "expires_at": p["values"]["administrator_trust_expires_at"],
        "bindings": {"workspaces": {"sandbox": "ws-sandbox", "bootstrap": "ws-bootstrap"}},
        "results": {"hcp": {"network-seed": {"complete": True, "final_state": p["source_state"]}}},
    }
    inputs = {
        "iam_handoff": {
            k: p["values"][k]
            for k in ("administrator_role_arn", "bedrock_model_id", "workload_expires_at")
        }
    }
    result = iam.prepare(Fake(), c, inputs, "bootstrap-bind-complete")
    assert result["values"] == p["values"]
    assert all(result["values"][k] != CAPTURE[k] for k in iam.FULL_KEYS)
