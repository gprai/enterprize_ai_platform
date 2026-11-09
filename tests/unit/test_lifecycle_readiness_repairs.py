from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from provision import bootstrap_authority as authority
from provision import destroy_source, hcp, iam_handoff
from provision.services import ServiceError

ROOT = Path(__file__).resolve().parents[2]


def retry_fixture(monkeypatch: pytest.MonkeyPatch) -> tuple[Any, dict[str, Any], list[str]]:
    old = {"id": "sv-old", "serial": 4, "lineage": "same"}
    new = {"id": "sv-partial", "serial": 5, "lineage": "same"}
    proof = {
        "bootstrap_state": old,
        "source_state": {"id": "sv-sandbox"},
        "values": {"binding": "unchanged"},
        "phase": "seed",
    }
    c = {
        "source": {"commit": "a" * 40},
        "results": {"hcp": {"bootstrap-bind-seed": {"run_id": "run-failed"}}},
        "bindings": {
            "workspaces": {"bootstrap": "ws-bootstrap"},
            "iam_handoffs": {"bootstrap-bind-seed": proof},
        },
    }
    prompts: list[str] = []

    class Fake:
        state = new
        creator = "run-failed"
        status = "errored"

        def hcp(self, path: str) -> Any:
            if path.startswith("/state-versions/"):
                return {"data": {"relationships": {"run": {"data": {"id": self.creator}}}}}
            return {"data": {"attributes": {"status": self.status}}}

        def hcp_pages(self, path: str) -> list[Any]:
            return []

        def current_state(self, workspace: str) -> Any:
            return deepcopy(self.state)

        def configuration(self, *args: Any) -> str:
            # Stop at the boundary before any configuration/run mutation.
            raise ServiceError("REACHED_FRESH_CONFIGURATION_BOUNDARY")

    fake = Fake()
    monkeypatch.setattr(iam_handoff, "assert_source", lambda *args: None)
    monkeypatch.setattr(
        iam_handoff,
        "prepare",
        lambda *args: dict(deepcopy(proof), bootstrap_state=deepcopy(fake.state)),
    )
    return fake, c, prompts


def retry(fake: Any, c: dict[str, Any], approve: Any) -> None:
    hcp.execute(
        fake, c, {}, "bootstrap-bind-seed", Path("."), lambda: None, approve, new_attempt=True
    )


def test_partial_apply_retry_rebinds_and_preserves_failed_proof(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake, c, prompts = retry_fixture(monkeypatch)
    with pytest.raises(ServiceError, match="REACHED_FRESH_CONFIGURATION_BOUNDARY"):
        retry(fake, c, prompts.append)
    assert len(prompts) == 1 and prompts[0].startswith("REBIND FAILED BOOTSTRAP ATTEMPT")
    assert (
        c["bindings"]["iam_handoffs"]["bootstrap-bind-seed"]["bootstrap_state"]["id"]
        == "sv-partial"
    )
    assert c["results"]["recovery_history"][0]["iam_handoff"]["bootstrap_state"]["id"] == "sv-old"
    assert not c["results"]["hcp"]


@pytest.mark.parametrize(
    "case", ["creator", "lineage", "serial", "live", "changed-values", "approval-race", "declined"]
)
def test_retry_rejects_unrelated_or_unapproved_state(
    monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    fake, c, prompts = retry_fixture(monkeypatch)
    if case == "creator":
        fake.creator = "run-other"
    elif case == "lineage":
        fake.state = dict(fake.state, lineage="other")
    elif case == "serial":
        fake.state = dict(fake.state, serial=3)
    elif case == "live":
        fake.status = "applying"
    elif case == "changed-values":
        p = dict(
            c["bindings"]["iam_handoffs"]["bootstrap-bind-seed"],
            bootstrap_state=fake.state,
            values={"binding": "other"},
        )
        monkeypatch.setattr(iam_handoff, "prepare", lambda *args: p)

    def approve(text: str) -> None:
        prompts.append(text)
        if case == "approval-race":
            fake.state = dict(fake.state, id="sv-raced")
        if case == "declined":
            raise ServiceError("OWNER_DECLINED")

    with pytest.raises(ServiceError) as exc:
        retry(fake, c, approve)
    assert "FRESH_CONFIGURATION" not in str(exc.value)
    assert c["results"]["hcp"]["bootstrap-bind-seed"]["run_id"] == "run-failed"
    assert c["bindings"]["iam_handoffs"]["bootstrap-bind-seed"]["bootstrap_state"]["id"] == "sv-old"


def test_destroy_overrides_cover_every_protected_iam_resource_and_block_deploy(
    tmp_path: Path,
) -> None:
    import shutil

    shutil.copytree(
        ROOT / "infra/bootstrap",
        tmp_path / "infra/bootstrap",
        ignore=shutil.ignore_patterns(".terraform", "*.tfstate*", "*.tfvars*"),
    )
    generated = destroy_source.expected(tmp_path)
    with pytest.raises(ServiceError, match="OVERRIDES_REQUIRED"):
        destroy_source.assert_mode(tmp_path, "bootstrap-teardown")
    for path, content in generated.items():
        path.write_text(content, encoding="utf-8")
        document = json.loads(content)
        assert all(kind.startswith("aws_iam_") for kind in document["resource"])
    destroy_source.assert_mode(tmp_path, "bootstrap-teardown")
    for operation in ("deploy", "rollback", "teardown"):
        with pytest.raises(ServiceError, match="CANNOT_DEPLOY"):
            destroy_source.assert_mode(tmp_path, operation)
    next(iter(generated)).write_text("{}", encoding="utf-8")
    with pytest.raises(ServiceError, match="OVERRIDES_REQUIRED"):
        destroy_source.assert_mode(tmp_path, "bootstrap-teardown")


@pytest.mark.parametrize("purpose", ["refresh", "teardown"])
def test_authority_is_exact_independent_and_phase_separated(purpose: str) -> None:
    specs = authority.documents(
        ROOT,
        "test-state-bucket",
        "test-lock",
        "arn:aws:kms:ap-southeast-1:526338061652:key/11111111-1111-1111-1111-111111111111",
        purpose=purpose,
        aliases=["arn:aws:kms:ap-southeast-1:526338061652:alias/test-state"],
    )
    for phase, spec in specs.items():
        assert len(hcp.canonical(spec["policy"])) < 10240
        trust = spec["trust"]["Statement"][0]
        assert trust["Condition"]["StringEquals"]["app.terraform.io:sub"].endswith(
            "run_phase:" + phase
        )
        actions = {a for s in spec["policy"]["Statement"] for a in s["Action"]}
        assert "iam:CreateRole" not in actions
        assert "iam:PassRole" not in actions
        assert ("iam:DeleteRole" in actions) == (phase == "apply" and purpose == "teardown")
        assert ("iam:UpdateAssumeRolePolicy" in actions) == (phase == "apply")
        for statement in spec["policy"]["Statement"]:
            assert spec["arn"] not in statement["Resource"]
            if "*" in statement["Resource"]:
                assert statement["Action"] == ["kms:ListAliases"]
                assert (
                    statement["Condition"]["StringEquals"]["aws:RequestedRegion"]
                    == "ap-southeast-1"
                )


def test_setup_rejects_existing_role_extra_authority() -> None:
    spec = authority.documents(
        ROOT,
        "test-state-bucket",
        "test-lock",
        "arn:aws:kms:ap-southeast-1:526338061652:key/11111111-1111-1111-1111-111111111111",
    )["plan"]

    class Fake:
        def get_role(self, **kwargs: Any) -> Any:
            return {"Role": {"Arn": spec["arn"], "AssumeRolePolicyDocument": spec["trust"]}}

        def list_attached_role_policies(self, **kwargs: Any) -> Any:
            return {"AttachedPolicies": [{"PolicyArn": "administrator"}]}

    with pytest.raises(ServiceError, match="EXTRA_AUTHORITY"):
        authority.check_role(Fake(), spec)


def test_owner_setup_plan_then_apply_uses_existing_credentials_and_never_runs_terraform(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from botocore.exceptions import ClientError

    roles: dict[str, Any] = {}
    variables: dict[str, Any] = {}
    writes: list[str] = []

    class Client:
        def get_caller_identity(self) -> Any:
            return {"Account": authority.ACCOUNT}

        def get_role(self, RoleName: str) -> Any:
            if RoleName not in roles:
                raise ClientError({"Error": {"Code": "NoSuchEntity"}}, "GetRole")
            return {"Role": roles[RoleName]}

        def list_attached_role_policies(self, **kwargs: Any) -> Any:
            return {"AttachedPolicies": []}

        def list_role_policies(self, RoleName: str) -> Any:
            return {"PolicyNames": [authority.POLICY_NAME] if "policy" in roles[RoleName] else []}

        def get_role_policy(self, RoleName: str, **kwargs: Any) -> Any:
            return {"PolicyDocument": roles[RoleName]["policy"]}

        def validate_policy(self, **kwargs: Any) -> Any:
            return {"findings": []}

        def create_role(self, RoleName: str, AssumeRolePolicyDocument: str, **kwargs: Any) -> None:
            writes.append("CreateRole")
            roles[RoleName] = {
                "Arn": f"arn:aws:iam::{authority.ACCOUNT}:role/{RoleName}",
                "AssumeRolePolicyDocument": json.loads(AssumeRolePolicyDocument),
            }

        def put_role_policy(self, RoleName: str, PolicyDocument: str, **kwargs: Any) -> None:
            writes.append("PutRolePolicy")
            roles[RoleName]["policy"] = json.loads(PolicyDocument)

    class Service:
        def hcp(self, path: str, method: str = "GET", body: Any = None) -> Any:
            assert path.startswith(f"/workspaces/{authority.WORKSPACE}")
            if method == "GET":
                return {
                    "data": {
                        "attributes": {
                            "name": "enterprise-ai-bootstrap",
                            "execution-mode": "remote",
                            "auto-apply": False,
                        }
                    }
                }
            assert "/vars" in path
            attrs = body["data"]["attributes"]
            writes.append("HCPVariable")
            variables[attrs["key"]] = {"id": "var-" + attrs["key"], "attributes": attrs}
            return {}

        def hcp_pages(self, path: str) -> Any:
            if "/runs" in path:
                return []
            return list(variables.values())

        def current_state(self, workspace: str) -> Any:
            return {"id": "sv-exact", "serial": 4, "lineage": "same"}

    monkeypatch.setattr(authority, "Services", lambda *args: Service())
    monkeypatch.setattr(authority, "source_identity", lambda *args: {"commit": "a" * 40})
    monkeypatch.setattr(authority, "EVIDENCE", tmp_path)
    monkeypatch.setattr(
        authority.boto3, "Session", lambda **kwargs: SimpleNamespace(client=lambda _: Client())
    )
    values = {
        "state_bucket_name": "test-bucket",
        "lock_table_name": "test-lock",
        "state_kms_key_arn": (
            "arn:aws:kms:ap-southeast-1:526338061652:key/11111111-1111-1111-1111-111111111111"
        ),
    }
    monkeypatch.setattr(authority, "output", lambda s, state, key: values[key])
    args = SimpleNamespace(
        plan=tmp_path / "review.json", profile="existing-sso", purpose="refresh", apply=False
    )
    authority.run(args)
    assert writes == []
    saved = json.loads(args.plan.read_bytes())
    monkeypatch.setattr("builtins.input", lambda _: "SETUP BOOTSTRAP AUTHORITY " + saved["sha256"])
    args.apply = True
    authority.run(args)
    assert writes == [
        "CreateRole",
        "PutRolePolicy",
        "CreateRole",
        "PutRolePolicy",
        "HCPVariable",
        "HCPVariable",
        "HCPVariable",
    ]
    assert variables["TFC_AWS_PROVIDER_AUTH"]["attributes"]["value"] == "true"
    assert len(roles) == 2
    result = json.loads(args.plan.with_suffix(".result.json").read_bytes())
    assert result["TerraformRunCreated"] is False
    assert result["ApplyRequested"] is False
    # Replanning after successful/partial setup does not create duplicate identities.
    args.plan = tmp_path / "review2.json"
    args.apply = False
    authority.run(args)
    saved = json.loads(args.plan.read_bytes())
    args.apply = True
    authority.run(args)
    assert len(writes) == 7
