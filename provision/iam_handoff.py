"""State-bound IAM refreshes. All writes remain HCP runs, never local AWS IAM calls."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from provision.services import ServiceError, Services

BOOTSTRAP_STAGES = {"bootstrap-bind-seed", "bootstrap-bind-complete"}
TARGETS = {
    "identity-seed": ["module.network.aws_vpc.this", "module.kms.aws_kms_key.this"],
    "network-seed": [
        "module.network.aws_default_security_group.restricted",
        "module.network.aws_subnet.private",
        "module.network.aws_route_table.private",
        "module.network.aws_security_group.endpoints",
    ],
}
PRIOR = {
    "bootstrap-bind-seed": "identity-seed",
    "network-seed": "bootstrap-bind-seed",
    "bootstrap-bind-complete": "network-seed",
    "base": "bootstrap-bind-complete",
}
PREFIX = "arn:aws:ec2:ap-southeast-1:526338061652:"
KINDS = {
    "sandbox_vpc_arn": "vpc/vpc-",
    "sandbox_default_security_group_arn": "security-group/sg-",
    "sandbox_endpoint_security_group_arn": "security-group/sg-",
    "sandbox_route_table_arn": "route-table/rtb-",
    "sandbox_subnet_a_arn": "subnet/subnet-",
    "sandbox_subnet_b_arn": "subnet/subnet-",
}
SEED_KEYS = {"sandbox_vpc_arn", "sandbox_default_security_group_arn", "sandbox_kms_key_arn"}
FULL_KEYS = set(KINDS) | {"sandbox_kms_key_arn"}
ENDPOINT_SID = "CreateVpcEndpointsUsingExactSandboxBindings"


def timestamp(value: str) -> datetime:
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if result.utcoffset() != timedelta(0):
            raise ValueError
        return result
    except (ValueError, TypeError) as exc:
        raise ServiceError("IAM_UTC_TIMESTAMP_REQUIRED") from exc


def validate_bindings(values: dict[str, str], phase: str, issued: str) -> None:
    required = (SEED_KEYS if phase == "seed" else FULL_KEYS) | {
        "administrator_role_arn",
        "administrator_trust_expires_at",
        "workload_expires_at",
        "bedrock_model_id",
    }
    if phase not in {"seed", "complete"} or set(values) != required:
        raise ServiceError("IAM_BINDING_KEYS_MISMATCH")
    for key in required & FULL_KEYS:
        pattern = (
            r"arn:aws:kms:ap-southeast-1:526338061652:key/[a-f0-9-]{36}"
            if key == "sandbox_kms_key_arn"
            else re.escape(PREFIX + KINDS[key]) + r"[a-f0-9]+"
        )
        if not re.fullmatch(pattern, values[key]):
            raise ServiceError("IAM_PHYSICAL_BINDING_INVALID_" + key)
    if not re.fullmatch(
        r"arn:aws:iam::526338061652:role/[\w+=,.@/-]+", values["administrator_role_arn"]
    ):
        raise ServiceError("IAM_ADMINISTRATOR_BINDING_INVALID")
    if any(not v or re.search(r'["*?$\n\r]', v) for v in values.values()):
        raise ServiceError("IAM_BINDING_WILDCARD_OR_TEMPLATE_PROHIBITED")
    start, trust, expiry = map(
        timestamp, (issued, values["administrator_trust_expires_at"], values["workload_expires_at"])
    )
    if not start <= datetime.now(UTC) < trust <= expiry <= start + timedelta(hours=24):
        raise ServiceError("IAM_APPROVAL_WINDOW_INVALID")


def output(services: Services, state: dict[str, Any], name: str) -> Any:
    rows = services.hcp_pages(f"/state-versions/{state['id']}/outputs")
    matches = [r["attributes"] for r in rows if r.get("attributes", {}).get("name") == name]
    if len(matches) != 1 or matches[0].get("sensitive") is not False:
        raise ServiceError("IAM_FINALIZED_STATE_OUTPUT_REQUIRED_" + name)
    return matches[0]["value"]


def assert_source(services: Services, context: dict[str, Any], proof: dict[str, Any]) -> None:
    workspace = context["bindings"]["workspaces"]["sandbox"]
    if services.current_state(workspace) != proof["source_state"]:
        raise ServiceError("IAM_SANDBOX_SOURCE_STATE_CHANGED")
    terminal = {
        "applied",
        "planned_and_finished",
        "errored",
        "canceled",
        "force_canceled",
        "discarded",
    }
    if any(
        r["attributes"]["status"] not in terminal
        for r in services.hcp_pages(f"/workspaces/{workspace}/runs?page[size]=100")
    ):
        raise ServiceError("IAM_SANDBOX_CONCURRENT_RUN")


def prepare(
    services: Services, context: dict[str, Any], inputs: dict[str, Any], stage: str
) -> dict[str, Any]:
    """Read exact finalized outputs; no captured value is a new binding default."""
    phase = "seed" if stage == "bootstrap-bind-seed" else "complete"
    workspaces = context["bindings"]["workspaces"]
    state = services.current_state(workspaces["sandbox"])
    prior = context["results"].get("hcp", {}).get(PRIOR[stage], {})
    if not prior.get("complete") or prior.get("final_state") != state:
        raise ServiceError("IAM_PREREQUISITE_STATE_CHECKPOINT_REQUIRED")
    name = "platform_iam_seed_bindings" if phase == "seed" else "platform_iam_network_bindings"
    values = output(services, state, name)
    if not isinstance(values, dict) or set(values) != (SEED_KEYS if phase == "seed" else FULL_KEYS):
        raise ServiceError("IAM_PREREQUISITE_OUTPUT_INVALID")
    approved = inputs.get("iam_handoff", {})
    values = dict(
        values,
        administrator_role_arn=approved.get("administrator_role_arn", ""),
        bedrock_model_id=approved.get("bedrock_model_id", ""),
        administrator_trust_expires_at=context["expires_at"],
        workload_expires_at=approved.get("workload_expires_at", ""),
    )
    validate_bindings(values, phase, context["created_at"])
    bootstrap_state = services.current_state(workspaces["bootstrap"])
    try:
        previous = output(services, bootstrap_state, "platform_iam_applied_bindings")
    except ServiceError as exc:
        if exc.code != "IAM_FINALIZED_STATE_OUTPUT_REQUIRED_platform_iam_applied_bindings":
            raise
        # Historical literals are permitted only on the BEFORE side of delta comparison.
        previous = json.loads(
            (
                services.root / "infra/bootstrap/platform-iam-config/bindings.captured.json"
            ).read_bytes()
        )
    bootstrap_key = output(services, bootstrap_state, "state_kms_key_arn")
    proof = {
        "source_state": state,
        "bootstrap_state": bootstrap_state,
        "phase": phase,
        "values": values,
        "previous": previous,
        "bootstrap_key": bootstrap_key,
    }
    assert_source(services, context, proof)
    if services.current_state(workspaces["bootstrap"]) != bootstrap_state:
        raise ServiceError("IAM_BOOTSTRAP_STATE_CHANGED")
    return proof


def variables(context: dict[str, Any], stage: str) -> dict[str, Any]:
    proof = context["bindings"]["iam_handoffs"][stage]
    validate_bindings(proof["values"], proof["phase"], context["created_at"])
    state = proof["source_state"]
    return {
        "platform_iam_binding_overrides": proof["values"],
        "platform_iam_binding_phase": proof["phase"],
        "platform_iam_source_state": {
            "workspace_id": context["bindings"]["workspaces"]["sandbox"],
            "state_version_id": state["id"],
            "serial": state["serial"],
        },
        "platform_iam_approval_issued_at": context["created_at"],
        "adopt_existing_platform_iam": False,
    }


def render(root: Path, file: str, proof: dict[str, Any]) -> dict[str, Any]:
    values = (
        dict.fromkeys(FULL_KEYS, "")
        | proof["values"]
        | {"bootstrap_kms_key_arn": proof["bootstrap_key"]}
    )
    text = (root / "infra/bootstrap/platform-iam-config" / file).read_text(encoding="utf-8")
    # Preserve escaped AWS IAM policy variables rather than interpreting them as bindings.
    text = re.sub(r"(?<!\$)\$\{([a-z_]+)\}", lambda m: values[m[1]], text)
    document: dict[str, Any] = json.loads(text.replace("$${", "${"))
    if proof["phase"] == "seed":
        document["Statement"] = [s for s in document["Statement"] if s.get("Sid") != ENDPOINT_SID]
    return document


def rewritten(value: Any, replacements: dict[str, str], expiry: str) -> Any:
    if isinstance(value, dict):
        return {k: rewritten(v, replacements, expiry) for k, v in value.items()}
    if isinstance(value, list):
        return [rewritten(v, replacements, expiry) for v in value]
    if isinstance(value, str):
        if re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", value):
            return expiry
        for old, new in replacements.items():
            value = value.replace(old, new)
    return value


def validate_delta(root: Path, plan: dict[str, Any], proof: dict[str, Any]) -> None:
    """Source-template equality for HCP policies; binding-only rewrites for workload IAM.

    No new role, attachment, resource, policy action or trust principal is authorized.
    This is deliberately stricter than a general bootstrap provisioning plan.
    """
    manifest = json.loads(
        (root / "infra/bootstrap/platform-iam-config/hcp-resources.json").read_bytes()
    )
    imports = (root / "infra/bootstrap/platform_iam_imports.tf").read_text(encoding="utf-8")
    destinations = set(re.findall(r"^\s*to\s*=\s*(.+)$", imports, re.MULTILINE))
    governance = {
        "aws_dynamodb_table.terraform_lock",
        "aws_kms_key.terraform_state",
        "aws_s3_bucket.terraform_state",
        "terraform_data.owner_expiry_gate",
    }
    replacements = {
        v: proof["values"][k]
        for k, v in proof["previous"].items()
        if v and k in proof["values"] and k in FULL_KEYS | {"bedrock_model_id"}
    }
    for row in plan.get("resource_changes", []):
        if row.get("mode") != "managed" or row["change"]["actions"] == ["no-op"]:
            continue
        address, change = row["address"], row["change"]
        if address not in destinations | governance or change["actions"] != ["update"]:
            raise ServiceError("IAM_REFRESH_UNEXPECTED_ADDRESS_OR_ACTION")
        before, after = change["before"], change["after"]
        unknown = change.get("after_unknown", {})
        if any(v for k, v in unknown.items() if k not in {"output"}):
            raise ServiceError("IAM_REFRESH_UNKNOWN_AUTHORITY")
        for key in set(before) | set(after):
            old, new = before.get(key), after.get(key)
            if old == new:
                continue
            expiry = proof["values"]["workload_expires_at"]
            if key in {"tags", "tags_all"}:
                if dict(old or {}, ExpiresAt=expiry) == new:
                    continue
            if address == "terraform_data.owner_expiry_gate" and key in {"input", "output"}:
                if key == "output" and unknown.get("output"):
                    continue
                if new == expiry:
                    continue
            if key in {"policy", "assume_role_policy"}:
                file = None
                match = re.fullmatch(r'aws_iam_(policy|role|role_policy)\.hcp\["(.+)"\]', address)
                if match:
                    kind, name = match.groups()
                    file = (
                        manifest["inline_policies"][name]["file"]
                        if kind == "role_policy"
                        else name + (".trust.json.tftpl" if kind == "role" else ".json.tftpl")
                    )
                if file and json.loads(new) == render(root, file, proof):
                    continue
                if not file:
                    expiry = (
                        proof["values"]["administrator_trust_expires_at"]
                        if key == "assume_role_policy"
                        else expiry
                    )
                    if rewritten(json.loads(old), replacements, expiry) == json.loads(new):
                        continue
            raise ServiceError("IAM_REFRESH_NON_BINDING_DELTA_" + key)


def validate_seed(plan: dict[str, Any], stage: str) -> None:
    allowed = set(TARGETS["identity-seed"] + ["terraform_data.owner_expiry_gate"])
    if stage == "network-seed":
        allowed |= set(TARGETS[stage]) - {"module.network.aws_subnet.private"}
        allowed |= {f"module.network.aws_subnet.private[{i}]" for i in range(2)}
    for row in plan.get("resource_changes", []):
        if row.get("mode") != "managed" or row["change"]["actions"] == ["no-op"]:
            continue
        if row["address"] not in allowed or row["change"]["actions"] not in [
            ["create"],
            ["update"],
        ]:
            raise ServiceError("IAM_PREREQUISITE_PLAN_SCOPE_CHANGED")


def authority(services: Services, inputs: dict[str, Any], workspace: str) -> None:
    """Require explicit dedicated remote roles, exact HCP OIDC trust and owner binding.

    This does not manufacture a privileged execution role or claim that IAM simulation
    proves all service authorization. The external trust root is an owner prerequisite.
    """
    expected = inputs.get("bootstrap_execution", {})
    rows = services.hcp_pages(f"/workspaces/{workspace}/vars")
    for phase in ("plan", "apply"):
        arn = expected.get(phase + "_role_arn", "")
        if not re.fullmatch(r"arn:aws:iam::526338061652:role/[\w+=,.@/-]+", arn):
            raise ServiceError("OWNER_BOOTSTRAP_REMOTE_ROLE_BINDING_REQUIRED")
        name = arn.rsplit("/", 1)[-1]
        if name.startswith("enterprise-ai-capstone-hcp-"):
            raise ServiceError("BOOTSTRAP_MUST_NOT_SELF_ADMINISTER_WORKLOAD_ROLE")
        key = "TFC_AWS_" + phase.upper() + "_ROLE_ARN"
        matches = [
            r["attributes"]
            for r in rows
            if r.get("attributes", {}).get("key") == key
            and r["attributes"].get("category") == "env"
        ]
        if len(matches) != 1 or matches[0].get("value") != arn:
            raise ServiceError("BOOTSTRAP_REMOTE_EXECUTION_BINDING_MISMATCH")
        role = services.aws("iam", "get-role", "--role-name", name)["Role"]
        if role.get("Arn") != arn:
            raise ServiceError("BOOTSTRAP_REMOTE_ROLE_IDENTITY_MISMATCH")
        subject = (
            "organization:Enterprise_AI_AWS_Arch:project:enterprise-ai-capstone:workspace:enterprise-ai-bootstrap:run_phase:"
            + phase
        )
        if expected.get(phase + "_subject", subject) != subject:
            raise ServiceError("BOOTSTRAP_REMOTE_TRUST_SUBJECT_INVALID")
        statements = role.get("AssumeRolePolicyDocument", {}).get("Statement", [])
        wanted = {"app.terraform.io:aud": "aws.workload.identity", "app.terraform.io:sub": subject}
        if (
            len(statements) != 1
            or statements[0].get("Effect") != "Allow"
            or statements[0].get("Action")
            not in ("sts:AssumeRoleWithWebIdentity", ["sts:AssumeRoleWithWebIdentity"])
            or statements[0].get("Principal")
            != {"Federated": "arn:aws:iam::526338061652:oidc-provider/app.terraform.io"}
            or statements[0].get("Condition") != {"StringEquals": wanted}
        ):
            raise ServiceError("BOOTSTRAP_REMOTE_TRUST_MISMATCH")
        verify_authority_permissions(services, arn, phase)


def verify_authority_permissions(services: Services, arn: str, phase: str) -> None:
    """Read-only simulation of the existing-object IAM refresh surface.

    Positive simulation is a preflight, not a guarantee about SCPs or service context.
    Missing/indeterminate context is not treated as authorization.
    """
    imports = (services.root / "infra/bootstrap/platform_iam_imports.tf").read_text(
        encoding="utf-8"
    )
    identities = re.findall(r'^\s*id\s*=\s*"([^"\n]+)"', imports, re.MULTILINE)
    roles = sorted(
        {"arn:aws:iam::526338061652:role/" + i for i in identities if "/" not in i and ":" not in i}
    )
    manifest = json.loads(
        (services.root / "infra/bootstrap/platform-iam-config/hcp-resources.json").read_bytes()
    )
    policies = sorted(p["arn"] for p in manifest["policies"].values())
    if len(roles) != 17 or len(policies) != 13:
        raise ServiceError("BOOTSTRAP_AUTHORITY_INVENTORY_MISMATCH")
    groups = [
        (
            roles,
            [
                "iam:GetRole",
                "iam:ListRolePolicies",
                "iam:GetRolePolicy",
                "iam:ListAttachedRolePolicies",
                "iam:ListRoleTags",
            ],
        ),
        (policies, ["iam:GetPolicy", "iam:GetPolicyVersion", "iam:ListPolicyVersions"]),
    ]
    if phase == "apply":
        groups += [
            (
                roles,
                ["iam:UpdateAssumeRolePolicy", "iam:TagRole", "iam:UntagRole", "iam:PutRolePolicy"],
            ),
            (
                policies,
                [
                    "iam:CreatePolicyVersion",
                    "iam:DeletePolicyVersion",
                    "iam:SetDefaultPolicyVersion",
                ],
            ),
        ]
    for resources, actions in groups:
        response = services.aws(
            "iam",
            "simulate-principal-policy",
            "--policy-source-arn",
            arn,
            "--action-names",
            *actions,
            "--resource-arns",
            *resources,
        )
        results = response.get("EvaluationResults", [])
        if {r.get("EvalActionName") for r in results} != set(actions):
            raise ServiceError("BOOTSTRAP_REMOTE_PERMISSION_SIMULATION_INCOMPLETE")
        for row in results:
            specific = row.get("ResourceSpecificResults", [])
            if (
                row.get("EvalDecision") != "allowed"
                or row.get("MissingContextValues")
                or {r.get("EvalResourceName") for r in specific} != set(resources)
                or any(
                    r.get("EvalResourceDecision") != "allowed" or r.get("MissingContextValues")
                    for r in specific
                )
            ):
                raise ServiceError("BOOTSTRAP_REMOTE_PERMISSION_GAP_" + row["EvalActionName"])


def review_policy(
    root: Path,
    inputs: dict[str, Any],
    plan: dict[str, Any],
    context: dict[str, Any],
    step: dict[str, Any],
) -> str:
    """Dedicated OPA check after source-template/delta validation, without exceptions."""
    executable = Path(inputs["opa"]["path"]).resolve(strict=True)
    if hashlib.sha256(executable.read_bytes()).hexdigest() != inputs["opa"]["sha256"]:
        raise ServiceError("OPA_EXECUTABLE_DIGEST_MISMATCH")
    version = subprocess.run(  # noqa: S603 -- owner-bound executable digest verified
        [str(executable), "version"], capture_output=True, timeout=30, check=False
    )
    if version.returncode or version.stdout.splitlines()[:1] != [b"Version: 1.20.0"]:
        raise ServiceError("OPA_VERSION_MISMATCH")
    policy = root / "policies/opa/iam_binding_refresh.rego"
    policy_sha = hashlib.sha256(policy.read_bytes()).hexdigest()
    payload = {
        "plan": plan,
        "stage": step["stage"],
        "source_state": context["bindings"]["iam_handoffs"][step["stage"]]["source_state"],
        "expires_at": context["expires_at"],
        "evaluation_time": datetime.now(UTC).isoformat(),
    }
    result = subprocess.run(  # noqa: S603 -- verified OPA, tracked policy, stdin only
        [
            str(executable),
            "eval",
            "--format=json",
            "--stdin-input",
            "--data",
            str(policy),
            "data.enterprise_ai.iam_refresh.allow",
        ],
        input=json.dumps(payload).encode(),
        capture_output=True,
        timeout=120,
        check=False,
    )
    try:
        rows = json.loads(result.stdout)["result"]
        allowed = (
            len(rows) == 1
            and len(rows[0]["expressions"]) == 1
            and rows[0]["expressions"][0]["value"] is True
        )
    except (KeyError, ValueError, TypeError):
        allowed = False
    if result.returncode or not allowed:
        raise ServiceError("OPA_IAM_REFRESH_DENIED")
    if hashlib.sha256(policy.read_bytes()).hexdigest() != policy_sha:
        raise ServiceError("OPA_POLICY_CHANGED")
    return policy_sha
