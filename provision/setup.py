"""Inspect retained setup; repair only explicitly described missing settings."""

from __future__ import annotations

import json
import os
import re
from collections.abc import Callable
from functools import partial
from pathlib import Path
from typing import Any
from urllib.parse import quote

from tools import capstone_release as release
from tools.platformctl.contracts import ContractError
from tools.platformctl.policy_runner import capstone_source_commit

from provision import iam_handoff
from provision.services import ServiceError, Services, command, relationship


def source_identity(services: Services) -> dict[str, str]:
    root = services.root
    top = Path(command(["git", "rev-parse", "--show-toplevel"], root)).resolve()
    common = Path(command(["git", "rev-parse", "--path-format=absolute", "--git-common-dir"], root))
    if top != root.resolve() or common.resolve() != (root / ".git").resolve():
        raise ServiceError("MAIN_TRACKED_CHECKOUT_REQUIRED")
    if command(["git", "branch", "--show-current"], root) != "main":
        raise ServiceError("MAIN_BRANCH_REQUIRED")
    # Operational source must be the reviewed bytes. Ignored reports/private inputs are excluded.
    if command(["git", "status", "--porcelain", "--untracked-files=normal"], root):
        raise ServiceError("TRACKED_MAIN_MUST_BE_CLEAN")
    commit = command(["git", "rev-parse", "HEAD"], root)
    tree = command(["git", "rev-parse", "HEAD^{tree}"], root)
    remote = services.github("/git/ref/heads/main")
    if remote.get("object", {}).get("sha") != commit:
        raise ServiceError("PROTECTED_MAIN_COMMIT_MISMATCH")
    # Git's clean filter can hide CRLF/LF differences. The OPA source contract
    # compares exact bytes; detect that mismatch before setup or an HCP run.
    try:
        with capstone_source_commit(commit, tree):
            pass
    except ContractError as exc:
        raise ServiceError("SOURCE_BYTES_DO_NOT_MATCH_REVIEWED_COMMIT_CHECK_LF_CHECKOUT") from exc
    return {"commit": commit, "tree": tree}


def missing_get(call: Callable[..., Any], path: str) -> Any:
    try:
        return call(path)
    except release.ReleaseError as exc:
        if exc.code not in {"HCP_HTTP_404", "GITHUB_HTTP_404"}:
            raise
        return None


def value_of(spec: dict[str, Any]) -> str:
    if "from_env" in spec:
        value = os.environ.get(spec["from_env"], "")
        if not value:
            raise ServiceError("SETUP_VALUE_UNAVAILABLE_" + spec["from_env"])
        return value
    if "value" not in spec:
        raise ServiceError("MISSING_OWNER_SETUP_VALUE")
    value = spec["value"]
    return json.dumps(value, separators=(",", ":")) if spec.get("hcl") else str(value)


def ensure_setup(
    services: Services,
    inputs: dict[str, Any],
    *,
    repair: bool,
    approve: Callable[[str], None],
    login: bool,
) -> dict[str, Any]:
    """Never update an existing variable. Missing authoritative values remain owner inputs."""
    config = release._config()
    summary: dict[str, Any] = {
        "existing": [],
        "created": [],
        "missing": [],
        "mismatched": [],
        "deferred": [],
    }

    def create(label: str, action: Callable[[], Any]) -> None:
        if not repair:
            summary["missing"].append(label)
            return
        approve("CREATE MISSING " + label)
        action()  # No write retry. A subsequent prepare re-reads before creating anything.
        summary["created"].append(label)

    try:
        caller = services.aws("sts", "get-caller-identity")
    except ServiceError:
        if not login:
            raise ServiceError("AWS_SESSION_UNAVAILABLE_USE_PREPARE_LOGIN") from None
        approve("ACTIVATE AWS SSO " + services.profile)
        command(["aws", "sso", "login", "--profile", services.profile], services.root, timeout=300)
        caller = services.aws("sts", "get-caller-identity")
    if caller.get("Account") != "526338061652":
        raise ServiceError("AWS_ACCOUNT_MISMATCH")
    summary["aws_account"] = caller["Account"]
    # A personal IDE token is valid for owner-led plans; workflow automation needs service identity.
    identity = services.hcp("/account/details")["data"]
    if identity.get("type") != "users" or not identity.get("id"):
        raise ServiceError("HCP_ACCOUNT_IDENTITY_INVALID")
    summary["hcp_identity_verified"] = True
    auth = identity.get("relationships", {}).get("authenticated-resource", {}).get("data", {})
    service_identity = bool(
        identity.get("attributes", {}).get("is-service-account") and auth.get("type") == "teams"
    )
    summary["workflow_automation_identity"] = (
        "TEAM_SERVICE_IDENTITY" if service_identity else "OWNER_PERSONAL_IDENTITY"
    )
    if service_identity:
        os.environ["W12_HCP_OWNER_TEAM_ID"] = auth["id"]
        os.environ["W12_HCP_SERVICE_USER_ID"] = identity["id"]

    organization = quote(config["hcp_organization"], safe="")
    project_name = config["hcp_project"]
    projects = services.hcp_pages(f"/organizations/{organization}/projects?page[size]=100")
    projects = [p for p in projects if p["attributes"].get("name") == project_name]
    if not projects:
        create(
            "HCP_PROJECT",
            lambda: services.hcp(
                f"/organizations/{organization}/projects",
                "POST",
                {"data": {"type": "projects", "attributes": {"name": project_name}}},
            ),
        )
        projects = [
            p
            for p in services.hcp_pages(f"/organizations/{organization}/projects")
            if p["attributes"].get("name") == project_name
        ]
    if len(projects) != 1:
        raise ServiceError("HCP_PROJECT_SETUP_REQUIRED")
    workspaces: dict[str, str] = {}
    for target, directory in (
        ("bootstrap", "infra/bootstrap"),
        ("sandbox", "infra/environments/sandbox"),
    ):
        name = config[f"hcp_{target}_workspace"]
        path = f"/organizations/{organization}/workspaces/{quote(name)}"
        workspace = missing_get(services.hcp, path)
        if workspace is None:
            vcs = inputs.get("vcs_connection", {})
            if not (vcs.get("oauth-token-id") or vcs.get("github-app-installation-id")):
                raise ServiceError("OWNER_VCS_CONNECTION_REQUIRED")
            body = {
                "data": {
                    "type": "workspaces",
                    "attributes": {
                        "name": name,
                        "auto-apply": False,
                        "execution-mode": "remote",
                        "working-directory": directory,
                        "terraform-version": "1.16.1",
                        "vcs-repo": {**vcs, "identifier": config["repository"], "branch": "main"},
                    },
                    "relationships": {
                        "project": {"data": {"id": projects[0]["id"], "type": "projects"}}
                    },
                }
            }
            create(
                "HCP_WORKSPACE_" + target,
                partial(services.hcp, f"/organizations/{organization}/workspaces", "POST", body),
            )
            workspace = missing_get(services.hcp, path)
        if workspace is None:
            raise ServiceError("HCP_WORKSPACE_SETUP_REQUIRED")
        data, attrs = workspace["data"], workspace["data"]["attributes"]
        expected = {
            "auto-apply": False,
            "execution-mode": "remote",
            "working-directory": directory,
            "terraform-version": "1.16.1",
        }
        if (
            any(attrs.get(k) != v for k, v in expected.items())
            or (relationship(data, "project") != projects[0]["id"])
            or attrs.get("vcs-repo", {}).get("identifier") != config["repository"]
            or (attrs.get("vcs-repo", {}).get("branch") != "main")
        ):
            raise ServiceError("HCP_WORKSPACE_CONFIGURATION_MISMATCH_" + target)
        workspaces[target] = data["id"]
        existing = services.hcp_pages(f"/workspaces/{data['id']}/vars")
        specs = inputs.get("hcp_variables", {}).get(target, {})
        required_env = {"TFC_AWS_PROVIDER_AUTH", "TFC_AWS_PLAN_ROLE_ARN", "TFC_AWS_APPLY_ROLE_ARN"}
        # Include every required (no default) variable from the tracked Terraform root.
        required_tf = required_variables(services.root / directory)
        for name in sorted(required_tf | required_env | set(specs)):
            category = (
                "env" if name in required_env else specs.get(name, {}).get("category", "terraform")
            )
            matches = [
                v
                for v in existing
                if v["attributes"].get("key") == name
                and v["attributes"].get("category") == category
            ]
            label = f"HCP_VARIABLE_{target}_{name}"
            if len(matches) > 1:
                raise ServiceError("DUPLICATE_" + label)
            if matches:
                summary["existing"].append(label)
                # Verify metadata and owner-declared expected values, without overwriting.
                if name in specs and not matches[0]["attributes"].get("sensitive"):
                    if matches[0]["attributes"].get("value") != value_of(specs[name]):
                        summary["mismatched"].append(label)
                continue
            if name not in specs:
                summary["missing"].append(label)
                continue
            spec = specs[name]
            attrs_var = {
                "key": name,
                "category": category,
                "value": value_of(spec),
                "hcl": bool(spec.get("hcl")),
                "sensitive": bool(spec.get("from_env")),
            }
            create(
                label,
                partial(
                    services.hcp,
                    f"/workspaces/{data['id']}/vars",
                    "POST",
                    {"data": {"type": "vars", "attributes": attrs_var}},
                ),
            )
            if repair:
                check = [
                    v["attributes"]
                    for v in services.hcp_pages(f"/workspaces/{data['id']}/vars")
                    if v["attributes"].get("key") == name
                    and v["attributes"].get("category") == category
                ]
                if len(check) != 1 or any(
                    check[0].get(k) != attrs_var[k] for k in ("hcl", "sensitive")
                ):
                    raise ServiceError("HCP_CREATED_VARIABLE_READBACK_FAILED")
                if not attrs_var["sensitive"] and check[0].get("value") != attrs_var["value"]:
                    raise ServiceError("HCP_CREATED_VARIABLE_VALUE_MISMATCH")
        if target in {"sandbox", "bootstrap"}:
            tasks = services.hcp_pages(f"/workspaces/{data['id']}/tasks?include=task")

            def task_matches(task: dict[str, Any]) -> bool:
                task_id = relationship(task, "task")
                if not task_id:
                    return False
                actual = services.hcp(f"/tasks/{task_id}")["data"]["attributes"]
                attrs_task = task.get("attributes", {})
                return (
                    actual.get("name") == "Infracost"
                    and actual.get("enabled") is True
                    and attrs_task.get("enforcement-level") == "mandatory"
                    and "post_plan" in attrs_task.get("stages", [])
                )

            if not any(task_matches(t) for t in tasks):
                spec = inputs.get("infracost_task_id")
                if spec:
                    create(
                        "HCP_INFRACOST_TASK",
                        partial(
                            services.hcp,
                            f"/workspaces/{data['id']}/tasks",
                            "POST",
                            {
                                "data": {
                                    "type": "workspace-tasks",
                                    "attributes": {
                                        "enforcement-level": "mandatory",
                                        "stages": ["post_plan"],
                                    },
                                    "relationships": {
                                        "task": {"data": {"id": spec, "type": "tasks"}}
                                    },
                                }
                            },
                        ),
                    )
                    if repair and not any(
                        task_matches(t)
                        for t in services.hcp_pages(f"/workspaces/{data['id']}/tasks")
                    ):
                        raise ServiceError("INFRACOST_SETUP_READBACK_FAILED")
                else:
                    summary["missing"].append("HCP_INFRACOST_TASK")

    branch = services.github("/branches/main")
    if branch.get("protected") is not True:
        spec = inputs.get("main_protection")
        if spec:
            create(
                "GITHUB_MAIN_PROTECTION",
                lambda: services.github("/branches/main/protection", "PUT", spec),
            )
            if repair and services.github("/branches/main").get("protected") is not True:
                raise ServiceError("MAIN_PROTECTION_READBACK_FAILED")
        else:
            summary["missing"].append("GITHUB_MAIN_PROTECTION")
    environment = missing_get(services.github, "/environments/sandbox")
    if environment is None:
        spec = inputs.get("sandbox_protection")
        if not spec or not spec.get("reviewers"):
            summary["missing"].append("GITHUB_SANDBOX_REVIEWERS")
        else:
            create(
                "GITHUB_SANDBOX_ENVIRONMENT",
                lambda: services.github("/environments/sandbox", "PUT", spec),
            )
            environment = missing_get(services.github, "/environments/sandbox")
    if environment and not any(
        r.get("type") == "required_reviewers" and r.get("reviewers")
        for r in environment.get("protection_rules", [])
    ):
        summary["mismatched"].append("GITHUB_SANDBOX_REQUIRED_REVIEWERS")
    permissions = services.github("/actions/permissions")
    if permissions.get("enabled") is not True:
        summary["mismatched"].append("GITHUB_ACTIONS_DISABLED")
    for workflow in ("capstone-release.yml", "w12-prerequisite-images.yml"):
        metadata = services.github(f"/actions/workflows/{workflow}")
        if metadata.get("state") != "active":
            summary["mismatched"].append("GITHUB_WORKFLOW_INACTIVE_" + workflow)
    variables = {v["name"]: v for v in services.github_pages("/actions/variables", "variables")}
    secrets = {v["name"] for v in services.github_pages("/actions/secrets", "secrets")}
    for workflow in ("capstone-release.yml", "w12-prerequisite-images.yml"):
        text = (services.root / ".github/workflows" / workflow).read_text(encoding="utf-8")
        for kind, names in (
            ("variables", set(re.findall(r"vars\.([A-Z][A-Z0-9_]+)", text))),
            ("secrets", set(re.findall(r"secrets\.([A-Z][A-Z0-9_]+)", text))),
        ):
            for name in sorted(names):
                label = "GITHUB_" + kind.upper() + "_" + name
                known = variables if kind == "variables" else secrets
                if name in known:
                    summary["existing"].append(label)
                    expected_spec = inputs.get("github_" + kind, {}).get(name)
                    if (
                        kind == "variables"
                        and expected_spec
                        and variables[name].get("value") != value_of(expected_spec)
                    ):
                        summary["mismatched"].append(label)
                    continue
                if kind == "variables" and name in {
                    "W12_BUILD_TOOLCHAIN_DIGEST",
                    "W12_ROOT_FINGERPRINT_SHA256",
                    "W12_TRUST_BUNDLE_SHA256",
                    "W12_SOURCE_BUCKET",
                    "W12_RELEASE_KMS_KEY_ARN",
                }:
                    summary["deferred"].append(label + "_CREATED_BY_PROVISION_BINDING_STAGE")
                    continue
                spec = inputs.get("github_" + kind, {}).get(name)
                if not spec:
                    summary["missing"].append(label)
                    continue
                value = value_of(spec)
                if kind == "secrets":
                    if name in {"TFC_TOKEN", "TFC_READ_TOKEN"}:
                        account = release._hcp_request("GET", "/account/details", value)[1]["data"]
                        if account.get("attributes", {}).get("is-service-account") is not True:
                            raise ServiceError("WORKFLOW_HCP_TEAM_SERVICE_IDENTITY_REQUIRED")
                    create(
                        label,
                        partial(
                            command,
                            ["gh", "secret", "set", name, "--repo", config["repository"]],
                            services.root,
                            stdin=value,
                        ),
                    )
                    if repair:
                        if name not in {
                            s["name"] for s in services.github_pages("/actions/secrets", "secrets")
                        }:
                            raise ServiceError("GITHUB_CREATED_SECRET_METADATA_MISSING")
                        secrets.add(name)
                else:
                    create(
                        label,
                        partial(
                            services.github,
                            "/actions/variables",
                            "POST",
                            {"name": name, "value": value},
                        ),
                    )
                    if repair:
                        actual = services.github(f"/actions/variables/{name}")
                        if actual.get("value") != value:
                            raise ServiceError("GITHUB_CREATED_VARIABLE_READBACK_FAILED")
                        variables[name] = actual
    if not inputs.get("bootstrap_execution"):
        summary["missing"].append("OWNER_BOOTSTRAP_REMOTE_EXECUTION_BINDINGS")
    else:
        try:
            iam_handoff.authority(services, inputs, workspaces["bootstrap"])
            summary["existing"].append("DEDICATED_BOOTSTRAP_REMOTE_EXECUTION_TRUST")
        except ServiceError as exc:
            summary["mismatched"].append(exc.code)
    summary["workspaces"] = workspaces
    summary["encrypted_value_verification"] = "NOT_READABLE_BY_API_WORKFLOW_VERIFIES_AT_USE"
    summary["classification"] = (
        "PASS" if not summary["missing"] and not summary["mismatched"] else "FAIL"
    )
    return summary


def required_variables(directory: Path) -> set[str]:
    """Conservative declaration lexer, not an HCL evaluator.

    Ignore strings/comments and track block depth so validation/default objects do
    not truncate declarations. Unsupported heredocs fail closed for setup review.
    Terraform itself remains the type/value validator in the remote plan.
    """
    names: set[str] = set()
    for path in directory.glob("*.tf"):
        source = path.read_text(encoding="utf-8")
        tokens = re.findall(
            r'"(?:\\.|[^"\\])*"|/\*[\s\S]*?\*/|//[^\n]*|\#[^\n]*|[A-Za-z_][A-Za-z_0-9]*|<<-?|[{}=]',
            source,
        )
        position = 0
        while position < len(tokens):
            if tokens[position] != "variable":
                position += 1
                continue
            name = json.loads(tokens[position + 1])
            if tokens[position + 2] != "{":
                raise ServiceError("TERRAFORM_VARIABLE_DECLARATION_INVALID")
            position += 3
            depth, has_default = 1, False
            while depth and position < len(tokens):
                lexeme = tokens[position]
                if lexeme.startswith("<<"):
                    raise ServiceError("VARIABLE_HEREDOC_REQUIRES_EXPLICIT_SETUP_CONTRACT")
                if depth == 1 and lexeme == "default" and tokens[position + 1] == "=":
                    has_default = True
                depth += (lexeme == "{") - (lexeme == "}")
                position += 1
            if depth:
                raise ServiceError("TERRAFORM_VARIABLE_UNCLOSED")
            if not has_default:
                names.add(name)
    return names
