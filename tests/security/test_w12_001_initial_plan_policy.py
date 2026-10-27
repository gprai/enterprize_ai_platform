"""Fail-closed checks for the W12 initial HCP plan review boundary."""

from __future__ import annotations

import json
import shutil
import subprocess
from collections.abc import Iterator
from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path

import pytest
from tools.platformctl.contracts import ContractError
from tools.platformctl.policy_runner import (
    PLATFORM_POLICY_DOCUMENT_BINDINGS,
    POLICY_IDS,
    _policy_document_binding,
    capstone_source_commit,
    normalize_plan,
)

from tests.security.test_w5_004_lifecycle_security import ecr_kms_reference_plan

ROOT = Path(__file__).resolve().parents[2]
OPA = Path(r"E:\AI\.tools\opa\1.20.0\opa.exe")


@contextmanager
def _current_reviewed_source() -> Iterator[None]:
    git_executable = shutil.which("git")
    if git_executable is None:
        pytest.skip("Git executable is required for source-bound plan review")
    commit = subprocess.run(  # noqa: S603 -- exact local Git source identity
        [git_executable, "rev-parse", "HEAD"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    ).stdout.strip()
    tree = subprocess.run(  # noqa: S603 -- exact local Git tree identity
        [git_executable, "rev-parse", "HEAD^{tree}"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    ).stdout.strip()
    with capstone_source_commit(commit, tree):
        yield


def _opa_value(plan: dict[str, object], query: str) -> object:
    if not OPA.is_file():
        pytest.skip("owner-controlled OPA 1.20.0 executable is absent")
    result = subprocess.run(  # noqa: S603 -- fixed owner-controlled executable
        [
            str(OPA),
            "eval",
            "--format=json",
            "--stdin-input",
            "--data",
            str(ROOT / "policies/opa/terraform_plan.rego"),
            query,
        ],
        input=json.dumps(plan),
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    evaluation = json.loads(result.stdout)
    if "result" not in evaluation:
        return False
    expressions = evaluation["result"][0]["expressions"]
    assert len(expressions) == 1
    return expressions[0]["value"]


@pytest.mark.parametrize("module_name", ("w12_toolchain_ecr", "w12_codebuild_ecr"))
def test_exact_w12_ecr_kms_reference_normalizes_only_verified_source(
    module_name: str,
) -> None:
    plan = ecr_kms_reference_plan()
    root = plan["configuration"]["root_module"]
    root["module_calls"][module_name] = root["module_calls"].pop("ecr")
    repository = plan["resource_changes"][1]
    repository["address"] = f"module.{module_name}.aws_ecr_repository.this"

    with pytest.raises(ContractError, match="policy-critical unknown"):
        normalize_plan(plan, evaluation_time="2026-10-27T01:00:00Z")

    with _current_reviewed_source():
        normalized = normalize_plan(plan, evaluation_time="2026-10-27T01:00:00Z")
    bindings = normalized["evaluation_context"]["resource_reference_unknowns"]
    assert bindings == [
        {
            "address": repository["address"],
            "type": "aws_ecr_repository",
            "unknown_paths": ["encryption_configuration[].kms_key"],
            "source_addresses": ["module.kms.aws_kms_key.this"],
            "relationship": "platform-ecr-kms-key-reference",
        }
    ]

    root["module_calls"][module_name]["expressions"]["kms_key_arn"] = {
        "references": ["module.other.key_arn", "module.other"]
    }
    with _current_reviewed_source(), pytest.raises(ContractError, match="policy-critical unknown"):
        normalize_plan(plan, evaluation_time="2026-10-27T01:00:00Z")


@pytest.mark.parametrize(
    ("consumer", "document"),
    (
        ("capstone_build", "capstone_build"),
        ("capstone_codebuild", "capstone_codebuild"),
        ("capstone_deploy_caller", "github_eks_deployment"),
        ("capstone_rollback_reader", "capstone_rollback_reader"),
        ("github_eks_deployment", "github_eks_deployment"),
    ),
)
def test_w12_iam_document_binding_is_exact_and_rejects_substitution(
    consumer: str, document: str
) -> None:
    consumer_address = f"module.iam.aws_iam_role_policy.{consumer}"
    document_address = f"module.iam.data.aws_iam_policy_document.{document}"
    binding = {
        "resource_address": consumer_address,
        "resource_type": "aws_iam_role_policy",
        "field_path": "policy",
        "policy_document_address": document_address,
        "relationship": "exact-policy-document",
    }
    plan = {
        "format_version": "1.2",
        "terraform_version": "1.16.1",
        "variables": {"aws_region": {"value": "ap-southeast-1"}},
        "evaluation_context": {
            "evaluation_time": "2026-10-27T01:00:00Z",
            "policy_ids": list(POLICY_IDS),
            "policy_document_bindings": [binding],
        },
        "resource_changes": [
            {
                "address": consumer_address,
                "type": "aws_iam_role_policy",
                "change": {"actions": ["create"], "after": {"policy": None}},
            },
            {
                "address": document_address,
                "type": "aws_iam_policy_document",
                "change": {
                    "actions": ["read"],
                    "before": None,
                    "after": {},
                    "after_unknown": {"json": True},
                    "after_sensitive": {},
                },
            },
        ],
    }
    findings = _opa_value(plan, "data.enterprise_ai.terraform.plan.findings")
    assert "W5-PLAN-001" not in {item["policy_id"] for item in findings}

    forged = deepcopy(plan)
    forged["evaluation_context"]["policy_document_bindings"][0]["policy_document_address"] = (
        "module.iam.data.aws_iam_policy_document.unrelated"
    )
    findings = _opa_value(forged, "data.enterprise_ai.terraform.plan.findings")
    assert "W5-PLAN-001" in {item["policy_id"] for item in findings}


@pytest.mark.parametrize(
    "consumer",
    (
        "capstone_build",
        "capstone_codebuild",
        "capstone_deploy_caller",
        "capstone_rollback_reader",
        "github_eks_deployment",
    ),
)
def test_w12_iam_normalizer_proves_document_source_and_sids(consumer: str) -> None:
    address = f"module.iam.aws_iam_role_policy.{consumer}"
    _type, document_address, sids = PLATFORM_POLICY_DOCUMENT_BINDINGS[(address, "policy")]
    document_name = document_address.rsplit(".", 1)[1]
    item = {
        "address": address,
        "type": "aws_iam_role_policy",
        "change": {"actions": ["create"], "after": {"policy": None}},
    }
    raw = {
        "configuration": {
            "root_module": {
                "resources": [],
                "module_calls": {
                    "iam": {
                        "expressions": {},
                        "module": {
                            "resources": [
                                {
                                    "address": f"aws_iam_role_policy.{consumer}",
                                    "mode": "managed",
                                    "type": "aws_iam_role_policy",
                                    "expressions": {
                                        "policy": {
                                            "references": [
                                                f"data.aws_iam_policy_document.{document_name}.json",
                                                f"data.aws_iam_policy_document.{document_name}",
                                            ]
                                        }
                                    },
                                },
                                {
                                    "address": f"data.aws_iam_policy_document.{document_name}",
                                    "mode": "data",
                                    "type": "aws_iam_policy_document",
                                    "expressions": {
                                        "statement": [
                                            {"sid": {"constant_value": sid}} for sid in sorted(sids)
                                        ]
                                    },
                                },
                            ]
                        },
                    }
                },
            }
        },
        "resource_changes": [
            item,
            {
                "address": document_address,
                "type": "aws_iam_policy_document",
                "change": {
                    "actions": ["read"],
                    "after": {},
                    "after_unknown": {"json": True},
                    "after_sensitive": {},
                },
            },
        ],
    }
    assert _policy_document_binding(raw, item, "policy") == {
        "resource_address": address,
        "resource_type": "aws_iam_role_policy",
        "field_path": "policy",
        "policy_document_address": document_address,
        "relationship": "exact-policy-document",
    }
    raw["configuration"]["root_module"]["module_calls"]["iam"]["module"]["resources"][1][
        "expressions"
    ]["statement"][0]["sid"]["constant_value"] = "UnreviewedPermission"
    assert _policy_document_binding(raw, item, "policy") is None


def _initial_profile_plan() -> dict[str, object]:
    return {
        "format_version": "1.2",
        "terraform_version": "1.16.1",
        "variables": {"aws_region": {"value": "ap-southeast-1"}},
        "evaluation_context": {
            "evaluation_time": "2026-10-27T01:00:00Z",
            "policy_ids": list(POLICY_IDS),
            "operation": {
                "schema_version": "w12-001.plan-review.v1",
                "action": "PLAN_REVIEW",
                "profile": "INITIAL_EMPTY_STATE",
                "record_sha256": "a" * 64,
                "source_commit": "b" * 40,
                "source_tree": "c" * 40,
                "configuration_version_id": "cv-Exact1",
                "run_id": "run-Exact1",
                "plan_id": "plan-Exact1",
                "plan_json_sha256": "d" * 64,
                "workspace": "enterprise-ai-sandbox",
                "input_state_version_id": None,
            },
        },
        "resource_changes": [
            {
                "address": "module.network.aws_vpc.this",
                "type": "aws_vpc",
                "change": {
                    "actions": ["create"],
                    "before": None,
                    "after": {"tags": {}},
                    "after_unknown": {},
                    "after_sensitive": {},
                },
            }
        ],
    }


def test_w12_initial_profile_requires_bound_identity_and_no_existing_state() -> None:
    plan = _initial_profile_plan()
    query = "data.enterprise_ai.terraform.plan.w12_initial_plan_review_profile_valid"
    assert _opa_value(plan, query) is True

    for field, value in (
        ("action", "APPLY"),
        ("record_sha256", "not-a-digest"),
        ("input_state_version_id", "sv-present"),
    ):
        changed = deepcopy(plan)
        changed["evaluation_context"]["operation"][field] = value
        assert _opa_value(changed, query) is False

    for actions in (["update"], ["delete"], ["delete", "create"]):
        changed = deepcopy(plan)
        changed["resource_changes"][0]["change"]["actions"] = actions
        assert _opa_value(changed, query) is False

    changed = deepcopy(plan)
    changed["resource_changes"][0]["change"]["after_unknown"] = {"vpc_id": True}
    assert _opa_value(changed, query) is False


def test_w12_initial_profile_is_required_by_production_decision() -> None:
    plan = _initial_profile_plan()
    query = "data.enterprise_ai.terraform.plan.decision"
    decision = _opa_value(plan, query)
    assert not any(
        finding["resource_address"] == "policy.operation" for finding in decision["findings"]
    )
    del plan["evaluation_context"]["operation"]
    decision = _opa_value(plan, query)
    assert any(
        finding["resource_address"] == "policy.operation" for finding in decision["findings"]
    )
