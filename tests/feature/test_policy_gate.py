"""Feature tests for the combined offline W5-003 OPA and Checkov gate."""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
POLICY_DIRECTORY = ROOT / "policies/opa"
CHECKOV_CONFIG = ROOT / ".checkov.yml"
OPA = Path(r"E:\AI\.tools\opa\1.20.0\opa.exe")
CHECKOV_PYTHON = Path(r"E:\AI\.venvs\enterprise-ai-platform-checkov-3.3.16\Scripts\python.exe")
CHECKOV_CLI = Path(r"E:\AI\.venvs\enterprise-ai-platform-checkov-3.3.16\Scripts\checkov")
POLICY_IDS = [
    "W5-PLAN-001",
    "W5-REG-001",
    "W5-TAG-001",
    "W5-TAG-002",
    "W5-PLAN-002",
    "W5-S3-001",
    "W5-S3-002",
    "W5-S3-003",
    "W5-S3-004",
    "W5-KMS-001",
    "W5-IAM-001",
    "W5-IAM-002",
    "W5-NET-001",
    "W5-NET-002",
    "W5-OS-001",
    "W5-OS-002",
    "W5-ECR-001",
    "W5-ECR-002",
    "W5-SEC-001",
    "W5-EXC-001",
]


def _base_plan() -> dict[str, Any]:
    return {
        "format_version": "1.2",
        "terraform_version": "1.14.0",
        "variables": {"aws_region": {"value": "ap-southeast-1"}},
        "evaluation_context": {
            "evaluation_time": "2026-09-04T00:00:00Z",
            "policy_ids": POLICY_IDS,
        },
        "resource_changes": [
            {
                "address": "aws_route_table_association.private[0]",
                "type": "aws_route_table_association",
                "change": {
                    "actions": ["create"],
                    "after": {
                        "route_table_id": "rtb-synthetic",
                        "subnet_id": "subnet-synthetic",
                    },
                },
            }
        ],
    }


def _local_environment() -> dict[str, str]:
    environment = os.environ.copy()
    for name in (
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "BC_API_KEY",
        "PRISMA_API_URL",
    ):
        environment.pop(name, None)
    return environment


def _opa_findings(tmp_path: Path, plan: dict[str, Any]) -> list[dict[str, str]]:
    if not OPA.is_file():
        pytest.skip(f"owner-controlled OPA executable is absent: {OPA}")
    input_path = tmp_path / "terraform-plan-shaped-input.json"
    input_path.write_text(json.dumps(plan), encoding="utf-8", newline="\n")
    completed = subprocess.run(  # noqa: S603 - fixed owner-controlled OPA executable
        [
            str(OPA),
            "eval",
            "--format=json",
            "--data",
            str(POLICY_DIRECTORY),
            "--input",
            str(input_path),
            "data.enterprise_ai.terraform.plan.findings",
        ],
        cwd=ROOT,
        env=_local_environment(),
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout)
    assert len(payload.get("result", [])) == 1, "OPA policy result is missing or unevaluated"
    expressions = payload["result"][0].get("expressions", [])
    assert len(expressions) == 1 and isinstance(expressions[0].get("value"), list)
    return expressions[0]["value"]


def _checkov(directory: Path) -> subprocess.CompletedProcess[str]:
    if not CHECKOV_PYTHON.is_file() or not CHECKOV_CLI.is_file():
        pytest.skip("owner-controlled Checkov 3.3.16 environment is absent")
    return subprocess.run(  # noqa: S603 - fixed owner-controlled Checkov interpreter
        [
            str(CHECKOV_PYTHON),
            str(CHECKOV_CLI),
            "--config-file",
            str(CHECKOV_CONFIG),
            "-d",
            str(directory),
        ],
        cwd=ROOT,
        env=_local_environment(),
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )


def _eligibility(
    opa_findings: list[dict[str, str]] | None,
    *,
    checkov_completed: bool,
    checkov_failed: int,
    checkov_skipped: int,
) -> str:
    if opa_findings is None or not checkov_completed:
        return "FAIL"
    if opa_findings or checkov_failed != 0 or checkov_skipped != 20:
        return "FAIL"
    return "PASS"


def test_secure_synthetic_plan_is_evaluated_and_passes(tmp_path: Path) -> None:
    assert _opa_findings(tmp_path, _base_plan()) == []


def test_runtime_finding_uses_only_safe_bounded_allowlisted_fields(tmp_path: Path) -> None:
    plan = _base_plan()
    plan["variables"] = {"aws_region": {"value": "us-east-1"}}

    findings = _opa_findings(tmp_path, plan)

    assert len(findings) == 1
    finding = findings[0]
    assert set(finding) == {
        "schema_version",
        "policy_id",
        "severity",
        "resource_address",
        "category",
        "remediation_code",
        "exception_status",
    }
    assert finding == {
        "schema_version": "w5-003.policy-finding.v1",
        "policy_id": "W5-REG-001",
        "severity": "CRITICAL",
        "resource_address": "policy.region",
        "category": "REGION",
        "remediation_code": "USE_APPROVED_REGION",
        "exception_status": "NONE",
    }
    assert all(isinstance(value, str) and len(value) <= 240 for value in finding.values())


@pytest.mark.parametrize(
    ("mutation", "expected_policy"),
    [
        ("wrong_region", "W5-REG-001"),
        ("unsupported_aws", "W5-PLAN-001"),
        ("secret_material", "W5-SEC-001"),
        ("destructive_change", "W5-PLAN-002"),
    ],
)
def test_insecure_synthetic_plan_fails_for_intended_rule(
    tmp_path: Path, mutation: str, expected_policy: str
) -> None:
    plan = _base_plan()
    if mutation == "wrong_region":
        plan["variables"] = {"aws_region": {"value": "us-east-1"}}
    elif mutation == "unsupported_aws":
        plan["resource_changes"] = [
            {
                "address": "aws_lambda_function.unapproved",
                "type": "aws_lambda_function",
                "change": {"actions": ["create"], "after": {}},
            }
        ]
    elif mutation == "secret_material":
        plan["api_key"] = "".join(("runtime", "-", "only"))
    else:
        plan["resource_changes"][0]["change"] = {"actions": ["delete"], "after": None}

    findings = _opa_findings(tmp_path, plan)
    assert expected_policy in {finding["policy_id"] for finding in findings}


def test_empty_missing_or_partially_evaluated_policy_cannot_pass() -> None:
    assert (
        _eligibility(None, checkov_completed=True, checkov_failed=0, checkov_skipped=20) == "FAIL"
    )
    assert _eligibility([], checkov_completed=False, checkov_failed=0, checkov_skipped=20) == "FAIL"


def test_opa_and_checkov_disagreement_is_fail() -> None:
    assert _eligibility([], checkov_completed=True, checkov_failed=0, checkov_skipped=20) == "PASS"
    assert _eligibility([], checkov_completed=True, checkov_failed=1, checkov_skipped=20) == "FAIL"
    assert (
        _eligibility(
            [{"policy_id": "W5-REG-001"}],
            checkov_completed=True,
            checkov_failed=0,
            checkov_skipped=20,
        )
        == "FAIL"
    )
    assert _eligibility([], checkov_completed=True, checkov_failed=0, checkov_skipped=19) == "FAIL"


def test_checkov_secure_and_insecure_hcl_stays_under_pytest_tmp_path(tmp_path: Path) -> None:
    secure = tmp_path / "secure"
    insecure = tmp_path / "insecure"
    secure.mkdir()
    insecure.mkdir()
    (secure / "main.tf").write_text(
        'variable "synthetic_region" {\n  type = string\n}\n',
        encoding="utf-8",
        newline="\n",
    )
    (insecure / "main.tf").write_text(
        'resource "aws_s3_bucket" "public" {\n'
        '  bucket = "w5-003-insecure-example"\n'
        '  acl    = "public-read"\n'
        "}\n",
        encoding="utf-8",
        newline="\n",
    )

    secure_result = _checkov(secure)
    insecure_result = _checkov(insecure)

    assert secure_result.returncode == 0, secure_result.stdout + secure_result.stderr
    assert insecure_result.returncode != 0
    assert secure.is_relative_to(tmp_path) and insecure.is_relative_to(tmp_path)


def test_current_terraform_checkov_baseline_is_exact() -> None:
    completed = _checkov(ROOT / "infra")
    combined = completed.stdout + completed.stderr
    counts = re.search(
        r"Passed checks:\s*(\d+),\s*Failed checks:\s*(\d+),\s*Skipped checks:\s*(\d+)",
        combined,
    )

    assert completed.returncode == 0, combined
    assert counts is not None, "Checkov did not emit the required complete scan counts"
    assert tuple(map(int, counts.groups())) == (226, 0, 20)
