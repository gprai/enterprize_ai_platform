"""Contract tests for exact W5-004 configuration, schemas, and commands."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import cast

import pytest
from tools.platformctl.cli import build_parser
from tools.platformctl.contracts import Action
from tools.platformctl.lifecycle_io import (
    canonical_json_bytes,
    decode_operational_record,
    load_lifecycle_config,
)
from tools.platformctl.lifecycle_models import ReviewPackage
from tools.platformctl.validate import EXPECTED_W5_004_IMPLEMENTATION_PATHS

from tests.fakes.platform_lifecycle import reviewed_package_fixture

ROOT = Path(__file__).resolve().parents[2]


def test_v2_records_round_trip_with_immutable_collections() -> None:
    package, _, _, _ = reviewed_package_fixture()
    decoded = decode_operational_record(canonical_json_bytes(package), ReviewPackage)
    assert decoded == package
    assert isinstance(decoded.profile.rules, tuple)


@pytest.mark.parametrize("change", ["extra", "missing", "old_version", "boolean_serial"])
def test_v2_records_reject_contract_drift(change: str) -> None:
    package, _, _, _ = reviewed_package_fixture()
    value = json.loads(canonical_json_bytes(package))
    if change == "extra":
        value["unexpected"] = True
    elif change == "missing":
        del value["action"]
    elif change == "old_version":
        value["schema_version"] = "w5-004.lifecycle.v1"
    else:
        value["state"]["serial"] = True
    with pytest.raises(ValueError):
        decode_operational_record(json.dumps(value).encode(), ReviewPackage)


COMMANDS = {
    "prepare-plan-owner-envelope",
    "validate",
    "w6-004-validate-source",
    "w6-004-validate-evidence",
    "w6-004-validate-runtime",
    "bootstrap-plan",
    "bootstrap-apply",
    "platform-plan",
    "policy-review",
    "cost-review",
    "platform-apply",
    "aws-verify",
    "infrastructure-rollback",
    "destroy-plan",
    "purge-sandbox",
    "platform-destroy",
    "bootstrap-destroy",
    "verify-clean",
    "prepare-plan-artifacts",
}


def test_exact_w5_004_manifest_is_owned_once() -> None:
    assert len(EXPECTED_W5_004_IMPLEMENTATION_PATHS) == 49
    assert len(set(EXPECTED_W5_004_IMPLEMENTATION_PATHS)) == 49
    assert all((ROOT / path).is_file() for path in EXPECTED_W5_004_IMPLEMENTATION_PATHS)


def test_exact_lifecycle_commands_and_mutation_actions() -> None:
    parser = build_parser()
    subparsers = next(
        action for action in parser._actions if isinstance(action, argparse._SubParsersAction)
    )
    assert set(subparsers.choices) == COMMANDS
    assert [action.value for action in Action] == [
        "BOOTSTRAP-APPLY",
        "PLATFORM-APPLY",
        "INFRASTRUCTURE-ROLLBACK",
        "PURGE-SANDBOX",
        "PLATFORM-DESTROY",
        "BOOTSTRAP-DESTROY",
    ]


def test_plan_sandbox_is_only_a_thin_w5_004_alias() -> None:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    assert "plan-sandbox: w5-004-platform-plan\n" in makefile
    assert makefile.count("plan-sandbox:") == 1


def test_configuration_records_exact_owner_decisions() -> None:
    config = load_lifecycle_config(ROOT / "configs/lifecycle/w5-004.json")
    aws = cast(dict[str, object], config["aws"])
    cost = cast(dict[str, object], config["cost"])
    lifecycle = cast(dict[str, object], config["lifecycle"])
    assert aws == {
        "account_id": "526338061652",
        "region": "ap-southeast-1",
        "profile": "default",
        "expected_caller_arn": "arn:aws:iam::526338061652:user/finopsinfra",
        "principal_class": "IAM user",
        "environment": "sandbox",
        "owner_governance_expires_at": "2026-12-09T23:59:59Z",
    }
    assert cost["lifecycle_test_ceiling"] == "3.00"
    from tools.platformctl.lifecycle_io import approved_lifecycle_exception

    assert cost["lifecycle_exception"] == approved_lifecycle_exception()
    assert cost["lifecycle_exception"]["lifecycle_ceiling_usd"] == "30.00"
    assert cost["daily_alert_threshold"] == "3.00"
    assert cost["direct_plan_json_api_upload"] is False
    assert lifecycle["maximum_resource_lifetime_hours"] == 24
    assert lifecycle["generated_resource_lifetime_minutes"] == 1425
