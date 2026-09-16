"""Contract tests for the exact W1-004 CLI and inventory surface."""

from __future__ import annotations

import argparse

import pytest
from tools.platformctl.aws_inventory import ServiceIdentifier
from tools.platformctl.cli import build_parser
from tools.platformctl.contracts import (
    REQUIRED_APPROVAL_FIELDS,
    Action,
    ExitCode,
)


def test_cli_exposes_exact_approved_commands() -> None:
    parser = build_parser()
    subparsers = next(
        action for action in parser._actions if isinstance(action, argparse._SubParsersAction)
    )
    assert set(subparsers.choices) == {
        "prepare-plan-owner-envelope",
        "prepare-plan-artifacts",
        "validate",
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
    }


def test_plan_artifact_producer_requires_explicit_owner_inputs() -> None:
    parser = build_parser()
    parsed = parser.parse_args(
        [
            "prepare-plan-artifacts",
            "--owner-input-file",
            "owner.json",
            "--owner-input-sha256",
            "a" * 64,
            "--operation-root",
            "saved-plan-009",
        ]
    )
    assert parsed.command == "prepare-plan-artifacts"
    assert parsed.owner_input_sha256 == "a" * 64


def test_plan_owner_envelope_producer_requires_all_bound_sources() -> None:
    parsed = build_parser().parse_args(
        [
            "prepare-plan-owner-envelope",
            "--owner-confirmation-file",
            "confirmation.json",
            "--owner-confirmation-sha256",
            "a" * 64,
            "--state-evidence-file",
            "state.json",
            "--state-evidence-sha256",
            "b" * 64,
            "--variables-example-file",
            "terraform.tfvars.example",
            "--variables-example-sha256",
            "c" * 64,
            "--backend-example-file",
            "backend.hcl.example",
            "--backend-example-sha256",
            "d" * 64,
            "--operation-root",
            "saved-plan-009",
        ]
    )
    assert parsed.command == "prepare-plan-owner-envelope"
    assert parsed.state_evidence_sha256 == "b" * 64


def test_cli_execution_is_explicit_and_request_bound() -> None:
    parser = build_parser()
    subparsers = next(
        action for action in parser._actions if isinstance(action, argparse._SubParsersAction)
    )
    assert "--execute" not in parser.format_help()
    for command in ("bootstrap-apply", "platform-apply"):
        assert "--resource-expires-at" not in subparsers.choices[command].format_help()
        assert "--execute" in subparsers.choices[command].format_help()
        assert "--request-file" in subparsers.choices[command].format_help()
        assert "--request-sha256" in subparsers.choices[command].format_help()


def test_diagnostic_mode_is_only_on_explicit_aws_verify() -> None:
    from tools.platformctl.cli import main

    arguments = ["aws-verify", "--environment", "sandbox", "--target", "platform", "--diagnostic"]
    assert main(arguments) == 1
    assert main([*arguments, "--execute"]) == 1
    with pytest.raises(SystemExit) as error:
        build_parser().parse_args(
            ["platform-plan", "--environment", "sandbox", "--target", "platform", "--diagnostic"]
        )
    assert error.value.code == 2


def test_diagnostic_schema_never_decodes_as_execution_authority() -> None:
    from tools.platformctl.contracts import ContractError
    from tools.platformctl.lifecycle_io import canonical_json_bytes, decode_operational_record
    from tools.platformctl.lifecycle_models import DIAGNOSTIC_SCHEMA_VERSION, ReviewRequest

    with pytest.raises(ContractError):
        decode_operational_record(
            canonical_json_bytes({"schema_version": DIAGNOSTIC_SCHEMA_VERSION}),
            ReviewRequest,
        )


def test_approval_contract_has_exact_fields_and_actions() -> None:
    assert REQUIRED_APPROVAL_FIELDS == {
        "schema_version",
        "approval_id",
        "action",
        "environment",
        "aws_account_id",
        "aws_region",
        "target",
        "artifact_sha256",
        "approver",
        "approved_at",
        "expires_at",
    }
    assert [action.value for action in Action] == [
        "BOOTSTRAP-APPLY",
        "PLATFORM-APPLY",
        "INFRASTRUCTURE-ROLLBACK",
        "PURGE-SANDBOX",
        "PLATFORM-DESTROY",
        "BOOTSTRAP-DESTROY",
    ]


def test_exit_codes_are_stable() -> None:
    assert {member.name: member.value for member in ExitCode} == {
        "SUCCESS": 0,
        "VALIDATION_FAILURE": 1,
        "USAGE_ERROR": 2,
        "PROVIDER_UNAVAILABLE": 3,
        "APPROVAL_FAILURE": 4,
    }


def test_inventory_contract_covers_every_approved_service() -> None:
    assert [service.value for service in ServiceIdentifier] == [
        "EKS",
        "ELB",
        "EBS",
        "ENI",
        "EIP",
        "OpenSearch",
        "S3",
        "DynamoDB",
        "ECR",
        "CloudWatch Logs",
        "Secrets Manager",
        "KMS",
        "IAM",
        "Lambda",
        "Glue",
        "Step Functions",
        "EventBridge",
    ]


def test_malformed_cli_input_uses_argparse_exit_two() -> None:
    with pytest.raises(SystemExit) as exc_info:
        build_parser().parse_args(["platform-plan", "--environment", "TODO_USER", "--target", "x"])
    assert exc_info.value.code == 2


def test_local_diagnostic_preparation_is_explicit_and_cannot_execute(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from pathlib import Path

    from tools.platformctl import cli

    calls: list[tuple[Path, Path, str]] = []

    def prepare(repository: Path, external: Path, digest: str) -> tuple[tuple[str, str], ...]:
        calls.append((repository, external, digest))
        return (("review-request.json", "a" * 64), ("review-runtime.json", "b" * 64))

    monkeypatch.setattr(cli.plan, "prepare_owner_diagnostic", prepare)
    base = [
        "aws-verify",
        "--environment",
        "sandbox",
        "--target",
        "platform",
        "--diagnostic",
        "--prepare-diagnostic",
        "--source-sha256",
        "c" * 64,
    ]
    assert cli.main([*base, "--execute"]) == 1
    assert calls == []
    assert "PREPARATION=PASS" not in capsys.readouterr().out
    assert cli.main(base) == 0
    assert len(calls) == 1
    output = capsys.readouterr().out
    assert "READY_FOR_OWNER_REVIEW" in output
    assert "AWS=NOT_RUN" in output
    assert "RECOVERY_ELIGIBILITY=NOT_ESTABLISHED" in output
    assert cli.main(base[:-2]) == 1
    assert len(calls) == 1


def test_local_diagnostic_preparation_failure_never_emits_pass(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from tools.platformctl import cli
    from tools.platformctl.contracts import ContractError

    def rejected(*_args: object) -> None:
        raise ContractError("DIAGNOSTIC_PREPARATION_REVIEWED_CONTENT_CHANGED")

    monkeypatch.setattr(cli.plan, "prepare_owner_diagnostic", rejected)
    assert (
        cli.main(
            [
                "aws-verify",
                "--environment",
                "sandbox",
                "--target",
                "platform",
                "--diagnostic",
                "--prepare-diagnostic",
                "--source-sha256",
                "c" * 64,
            ]
        )
        == 1
    )
    captured = capsys.readouterr()
    assert "REVIEWED_CONTENT_CHANGED" in captured.err
    assert "PASS" not in captured.out


@pytest.mark.parametrize(
    "extra", [[], ["--prepare-diagnostic"], ["--request-file", "unexpected.json"]]
)
def test_resolution_cli_rejects_incomplete_or_mixed_modes(monkeypatch, capsys, extra):
    from tools.platformctl import cli

    def forbidden(*_args, **_kwargs):
        raise AssertionError("Rejected dispatch must not construct an AWS provider")

    monkeypatch.setattr(cli.plan, "run_owner_resolution", forbidden)
    arguments = [
        "aws-verify",
        "--environment",
        "sandbox",
        "--target",
        "platform",
        "--diagnostic",
        "--resolution",
        "--source-sha256",
        "a" * 64,
        "--evidence-sha256",
        "b" * 64,
    ]
    if extra:
        arguments.append("--execute")
    assert cli.main(arguments + extra) == 1
    assert "PASS" not in capsys.readouterr().out


@pytest.mark.parametrize(
    "extra", [[], ["--resolution"], ["--prepare-diagnostic"], ["--runtime-file", "unexpected.json"]]
)
def test_followup_cli_dispatch_is_closed(monkeypatch, capsys, extra):
    from tools.platformctl import cli

    calls = []

    def execute(*args, **kwargs):
        calls.append((args, kwargs))
        return 1, "RESOLUTION_PREREQUISITES_UNRESOLVED"

    monkeypatch.setattr(cli.plan, "run_owner_resolution", execute)
    args = [
        "aws-verify",
        "--environment",
        "sandbox",
        "--target",
        "platform",
        "--diagnostic",
        "--resolution-followup",
        "--execute",
        "--source-sha256",
        "a" * 64,
        "--evidence-sha256",
        "b" * 64,
    ]
    assert cli.main(args + extra) == 1
    assert len(calls) == (0 if extra else 1)
    if calls:
        assert calls[0][1]["followup"] is True
    assert "PASS" not in capsys.readouterr().out


@pytest.mark.parametrize(
    "extra",
    [
        [],
        ["--resolution"],
        ["--resolution-followup"],
        ["--prepare-diagnostic"],
        ["--runtime-file", "unexpected.json"],
    ],
)
@pytest.mark.parametrize("correction", [False, True])
def test_prerequisite_cli_dispatch_is_closed(monkeypatch, capsys, extra, correction):
    from tools.platformctl import cli

    calls = []

    def execute(*args, **kwargs):
        calls.append((args, kwargs))
        return 1, "PREREQUISITES_UNRESOLVED"

    monkeypatch.setattr(cli.plan, "run_owner_prerequisite", execute)
    args = [
        "aws-verify",
        "--environment",
        "sandbox",
        "--target",
        "platform",
        "--diagnostic",
        "--prerequisite-resolution",
        "--execute",
        "--source-sha256",
        "a" * 64,
        "--evidence-sha256",
        "b" * 64,
        "--evidence-identity-sha256",
        "c" * 64,
    ]
    mode = ["--prerequisite-correction"] if correction else []
    assert cli.main(args + mode + extra) == 1
    assert len(calls) == (0 if extra else 1)
    if calls:
        assert calls[0][1].get("correction", False) is correction
    assert "PASS" not in capsys.readouterr().out
    calls.clear()
    assert cli.main(args[:-2]) == 1
    assert calls == []


def test_correction_owner_arguments_cannot_leak_into_execution(monkeypatch, capsys):
    from tools.platformctl import cli

    def forbidden(*_args, **_kwargs):
        raise AssertionError("Invalid mode must not access AWS")

    monkeypatch.setattr(cli.plan, "run_owner_prerequisite", forbidden)
    assert (
        cli.main(
            [
                "aws-verify",
                "--environment",
                "sandbox",
                "--target",
                "platform",
                "--diagnostic",
                "--owner-approval-file",
                "unexpected.json",
            ]
        )
        == 1
    )
    assert "CORRECTION_PREPARATION_FLAG_REQUIRED" in capsys.readouterr().err
