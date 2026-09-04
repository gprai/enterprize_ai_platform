"""Contract tests for the strict W5-003 owner exception registry."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
EXCEPTIONS_PATH = ROOT / "policies/opa/exceptions.json"
SCHEMA_VERSION = "w5-003.policy-exceptions.v1"
POLICY_IDS = (
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
)
NON_EXEMPTIBLE = {"W5-PLAN-001", "W5-SEC-001", "W5-EXC-001"}
EXCEPTION_KEYS = (
    "exception_id",
    "policy_id",
    "resource_addresses",
    "owner",
    "approver",
    "rationale",
    "evidence_reference",
    "issued_at",
    "expires_at",
    "status",
)
ADDRESS_PATTERN = re.compile(r'^[A-Za-z0-9_.\[\]"-]*(?:^|\.)aws_[a-z0-9_]+\.[A-Za-z0-9_"\[\]-]+$')


class DuplicateKeyError(ValueError):
    """Raised when JSON contains a duplicate key."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(key)
        result[key] = value
    return result


def _timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.endswith("Z") or len(value) > 40:
        return None
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError:
        return None
    return parsed if parsed.tzinfo == UTC else None


def _exception_state(exception: dict[str, Any], evaluation_time: datetime) -> str:
    if exception["status"] == "REVOKED":
        return "REVOKED"
    issued_at = _timestamp(exception["issued_at"])
    expires_at = _timestamp(exception["expires_at"])
    if issued_at is None or expires_at is None:
        return "INVALID"
    if issued_at > evaluation_time:
        return "FUTURE"
    if expires_at <= evaluation_time:
        return "EXPIRED"
    return "ACTIVE"


def _validate_registry(data: object) -> list[str]:
    if not isinstance(data, dict):
        return ["top_level"]
    errors: list[str] = []
    if tuple(data) != ("schema_version", "exceptions"):
        errors.append("top_level_keys")
    if data.get("schema_version") != SCHEMA_VERSION:
        errors.append("schema_version")
    exceptions = data.get("exceptions")
    if not isinstance(exceptions, list):
        return [*errors, "exceptions_type"]

    ids: list[str] = []
    bindings: list[tuple[str, str]] = []
    for exception in exceptions:
        if not isinstance(exception, dict):
            errors.append("exception_type")
            continue
        if tuple(exception) != EXCEPTION_KEYS:
            errors.append("exception_keys")
            continue
        exception_id = exception["exception_id"]
        if not isinstance(exception_id, str) or not re.fullmatch(
            r"W5-EXC-[A-Z0-9][A-Z0-9-]{0,71}", exception_id
        ):
            errors.append("exception_id")
        else:
            ids.append(exception_id)
        policy_id = exception["policy_id"]
        if policy_id not in POLICY_IDS or policy_id in NON_EXEMPTIBLE:
            errors.append("policy_id")
        addresses = exception["resource_addresses"]
        if not isinstance(addresses, list) or not 1 <= len(addresses) <= 10:
            errors.append("resource_count")
        elif len(set(addresses)) != len(addresses):
            errors.append("duplicate_resource")
        else:
            for address in addresses:
                if not isinstance(address, str) or not ADDRESS_PATTERN.fullmatch(address):
                    errors.append("resource_scope")
                elif address.endswith((".tf", ".py", "/")):
                    errors.append("resource_scope")
                else:
                    bindings.append((str(policy_id), address))
        if exception["owner"] != "Gyan Prakash Rai":
            errors.append("owner")
        if exception["approver"] != "Gyan Prakash Rai":
            errors.append("approver")
        rationale = exception["rationale"]
        evidence = exception["evidence_reference"]
        if not isinstance(rationale, str) or not 1 <= len(rationale) <= 500:
            errors.append("rationale")
        if not isinstance(evidence, str) or not 1 <= len(evidence) <= 256:
            errors.append("evidence_reference")
        issued_at = _timestamp(exception["issued_at"])
        expires_at = _timestamp(exception["expires_at"])
        if issued_at is None or expires_at is None:
            errors.append("timestamp")
        elif expires_at <= issued_at or (expires_at - issued_at).total_seconds() > 604800:
            errors.append("validity_window")
        if exception["status"] not in {"ACTIVE", "REVOKED"}:
            errors.append("status")
    if len(ids) != len(set(ids)):
        errors.append("duplicate_id")
    if len(bindings) != len(set(bindings)):
        errors.append("duplicate_binding")
    return errors


def _exception(
    *,
    policy_id: str = "W5-PLAN-002",
    addresses: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "exception_id": "W5-EXC-OWNER-001",
        "policy_id": policy_id,
        "resource_addresses": addresses or ["aws_route_table_association.private[0]"],
        "owner": "Gyan Prakash Rai",
        "approver": "Gyan Prakash Rai",
        "rationale": "Bounded synthetic owner review",
        "evidence_reference": "W5-003-owner-review",
        "issued_at": "2026-09-04T00:00:00Z",
        "expires_at": "2026-09-05T00:00:00Z",
        "status": "ACTIVE",
    }


def _registry(exceptions: list[dict[str, Any]]) -> dict[str, Any]:
    return {"schema_version": SCHEMA_VERSION, "exceptions": exceptions}


def test_committed_registry_is_canonical_empty_json() -> None:
    raw = EXCEPTIONS_PATH.read_bytes()

    assert not raw.startswith(b"\xef\xbb\xbf")
    assert b"\r" not in raw
    assert raw.endswith(b"\n") and not raw.endswith(b"\n\n")
    assert raw == b'{\n  "schema_version": "w5-003.policy-exceptions.v1",\n  "exceptions": []\n}\n'
    data = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    assert tuple(data) == ("schema_version", "exceptions")
    assert _validate_registry(data) == []


def test_duplicate_json_keys_are_rejected() -> None:
    raw = '{"schema_version":"a","schema_version":"b","exceptions":[]}'
    with pytest.raises(DuplicateKeyError):
        json.loads(raw, object_pairs_hook=_reject_duplicate_keys)


def test_top_level_missing_extra_reordered_and_wrong_schema_fail() -> None:
    variants = (
        {"schema_version": SCHEMA_VERSION},
        {"schema_version": SCHEMA_VERSION, "exceptions": [], "extra": False},
        {"exceptions": [], "schema_version": SCHEMA_VERSION},
        {"schema_version": "wrong", "exceptions": []},
    )

    assert all(_validate_registry(variant) for variant in variants)


def test_valid_one_and_ten_address_exceptions_pass() -> None:
    one = _exception()
    ten = _exception(
        addresses=[f"module.storage.aws_s3_bucket.item[{index}]" for index in range(10)]
    )
    ten["exception_id"] = "W5-EXC-OWNER-002"

    assert _validate_registry(_registry([one])) == []
    assert _validate_registry(_registry([ten])) == []


@pytest.mark.parametrize("count", [0, 11])
def test_zero_or_more_than_ten_addresses_fail(count: int) -> None:
    exception = _exception(addresses=[f"aws_s3_bucket.item[{index}]" for index in range(count)])
    if count == 0:
        exception["resource_addresses"] = []
    assert "resource_count" in _validate_registry(_registry([exception]))


def test_duplicate_ids_addresses_and_bindings_fail() -> None:
    duplicate_address = _exception(addresses=["aws_s3_bucket.one", "aws_s3_bucket.one"])
    first = _exception(addresses=["aws_s3_bucket.one"])
    second = _exception(addresses=["aws_s3_bucket.two"])
    second["resource_addresses"] = ["aws_s3_bucket.one"]

    assert "duplicate_resource" in _validate_registry(_registry([duplicate_address]))
    errors = _validate_registry(_registry([first, second]))
    assert "duplicate_id" in errors
    assert "duplicate_binding" in errors


def test_missing_extra_and_reordered_keys_fail() -> None:
    missing = _exception()
    missing.pop("status")
    extra = _exception()
    extra["extra"] = "no"
    reordered = {key: _exception()[key] for key in reversed(EXCEPTION_KEYS)}

    for invalid in (missing, extra, reordered):
        assert "exception_keys" in _validate_registry(_registry([invalid]))


@pytest.mark.parametrize(
    ("field", "value", "error"),
    [
        ("owner", "Someone Else", "owner"),
        ("approver", "Someone Else", "approver"),
        ("rationale", "", "rationale"),
        ("rationale", "x" * 501, "rationale"),
        ("evidence_reference", "", "evidence_reference"),
        ("evidence_reference", "x" * 257, "evidence_reference"),
        ("policy_id", "W5-UNKNOWN-001", "policy_id"),
        ("status", "APPROVED", "status"),
    ],
)
def test_identity_content_policy_and_status_are_exact(field: str, value: str, error: str) -> None:
    exception = _exception()
    exception[field] = value
    assert error in _validate_registry(_registry([exception]))


@pytest.mark.parametrize("policy_id", sorted(NON_EXEMPTIBLE))
def test_non_exemptible_policies_fail(policy_id: str) -> None:
    assert "policy_id" in _validate_registry(_registry([_exception(policy_id=policy_id)]))


@pytest.mark.parametrize(
    "address",
    [
        "*",
        "aws_s3_bucket.*",
        "aws_s3_bucket.item?",
        "infra/",
        "main.tf",
        "aws_s3_bucket.item.tf",
        "aws_s3_bucket",
    ],
)
def test_wildcard_glob_directory_extension_prefix_and_blanket_scopes_fail(
    address: str,
) -> None:
    assert "resource_scope" in _validate_registry(_registry([_exception(addresses=[address])]))


@pytest.mark.parametrize(
    ("issued_at", "expires_at", "error"),
    [
        ("not-a-time", "2026-09-05T00:00:00Z", "timestamp"),
        ("2026-09-04T00:00:00+00:00", "2026-09-05T00:00:00Z", "timestamp"),
        ("2026-09-05T00:00:00Z", "2026-09-04T00:00:00Z", "validity_window"),
        ("2026-09-04T00:00:00Z", "2026-09-12T00:00:00Z", "validity_window"),
    ],
)
def test_malformed_reversed_and_over_seven_day_timestamps_fail(
    issued_at: str, expires_at: str, error: str
) -> None:
    exception = _exception()
    exception["issued_at"] = issued_at
    exception["expires_at"] = expires_at
    assert error in _validate_registry(_registry([exception]))


def test_active_future_expired_and_revoked_states_are_explicit() -> None:
    evaluation_time = datetime(2026, 9, 4, 12, tzinfo=UTC)
    active = _exception()
    future = _exception()
    future["issued_at"] = "2026-09-05T00:00:00Z"
    future["expires_at"] = "2026-09-06T00:00:00Z"
    expired = _exception()
    expired["issued_at"] = "2026-09-02T00:00:00Z"
    expired["expires_at"] = "2026-09-03T00:00:00Z"
    revoked = _exception()
    revoked["status"] = "REVOKED"

    assert _exception_state(active, evaluation_time) == "ACTIVE"
    assert _exception_state(future, evaluation_time) == "FUTURE"
    assert _exception_state(expired, evaluation_time) == "EXPIRED"
    assert _exception_state(revoked, evaluation_time) == "REVOKED"
    assert all(
        _validate_registry(_registry([item])) == [] for item in (active, future, expired, revoked)
    )


def test_serialization_is_deterministic() -> None:
    registry = _registry([_exception()])
    first = json.dumps(registry, ensure_ascii=True, separators=(",", ":"))
    second = json.dumps(registry, ensure_ascii=True, separators=(",", ":"))
    assert first == second
