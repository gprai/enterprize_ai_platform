import asyncio
import base64
import hashlib
import hmac
import json
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi import Request
from tools.platformctl.image_lifecycle import validate_image_evidence
from tools.platformctl.live_validation import (
    SCHEMA_FIELDS,
    SOURCE_STATUS,
    W6004Error,
    canonical_evidence_sha256,
    canonical_sha256,
    validate_evidence_record,
    validate_operation_exclusivity,
    validate_runtime_bindings,
    validate_source_contract,
)
from tools.platformctl.rollback import validate_w6_004_known_good_identity

from enterprise_ai_platform.api.errors import AuthenticationInvalidError
from enterprise_ai_platform.api.sandbox_auth import SandboxTokenAuthenticator
from tests.fakes.w6_004_lifecycle import (
    evidence_record,
    image_evidence,
    runtime_bindings,
    vulnerability_evidence,
)

ROOT = Path(__file__).resolve().parents[2]
SIGNING_MATERIAL = "fixture-only-signing-material-" * 2  # noqa: S105


def _encoded(value: object) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(payload).decode().rstrip("=")


def _request_token(
    *,
    tenant_id: str,
    expires: int,
    issuer: str = "enterprise-ai-sandbox",
    audience: str = "enterprise-ai-api",
    issued_at: int | None = None,
    not_before: int | None = None,
) -> Request:
    now = int(time.time()) if issued_at is None else issued_at
    header = _encoded({"alg": "HS256", "typ": "JWT"})
    claims = _encoded(
        {
            "iss": issuer,
            "aud": audience,
            "sub": "synthetic-owner",
            "tenant_id": tenant_id,
            "roles": ["reader"],
            "clearance": "INTERNAL",
            "iat": now - 1,
            "nbf": now - 1 if not_before is None else not_before,
            "exp": expires,
            "jti": "synthetic-token-0001",
            "data_classification": "INTERNAL",
        }
    )
    signature = hmac.new(
        SIGNING_MATERIAL.encode(),
        f"{header}.{claims}".encode(),
        hashlib.sha256,
    ).digest()
    token = f"{header}.{claims}.{base64.urlsafe_b64encode(signature).decode().rstrip('=')}"
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/health/ready",
            "headers": [(b"authorization", f"Bearer {token}".encode())],
        }
    )


def test_source_contract_is_inert_and_complete() -> None:
    assert validate_source_contract(ROOT / "configs/lifecycle/w6-004.json") == SOURCE_STATUS


def test_canonical_hash_uses_compact_sorted_utf8_json_with_terminal_newline() -> None:
    value = {"z": [2, 1], "a": "fixture"}
    expected = hashlib.sha256(b'{"a":"fixture","z":[2,1]}\n').hexdigest()
    assert canonical_sha256(value) == expected


def test_external_runtime_bindings_replace_every_sentinel_and_are_time_bounded() -> None:
    bindings = runtime_bindings()
    assert (
        validate_runtime_bindings(
            bindings,
            now=datetime(2026, 10, 3, 0, 30, tzinfo=UTC),
        )
        == bindings
    )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("aws_cli_profile", "OWNER_BINDING_REQUIRED", "sentinel"),
        ("owner_api_cidr", "10.60.0.1/32", "public IPv4 /32"),
        ("collector_image_digest", "latest", "immutable"),
        ("alert_recipients", ["same@example.invalid", "same@example.invalid"], "distinct"),
    ],
)
def test_external_runtime_bindings_reject_unresolved_or_unsafe_values(
    field: str,
    value: object,
    message: str,
) -> None:
    bindings = runtime_bindings()
    bindings[field] = value
    with pytest.raises(W6004Error, match=message):
        validate_runtime_bindings(
            bindings,
            now=datetime(2026, 10, 3, 0, 30, tzinfo=UTC),
        )


def test_external_runtime_bindings_reject_expired_or_unknown_inventory() -> None:
    expired = runtime_bindings()
    with pytest.raises(W6004Error, match="window"):
        validate_runtime_bindings(
            expired,
            now=datetime(2026, 10, 3, 9, 1, tzinfo=UTC),
        )
    unknown = runtime_bindings()
    unknown["unapproved"] = "fixture"
    with pytest.raises(W6004Error, match="inventory"):
        validate_runtime_bindings(
            unknown,
            now=datetime(2026, 10, 3, 0, 30, tzinfo=UTC),
        )


def test_image_evidence_binds_every_identity() -> None:
    assert validate_image_evidence(image_evidence())["registry_digest"].startswith("sha256:")


@pytest.mark.parametrize("schema", sorted(SCHEMA_FIELDS))
def test_every_closed_evidence_schema_accepts_only_complete_metadata(schema: str) -> None:
    value = evidence_record(schema)
    assert validate_evidence_record(value, expected_schema=schema)["status"] == "PASS"


def test_evidence_rejects_unknown_fields_scope_expiry_and_consumed_approval() -> None:
    value = evidence_record("w6-004.image.v1")
    value["unexpected"] = "fixture"
    with pytest.raises(W6004Error, match="fields or schema"):
        validate_evidence_record(value, expected_schema="w6-004.image.v1")

    value = evidence_record("w6-004.image.v1")
    value["evidence_scope"] = "discovery"
    value["evidence_sha256"] = canonical_evidence_sha256(value)
    with pytest.raises(W6004Error, match="scope"):
        validate_evidence_record(value, expected_schema="w6-004.image.v1")

    value = evidence_record("w6-004.image.v1")
    with pytest.raises(W6004Error, match="expired"):
        validate_evidence_record(
            value,
            expected_schema="w6-004.image.v1",
            now=datetime.now(UTC) + timedelta(hours=2),
        )

    value = evidence_record("w6-004.approval.v1")
    with pytest.raises(W6004Error, match="already been consumed"):
        validate_evidence_record(
            value,
            expected_schema="w6-004.approval.v1",
            consumed_approvals=("approval-fixture-0001",),
        )


def test_critical_findings_fail_closed() -> None:
    value = vulnerability_evidence(critical=1)
    with pytest.raises(W6004Error, match="Critical"):
        validate_evidence_record(
            value,
            expected_schema="w6-004.vulnerability-scan.v1",
        )


def test_known_good_rollback_requires_a_distinct_regression() -> None:
    known_good = "sha256:" + "1" * 64
    validate_w6_004_known_good_identity(
        current_digest=known_good,
        regression_digest="sha256:" + "2" * 64,
        known_good_digest=known_good,
    )


def test_sandbox_token_accepts_only_the_exact_synthetic_tenant() -> None:
    authenticator = SandboxTokenAuthenticator(
        signing_key=SIGNING_MATERIAL,
        issuer="enterprise-ai-sandbox",
        audience="enterprise-ai-api",
        tenant_id="synthetic-sandbox-tenant",
    )
    accepted = asyncio.run(
        authenticator.authenticate(
            _request_token(
                tenant_id="synthetic-sandbox-tenant",
                expires=int(time.time()) + 60,
            )
        )
    )
    assert accepted.tenant_id == "synthetic-sandbox-tenant"
    with pytest.raises(AuthenticationInvalidError):
        asyncio.run(
            authenticator.authenticate(
                _request_token(tenant_id="wrong-tenant", expires=int(time.time()) + 60)
            )
        )


@pytest.mark.parametrize(
    "candidate_request",
    [
        _request_token(
            tenant_id="synthetic-sandbox-tenant",
            expires=int(time.time()) + 60,
            issuer="wrong-issuer",
        ),
        _request_token(
            tenant_id="synthetic-sandbox-tenant",
            expires=int(time.time()) + 60,
            audience="wrong-audience",
        ),
        _request_token(
            tenant_id="synthetic-sandbox-tenant",
            issued_at=int(time.time()) + 120,
            not_before=int(time.time()) + 120,
            expires=int(time.time()) + 180,
        ),
        _request_token(
            tenant_id="synthetic-sandbox-tenant",
            expires=int(time.time()) - 60,
        ),
        Request(
            {
                "type": "http",
                "method": "GET",
                "path": "/health/ready",
                "headers": [(b"authorization", b"Bearer unsigned.malformed.token")],
            }
        ),
    ],
)
def test_sandbox_token_rejects_wrong_or_malformed_identity(
    candidate_request: Request,
) -> None:
    authenticator = SandboxTokenAuthenticator(
        signing_key=SIGNING_MATERIAL,
        issuer="enterprise-ai-sandbox",
        audience="enterprise-ai-api",
        tenant_id="synthetic-sandbox-tenant",
    )
    with pytest.raises(AuthenticationInvalidError):
        asyncio.run(authenticator.authenticate(candidate_request))


def test_duplicate_or_concurrent_lifecycle_operation_is_rejected() -> None:
    with pytest.raises(W6004Error, match="another lifecycle operation"):
        validate_operation_exclusivity(
            "operation-0002",
            active_operation_ids=("operation-0001",),
            completed_operation_ids=(),
        )
    with pytest.raises(W6004Error, match="already consumed"):
        validate_operation_exclusivity(
            "operation-0001",
            active_operation_ids=(),
            completed_operation_ids=("operation-0001",),
        )
