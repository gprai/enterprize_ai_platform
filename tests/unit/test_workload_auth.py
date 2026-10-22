"""TokenReview backed, Pod-bound probe identity without HS256 fallback."""

from __future__ import annotations

import asyncio
import base64
import json
import time
from pathlib import Path

import pytest
from starlette.requests import Request

from enterprise_ai_platform.api.errors import AuthenticationInvalidError
from enterprise_ai_platform.api.workload_auth import (
    TOKEN_AUDIENCE,
    TOKEN_SUBJECT,
    ProbeAwareAuthenticator,
    WorkloadTokenAuthenticator,
)


def _request(token: str, marker: str = "v1") -> Request:
    headers = [
        (b"authorization", ("Bearer " + token).encode()),
        (b"x-enterprise-ai-workload-probe", marker.encode()),
    ]
    return Request({"type": "http", "method": "GET", "path": "/v1/query", "headers": headers})


def _token(**changes) -> tuple[str, dict]:
    now = int(time.time())
    claims = {
        "iss": "https://issuer.example.invalid",
        "sub": TOKEN_SUBJECT,
        "aud": [TOKEN_AUDIENCE],
        "iat": now,
        "exp": now + 300,
        "kubernetes.io": {
            "pod": {
                "name": "enterprise-ai-capstone-probe-abc",
                "uid": "123e4567-e89b-42d3-a456-426614174000",
            }
        },
    }
    claims.update(changes)
    payload = (
        base64.urlsafe_b64encode(json.dumps(claims, separators=(",", ":")).encode())
        .decode()
        .rstrip("=")
    )
    return "eyJhbGciOiJSUzI1NiJ9." + payload + ".signature", claims


def _review(claims: dict) -> dict:
    pod = claims["kubernetes.io"]["pod"]
    return {
        "status": {
            "authenticated": True,
            "audiences": [TOKEN_AUDIENCE],
            "user": {
                "username": TOKEN_SUBJECT,
                "extra": {
                    "authentication.kubernetes.io/pod-name": [pod["name"]],
                    "authentication.kubernetes.io/pod-uid": [pod["uid"]],
                },
            },
        }
    }


def test_valid_projected_token_requires_matching_tokenreview(tmp_path: Path) -> None:
    token, claims = _token()
    auth = WorkloadTokenAuthenticator(
        issuer=claims["iss"],
        tenant_id="approved-tenant",
        api_token_file=tmp_path / "token",
        api_ca_file=tmp_path / "ca",
        reviewer=lambda _token: _review(claims),
    )
    context = asyncio.run(auth.authenticate(_request(token)))
    assert context.subject_id == TOKEN_SUBJECT
    assert context.tenant_id == "approved-tenant"


@pytest.mark.parametrize(
    "change",
    [
        {"iss": "https://wrong.example.invalid"},
        {"aud": ["wrong"]},
        {"sub": "system:serviceaccount:other:probe"},
        {"exp": 1},
    ],
)
def test_wrong_issuer_audience_subject_or_expiry_rejected(change: dict, tmp_path: Path) -> None:
    token, claims = _token(**change)
    auth = WorkloadTokenAuthenticator(
        issuer="https://issuer.example.invalid",
        tenant_id="approved-tenant",
        api_token_file=tmp_path / "token",
        api_ca_file=tmp_path / "ca",
        reviewer=lambda _token: _review(claims),
    )
    with pytest.raises(AuthenticationInvalidError):
        asyncio.run(auth.authenticate(_request(token)))


def test_failed_probe_never_falls_back_to_regular_authenticator(tmp_path: Path) -> None:
    token, claims = _token(aud=["wrong"])
    calls = []

    class Regular:
        async def authenticate(self, _request):
            calls.append("regular")
            raise AssertionError("HS256 fallback")

    probe = WorkloadTokenAuthenticator(
        issuer="https://issuer.example.invalid",
        tenant_id="approved-tenant",
        api_token_file=tmp_path / "token",
        api_ca_file=tmp_path / "ca",
        reviewer=lambda _token: _review(claims),
    )
    with pytest.raises(AuthenticationInvalidError):
        asyncio.run(ProbeAwareAuthenticator(probe, Regular()).authenticate(_request(token)))
    assert calls == []
