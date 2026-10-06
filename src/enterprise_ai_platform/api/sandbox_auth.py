"""Bounded signed synthetic-token authentication for the W6-004 sandbox."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import time
from collections.abc import Mapping
from datetime import UTC, datetime

from fastapi import Request

from enterprise_ai_platform.retrieval.models import AuthContext, Classification, Role

from .errors import AuthenticationInvalidError, AuthenticationRequiredError

ALGORITHM = "HS256"
MAX_TOKEN_TTL_SECONDS = 900
CLOCK_SKEW_SECONDS = 30


def _decode(segment: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    except (ValueError, TypeError, binascii.Error):
        raise AuthenticationInvalidError from None


def _json(segment: str) -> Mapping[str, object]:
    def unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in pairs:
            if key in value:
                raise AuthenticationInvalidError
            value[key] = item
        return value

    try:
        value = json.loads(_decode(segment), object_pairs_hook=unique_pairs)
    except (UnicodeError, json.JSONDecodeError):
        raise AuthenticationInvalidError from None
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise AuthenticationInvalidError
    return value


class SandboxTokenAuthenticator:
    """Verify a non-production HMAC token without network or discovery calls."""

    def __init__(
        self,
        *,
        signing_key: str,
        issuer: str,
        audience: str,
        tenant_id: str,
    ) -> None:
        if (
            len(signing_key.encode()) < 32
            or not issuer.strip()
            or not audience.strip()
            or not tenant_id.strip()
        ):
            raise ValueError("sandbox token verifier requires an explicit strong key and identity")
        self._key = signing_key.encode()
        self._issuer = issuer
        self._audience = audience
        self._tenant_id = tenant_id

    async def authenticate(self, request: Request) -> AuthContext:
        authorization = request.headers.get("Authorization")
        if not authorization or not authorization.startswith("Bearer "):
            raise AuthenticationRequiredError
        token = authorization.removeprefix("Bearer ").strip()
        parts = token.split(".")
        if len(parts) != 3 or any(not part for part in parts):
            raise AuthenticationInvalidError
        header, claims = _json(parts[0]), _json(parts[1])
        if header != {"alg": ALGORITHM, "typ": "JWT"}:
            raise AuthenticationInvalidError
        expected = hmac.new(self._key, f"{parts[0]}.{parts[1]}".encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(expected, _decode(parts[2])):
            raise AuthenticationInvalidError
        required = {
            "iss",
            "aud",
            "sub",
            "tenant_id",
            "roles",
            "clearance",
            "iat",
            "nbf",
            "exp",
            "jti",
            "data_classification",
        }
        if set(claims) != required:
            raise AuthenticationInvalidError
        text_claims = (
            "iss",
            "aud",
            "sub",
            "tenant_id",
            "clearance",
            "jti",
            "data_classification",
        )
        text_values: dict[str, str] = {}
        for field in text_claims:
            item = claims[field]
            if not isinstance(item, str) or not item.strip():
                raise AuthenticationInvalidError
            text_values[field] = item
        if text_values["iss"] != self._issuer or text_values["aud"] != self._audience:
            raise AuthenticationInvalidError
        if text_values["tenant_id"] != self._tenant_id:
            raise AuthenticationInvalidError
        if text_values["data_classification"] not in {"PUBLIC", "INTERNAL"}:
            raise AuthenticationInvalidError
        if text_values["clearance"] != text_values["data_classification"]:
            raise AuthenticationInvalidError
        roles = claims["roles"]
        if (
            not isinstance(roles, list)
            or not roles
            or any(not isinstance(role, str) or not role.strip() for role in roles)
        ):
            raise AuthenticationInvalidError
        issued, not_before, expires = claims["iat"], claims["nbf"], claims["exp"]
        if isinstance(issued, bool) or not isinstance(issued, int):
            raise AuthenticationInvalidError
        if isinstance(not_before, bool) or not isinstance(not_before, int):
            raise AuthenticationInvalidError
        if isinstance(expires, bool) or not isinstance(expires, int):
            raise AuthenticationInvalidError
        now = int(time.time())
        if (
            issued > now + CLOCK_SKEW_SECONDS
            or not_before > now + CLOCK_SKEW_SECONDS
            or not_before < issued
            or expires <= not_before
            or expires <= now - CLOCK_SKEW_SECONDS
        ):
            raise AuthenticationInvalidError
        if expires - issued <= 0 or expires - issued > MAX_TOKEN_TTL_SECONDS:
            raise AuthenticationInvalidError
        try:
            return AuthContext(
                subject_id=text_values["sub"],
                tenant_id=text_values["tenant_id"],
                roles=frozenset(Role(item) for item in roles),
                clearance=Classification(text_values["clearance"]),
                issuer=self._issuer,
                audience=self._audience,
                expires_at=datetime.fromtimestamp(expires, tz=UTC),
                request_id=text_values["jti"],
            )
        except (TypeError, ValueError):
            raise AuthenticationInvalidError from None
