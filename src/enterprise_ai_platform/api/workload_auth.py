"""TokenReview-validated identity for the single in-cluster W12 probe."""

from __future__ import annotations

import asyncio
import base64
import json
import re
import ssl
import time
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import Request

from enterprise_ai_platform.retrieval.models import AuthContext, Classification, Role

from .dependencies import Authenticator
from .errors import AuthenticationInvalidError, AuthenticationRequiredError

TOKEN_AUDIENCE = "enterprise-ai-capstone-probe"  # noqa: S105 -- public audience, not a secret
TOKEN_SUBJECT = "system:serviceaccount:enterprise-ai-sandbox:enterprise-ai-capstone-probe"  # noqa: S105
TOKENREVIEW_URL = "https://kubernetes.default.svc/apis/authentication.k8s.io/v1/tokenreviews"
MAX_TOKEN_BYTES = 8192
PROBE_MARKER = "v1"


def _unique_jwt_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise AuthenticationInvalidError
        value[key] = item
    return value


def _jwt_payload(token: str) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3 or any(not re.fullmatch(r"[A-Za-z0-9_-]+", part) for part in parts):
        raise AuthenticationInvalidError
    segment = parts[1]
    try:
        raw = base64.b64decode(segment + "=" * (-len(segment) % 4), altchars=b"-_", validate=True)
        if len(raw) > 4096 or base64.urlsafe_b64encode(raw).decode().rstrip("=") != segment:
            raise AuthenticationInvalidError
        claims = json.loads(raw, object_pairs_hook=_unique_jwt_pairs)
    except (ValueError, UnicodeError, json.JSONDecodeError):
        raise AuthenticationInvalidError from None
    if not isinstance(claims, dict):
        raise AuthenticationInvalidError
    return claims


class WorkloadTokenAuthenticator:
    """Accept only a live Pod-bound projected token for a fixed server-side principal."""

    def __init__(
        self,
        *,
        issuer: str,
        tenant_id: str,
        api_token_file: Path,
        api_ca_file: Path,
        reviewer: Any | None = None,
    ) -> None:
        if (
            not issuer.startswith("https://")
            or not tenant_id
            or not api_token_file.is_absolute()
            or not api_ca_file.is_absolute()
        ):
            raise ValueError(
                "workload authentication requires approved issuer, tenant and API mounts"
            )
        self._issuer = issuer
        self._tenant_id = tenant_id
        self._api_token_file = api_token_file
        self._api_ca_file = api_ca_file
        self._reviewer = reviewer or self._token_review

    def _token_review(self, token: str) -> dict[str, Any]:
        api_token = self._api_token_file.read_text(encoding="ascii").strip()
        if not api_token or len(api_token) > MAX_TOKEN_BYTES:
            raise AuthenticationInvalidError
        body = json.dumps(
            {
                "apiVersion": "authentication.k8s.io/v1",
                "kind": "TokenReview",
                "spec": {"token": token, "audiences": [TOKEN_AUDIENCE]},
            }
        ).encode()
        request = urllib.request.Request(
            TOKENREVIEW_URL,
            data=body,
            method="POST",
            headers={"Authorization": "Bearer " + api_token, "Content-Type": "application/json"},
        )
        context = ssl.create_default_context(cafile=str(self._api_ca_file))

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
                return None

        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=context), NoRedirect()
        )
        with opener.open(request, timeout=3) as response:
            if response.status != 201 and response.status != 200:
                raise AuthenticationInvalidError
            raw = response.read(16_385)
            if len(raw) > 16_384:
                raise AuthenticationInvalidError
        result = json.loads(raw)
        if not isinstance(result, dict):
            raise AuthenticationInvalidError
        return result

    async def authenticate(self, request: Request) -> AuthContext:
        authorization = request.headers.get("Authorization")
        if not authorization or not authorization.startswith("Bearer "):
            raise AuthenticationRequiredError
        token = authorization[7:]
        if not token or len(token.encode("ascii", errors="ignore")) > MAX_TOKEN_BYTES:
            raise AuthenticationInvalidError
        claims = _jwt_payload(token)
        kubernetes = claims.get("kubernetes.io")
        pod = kubernetes.get("pod") if isinstance(kubernetes, dict) else None
        if (
            claims.get("iss") != self._issuer
            or claims.get("sub") != TOKEN_SUBJECT
            or claims.get("aud") != [TOKEN_AUDIENCE]
            or not isinstance(pod, dict)
            or not isinstance(pod.get("name"), str)
            or not pod["name"].startswith("enterprise-ai-capstone-probe-")
            or not isinstance(pod.get("uid"), str)
            or not re.fullmatch(r"[0-9a-f-]{36}", pod["uid"])
            or type(claims.get("exp")) is not int
            or type(claims.get("iat")) is not int
            or not 0 < claims["exp"] - claims["iat"] <= 600
            or not claims["iat"] <= int(time.time()) < claims["exp"]
        ):
            raise AuthenticationInvalidError
        try:
            review = await asyncio.wait_for(asyncio.to_thread(self._reviewer, token), timeout=4)
        except (TimeoutError, OSError, ValueError):
            raise AuthenticationInvalidError from None
        status = review.get("status") if isinstance(review, dict) else None
        user = status.get("user") if isinstance(status, dict) else None
        extra = user.get("extra") if isinstance(user, dict) else None
        if (
            not isinstance(status, dict)
            or status.get("authenticated") is not True
            or status.get("audiences") != [TOKEN_AUDIENCE]
            or not isinstance(user, dict)
            or user.get("username") != TOKEN_SUBJECT
            or not isinstance(extra, dict)
            or extra.get("authentication.kubernetes.io/pod-name") != [pod["name"]]
            or extra.get("authentication.kubernetes.io/pod-uid") != [pod["uid"]]
        ):
            raise AuthenticationInvalidError
        return AuthContext(
            subject_id=TOKEN_SUBJECT,
            tenant_id=self._tenant_id,
            roles=frozenset({Role.READER}),
            clearance=Classification.PUBLIC,
            issuer=self._issuer,
            audience=TOKEN_AUDIENCE,
            expires_at=datetime.fromtimestamp(claims["exp"], UTC),
        )


class ProbeAwareAuthenticator:
    """Route marked probe tokens only to TokenReview, never to the HS256 verifier."""

    def __init__(self, probe: WorkloadTokenAuthenticator, regular: Authenticator) -> None:
        self._probe = probe
        self._regular = regular

    async def authenticate(self, request: Request) -> AuthContext:
        marker = request.headers.get("X-Enterprise-AI-Workload-Probe")
        if marker is None:
            return await self._regular.authenticate(request)
        if marker != PROBE_MARKER:
            raise AuthenticationInvalidError
        return await self._probe.authenticate(request)
