"""Provider-neutral, offline OIDC/JWT validated-claim contract."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Final

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from enterprise_ai_platform.retrieval.models import AuthContext, Classification, Role

MAX_TOKEN_LIFETIME: Final = timedelta(hours=1)
CLOCK_SKEW: Final = timedelta(seconds=30)


class SessionStatus(StrEnum):
    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"
    UNKNOWN = "UNKNOWN"


class ProductionIdentityClaims(BaseModel):
    """Claims accepted only after provider-neutral signature validation upstream."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    issuer: str = Field(min_length=1, max_length=500)
    audience: str = Field(min_length=1, max_length=500)
    subject: str = Field(min_length=1, max_length=256)
    tenant: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,127}$")
    groups: frozenset[str] = Field(max_length=100)
    roles: frozenset[Role] = Field(min_length=1, max_length=4)
    key_id: str = Field(min_length=1, max_length=256)
    issued_at: datetime
    not_before: datetime
    expires_at: datetime
    session_status: SessionStatus
    claim_source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    authentication_strength: str | None = Field(default=None, min_length=1, max_length=128)
    clearance: Classification
    token_id: str = Field(min_length=1, max_length=256)

    @field_validator("issued_at", "not_before", "expires_at")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError("token times must be UTC-aware")
        return value.astimezone(UTC)

    @field_validator("groups")
    @classmethod
    def validate_groups(cls, values: frozenset[str]) -> frozenset[str]:
        if any(not value or len(value) > 128 for value in values):
            raise ValueError("group claim is malformed")
        return values

    @model_validator(mode="after")
    def require_coherent_claims(self) -> ProductionIdentityClaims:
        if self.not_before < self.issued_at or self.expires_at <= self.not_before:
            raise ValueError("token time ordering is invalid")
        if self.expires_at - self.issued_at > MAX_TOKEN_LIFETIME:
            raise ValueError("token lifetime exceeds the approved boundary")
        if self.session_status is not SessionStatus.ACTIVE:
            raise ValueError("session is not active")
        return self

    def to_auth_context(self, *, now: datetime) -> AuthContext:
        """Create the existing trusted context; transport headers are never inputs."""
        if now.tzinfo is None or now.utcoffset() != timedelta(0):
            raise ValueError("identity evaluation time must be UTC-aware")
        checked = now.astimezone(UTC)
        if checked + CLOCK_SKEW < self.not_before or checked - CLOCK_SKEW >= self.expires_at:
            raise ValueError("token is premature or stale")
        return AuthContext(
            subject_id=self.subject,
            tenant_id=self.tenant,
            roles=self.roles,
            groups=self.groups,
            clearance=self.clearance,
            issuer=self.issuer,
            audience=self.audience,
            expires_at=self.expires_at,
            request_id=self.token_id,
        )


def validate_trusted_claims(
    claims: object,
    *,
    trusted_issuer: str,
    trusted_audience: str,
    now: datetime,
) -> AuthContext:
    """Validate already signature-checked claims without discovery or provider activation."""
    value = ProductionIdentityClaims.model_validate(claims, strict=True)
    if value.issuer != trusted_issuer or value.audience != trusted_audience:
        raise ValueError("issuer or audience conflicts with trusted configuration")
    return value.to_auth_context(now=now)
