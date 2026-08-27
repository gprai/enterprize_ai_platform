"""Content-free contracts for optional guardrail adapters."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, model_validator


class GuardrailAssessment(BaseModel):
    """A normalized adapter decision that cannot retain inspected content."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        validate_default=True,
    )

    enabled: bool
    blocked: bool

    @model_validator(mode="after")
    def require_enabled_blocker(self) -> GuardrailAssessment:
        if self.blocked and not self.enabled:
            raise ValueError("a disabled guardrail adapter cannot block content")
        return self
