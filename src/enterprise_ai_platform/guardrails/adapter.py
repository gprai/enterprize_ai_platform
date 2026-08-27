"""Unwired optional guardrail adapter boundary and disabled local adapter."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from enterprise_ai_platform.guardrails.models import GuardrailAssessment


@runtime_checkable
class GuardrailAdapter(Protocol):
    """Optional supplement to deterministic policy; not invoked by W3-003."""

    async def assess(self, content: str) -> GuardrailAssessment:
        """Return a content-free assessment without executing an instruction."""

        ...


class DisabledGuardrailAdapter:
    """Stateless local adapter that performs no inspection or external activity."""

    __slots__ = ()

    async def assess(self, content: str) -> GuardrailAssessment:
        del content
        return GuardrailAssessment(enabled=False, blocked=False)
