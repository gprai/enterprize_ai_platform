"""Stable, content-free failures for deterministic guardrail policy."""

from __future__ import annotations

from typing import Literal


class GuardrailInputError(Exception):
    """Reject invalid RAG input without retaining or exposing its content."""

    code: Literal["guardrail_input_invalid"] = "guardrail_input_invalid"
    public_message = "The RAG input is invalid."

    def __init__(self) -> None:
        super().__init__(self.public_message)
