"""Strict two-tool allowlist and normalized local-only outcomes."""

from __future__ import annotations

import asyncio

import pytest
from pydantic import ValidationError

from enterprise_ai_platform.agent.errors import AgentToolValidationError
from enterprise_ai_platform.agent.models import (
    MockSetServiceModeArguments,
    ServiceStatusArguments,
    ToolKind,
    ToolProposal,
)
from enterprise_ai_platform.agent.tools import ToolRegistry
from tests.fakes.agent import FakeLocalStatusProvider


def test_registry_contains_exactly_one_read_and_one_mock_write_tool() -> None:
    registry = ToolRegistry(FakeLocalStatusProvider(), mock_write_enabled=True)
    assert registry.names == ("get_service_status", "mock_set_service_mode")


def test_read_tool_accepts_only_query_wiring_and_returns_reference() -> None:
    status = FakeLocalStatusProvider("ready")
    registry = ToolRegistry(status, mock_write_enabled=False)
    proposal = ToolProposal(
        name="get_service_status",
        kind=ToolKind.READ,
        arguments=ServiceStatusArguments(component="query_wiring"),
    )
    result = asyncio.run(registry.execute_read(proposal))

    assert len(result) == 64
    assert status.calls == 1


def test_mock_write_is_simulated_and_separately_disabled() -> None:
    proposal = ToolProposal(
        name="mock_set_service_mode",
        kind=ToolKind.MOCK_WRITE,
        arguments=MockSetServiceModeArguments(mode="maintenance"),
    )
    enabled = ToolRegistry(FakeLocalStatusProvider(), mock_write_enabled=True)
    disabled = ToolRegistry(FakeLocalStatusProvider(), mock_write_enabled=False)

    assert len(enabled.execute_mock_write(proposal)) == 64
    with pytest.raises(AgentToolValidationError):
        disabled.execute_mock_write(proposal)


def test_unknown_extra_or_wrong_arguments_are_rejected() -> None:
    with pytest.raises(ValidationError):
        ServiceStatusArguments.model_validate(
            {"component": "query_wiring", "extra": "denied"},
            strict=True,
        )
    with pytest.raises(ValidationError):
        MockSetServiceModeArguments.model_validate(
            {"mode": "production"},
            strict=True,
        )
    with pytest.raises(ValidationError):
        ToolProposal.model_validate(
            {
                "name": "get_service_status",
                "version": "2.0",
                "kind": "read",
                "arguments": {"component": "query_wiring"},
            },
            strict=True,
        )
