"""Immutable two-tool registry for the W4-002 local proof boundary."""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Final

from .contracts import LocalStatusProvider
from .errors import AgentToolValidationError
from .models import (
    MockSetServiceModeArguments,
    ServiceStatusArguments,
    ToolKind,
    ToolProposal,
)
from .serialization import fingerprint

READ_TOOL_NAME: Final = "get_service_status"
WRITE_TOOL_NAME: Final = "mock_set_service_mode"
TOOL_VERSION: Final = "1.0"


class ToolRegistry:
    """Validate exact schemas and return only normalized local outcomes."""

    def __init__(
        self,
        status_provider: LocalStatusProvider,
        *,
        mock_write_enabled: bool,
    ) -> None:
        self._status_provider = status_provider
        self._mock_write_enabled = mock_write_enabled
        self._registry: Mapping[str, ToolKind] = MappingProxyType(
            {
                READ_TOOL_NAME: ToolKind.READ,
                WRITE_TOOL_NAME: ToolKind.MOCK_WRITE,
            }
        )

    @property
    def names(self) -> tuple[str, str]:
        return (READ_TOOL_NAME, WRITE_TOOL_NAME)

    def validate(self, proposal: ToolProposal) -> None:
        if self._registry.get(proposal.name) is not proposal.kind:
            raise AgentToolValidationError
        if proposal.version != TOOL_VERSION:
            raise AgentToolValidationError
        if proposal.name == READ_TOOL_NAME and not isinstance(
            proposal.arguments,
            ServiceStatusArguments,
        ):
            raise AgentToolValidationError
        if proposal.name == WRITE_TOOL_NAME and not isinstance(
            proposal.arguments,
            MockSetServiceModeArguments,
        ):
            raise AgentToolValidationError

    def arguments_fingerprint(self, proposal: ToolProposal) -> str:
        self.validate(proposal)
        return fingerprint(proposal.arguments)

    async def execute_read(self, proposal: ToolProposal) -> str:
        self.validate(proposal)
        if proposal.name != READ_TOOL_NAME:
            raise AgentToolValidationError
        status = await self._status_provider.query_wiring_status()
        if status not in {"ready", "degraded"}:
            raise AgentToolValidationError
        return fingerprint({"status": status})

    def execute_mock_write(self, proposal: ToolProposal) -> str:
        self.validate(proposal)
        if proposal.name != WRITE_TOOL_NAME or not self._mock_write_enabled:
            raise AgentToolValidationError
        return fingerprint({"effect": "simulated", "mode": "maintenance"})
