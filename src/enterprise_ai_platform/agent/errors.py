"""Stable, content-free failures for the W4-002 agent boundary."""

from __future__ import annotations


class AgentError(Exception):
    """Base failure exposing only a policy-defined code and safe message."""

    code = "internal_error"
    safe_message = "The agent request could not be completed."

    def __init__(self) -> None:
        super().__init__(self.safe_message)


class AgentNotConfiguredError(AgentError):
    code = "agent_not_configured"
    safe_message = "The agent controller is not configured."


class AgentAuthorizationError(AgentError):
    code = "authorization_denied"
    safe_message = "The operation is not authorized."


class AgentApprovalConflictError(AgentError):
    code = "agent_approval_conflict"
    safe_message = "The approval decision conflicts with the current state."


class AgentDeadlineError(AgentError):
    code = "agent_deadline_exceeded"
    safe_message = "The agent deadline was exceeded."


class AgentOverloadedError(AgentError):
    code = "agent_overloaded"
    safe_message = "The agent service is at capacity."


class AgentStateUnavailableError(AgentError):
    code = "agent_state_unavailable"
    safe_message = "The agent state is unavailable."


class AgentStateValidationError(AgentStateUnavailableError):
    """Malformed, corrupt, version-mismatched, or oversized state."""


class AgentToolValidationError(AgentError):
    code = "agent_tool_invalid"
    safe_message = "The requested agent tool operation is invalid."


class AgentBudgetError(AgentError):
    code = "agent_budget_exceeded"
    safe_message = "The agent stopped at an approved budget."
