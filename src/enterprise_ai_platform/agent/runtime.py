"""Non-queuing admission, deadlines, and budget checks for W4-002."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from time import monotonic

from .models import AgentBudgets, AgentOutcome, AgentState, TerminalReason


class AgentCapacityLimiter:
    """Atomic one-run admission with no waiter or hidden queue."""

    def __init__(self, maximum: int = 1) -> None:
        if maximum != 1:
            raise ValueError("W4-002 agent capacity must be one")
        self._maximum = maximum
        self._active = 0
        self._lock = threading.Lock()

    @property
    def active(self) -> int:
        with self._lock:
            return self._active

    def try_acquire(self) -> bool:
        with self._lock:
            if self._active >= self._maximum:
                return False
            self._active += 1
            return True

    def release(self) -> None:
        with self._lock:
            if self._active != 1:
                raise RuntimeError("agent capacity released without admission")
            self._active = 0


@dataclass(frozen=True, slots=True)
class DeadlineClock:
    started: float
    deadline_seconds: int

    @classmethod
    def start(cls, deadline_seconds: int) -> DeadlineClock:
        return cls(started=monotonic(), deadline_seconds=deadline_seconds)

    def elapsed_milliseconds(self) -> int:
        return max(0, int((monotonic() - self.started) * 1000))

    def expired(self) -> bool:
        return self.elapsed_milliseconds() >= self.deadline_seconds * 1000


def apply_budget_terminal(
    state: AgentState,
    budgets: AgentBudgets,
    *,
    serialized_bytes: int | None = None,
) -> AgentState:
    """Return a content-free terminal state when any exact bound is exceeded."""

    reason: TerminalReason | None = None
    if state.step_count > budgets.maximum_graph_steps:
        reason = TerminalReason.STEP_BUDGET_EXCEEDED
    elif state.tool_call_count > budgets.maximum_tool_calls:
        reason = TerminalReason.TOOL_BUDGET_EXCEEDED
    elif state.provider_attempt_count > budgets.maximum_provider_attempts:
        reason = TerminalReason.PROVIDER_BUDGET_EXCEEDED
    elif state.total_tokens > budgets.maximum_total_tokens:
        reason = TerminalReason.TOKEN_BUDGET_EXCEEDED
    elif serialized_bytes is not None and serialized_bytes > budgets.maximum_serialized_state_bytes:
        reason = TerminalReason.STATE_BUDGET_EXCEEDED
    if reason is None:
        return state
    values = state.model_dump(mode="python")
    values.update(
        outcome=AgentOutcome.BUDGET_EXCEEDED,
        terminal_reason=reason,
        safe_error_code="agent_budget_exceeded",
    )
    return AgentState.model_validate(values, strict=True)
