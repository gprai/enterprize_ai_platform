"""Fail-closed errors for offline capacity and cost evaluation."""


class CapacityError(ValueError):
    """Base error for W8-004 capacity contracts."""


class CapacityValidationError(CapacityError):
    """Raised when policy or aggregate evidence is malformed or inconsistent."""
