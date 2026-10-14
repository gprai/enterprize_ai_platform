"""Fail-closed errors for governed W9-001 training contracts."""


class TrainingError(ValueError):
    """Base error for governed training."""


class TrainingValidationError(TrainingError):
    """Raised when an identity, policy, or request is invalid."""


class TrainingAuthorizationError(TrainingError):
    """Raised before provider preparation when authorization is invalid."""


class TrainingCapabilityError(TrainingError):
    """Raised when requested compute is unavailable or inconsistent."""


class TrainingAdmissionError(TrainingError):
    """Raised when an approval, budget, or concurrency gate rejects work."""
