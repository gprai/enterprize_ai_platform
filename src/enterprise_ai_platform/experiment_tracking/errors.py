"""Fail-closed errors for W9-002 experiment lineage."""


class ExperimentTrackingError(ValueError):
    """Base error for governed experiment tracking."""


class ExperimentValidationError(ExperimentTrackingError):
    """Raised when an identity, policy, record, or transition is invalid."""


class ExperimentAuthorizationError(ExperimentTrackingError):
    """Raised before the tracking-store boundary when authorization fails."""


class ExperimentAdmissionError(ExperimentTrackingError):
    """Raised when limits, deadlines, or idempotency reject a run."""


class ExperimentStateError(ExperimentTrackingError):
    """Raised when a run or store transition is not permitted."""
