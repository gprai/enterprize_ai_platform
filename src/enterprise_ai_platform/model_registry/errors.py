"""Fail-closed errors for W9-003 model-package governance."""


class ModelRegistryError(ValueError):
    """Base error for the governed model registry."""


class RegistryValidationError(ModelRegistryError):
    """Raised when an identity, policy, or serialized record is invalid."""


class RegistryAuthorizationError(ModelRegistryError):
    """Raised before registry access when authorization fails."""


class RegistryAdmissionError(ModelRegistryError):
    """Raised when limits, deadlines, or idempotency reject a mutation."""


class RegistryStateError(ModelRegistryError):
    """Raised when a registry transition is not permitted."""
