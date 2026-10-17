"""W9-004 model supply-chain failure types."""


class ModelSupplyChainError(ValueError):
    """Base error for fail-closed model supply-chain controls."""


class SupplyChainValidationError(ModelSupplyChainError):
    """Raised when configuration or evidence is malformed."""


class SupplyChainAdmissionError(ModelSupplyChainError):
    """Raised when a candidate is not eligible for registry admission."""
