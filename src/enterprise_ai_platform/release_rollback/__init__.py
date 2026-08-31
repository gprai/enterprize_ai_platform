"""Public contracts for the local W4-11 release rollback control plane."""

from .errors import ReleaseRollbackError
from .identity import (
    APPROVED_ARTIFACT_COUNT,
    APPROVED_ARTIFACT_PATHS,
    APPROVED_COMPOSITION_SHA256,
    descriptor_sha256,
    load_release_descriptor,
    validate_release_pair,
)
from .models import (
    ActiveReleaseState,
    CandidateProbeResult,
    CleanlinessResult,
    RegressionReport,
    ReleaseDescriptor,
    ReleaseLifecycleResult,
    ReleaseValidationResult,
    RestoredProbeResult,
    RollbackReport,
    SmokeReport,
)
from .service import (
    cleanup,
    rollback_release,
    smoke,
    validate,
    verify_clean,
    verify_zero_residue,
)

__all__ = [
    "APPROVED_ARTIFACT_COUNT",
    "APPROVED_ARTIFACT_PATHS",
    "APPROVED_COMPOSITION_SHA256",
    "ActiveReleaseState",
    "CandidateProbeResult",
    "CleanlinessResult",
    "RegressionReport",
    "ReleaseDescriptor",
    "ReleaseLifecycleResult",
    "ReleaseRollbackError",
    "ReleaseValidationResult",
    "RestoredProbeResult",
    "RollbackReport",
    "SmokeReport",
    "cleanup",
    "descriptor_sha256",
    "load_release_descriptor",
    "rollback_release",
    "smoke",
    "validate",
    "validate_release_pair",
    "verify_clean",
    "verify_zero_residue",
]
