"""Content-free failures for the local W4-11 release rollback control plane."""

from __future__ import annotations


class ReleaseRollbackError(Exception):
    """Base failure whose public representation contains no protected content."""

    code = "release_rollback_error"

    def __init__(self) -> None:
        super().__init__(self.code)


class ReleaseConfigurationError(ReleaseRollbackError):
    code = "release_configuration_invalid"


class ReleaseIdentityError(ReleaseRollbackError):
    code = "release_identity_mismatch"


class ReleaseUnsafePathError(ReleaseRollbackError):
    code = "release_unsafe_path"


class ReleaseStateError(ReleaseRollbackError):
    code = "release_state_ambiguous"


class ReleaseLockError(ReleaseRollbackError):
    code = "release_lock_contended"


class ReleaseStateConflictError(ReleaseRollbackError):
    code = "release_active_state_conflict"


class ReleaseArtifactExistsError(ReleaseRollbackError):
    code = "release_artifact_exists"


class ReleaseProbeError(ReleaseRollbackError):
    code = "release_probe_failed"


class ReleaseDeadlineError(ReleaseRollbackError):
    code = "release_rollback_deadline_exceeded"


class ReleaseCleanupError(ReleaseRollbackError):
    code = "release_cleanup_failed"
