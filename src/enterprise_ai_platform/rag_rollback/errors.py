"""Content-free failures for the local W3-004 rollback drill."""

from __future__ import annotations


class RAGRollbackError(Exception):
    """Base failure whose public representation contains no evaluated content."""

    code = "rag_rollback_error"

    def __init__(self) -> None:
        super().__init__(self.code)


class RollbackConfigurationError(RAGRollbackError):
    code = "rollback_configuration_invalid"


class RollbackBaselineError(RAGRollbackError):
    code = "rollback_baseline_invalid"


class RollbackIdentityError(RAGRollbackError):
    code = "rollback_identity_mismatch"


class RollbackUnsafePathError(RAGRollbackError):
    code = "rollback_unsafe_path"


class RollbackStateError(RAGRollbackError):
    code = "rollback_state_ambiguous"


class RollbackLockError(RAGRollbackError):
    code = "rollback_lock_contended"


class RollbackStateConflictError(RAGRollbackError):
    code = "rollback_active_state_conflict"


class RollbackArtifactExistsError(RAGRollbackError):
    code = "rollback_artifact_exists"


class RollbackEvaluationError(RAGRollbackError):
    code = "rollback_evaluation_failed"


class RollbackCleanupError(RAGRollbackError):
    code = "rollback_cleanup_failed"
