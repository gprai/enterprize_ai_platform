"""Contract tests for public W3-004 models, errors, paths and CLI."""

from __future__ import annotations

import pytest
from pydantic import ValidationError
from tools.ragrollbackctl import _COMMANDS, build_parser

import enterprise_ai_platform.rag_rollback as rollback_api
from enterprise_ai_platform.rag_rollback.errors import RAGRollbackError
from enterprise_ai_platform.rag_rollback.models import (
    ActivationState,
    StrictRollbackModel,
)
from enterprise_ai_platform.rag_rollback.state import (
    ACTIVATION_LOCK_PATH,
    ACTIVE_STATE_PATH,
    REGRESSION_REPORT_PATH,
    RESTORED_REPORT_PATH,
    ROLLBACK_RECORD_PATH,
)


def test_public_api_exports_only_explicit_rollback_contracts() -> None:
    expected = {
        "ActivationOutcome",
        "ActivationState",
        "CleanlinessResult",
        "EvaluationOutcome",
        "IdentityValidationResult",
        "RAGIdentityDescriptor",
        "RAGRollbackError",
        "RollbackArtifactExistsError",
        "RollbackBaselineError",
        "RollbackCleanupError",
        "RollbackConfigurationError",
        "RollbackEvaluationError",
        "RollbackIdentityError",
        "RollbackLockError",
        "RollbackRecord",
        "RollbackStateConflictError",
        "RollbackStateError",
        "RollbackUnsafePathError",
        "activate_regression",
        "cleanup",
        "evaluate_regression",
        "evaluate_restored",
        "finalize",
        "initialize",
        "rollback",
        "validate",
        "verify_clean",
        "verify_zero_residue",
    }
    assert set(rollback_api.__all__) == expected


def test_errors_are_content_free_and_models_are_strict_immutable() -> None:
    assert str(RAGRollbackError()) == "rag_rollback_error"
    state = ActivationState(
        schema_version="w3-004.activation.v1",
        generation=1,
        active_identity="known-good",
        identity_sha256="a" * 64,
    )
    with pytest.raises(ValidationError):
        ActivationState.model_validate(
            {**state.model_dump(mode="json"), "raw_content": "forbidden"},
            strict=True,
        )
    with pytest.raises(ValidationError):
        ActivationState.model_validate(
            {**state.model_dump(mode="json"), "generation": "1"},
            strict=True,
        )
    with pytest.raises(ValidationError):
        state.generation = 2  # type: ignore[misc]
    assert issubclass(ActivationState, StrictRollbackModel)


def test_runtime_paths_and_cli_commands_are_exact() -> None:
    assert (
        ACTIVE_STATE_PATH.as_posix(),
        REGRESSION_REPORT_PATH.as_posix(),
        RESTORED_REPORT_PATH.as_posix(),
        ROLLBACK_RECORD_PATH.as_posix(),
        ACTIVATION_LOCK_PATH.as_posix(),
    ) == (
        "reports/w3-004/active.json",
        "reports/w3-004/regression.json",
        "reports/w3-004/restored.json",
        "reports/w3-004/rollback-record.json",
        "reports/w3-004/activation.lock",
    )
    assert _COMMANDS == (
        "validate",
        "initialize",
        "activate-regression",
        "evaluate-regression",
        "rollback",
        "evaluate-restored",
        "finalize",
        "verify-clean",
        "cleanup",
        "verify-zero-residue",
    )
    parser = build_parser()
    for command in _COMMANDS:
        arguments = parser.parse_args([command])
        assert arguments.command == command
