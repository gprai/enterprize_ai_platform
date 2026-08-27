"""Bounded activation state and artifact lifecycle for the W3-004 drill."""

from __future__ import annotations

import os
import re
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Final

from pydantic import ValidationError

from enterprise_ai_platform.json_contracts import strict_json_loads

from . import identity as identity_module
from .errors import (
    RAGRollbackError,
    RollbackArtifactExistsError,
    RollbackCleanupError,
    RollbackLockError,
    RollbackStateConflictError,
    RollbackStateError,
    RollbackUnsafePathError,
)
from .identity import canonical_json_bytes, identity_sha256, load_identity
from .models import (
    ActivationOutcome,
    ActivationState,
    ExpectedCurrent,
    IdentityAlias,
)

RUNTIME_DIRECTORY: Final[Path] = Path("reports/w3-004")
ACTIVE_STATE_PATH: Final[Path] = RUNTIME_DIRECTORY / "active.json"
REGRESSION_REPORT_PATH: Final[Path] = RUNTIME_DIRECTORY / "regression.json"
RESTORED_REPORT_PATH: Final[Path] = RUNTIME_DIRECTORY / "restored.json"
ROLLBACK_RECORD_PATH: Final[Path] = RUNTIME_DIRECTORY / "rollback-record.json"
ACTIVATION_LOCK_PATH: Final[Path] = RUNTIME_DIRECTORY / "activation.lock"

_ARTIFACT_PATHS: Final[frozenset[Path]] = frozenset(
    {
        ACTIVE_STATE_PATH,
        REGRESSION_REPORT_PATH,
        RESTORED_REPORT_PATH,
        ROLLBACK_RECORD_PATH,
    }
)
_PUBLISHABLE_PATHS: Final[frozenset[Path]] = frozenset(
    {
        REGRESSION_REPORT_PATH,
        RESTORED_REPORT_PATH,
        ROLLBACK_RECORD_PATH,
    }
)
_TEMPORARY_NAME = re.compile(
    r"^\.(?:active|regression|restored|rollback-record)\.json\.\d+\.\d+\.tmp$"
)


def _repository_root() -> Path:
    try:
        return identity_module.REPOSITORY_ROOT.resolve(strict=True)
    except OSError:
        raise RollbackUnsafePathError from None


def _runtime_directory(*, create: bool) -> Path:
    root = _repository_root()
    reports = root / "reports"
    try:
        reports_resolved = reports.resolve(strict=True)
    except OSError:
        raise RollbackUnsafePathError from None
    if reports.is_symlink() or reports_resolved != reports:
        raise RollbackUnsafePathError

    directory = root / RUNTIME_DIRECTORY
    if directory.exists() or directory.is_symlink():
        try:
            resolved = directory.resolve(strict=True)
        except OSError:
            raise RollbackUnsafePathError from None
        if directory.is_symlink() or resolved != directory or not resolved.is_dir():
            raise RollbackUnsafePathError
    elif create:
        try:
            directory.mkdir()
        except FileExistsError:
            return _runtime_directory(create=False)
        except OSError:
            raise RollbackStateError from None
    return directory


def _runtime_file(relative: Path, *, require_exists: bool = False) -> Path:
    if relative.parent != RUNTIME_DIRECTORY:
        raise RollbackUnsafePathError
    directory = _runtime_directory(create=False)
    path = _repository_root() / relative
    if path.exists() or path.is_symlink():
        try:
            resolved = path.resolve(strict=True)
        except OSError:
            raise RollbackUnsafePathError from None
        if path.is_symlink() or resolved != path or not resolved.is_file():
            raise RollbackUnsafePathError
    elif require_exists:
        raise RollbackStateError
    if directory.exists() and path.parent != directory:
        raise RollbackUnsafePathError
    return path


def _temporary_for(target: Path) -> Path:
    return target.with_name(
        f".{target.name}.{os.getpid()}.{threading.get_ident()}.tmp"
    )


@contextmanager
def _exclusive_writer_lock() -> Iterator[None]:
    _runtime_directory(create=True)
    lock = _runtime_file(ACTIVATION_LOCK_PATH)
    descriptor: int | None = None
    try:
        descriptor = os.open(
            lock,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY,
            0o600,
        )
        os.write(descriptor, b"w3-004\n")
        os.fsync(descriptor)
    except FileExistsError:
        raise RollbackLockError from None
    except OSError:
        raise RollbackStateError from None
    try:
        yield
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            lock.unlink()
        except OSError:
            raise RollbackStateError from None


def _load_state_file(path: Path) -> ActivationState:
    try:
        text = path.read_text(encoding="utf-8", errors="strict")
        strict_json_loads(text)
        state = ActivationState.model_validate_json(text, strict=True)
        identity = load_identity(state.active_identity)
    except RAGRollbackError:
        raise
    except (OSError, UnicodeError, TypeError, ValueError, ValidationError):
        raise RollbackStateError from None
    if state.identity_sha256 != identity_sha256(identity):
        raise RollbackStateError
    return state


def read_activation_state() -> ActivationState | None:
    """Read one complete active state or fail closed on ambiguity."""

    directory = _runtime_directory(create=False)
    if not directory.exists():
        return None
    path = _runtime_file(ACTIVE_STATE_PATH)
    if not path.exists():
        return None
    return _load_state_file(path)


def require_activation_state(alias: IdentityAlias) -> ActivationState:
    state = read_activation_state()
    if state is None or state.active_identity != alias:
        raise RollbackStateConflictError
    return state


def _state_signature(state: ActivationState | None) -> tuple[object, ...]:
    if state is None:
        return (None,)
    return (state.generation, state.active_identity, state.identity_sha256)


def _expected_state_matches(
    state: ActivationState | None,
    expected_current: ExpectedCurrent,
) -> bool:
    if expected_current == "absent":
        return state is None
    return state is not None and state.active_identity == expected_current


def _atomic_replace_state(state: ActivationState) -> None:
    target = _runtime_file(ACTIVE_STATE_PATH)
    temporary = _temporary_for(target)
    if temporary.exists() or temporary.is_symlink():
        raise RollbackStateError
    try:
        with temporary.open("xb") as handle:
            handle.write(canonical_json_bytes(state.model_dump(mode="json")))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
    except OSError:
        raise RollbackStateError from None
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            raise RollbackStateError from None


def activate_identity(
    target_alias: IdentityAlias,
    *,
    expected_current: ExpectedCurrent,
) -> ActivationOutcome:
    """Atomically activate one immutable identity using a generation CAS."""

    target_identity = load_identity(target_alias)
    target_digest = identity_sha256(target_identity)
    before = read_activation_state()
    before_signature = _state_signature(before)

    with _exclusive_writer_lock():
        current = read_activation_state()
        if _state_signature(current) != before_signature:
            raise RollbackStateConflictError
        if current is not None and current.active_identity == target_alias:
            return ActivationOutcome(
                status="ALREADY_ACTIVE",
                active_identity=target_alias,
                identity_sha256=target_digest,
                generation=current.generation,
            )
        if not _expected_state_matches(current, expected_current):
            raise RollbackStateConflictError
        next_state = ActivationState(
            schema_version="w3-004.activation.v1",
            generation=1 if current is None else current.generation + 1,
            active_identity=target_alias,
            identity_sha256=target_digest,
        )
        _atomic_replace_state(next_state)
        verified = read_activation_state()
        if verified != next_state:
            raise RollbackStateError
        return ActivationOutcome(
            status="ACTIVATED",
            active_identity=target_alias,
            identity_sha256=target_digest,
            generation=next_state.generation,
        )


def _atomic_write_no_overwrite(target: Path, payload: bytes) -> None:
    if target.exists() or target.is_symlink():
        raise RollbackArtifactExistsError
    temporary = _temporary_for(target)
    if temporary.exists() or temporary.is_symlink():
        raise RollbackStateError
    try:
        with temporary.open("xb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, target)
        except FileExistsError:
            raise RollbackArtifactExistsError from None
    except RollbackArtifactExistsError:
        raise
    except OSError:
        raise RollbackStateError from None
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            raise RollbackStateError from None


def publish_artifact(
    relative: Path,
    payload: bytes,
    *,
    expected_state: ActivationState,
) -> None:
    """Publish one approved artifact iff the active generation is unchanged."""

    if relative not in _PUBLISHABLE_PATHS:
        raise RollbackUnsafePathError
    _runtime_directory(create=True)
    target = _runtime_file(relative)
    with _exclusive_writer_lock():
        if read_activation_state() != expected_state:
            raise RollbackStateConflictError
        _atomic_write_no_overwrite(target, payload)


def load_artifact_bytes(relative: Path) -> bytes:
    if relative not in _PUBLISHABLE_PATHS:
        raise RollbackUnsafePathError
    path = _runtime_file(relative, require_exists=True)
    try:
        return path.read_bytes()
    except OSError:
        raise RollbackStateError from None


def _inventory() -> tuple[set[Path], set[Path]]:
    directory = _runtime_directory(create=False)
    if not directory.exists():
        return set(), set()
    approved: set[Path] = set()
    unexpected: set[Path] = set()
    try:
        children = tuple(directory.iterdir())
    except OSError:
        raise RollbackStateError from None
    for child in children:
        relative = RUNTIME_DIRECTORY / child.name
        if child.is_symlink() or not child.is_file():
            unexpected.add(relative)
        elif relative in _ARTIFACT_PATHS or relative == ACTIVATION_LOCK_PATH:
            approved.add(relative)
        elif _TEMPORARY_NAME.fullmatch(child.name):
            approved.add(relative)
        else:
            unexpected.add(relative)
    return approved, unexpected


def verify_runtime_inventory(*, require_complete: bool) -> int:
    approved, unexpected = _inventory()
    if unexpected or ACTIVATION_LOCK_PATH in approved:
        raise RollbackCleanupError
    temporary = {
        path
        for path in approved
        if path not in _ARTIFACT_PATHS
    }
    if temporary:
        raise RollbackCleanupError
    artifacts = approved.intersection(_ARTIFACT_PATHS)
    if require_complete and artifacts != _ARTIFACT_PATHS:
        raise RollbackCleanupError
    return len(artifacts)


def cleanup_complete_drill(*, external_archive_verified: bool) -> None:
    """Remove only captured local drill outputs after external archival."""

    if not external_archive_verified:
        raise RollbackCleanupError
    verify_runtime_inventory(require_complete=False)
    with _exclusive_writer_lock():
        approved, unexpected = _inventory()
        allowed = _ARTIFACT_PATHS | {ACTIVATION_LOCK_PATH}
        if (
            unexpected
            or ACTIVATION_LOCK_PATH not in approved
            or not approved.issubset(allowed)
        ):
            raise RollbackCleanupError
        for relative in (
            REGRESSION_REPORT_PATH,
            RESTORED_REPORT_PATH,
            ROLLBACK_RECORD_PATH,
            ACTIVE_STATE_PATH,
        ):
            try:
                path = _runtime_file(relative)
                if path.exists():
                    path.unlink()
            except OSError:
                raise RollbackCleanupError from None
    directory = _runtime_directory(create=False)
    try:
        directory.rmdir()
    except OSError:
        raise RollbackCleanupError from None


def verify_zero_residue() -> None:
    directory = _runtime_directory(create=False)
    if directory.exists():
        raise RollbackCleanupError


def redacted_inventory() -> dict[str, object]:
    approved, unexpected = _inventory()
    return {
        "approved_artifact_count": len(approved),
        "unexpected_residue_count": len(unexpected),
    }
