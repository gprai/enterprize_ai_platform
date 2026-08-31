"""Bounded atomic runtime state for the local W4-11 release rollback drill."""

from __future__ import annotations

import os
import re
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Final

from pydantic import BaseModel, ValidationError

from enterprise_ai_platform.json_contracts import strict_json_loads

from . import identity as identity_module
from .errors import (
    ReleaseArtifactExistsError,
    ReleaseCleanupError,
    ReleaseLockError,
    ReleaseRollbackError,
    ReleaseStateConflictError,
    ReleaseStateError,
    ReleaseUnsafePathError,
)
from .identity import (
    canonical_json_bytes,
    descriptor_sha256,
    load_release_descriptor,
)
from .models import (
    ActiveReleaseState,
    ExpectedCurrent,
    ReleaseActivationOutcome,
    ReleaseVersion,
    SmokeReport,
)

REPOSITORY_ROOT: Path = identity_module.REPOSITORY_ROOT
RUNTIME_DIRECTORY: Final[Path] = Path("reports/w4-release")
ACTIVE_STATE_PATH: Final[Path] = RUNTIME_DIRECTORY / "active.json"
REGRESSION_REPORT_PATH: Final[Path] = RUNTIME_DIRECTORY / "regression.json"
ROLLBACK_REPORT_PATH: Final[Path] = RUNTIME_DIRECTORY / "rollback.json"
SMOKE_REPORT_PATH: Final[Path] = RUNTIME_DIRECTORY / "smoke.json"
ACTIVATION_LOCK_PATH: Final[Path] = RUNTIME_DIRECTORY / "activation.lock"
LOCK_TIMEOUT_SECONDS: Final = 1.0
LOCK_POLL_SECONDS: Final = 0.01

_REPORT_PATHS: Final[frozenset[Path]] = frozenset(
    {REGRESSION_REPORT_PATH, ROLLBACK_REPORT_PATH, SMOKE_REPORT_PATH}
)
_ARTIFACT_PATHS: Final[frozenset[Path]] = _REPORT_PATHS | {ACTIVE_STATE_PATH}
_TEMPORARY_NAME = re.compile(r"^\.(?:active|regression|rollback|smoke)\.json\.\d+\.\d+\.tmp$")


def _repository_root() -> Path:
    try:
        root = REPOSITORY_ROOT.resolve(strict=True)
    except OSError:
        raise ReleaseUnsafePathError from None
    if REPOSITORY_ROOT.is_symlink() or not root.is_dir():
        raise ReleaseUnsafePathError
    return root


def _runtime_directory(*, create: bool) -> Path:
    root = _repository_root()
    reports = root / "reports"
    try:
        reports_resolved = reports.resolve(strict=True)
    except OSError:
        raise ReleaseUnsafePathError from None
    if reports.is_symlink() or reports_resolved != reports or not reports.is_dir():
        raise ReleaseUnsafePathError

    directory = root / RUNTIME_DIRECTORY
    if directory.exists() or directory.is_symlink():
        try:
            resolved = directory.resolve(strict=True)
        except OSError:
            raise ReleaseUnsafePathError from None
        if directory.is_symlink() or resolved != directory or not resolved.is_dir():
            raise ReleaseUnsafePathError
    elif create:
        try:
            directory.mkdir()
        except FileExistsError:
            return _runtime_directory(create=False)
        except OSError:
            raise ReleaseStateError from None
    return directory


def _runtime_file(relative: Path, *, require_exists: bool = False) -> Path:
    if relative.parent != RUNTIME_DIRECTORY:
        raise ReleaseUnsafePathError
    directory = _runtime_directory(create=False)
    path = _repository_root() / relative
    if path.exists() or path.is_symlink():
        try:
            resolved = path.resolve(strict=True)
        except OSError:
            raise ReleaseUnsafePathError from None
        if path.is_symlink() or resolved != path or not resolved.is_file():
            raise ReleaseUnsafePathError
    elif require_exists:
        raise ReleaseStateError
    if directory.exists() and path.parent != directory:
        raise ReleaseUnsafePathError
    return path


def _temporary_for(target: Path) -> Path:
    return target.with_name(f".{target.name}.{os.getpid()}.{threading.get_ident()}.tmp")


@contextmanager
def _exclusive_writer_lock() -> Iterator[None]:
    """Acquire the fixed lock with bounded monotonic polling and no stale cleanup."""

    _runtime_directory(create=True)
    lock = _runtime_file(ACTIVATION_LOCK_PATH)
    deadline = time.monotonic() + LOCK_TIMEOUT_SECONDS
    descriptor: int | None = None
    while descriptor is None:
        try:
            descriptor = os.open(
                lock,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                0o600,
            )
        except FileExistsError:
            if time.monotonic() >= deadline:
                raise ReleaseLockError from None
            time.sleep(LOCK_POLL_SECONDS)
        except OSError:
            raise ReleaseStateError from None
    try:
        os.write(descriptor, b"w4-011\n")
        os.fsync(descriptor)
        yield
    finally:
        os.close(descriptor)
        try:
            lock.unlink()
        except OSError:
            raise ReleaseStateError from None


def _load_state_file(path: Path) -> ActiveReleaseState:
    try:
        payload = path.read_bytes()
        text = payload.decode("utf-8", errors="strict")
        strict_json_loads(text)
        state = ActiveReleaseState.model_validate_json(text, strict=True)
        descriptor = load_release_descriptor(state.active_release)
    except ReleaseRollbackError:
        raise
    except (OSError, UnicodeError, TypeError, ValueError, ValidationError):
        raise ReleaseStateError from None
    if (
        payload != canonical_json_bytes(state.model_dump(mode="json"))
        or state.descriptor_sha256 != descriptor_sha256(descriptor)
        or state.composition_sha256 != descriptor.composition_sha256
    ):
        raise ReleaseStateError
    return state


def read_active_state() -> ActiveReleaseState | None:
    """Read one complete active state or fail closed on ambiguity."""

    directory = _runtime_directory(create=False)
    if not directory.exists():
        return None
    path = _runtime_file(ACTIVE_STATE_PATH)
    if not path.exists():
        return None
    return _load_state_file(path)


def require_active_state(version: ReleaseVersion) -> ActiveReleaseState:
    state = read_active_state()
    if state is None or state.active_release != version:
        raise ReleaseStateConflictError
    return state


def _state_signature(state: ActiveReleaseState | None) -> tuple[object, ...]:
    if state is None:
        return (None,)
    return (
        state.generation,
        state.active_release,
        state.descriptor_sha256,
        state.composition_sha256,
        state.agent_route_allowed,
    )


def _expected_state_matches(
    state: ActiveReleaseState | None,
    expected_current: ExpectedCurrent,
) -> bool:
    if expected_current == "absent":
        return state is None
    return state is not None and state.active_release == expected_current


def _atomic_replace_state(state: ActiveReleaseState) -> None:
    target = _runtime_file(ACTIVE_STATE_PATH)
    temporary = _temporary_for(target)
    if temporary.exists() or temporary.is_symlink():
        raise ReleaseStateError
    try:
        with temporary.open("xb") as handle:
            handle.write(canonical_json_bytes(state.model_dump(mode="json")))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
    except OSError:
        raise ReleaseStateError from None
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            raise ReleaseStateError from None


def activate_release(
    target_version: ReleaseVersion,
    *,
    expected_current: ExpectedCurrent,
) -> ReleaseActivationOutcome:
    """Atomically activate one immutable release through a generation CAS."""

    target = load_release_descriptor(target_version)
    target_digest = descriptor_sha256(target)
    before = read_active_state()
    before_signature = _state_signature(before)
    with _exclusive_writer_lock():
        current = read_active_state()
        if _state_signature(current) != before_signature:
            raise ReleaseStateConflictError
        if current is not None and current.active_release == target_version:
            return ReleaseActivationOutcome(
                status="ALREADY_ACTIVE",
                active_release=target_version,
                descriptor_sha256=target_digest,
                generation=current.generation,
                agent_route_allowed=current.agent_route_allowed,
            )
        if not _expected_state_matches(current, expected_current):
            raise ReleaseStateConflictError
        next_state = ActiveReleaseState(
            schema_version="w4-011.active.v1",
            generation=1 if current is None else current.generation + 1,
            active_release=target_version,
            descriptor_sha256=target_digest,
            composition_sha256=target.composition_sha256,
            agent_route_allowed=False,
        )
        _atomic_replace_state(next_state)
        verified = read_active_state()
        if verified != next_state:
            raise ReleaseStateError
        return ReleaseActivationOutcome(
            status="ACTIVATED",
            active_release=target_version,
            descriptor_sha256=target_digest,
            generation=next_state.generation,
            agent_route_allowed=False,
        )


def _atomic_write_no_overwrite(target: Path, payload: bytes) -> None:
    if target.exists() or target.is_symlink():
        raise ReleaseArtifactExistsError
    temporary = _temporary_for(target)
    if temporary.exists() or temporary.is_symlink():
        raise ReleaseStateError
    try:
        with temporary.open("xb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, target)
        except FileExistsError:
            raise ReleaseArtifactExistsError from None
    except ReleaseArtifactExistsError:
        raise
    except OSError:
        raise ReleaseStateError from None
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            raise ReleaseStateError from None


def publish_report(
    relative: Path,
    report: BaseModel,
    *,
    expected_state: ActiveReleaseState,
) -> None:
    """Create one approved report iff the active generation is unchanged."""

    if relative not in _REPORT_PATHS:
        raise ReleaseUnsafePathError
    _runtime_directory(create=True)
    target = _runtime_file(relative)
    with _exclusive_writer_lock():
        if read_active_state() != expected_state:
            raise ReleaseStateConflictError
        payload = canonical_json_bytes(report.model_dump(mode="json"))
        _atomic_write_no_overwrite(target, payload)
        try:
            if target.read_bytes() != payload:
                raise ReleaseStateError
        except OSError:
            raise ReleaseStateError from None


def publish_smoke_and_enable(
    report: SmokeReport,
    *,
    expected_state: ActiveReleaseState,
) -> ActiveReleaseState:
    """Publish passed gates before atomically opening the restored-N latch."""

    target = _runtime_file(SMOKE_REPORT_PATH)
    created = False
    with _exclusive_writer_lock():
        current = read_active_state()
        if (
            current != expected_state
            or current.active_release != "w4-known-good-v1"
            or current.agent_route_allowed
        ):
            raise ReleaseStateConflictError
        try:
            payload = canonical_json_bytes(report.model_dump(mode="json"))
            _atomic_write_no_overwrite(target, payload)
            created = True
            try:
                if target.read_bytes() != payload:
                    raise ReleaseStateError
            except OSError:
                raise ReleaseStateError from None
            enabled = current.model_copy(update={"agent_route_allowed": True})
            _atomic_replace_state(enabled)
            verified = read_active_state()
            if verified != enabled:
                raise ReleaseStateError
        except Exception:
            if created:
                try:
                    target.unlink(missing_ok=True)
                except OSError:
                    raise ReleaseStateError from None
            raise
    return enabled


def load_report_bytes(relative: Path) -> bytes:
    if relative not in _REPORT_PATHS:
        raise ReleaseUnsafePathError
    path = _runtime_file(relative, require_exists=True)
    try:
        return path.read_bytes()
    except OSError:
        raise ReleaseStateError from None


def _inventory() -> tuple[set[Path], set[Path]]:
    directory = _runtime_directory(create=False)
    if not directory.exists():
        return set(), set()
    approved: set[Path] = set()
    unexpected: set[Path] = set()
    try:
        children = tuple(directory.iterdir())
    except OSError:
        raise ReleaseStateError from None
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
        raise ReleaseCleanupError
    temporary = {path for path in approved if path not in _ARTIFACT_PATHS}
    if temporary:
        raise ReleaseCleanupError
    artifacts = approved.intersection(_ARTIFACT_PATHS)
    if require_complete and artifacts != _ARTIFACT_PATHS:
        raise ReleaseCleanupError
    return len(artifacts)


def cleanup_complete_lifecycle(*, owner_output_captured: bool) -> None:
    """Remove only owner-captured runtime state; immutable descriptors remain."""

    if not owner_output_captured:
        raise ReleaseCleanupError
    verify_runtime_inventory(require_complete=False)
    with _exclusive_writer_lock():
        approved, unexpected = _inventory()
        allowed = _ARTIFACT_PATHS | {ACTIVATION_LOCK_PATH}
        if unexpected or ACTIVATION_LOCK_PATH not in approved or not approved.issubset(allowed):
            raise ReleaseCleanupError
        for relative in (
            SMOKE_REPORT_PATH,
            ROLLBACK_REPORT_PATH,
            REGRESSION_REPORT_PATH,
            ACTIVE_STATE_PATH,
        ):
            try:
                path = _runtime_file(relative)
                if path.exists():
                    path.unlink()
            except OSError:
                raise ReleaseCleanupError from None
    directory = _runtime_directory(create=False)
    try:
        directory.rmdir()
    except OSError:
        raise ReleaseCleanupError from None


def verify_zero_residue() -> None:
    if _runtime_directory(create=False).exists():
        raise ReleaseCleanupError


def redacted_inventory() -> dict[str, int]:
    approved, unexpected = _inventory()
    return {
        "approved_artifact_count": len(approved),
        "unexpected_residue_count": len(unexpected),
    }
