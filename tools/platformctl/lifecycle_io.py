"""Strict canonical serialization and external path boundaries for W5-004."""

from __future__ import annotations

import ctypes
import importlib
import json
import math
import os
import stat
import types
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import fields, is_dataclass
from decimal import Decimal
from enum import Enum
from hashlib import sha256
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, cast, get_args, get_origin, get_type_hints
from uuid import uuid4

from .contracts import ContractError

if TYPE_CHECKING:
    from .lifecycle_models import EvidenceRef

MAX_JSON_BYTES = 8 * 1024 * 1024
LIFECYCLE_BASELINE_HEAD = "78576879b2c1d13507680872f471345c7b9b6be0"
LIFECYCLE_ROOT_FILES = frozenset(
    {
        ".checkov.yml",
        ".env.example",
        ".gitattributes",
        ".gitignore",
        ".pre-commit-config.yaml",
        ".tflint.hcl",
        "Makefile",
        "docker-compose.w2-004.yml",
        "docker-compose.yml",
        "feature-matrix.yaml",
        "pyproject.toml",
        "requirements-checkov.lock",
        "requirements-checkov.txt",
        "requirements-ci.lock",
        "requirements-dev.txt",
        "requirements-runtime.lock",
        "requirements.txt",
    }
)
LIFECYCLE_ADMITTED_FILES = (
    "tools/secret_scan.py",
    "configs/lifecycle/w5-004.json",
    "tests/contract/test_w5_004_lifecycle_contract.py",
    "tests/fakes/platform_lifecycle.py",
    "tests/feature/test_w5_004_aws_lifecycle.py",
    "tests/integration/test_w5_004_lifecycle_composition.py",
    "tests/rollback/test_w5_004_infrastructure_rollback.py",
    "tests/security/test_w5_004_lifecycle_security.py",
    "tests/teardown/test_w5_004_cleanliness.py",
    "tests/unit/test_platformctl_cost.py",
    "tests/unit/test_platformctl_operation_state.py",
    "tests/unit/test_platformctl_plan_identity.py",
    "tools/platformctl/aws_live.py",
    "tools/platformctl/cost.py",
    "tools/platformctl/lifecycle_io.py",
    "tools/platformctl/lifecycle_models.py",
    "tools/platformctl/operation_state.py",
    "tools/platformctl/plan_artifact_producer.py",
    "tools/platformctl/policy_runner.py",
    "tools/platformctl/terraform_runner.py",
)
LIFECYCLE_TRACKED_EDITS = (
    ".pre-commit-config.yaml",
    ".github/workflows/ci.yml",
    "pyproject.toml",
    "Makefile",
    "tools/platformctl/cli.py",
    "tools/platformctl/contracts.py",
    "tools/platformctl/plan.py",
    "tools/platformctl/bootstrap.py",
    "tools/platformctl/deploy.py",
    "tools/platformctl/rollback.py",
    "tools/platformctl/destroy.py",
    "tools/platformctl/aws_inventory.py",
    "tools/platformctl/verify_clean.py",
    "tools/platformctl/validate.py",
    "policies/opa/terraform_plan.rego",
    "policies/opa/terraform_plan_test.rego",
    "tests/contract/test_platformctl_cli_contract.py",
    "tests/feature/test_policy_gate.py",
    "tests/integration/test_platformctl_dry_run.py",
    "tests/security/test_platformctl_approval_gates.py",
    "tests/unit/test_platformctl.py",
    "tests/unit/test_platformctl_lifecycle.py",
    "tests/unit/test_platformctl_verify_clean.py",
    "tests/smoke/test_platformctl_help.py",
)
LIFECYCLE_PROTECTED_DIRTY = (
    ".secrets.baseline",
    "docs/governance/Enterprise_AI_Architecture_6_Week_Execution_Tracker_v1.3.5.xlsx",
    "feature-matrix.yaml",
    "infra/bootstrap/main.tf",
    "infra/bootstrap/versions.tf",
    "infra/environments/sandbox/main.tf",
    "infra/environments/sandbox/versions.tf",
    "tests/contract/test_terraform_module_contract.py",
    "tests/feature/test_feature_matrix.py",
    "tests/feature/test_mvp_001_platformctl.py",
    "tests/security/test_precommit_controls.py",
    "tests/security/test_repository_security.py",
    "tests/security/test_terraform_security.py",
    "tests/teardown/test_platformctl_cleanup.py",
    "tests/teardown/test_terraform_state_boundary.py",
    "tests/teardown/test_w1_08_cleanliness.py",
    "tools/platformctl/__init__.py",
)
LIFECYCLE_PROTECTED_PATHS = (
    *LIFECYCLE_PROTECTED_DIRTY,
    "docs/governance/Enterprise_AI_Architecture_Source_of_Truth_v1.1.docx",
    "docs/learning/W5-002-W5-003-security-learning-review.docx",
    "configs/eval/baselines/w3-002-v1.json",
    "infra/environments/sandbox/terraform.tfvars.example",
    "docs/cost-estimates/W5-inputs.md",
    "infra/bootstrap/.terraform.lock.hcl",
    "infra/environments/sandbox/.terraform.lock.hcl",
    "requirements-runtime.lock",
    "requirements-ci.lock",
    "requirements-checkov.lock",
    "policies/opa/exceptions.json",
)
FORBIDDEN_EVIDENCE_KEYS = frozenset(
    {
        "access_key",
        "api_key",
        "authorization",
        "credential",
        "password",
        "private_key",
        "secret",
        "secret_key",
        "session_token",
        "token",
    }
)


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError("DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def canonical_value(value: object) -> object:
    """Convert approved types to deterministic JSON values."""
    if is_dataclass(value) and not isinstance(value, type):
        return {field.name: canonical_value(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, Enum):
        return canonical_value(value.value)
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise ContractError("NONFINITE_DECIMAL")
        return format(value, "f")
    if isinstance(value, Mapping):
        converted: dict[str, object] = {}
        for key, child in value.items():
            if not isinstance(key, str):
                raise ContractError("JSON object keys must be strings")
            if key.casefold() in FORBIDDEN_EVIDENCE_KEYS:
                raise ContractError(f"sensitive field is prohibited: {key}")
            converted[key] = canonical_value(child)
        return converted
    if isinstance(value, (tuple, list)):
        return [canonical_value(child) for child in value]
    if value is None or isinstance(value, (str, int, bool, float)):
        return value
    raise ContractError(f"unsupported canonical value type: {type(value).__name__}")


def canonical_json_bytes(value: object) -> bytes:
    """Return UTF-8, sorted, compact JSON with exactly one final newline."""
    rendered = json.dumps(
        canonical_value(value),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    )
    return (rendered + "\n").encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    """Return the lowercase SHA-256 for bytes."""
    return sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    """Hash a readable ordinary file without modifying it."""
    validate_original_ancestors(path)
    if not path.is_file() or path.is_symlink():
        raise ContractError("hash target must be an ordinary file")
    digest = sha256()
    try:
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as exc:
        raise ContractError("hash target is unavailable") from exc
    return digest.hexdigest()


def ensure_external_path(path: Path, allowed_root: Path, repository_root: Path) -> Path:
    """Require an external path inside one exact owner-approved root."""
    for original in (path, allowed_root, repository_root):
        validate_original_ancestors(original)
    resolved = path.resolve(strict=False)
    allowed = allowed_root.resolve(strict=False)
    repository = repository_root.resolve(strict=False)
    try:
        resolved.relative_to(allowed)
    except ValueError as exc:
        raise ContractError("path is outside the approved external root") from exc
    try:
        resolved.relative_to(repository)
    except ValueError:
        pass
    else:
        raise ContractError("runtime evidence must not be written inside the repository")
    for parent in (resolved, *resolved.parents):
        if parent == allowed.parent:
            break
        if parent.exists() and parent.is_symlink():
            raise ContractError("external path must not traverse a symbolic link")
    return resolved


@contextmanager
def private_transient_bytes(
    path: Path,
    payload: bytes,
    *,
    allowed_root: Path,
    repository_root: Path,
) -> Iterator[Path]:
    """Create one owner-bounded private file and guarantee its removal."""
    target = ensure_external_path(path, allowed_root, repository_root)
    parent = target.parent
    if not parent.is_dir() or parent.is_symlink():
        raise ContractError("transient file parent must be an ordinary directory")
    verify_private_directory(parent)
    if target.exists():
        raise ContractError("transient file target already exists")

    descriptor: int | None = None
    owned_identity: tuple[int, int] | None = None

    def record_creation(created_descriptor: int) -> None:
        nonlocal descriptor, owned_identity
        descriptor = created_descriptor
        metadata = os.fstat(created_descriptor)
        owned_identity = (metadata.st_dev, metadata.st_ino)

    try:
        descriptor = _create_private_file(target, record_creation)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = None
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        if not target.is_file() or target.is_symlink():
            raise ContractError("transient file must be an ordinary file")
        yield target
    except OSError as exc:
        raise ContractError("transient file operation failed") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if owned_identity is not None:
            validate_original_ancestors(target)
            try:
                current = target.lstat()
                if (current.st_dev, current.st_ino) != owned_identity:
                    raise ContractError("TRANSIENT_OWNERSHIP_CHANGED")
                target.unlink()
            except OSError as exc:
                raise ContractError("TRANSIENT_CLEANUP_FAILED") from exc
            if target.exists():
                raise ContractError("TRANSIENT_RESIDUE")


def _create_private_file(path: Path, record_creation: Callable[[int], None]) -> int:
    """Exclusive creation with verified protection before any private bytes are written."""
    if os.name != "nt":
        file_descriptor = os.open(
            path, os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600
        )
        record_creation(file_descriptor)
        if stat.S_IMODE(os.fstat(file_descriptor).st_mode) != 0o600:
            raise ContractError("PRIVATE_FILE_MODE_UNVERIFIED")
        return file_descriptor
    # Protected DACL: only SYSTEM and the object's owner, no inherited ACEs.
    # The descriptor is applied by CREATE_NEW, not by repairing a pre-existing file.
    from ctypes import wintypes

    class SecurityAttributes(ctypes.Structure):
        _fields_ = [
            ("length", wintypes.DWORD),
            ("descriptor", ctypes.c_void_p),
            ("inherit", wintypes.BOOL),
        ]

    library = vars(ctypes)["WinDLL"]
    security = library("advapi32", use_last_error=True)
    kernel = library("kernel32", use_last_error=True)
    security.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.DWORD),
    ]
    security.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    kernel.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(SecurityAttributes),
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    security.GetSecurityInfo.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    security.GetSecurityInfo.restype = wintypes.DWORD
    security.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPWSTR),
        ctypes.POINTER(wintypes.DWORD),
    ]
    security.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = wintypes.BOOL
    descriptor = ctypes.c_void_p()
    sddl = "D:P(A;;FA;;;SY)(A;;FA;;;OW)"
    if not security.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl, 1, ctypes.byref(descriptor), None
    ):
        raise ContractError("WINDOWS_PRIVATE_DESCRIPTOR_FAILED")
    handle: int | None = None
    try:
        attributes = SecurityAttributes(ctypes.sizeof(SecurityAttributes), descriptor, False)
        handle = kernel.CreateFileW(
            str(path), 0xC0000000, 0, ctypes.byref(attributes), 1, 0x00200100, None
        )
        if handle == ctypes.c_void_p(-1).value or handle is None:
            handle = None
            raise ContractError("PRIVATE_FILE_CREATION_FAILED")
        msvcrt = importlib.import_module("msvcrt")
        native_handle = handle
        result = int(msvcrt.open_osfhandle(handle, os.O_RDWR | getattr(os, "O_BINARY", 0)))
        handle = None
        # Transfer ownership before verifying protection: a verification failure
        # still closes and removes only the empty file this operation created.
        record_creation(result)
        observed = ctypes.c_void_p()
        rendered = wintypes.LPWSTR()
        try:
            if (
                security.GetSecurityInfo(
                    native_handle, 1, 4, None, None, None, None, ctypes.byref(observed)
                )
                != 0
            ):
                raise ContractError("WINDOWS_PRIVATE_DACL_UNVERIFIED")
            if not security.ConvertSecurityDescriptorToStringSecurityDescriptorW(
                observed, 1, 4, ctypes.byref(rendered), None
            ) or rendered.value not in {
                sddl,
                "D:P(A;;FA;;;OW)(A;;FA;;;SY)",
            }:
                raise ContractError("WINDOWS_PRIVATE_DACL_UNVERIFIED")
        finally:
            if rendered:
                kernel.LocalFree(ctypes.cast(rendered, ctypes.c_void_p))
            if observed:
                kernel.LocalFree(observed)
        return result
    finally:
        if handle is not None:
            kernel.CloseHandle(handle)
        kernel.LocalFree(descriptor)


def decode_json_strict(raw: bytes, *, maximum_bytes: int = MAX_JSON_BYTES) -> object:
    """Decode bounded UTF-8 JSON while rejecting duplicates and trailing data."""
    if not raw or len(raw) > maximum_bytes or raw.startswith(b"\xef\xbb\xbf"):
        raise ContractError("JSON input size or encoding is not permitted")
    try:
        text = raw.decode("utf-8")
        decoder = json.JSONDecoder(
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
            parse_float=_finite_json_float,
        )
        value, end = decoder.raw_decode(text, len(text) - len(text.lstrip()))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ContractError("JSON input is malformed") from exc
    if text[end:].strip():
        raise ContractError("JSON input contains trailing content")
    # Private decoding must not project, redact, serialize or log Terraform values.
    return cast(object, value)


def _reject_json_constant(value: str) -> object:
    del value
    raise ContractError("NONFINITE_JSON_NUMBER")


def _finite_json_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise ContractError("NONFINITE_JSON_NUMBER")
    return number


def validate_original_ancestors(path: Path) -> None:
    """Inspect the original spelling before resolution can hide a junction."""
    for candidate in (*reversed(path.parents), path):
        try:
            metadata = candidate.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise ContractError("PATH_INSPECTION_UNAVAILABLE") from exc
        if stat.S_ISLNK(metadata.st_mode) or (
            getattr(metadata, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        ):
            raise ContractError("PATH_LINK_OR_REPARSE_POINT")
        if not (stat.S_ISREG(metadata.st_mode) or stat.S_ISDIR(metadata.st_mode)):
            raise ContractError("PATH_TYPE_UNSUPPORTED")


def bounded_relative_path(value: str) -> str:
    """Reject traversal, ambiguous Windows aliases and case-changing normalization."""
    if not value or "\\" in value or "\x00" in value:
        raise ContractError("RELATIVE_PATH_INVALID")
    path = PurePosixPath(value)
    if path.is_absolute() or path.as_posix() != value:
        raise ContractError("RELATIVE_PATH_INVALID")
    reserved = {"CON", "PRN", "AUX", "NUL"} | {
        f"{prefix}{number}" for prefix in ("COM", "LPT") for number in range(1, 10)
    }
    for part in path.parts:
        if (
            part in {".", ".."}
            or part.endswith((".", " "))
            or ":" in part
            or any(ord(character) < 32 for character in part)
            or part.split(".", 1)[0].upper() in reserved
        ):
            raise ContractError("RELATIVE_PATH_INVALID")
    return value


def unique_paths(paths: tuple[str, ...]) -> tuple[str, ...]:
    """Sort explicit sets ordinally while rejecting Windows-equivalent duplicates."""
    seen: set[str] = set()
    for path in paths:
        bounded_relative_path(path)
        folded = path.casefold()
        if folded in seen:
            raise ContractError("PATH_COLLISION")
        seen.add(folded)
    return tuple(sorted(paths))


def parse_git_status(raw: bytes) -> tuple[tuple[str, str, str | None], ...]:
    """Parse porcelain v1 -z, preserving status spaces and rename destination first."""
    if raw and not raw.endswith(b"\x00"):
        raise ContractError("GIT_STATUS_TRUNCATED")
    try:
        records = raw.decode("utf-8", errors="strict").split("\x00")[:-1]
    except UnicodeDecodeError as exc:
        raise ContractError("GIT_PATH_ENCODING") from exc
    result: list[tuple[str, str, str | None]] = []
    index = 0
    while index < len(records):
        record = records[index]
        index += 1
        if len(record) < 4 or record[2] != " ":
            raise ContractError("GIT_STATUS_MALFORMED")
        status = record[:2]
        if status in {"DD", "AU", "UD", "UA", "DU", "AA", "UU"} or "U" in status:
            raise ContractError("GIT_UNMERGED")
        if status != "??" and any(character not in " MADRC?!" for character in status):
            raise ContractError("GIT_STATUS_UNSUPPORTED")
        destination = bounded_relative_path(record[3:])
        original: str | None = None
        if "R" in status or "C" in status:
            if index >= len(records):
                raise ContractError("GIT_RENAME_TRUNCATED")
            original = bounded_relative_path(records[index])
            index += 1
        result.append((status, destination, original))
    unique_paths(tuple(record[1] for record in result))
    return tuple(sorted(result, key=lambda record: record[1]))


def parse_git_index(raw: bytes) -> tuple[tuple[str, str, int, str], ...]:
    """Retain index mode/object/stage/path without conflating index and worktree."""
    if raw and not raw.endswith(b"\x00"):
        raise ContractError("GIT_INDEX_TRUNCATED")
    result: list[tuple[str, str, int, str]] = []
    try:
        for record in raw.decode("utf-8", errors="strict").split("\x00")[:-1]:
            prefix, path = record.split("\t", 1)
            mode, object_id, stage_text = prefix.split(" ")
            if mode not in {"100644", "100755"} or stage_text != "0":
                raise ContractError("GIT_INDEX_MODE_OR_STAGE")
            if len(object_id) not in {40, 64} or any(
                c not in "0123456789abcdef" for c in object_id
            ):
                raise ContractError("GIT_OBJECT_ID_INVALID")
            result.append((mode, object_id, 0, bounded_relative_path(path)))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ContractError("GIT_INDEX_MALFORMED") from exc
    unique_paths(tuple(record[3] for record in result))
    return tuple(sorted(result, key=lambda record: record[3]))


def working_manifest(
    repository: Path, paths: tuple[str, ...]
) -> tuple[tuple[str, str, int | None, str | None], ...]:
    """Hash raw bytes and explicit deletions, without line-ending conversion."""
    records: list[tuple[str, str, int | None, str | None]] = []
    for name in unique_paths(paths):
        path = repository / name
        validate_original_ancestors(path)
        try:
            before = path.stat()
        except FileNotFoundError:
            records.append((name, "DELETED", None, None))
            continue
        if not stat.S_ISREG(before.st_mode):
            raise ContractError("WORKTREE_FILE_TYPE")
        digest = sha256_file(path)
        after = path.stat()
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise ContractError("WORKTREE_CHANGED_DURING_HASHING")
        records.append((name, "FILE", before.st_size, digest))
    return tuple(records)


def lifecycle_scope(baseline_tree_names: bytes) -> tuple[str, ...]:
    """Compute the approved immutable-tree membership without discovering new files."""
    if not baseline_tree_names.endswith(b"\x00"):
        raise ContractError("BASELINE_TREE_TRUNCATED")
    try:
        names = baseline_tree_names.decode("utf-8", errors="strict").split("\x00")[:-1]
    except UnicodeDecodeError as exc:
        raise ContractError("BASELINE_TREE_ENCODING") from exc
    all_names = unique_paths(tuple(names))
    prefixes = (
        "src/",
        "tools/",
        "tests/",
        "infra/",
        "policies/",
        "configs/",
        ".github/",
        "docker/",
    )
    baseline = tuple(
        name for name in all_names if name in LIFECYCLE_ROOT_FILES or name.startswith(prefixes)
    )
    if len(baseline) != 365 or set(baseline).intersection(LIFECYCLE_ADMITTED_FILES):
        raise ContractError("LIFECYCLE_SCOPE_MEMBERSHIP_MISMATCH")
    result = unique_paths((*baseline, *LIFECYCLE_ADMITTED_FILES))
    if len(result) != 385:
        raise ContractError("LIFECYCLE_SCOPE_MEMBERSHIP_MISMATCH")
    return result


class BoundEvidenceReader:
    """Immutable operation-relative reads checked before and after loading."""

    def __init__(self, operation_root: Path, repository_root: Path) -> None:
        self.root = ensure_external_path(operation_root, operation_root, repository_root)
        self.repository_root = repository_root

    def read(self, relative_path: str, expected_sha256: str, byte_count: int) -> bytes:
        bounded_relative_path(relative_path)
        path = ensure_external_path(self.root / relative_path, self.root, self.repository_root)
        if type(byte_count) is not int or not 0 < byte_count <= 64 * 1024 * 1024:
            raise ContractError("EVIDENCE_SIZE_INVALID")
        if path.stat().st_size != byte_count or sha256_file(path) != expected_sha256:
            raise ContractError("EVIDENCE_IDENTITY_MISMATCH")
        payload = path.read_bytes()
        if (
            len(payload) != byte_count
            or sha256_bytes(payload) != expected_sha256
            or sha256_file(path) != expected_sha256
        ):
            raise ContractError("EVIDENCE_CHANGED_DURING_READ")
        return payload


class DiagnosticEvidenceReader:
    """Resolve reviewed evidence without copying it into a diagnostic operation."""

    def __init__(
        self,
        sources: tuple[tuple[EvidenceRef, str], ...],
        external_root: Path,
        repository_root: Path,
    ) -> None:
        self.sources = {reference.path: (reference, source) for reference, source in sources}
        if len(self.sources) != len(sources):
            raise ContractError("DIAGNOSTIC_EVIDENCE_DUPLICATED")
        self.external_root, self.repository_root = external_root, repository_root

    def read(self, relative_path: str, expected_sha256: str, byte_count: int) -> bytes:
        bounded_relative_path(relative_path)
        if relative_path not in self.sources:
            raise ContractError("DIAGNOSTIC_EVIDENCE_MISSING")
        reference, source = self.sources[relative_path]
        if (expected_sha256, byte_count) != (reference.sha256, reference.byte_count):
            raise ContractError("DIAGNOSTIC_EVIDENCE_BINDING")
        path = ensure_external_path(Path(source), self.external_root, self.repository_root)
        return BoundEvidenceReader(path.parent, self.repository_root).read(
            path.name, expected_sha256, byte_count
        )

    def verify_all(self) -> None:
        for reference, _ in self.sources.values():
            self.read(reference.path, reference.sha256, reference.byte_count)


def reserve_operation_directory(path: Path, allowed_root: Path, repository_root: Path) -> None:
    """Reserve a single-use leaf; never adopt or remove pre-existing operation content."""
    target = ensure_external_path(path, allowed_root, repository_root)
    if not target.parent.is_dir():
        raise ContractError("OPERATION_PARENT_REQUIRED")
    try:
        if os.name == "nt":
            _create_private_windows_directory(target)
        else:
            target.mkdir(mode=0o700, exist_ok=False)
            if stat.S_IMODE(target.stat().st_mode) != 0o700:
                raise ContractError("OPERATION_DIRECTORY_PROTECTION_UNVERIFIED")
    except OSError as exc:
        raise ContractError("OPERATION_DIRECTORY_COLLISION_OR_UNAVAILABLE") from exc
    validate_original_ancestors(target)


def _create_private_windows_directory(path: Path, *, verify_existing: bool = False) -> None:
    """Create with a protected inheritable DACL; never adopt or repair another directory."""
    from ctypes import wintypes

    class SecurityAttributes(ctypes.Structure):
        _fields_ = [
            ("length", wintypes.DWORD),
            ("descriptor", ctypes.c_void_p),
            ("inherit", wintypes.BOOL),
        ]

    library = vars(ctypes)["WinDLL"]
    security = library("advapi32", use_last_error=True)
    kernel = library("kernel32", use_last_error=True)
    security.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.DWORD),
    ]
    security.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    kernel.CreateDirectoryW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(SecurityAttributes)]
    kernel.CreateDirectoryW.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    security.GetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    security.GetNamedSecurityInfoW.restype = wintypes.DWORD
    security.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPWSTR),
        ctypes.POINTER(wintypes.DWORD),
    ]
    security.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = wintypes.BOOL
    sddl = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;OW)"
    descriptor = ctypes.c_void_p()
    observed = ctypes.c_void_p()
    rendered = wintypes.LPWSTR()
    if not security.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl, 1, ctypes.byref(descriptor), None
    ):
        raise ContractError("WINDOWS_DIRECTORY_DESCRIPTOR_FAILED")
    try:
        attributes = SecurityAttributes(ctypes.sizeof(SecurityAttributes), descriptor, False)
        if not verify_existing and not kernel.CreateDirectoryW(str(path), ctypes.byref(attributes)):
            raise ContractError("OPERATION_DIRECTORY_COLLISION_OR_UNAVAILABLE")
        # Failure leaves an empty, task-owned directory for explicit reconciliation.
        # No existing directory ACL or content is ever changed here.
        validate_original_ancestors(path)
        if (
            security.GetNamedSecurityInfoW(
                str(path), 1, 4, None, None, None, None, ctypes.byref(observed)
            )
            != 0
        ):
            raise ContractError("WINDOWS_DIRECTORY_DACL_UNVERIFIED")
        if not security.ConvertSecurityDescriptorToStringSecurityDescriptorW(
            observed, 1, 4, ctypes.byref(rendered), None
        ) or rendered.value not in {sddl, "D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)"}:
            raise ContractError("WINDOWS_DIRECTORY_DACL_UNVERIFIED")
    finally:
        if rendered:
            kernel.LocalFree(ctypes.cast(rendered, ctypes.c_void_p))
        if observed:
            kernel.LocalFree(observed)
        kernel.LocalFree(descriptor)


def verify_private_directory(path: Path) -> None:
    """Read protection only; never repair a pre-existing path's permissions."""
    validate_original_ancestors(path)
    if not path.is_dir():
        raise ContractError("PRIVATE_DIRECTORY_REQUIRED")
    if os.name == "nt":
        _create_private_windows_directory(path, verify_existing=True)
    elif stat.S_IMODE(path.stat().st_mode) != 0o700:
        raise ContractError("PRIVATE_DIRECTORY_PROTECTION_UNVERIFIED")


def private_directory_chain(path: Path, root: Path, repository: Path) -> None:
    """Create missing adapter-owned descendants; verify, never repair, existing ACLs."""
    target = ensure_external_path(path, root, repository)
    relative = target.relative_to(root.resolve(strict=False))
    current = root.resolve(strict=False)
    verify_private_directory(current)
    for component in relative.parts:
        current = current / component
        if current.exists():
            verify_private_directory(current)
        else:
            reserve_operation_directory(current, root, repository)


def remove_private_operation_outputs(
    paths: tuple[Path, ...],
    operation_root: Path,
    *,
    allowed_root: Path,
    repository_root: Path,
) -> None:
    """Remove only ordinary files and empty directories owned by one failed operation."""
    root = ensure_external_path(operation_root, allowed_root, repository_root)
    inputs = root / "inputs"
    permitted_parents = {root, inputs}
    for supplied in reversed(paths):
        path = ensure_external_path(supplied, allowed_root, repository_root)
        if path.parent not in permitted_parents:
            raise ContractError("PRIVATE_OPERATION_CLEANUP_SCOPE")
        validate_original_ancestors(path)
        try:
            if path.is_symlink():
                raise ContractError("PRIVATE_OPERATION_CLEANUP_FILE_TYPE")
            if path.exists():
                if not path.is_file():
                    raise ContractError("PRIVATE_OPERATION_CLEANUP_FILE_TYPE")
                path.unlink()
        except OSError as exc:
            raise ContractError("PRIVATE_OPERATION_CLEANUP_FAILED") from exc
    for directory in (inputs, root):
        validate_original_ancestors(directory)
        try:
            if directory.is_symlink():
                raise ContractError("PRIVATE_OPERATION_CLEANUP_DIRECTORY_TYPE")
            if directory.exists():
                if not directory.is_dir():
                    raise ContractError("PRIVATE_OPERATION_CLEANUP_DIRECTORY_TYPE")
                directory.rmdir()
        except OSError as exc:
            raise ContractError("PRIVATE_OPERATION_CLEANUP_FAILED") from exc


def _decode_typed(value: object, expected: object) -> object:
    """Decode only a statically supplied record type; input cannot name Python types."""
    origin = get_origin(expected)
    arguments = get_args(expected)
    if origin is types.UnionType:
        for option in arguments:
            try:
                return _decode_typed(value, option)
            except ContractError:
                continue
        raise ContractError("RECORD_UNION_TYPE")
    if expected is type(None):
        if value is not None:
            raise ContractError("RECORD_NULL_REQUIRED")
        return None
    if origin is tuple:
        if not isinstance(value, list):
            raise ContractError("RECORD_ARRAY_REQUIRED")
        if len(arguments) == 2 and arguments[1] is Ellipsis:
            return tuple(_decode_typed(child, arguments[0]) for child in value)
        if len(value) != len(arguments):
            raise ContractError("RECORD_TUPLE_LENGTH")
        return tuple(
            _decode_typed(child, kind) for child, kind in zip(value, arguments, strict=True)
        )
    if isinstance(expected, type) and issubclass(expected, Enum):
        if not isinstance(value, str):
            raise ContractError("RECORD_ENUM_TYPE")
        try:
            return expected(value)
        except ValueError as exc:
            raise ContractError("RECORD_ENUM_VALUE") from exc
    if isinstance(expected, type) and is_dataclass(expected):
        if not isinstance(value, dict):
            raise ContractError("RECORD_OBJECT_REQUIRED")
        kinds = get_type_hints(expected)
        # Pre-amendment v2 cost records retain the default binding monthly gate.
        # No other missing operational field is accepted.
        from .lifecycle_models import CostResultV2, CostReviewTerms

        if expected in (CostResultV2, CostReviewTerms) and (
            set(kinds) - {"monthly_amendment", "lifecycle_amendment"} <= set(value) <= set(kinds)
        ):
            value = {"monthly_amendment": None, "lifecycle_amendment": None, **value}
        if set(value) != set(kinds):
            raise ContractError("RECORD_FIELDS_NOT_EXACT")
        return expected(**{name: _decode_typed(value[name], kind) for name, kind in kinds.items()})
    if expected in (str, int, bool) and type(value) is expected:
        return value
    raise ContractError("RECORD_TYPE_INVALID")


def decode_operational_record[RecordT](raw: bytes, record_type: type[RecordT]) -> RecordT:
    """Strict v2 operational decoding; v1 cannot establish current authorization."""
    value = decode_json_strict(raw)
    if not isinstance(value, dict) or value.get("schema_version") != "w5-004.lifecycle.v2":
        raise ContractError("OPERATIONAL_SCHEMA_REQUIRED")
    return cast(RecordT, _decode_typed(value, record_type))


def decode_record[RecordT](value: object, record_type: type[RecordT]) -> RecordT:
    """Strict nested-record decoding; callers must supply a static reviewed type."""
    return cast(RecordT, _decode_typed(value, record_type))


def decode_diagnostic_record[RecordT](raw: bytes, record_type: type[RecordT]) -> RecordT:
    """The distinct schema prevents incomplete diagnostics becoming execution inputs."""
    from .lifecycle_models import DIAGNOSTIC_SCHEMA_VERSION

    value = decode_json_strict(raw, maximum_bytes=1024 * 1024)
    if not isinstance(value, dict) or value.get("schema_version") != DIAGNOSTIC_SCHEMA_VERSION:
        raise ContractError("DIAGNOSTIC_SCHEMA_REQUIRED")
    return decode_record(value, record_type)


def read_private_state(path: Path, *, approved_path: Path, repository: Path) -> bytes:
    """Read only the exact local bootstrap state, never write or serialize it."""
    if path != approved_path:
        raise ContractError("DIAGNOSTIC_LOCAL_STATE_PATH")
    candidate = ensure_external_path(path, approved_path.parent, repository)
    validate_original_ancestors(candidate)
    if not candidate.is_file() or candidate.stat().st_size > 64 * 1024 * 1024:
        raise ContractError("DIAGNOSTIC_STATE_TYPE_OR_SIZE")
    before = candidate.stat()
    with candidate.open("rb") as stream:
        raw = stream.read(64 * 1024 * 1024 + 1)
    after = candidate.stat()
    if len(raw) > 64 * 1024 * 1024 or (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        raise ContractError("DIAGNOSTIC_STATE_CHANGED")
    return raw


def copy_reviewed_evidence(
    reference: EvidenceRef,
    source: Path,
    *,
    operation_root: Path,
    external_root: Path,
    repository_root: Path,
) -> None:
    """Publish only exact safe canonical evidence; never rewrite an existing artifact."""
    candidate = ensure_external_path(source, external_root, repository_root)
    raw = BoundEvidenceReader(candidate.parent, repository_root).read(
        candidate.name, reference.sha256, reference.byte_count
    )
    value = decode_json_strict(raw)
    if canonical_json_bytes(value) != raw:
        raise ContractError("EXTERNAL_EVIDENCE_NOT_CANONICAL")
    target = operation_root / bounded_relative_path(reference.path)
    if target.exists():
        BoundEvidenceReader(operation_root, repository_root).read(
            reference.path, reference.sha256, reference.byte_count
        )
    else:
        write_canonical_json_atomic(
            target, value, allowed_root=external_root, repository_root=repository_root
        )


def load_json_strict(path: Path, *, maximum_bytes: int = MAX_JSON_BYTES) -> object:
    """Read bounded strict JSON from one ordinary file."""
    validate_original_ancestors(path)
    if not path.is_file() or path.is_symlink():
        raise ContractError("JSON input must be an ordinary file")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ContractError("JSON input is unavailable") from exc
    return decode_json_strict(raw, maximum_bytes=maximum_bytes)


def load_lifecycle_config(path: Path) -> dict[str, object]:
    """Load and validate the exact non-secret W5-004 owner decision contract."""
    value = load_json_strict(path)
    if not isinstance(value, dict):
        raise ContractError("W5-004 lifecycle configuration must be an object")
    config = cast(dict[str, object], value)
    expected_keys = {
        "schema_version",
        "task_id",
        "repository",
        "aws",
        "terraform",
        "lifecycle",
        "cost",
        "external_paths",
        "governance",
    }
    if set(config) != expected_keys:
        raise ContractError("W5-004 lifecycle configuration fields are not exact")
    if config.get("schema_version") != "w5-004.lifecycle.v2":
        raise ContractError("W5-004 lifecycle schema_version is not approved")
    if config.get("task_id") != "W5-004":
        raise ContractError("W5-004 task identity is not approved")
    aws = config.get("aws")
    repository = config.get("repository")
    terraform = config.get("terraform")
    cost = config.get("cost")
    lifecycle = config.get("lifecycle")
    governance = config.get("governance")
    external_paths = config.get("external_paths")
    if not all(
        isinstance(section, dict)
        for section in (
            repository,
            aws,
            terraform,
            cost,
            lifecycle,
            governance,
            external_paths,
        )
    ):
        raise ContractError("W5-004 lifecycle configuration section is malformed")
    repository_values = cast(dict[str, object], repository)
    aws_values = cast(dict[str, object], aws)
    terraform_values = cast(dict[str, object], terraform)
    cost_values = cast(dict[str, object], cost)
    lifecycle_values = cast(dict[str, object], lifecycle)
    monthly_exception = cost_values.get("monthly_exception")
    if monthly_exception is not None and monthly_exception != approved_monthly_exception():
        raise ContractError("MONTHLY_EXCEPTION_CONFIGURATION_NOT_APPROVED")
    governance_values = cast(dict[str, object], governance)
    external_values = cast(dict[str, object], external_paths)
    if repository_values != {
        "branch": "main",
        "head": "78576879b2c1d13507680872f471345c7b9b6be0",
        "source_composition_sha256": (
            "d9596bcbbab2953f2aa9398d34a2b87a5f2d8751f298f680f287d1bd5648ddff"
        ),
    }:
        raise ContractError("W5-004 repository baseline does not match")
    if (
        aws_values.get("account_id") != "526338061652"
        or aws_values.get("region") != "ap-southeast-1"
        or aws_values.get("profile") != "default"
        or aws_values.get("expected_caller_arn") != "arn:aws:iam::526338061652:user/finopsinfra"
        or aws_values.get("owner_governance_expires_at") != "2026-12-09T23:59:59Z"
    ):
        raise ContractError("W5-004 AWS owner decisions do not match")
    if (
        terraform_values.get("version") != "1.16.1"
        or terraform_values.get("aws_provider_version") != "6.55.0"
        or terraform_values.get("platform_backend") != "s3"
    ):
        raise ContractError("W5-004 Terraform identity does not match")
    if (
        cost_values.get("lifecycle_test_ceiling") != "3.00"
        or cost_values.get("lifecycle_exception") != approved_lifecycle_exception()
        or cost_values.get("monthly_sandbox_ceiling") != "60.00"
        or cost_values.get("infracost_version") != "0.10.45"
        or cost_values.get("infracost_executable")
        != r"E:\AI\.tools\infracost\0.10.45\infracost.exe"
        or cost_values.get("infracost_archive_sha256")
        != "7f627fac5cad9b7260e1123c1378d2fb4f308cdc64f78e99d6e69727d9549d06"
        or cost_values.get("infracost_checksum_sidecar_sha256")
        != "4a9668bab905dec316487ef1403e8f1ed59e6bbb897b4a08e521d3039f0aa413"
        or cost_values.get("pricing_endpoint") != "https://pricing.api.infracost.io"
        or cost_values.get("conditional_account_endpoint") != "https://dashboard.api.infracost.io"
        or cost_values.get("infracost_license") != "Apache-2.0"
        or cost_values.get("direct_plan_json_api_upload") is not False
    ):
        raise ContractError("W5-004 cost boundary does not match")
    if lifecycle_values.get("plan_lifetime_minutes") != 60:
        raise ContractError("W5-004 plan lifetime must be 60 minutes")
    if (
        lifecycle_values.get("maximum_resource_lifetime_hours") != 24
        or lifecycle_values.get("generated_resource_lifetime_minutes") != 1425
    ):
        raise ContractError("W5-004 generated resource lifetime does not match")
    if governance_values.get("bedrock_result") != ("FAIL_ACCEPTED_FOR_INFRASTRUCTURE_ONLY"):
        raise ContractError("W5-001 Bedrock limitation is not preserved")
    if external_values != {
        "evidence_root": (r"E:\AI\.runtime\enterprise_ai_platform\w5-004\owner-test-01"),
        "temporary_root": (r"E:\AI\.tmp\enterprise-ai-platform-w5-004\owner-test-01"),
        "terraform_cache": (r"E:\AI\.terraform-cache\enterprise-ai-platform-w5-004"),
        "pre_commit_cache": (r"E:\AI\.pre-commit-cache\enterprise-ai-platform-global"),
    }:
        raise ContractError("W5-004 external paths do not match")
    if (
        lifecycle_values.get("identity_scope_version") != "w5-004.lifecycle-content.v1"
        or lifecycle_values.get("identity_member_count") != 385
        or lifecycle_values.get("dispatch_observation_max_seconds") != 60
        or lifecycle_values.get("native_observation_max_seconds") != 900
        or lifecycle_values.get("pricing_observation_max_seconds") != 3600
        or lifecycle_values.get("execution_requires_v2_review") is not True
        or cost_values.get("infracost_executable_sha256")
        != "6a85c7a000eb5fb3e9a01df6a9ed4359580c07f5c7da9d13c1dfbe847bedf600"
        or cost_values.get("asset_attestation") != "INDETERMINATE"
        or cost_values.get("unknown_incurred_cost") != "INDETERMINATE"
    ):
        raise ContractError("W5-004 operational identity or freshness contract differs")
    return config


def approved_lifecycle_exception() -> dict[str, str]:
    """Static approved policy; execution additionally needs fresh bound authority."""
    return {
        "amendment_id": "w5-004-cycle-a-total-lifecycle-30",
        "cycle_id": "W5-CYCLE-A",
        "account_id": "526338061652",
        "region": "ap-southeast-1",
        "environment": "sandbox",
        "bootstrap_lineage": "c446f9a2-77d4-9954-20fa-523205d86a8a",
        "platform_lineage": "7465ed2e-a39c-afdd-f172-5792d3ec2f85",
        "lifecycle_ceiling_usd": "30.00",
        "accounting_scope": "TOTAL_CYCLE_INCLUDING_INCURRED_AND_RETENTION",
        "valid_until": "2026-12-09T23:59:59Z",
    }


def approved_monthly_exception() -> dict[str, str]:
    """The approved current-cycle exception; absence keeps the USD 60 default."""
    return {
        "amendment_id": "w5-004-cycle-a-temporary-mvp-monthly",
        "cycle_id": "W5-CYCLE-A",
        "account_id": "526338061652",
        "region": "ap-southeast-1",
        "environment": "sandbox",
        "bootstrap_lineage": "c446f9a2-77d4-9954-20fa-523205d86a8a",
        "platform_lineage": "7465ed2e-a39c-afdd-f172-5792d3ec2f85",
        "monthly_treatment": "INFORMATIONAL",
        "lifecycle_ceiling_usd": "3.00",
        "valid_until": "2026-12-09T23:59:59Z",
    }


def write_private_bytes_exclusive(
    path: Path,
    payload: bytes,
    *,
    allowed_root: Path,
    repository_root: Path,
) -> str:
    """Publish bounded private comparison bytes without changing their representation."""
    if not isinstance(payload, bytes) or not 0 < len(payload) <= MAX_JSON_BYTES:
        raise ContractError("PRIVATE_COMPARISON_SIZE")
    target = ensure_external_path(path, allowed_root, repository_root)
    verify_private_directory(target.parent)
    if target.exists():
        raise ContractError("PRIVATE_COMPARISON_EXISTS")
    temporary = target.parent / f".{target.name}.{uuid4().hex}.pending"
    with private_transient_bytes(
        temporary, payload, allowed_root=allowed_root, repository_root=repository_root
    ):
        owned = temporary.stat()
        os.link(temporary, target)
        published = target.stat()
        if (owned.st_dev, owned.st_ino) != (published.st_dev, published.st_ino):
            raise ContractError("PRIVATE_COMPARISON_IDENTITY")
        if sha256_file(target) != sha256_bytes(payload):
            raise ContractError("PRIVATE_COMPARISON_CONTENT")
    return sha256_bytes(payload)


def write_canonical_json_atomic(
    path: Path,
    value: object,
    *,
    allowed_root: Path,
    repository_root: Path,
) -> str:
    """Atomically write one canonical external report and return its hash."""
    target = ensure_external_path(path, allowed_root, repository_root)
    if not target.parent.is_dir():
        existing = target.parent
        while not existing.exists():
            existing = existing.parent
        ensure_external_path(existing, allowed_root, repository_root)
        private_directory_chain(target.parent, existing, repository_root)
    verify_private_directory(target.parent)
    if target.exists():
        raise ContractError("canonical report target already exists")
    payload = canonical_json_bytes(value)
    temporary_path = target.parent / f".{target.name}.{uuid4().hex}.pending"
    try:
        with private_transient_bytes(
            temporary_path,
            payload,
            allowed_root=allowed_root,
            repository_root=repository_root,
        ) as temporary:
            owned = temporary.stat()
            # Hard-link publication is exclusive: it cannot replace an existing
            # evidence artifact. The transient adapter owns only its original name.
            os.link(temporary, target)
            published = target.stat()
            if (owned.st_dev, owned.st_ino) != (published.st_dev, published.st_ino):
                raise ContractError("CANONICAL_PUBLICATION_IDENTITY_MISMATCH")
            if sha256_file(target) != sha256_bytes(payload):
                raise ContractError("CANONICAL_PUBLICATION_CONTENT_MISMATCH")
    except OSError as exc:
        raise ContractError("canonical report write failed") from exc
    return sha256_bytes(payload)


@contextmanager
def private_tool_directory(allowed_root: Path, repository_root: Path) -> Iterator[Path]:
    """Own a fresh tool home; remove only its unchanged, empty directory structure."""
    parent = ensure_external_path(allowed_root, allowed_root, repository_root)
    if not parent.is_dir():
        raise ContractError("TOOL_ISOLATION_PARENT_REQUIRED")
    if any(path.name.startswith("tool-launch-") for path in parent.iterdir()):
        raise ContractError("TOOL_ISOLATION_LEFTOVER_REQUIRES_REVIEW")
    home = parent / f"tool-launch-{uuid4().hex}"
    created: dict[Path, tuple[int, int]] = {}
    try:
        for directory in (home, home / ".config", home / ".config" / "infracost"):
            reserve_operation_directory(directory, parent, repository_root)
            metadata = directory.lstat()
            created[directory] = (metadata.st_dev, metadata.st_ino)
        yield home
    finally:
        # Reconcile the whole inventory before deleting anything. Unexpected tool
        # output, replacement, or a reparse point remains for owner inspection.
        for directory, identity in created.items():
            validate_original_ancestors(directory)
            try:
                metadata = directory.lstat()
                if (metadata.st_dev, metadata.st_ino) != identity:
                    raise ContractError("TOOL_ISOLATION_OWNERSHIP_CHANGED")
                verify_private_directory(directory)
                children = {path for path in created if path.parent == directory}
                if set(directory.iterdir()) != children:
                    raise ContractError("TOOL_ISOLATION_UNEXPECTED_RESIDUE")
            except OSError as exc:
                raise ContractError("TOOL_ISOLATION_RECONCILIATION_FAILED") from exc
        for directory in reversed(created):
            validate_original_ancestors(directory)
            metadata = directory.lstat()
            if (metadata.st_dev, metadata.st_ino) != created[directory]:
                raise ContractError("TOOL_ISOLATION_OWNERSHIP_CHANGED")
            try:
                directory.rmdir()
            except OSError as exc:
                raise ContractError("TOOL_ISOLATION_CLEANUP_FAILED") from exc


def capture_private_tool_json(
    path: Path,
    producer: Callable[[Path], None],
    *,
    allowed_root: Path,
    repository_root: Path,
) -> object:
    """Let a tool fill an exclusively owned file; parse privately and remove it."""
    with private_transient_bytes(
        path, b"", allowed_root=allowed_root, repository_root=repository_root
    ) as target:
        owned = target.lstat()
        producer(target)
        validate_original_ancestors(target)
        current = target.lstat()
        if (
            not stat.S_ISREG(current.st_mode)
            or (current.st_dev, current.st_ino) != (owned.st_dev, owned.st_ino)
            or current.st_nlink != 1
        ):
            raise ContractError("PRIVATE_TOOL_OUTPUT_OWNERSHIP_CHANGED")
        value = load_json_strict(target)
    return value
