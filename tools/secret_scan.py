"""Check-only, offline integration of the approved detect-secrets scanner."""

from __future__ import annotations

import argparse
import copy
import importlib
import io
import json
import os
import re
import shutil
import socket
import stat
import subprocess
from collections.abc import Iterator, Sequence
from contextlib import ExitStack, contextmanager, redirect_stderr, redirect_stdout
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from importlib.metadata import version
from pathlib import Path
from typing import Any
from unittest.mock import patch

from tools.platformctl.contracts import ContractError
from tools.platformctl.lifecycle_io import (
    decode_json_strict,
    ensure_external_path,
    reserve_operation_directory,
    validate_original_ancestors,
    write_private_bytes_exclusive,
)

REPOSITORY = Path(__file__).absolute().parents[1]
BASELINE_NAME = ".secrets.baseline"
MAINTENANCE_PARENT = Path(r"E:\AI\.tmp\enterprise-ai-platform-w5-004\owner-test-01")
PLUGIN_NAMES = (
    "ArtifactoryDetector AWSKeyDetector AzureStorageKeyDetector Base64HighEntropyString "
    "BasicAuthDetector CloudantDetector DiscordBotTokenDetector GitHubTokenDetector "
    "GitLabTokenDetector HexHighEntropyString IbmCloudIamDetector IbmCosHmacDetector "
    "IPPublicDetector JwtTokenDetector KeywordDetector MailchimpDetector NpmDetector "
    "OpenAIDetector PrivateKeyDetector PypiTokenDetector SendGridDetector SlackDetector "
    "SoftlayerDetector SquareOAuthDetector StripeDetector TelegramBotTokenDetector "
    "TwilioKeyDetector"
).split()
FILTER_NAMES = (
    "allowlist.is_line_allowlisted common.is_ignored_due_to_verification_policies "
    "heuristic.is_indirect_reference heuristic.is_likely_id_string heuristic.is_lock_file "
    "heuristic.is_not_alphanumeric_string heuristic.is_potential_uuid "
    "heuristic.is_prefixed_with_dollar_sign heuristic.is_sequential_string "
    "heuristic.is_swagger_file heuristic.is_templated_secret regex.should_exclude_file"
).split()
MAX_FILE_BYTES = 64 * 1024 * 1024


class ScanError(Exception):
    """Only fixed, non-sensitive reason codes cross the reporting boundary."""


def scanner_configuration() -> dict[str, object]:
    plugins: list[dict[str, object]] = [{"name": name} for name in PLUGIN_NAMES]
    for plugin in plugins:
        if plugin["name"] == "Base64HighEntropyString":
            plugin["limit"] = 4.5
        elif plugin["name"] == "HexHighEntropyString":
            plugin["limit"] = 3.0
        elif plugin["name"] == "KeywordDetector":
            plugin["keyword_exclude"] = ""
    filters: list[dict[str, object]] = [
        {"path": "detect_secrets.filters." + name} for name in FILTER_NAMES
    ]
    filters[1]["min_level"] = 2
    filters[-1]["pattern"] = [r"^\.secrets\.baseline$"]
    return {"plugins_used": plugins, "filters_used": filters}


def _git(repository: Path, *arguments: str) -> bytes:
    executable = shutil.which("git")
    if executable is None:
        raise ScanError("GIT_UNAVAILABLE")
    # No shell, writes, caller-supplied Git flags, or ambient optional index locking.
    result = subprocess.run(  # noqa: S603 -- fixed read-only queries below
        [executable, "-C", str(repository), *arguments],
        capture_output=True,
        timeout=30,
        check=False,
        env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"},
    )
    if result.returncode != 0 or len(result.stdout) > MAX_FILE_BYTES:
        raise ScanError("GIT_READ_FAILED")
    return result.stdout


def _path(repository: Path, supplied: str) -> tuple[Path, str]:
    if not supplied or any(ord(char) < 32 for char in supplied):
        raise ScanError("UNSAFE_PATH")
    path = Path(supplied)
    if path.drive and not path.is_absolute():
        raise ScanError("UNSAFE_PATH")
    if supplied.startswith(("\\\\", "//")):
        raise ScanError("UNSAFE_PATH")
    parts = path.parts[1:] if path.anchor else path.parts
    if any(
        part == ".." or ":" in part or part.endswith((".", " ")) or "~" in part for part in parts
    ):
        raise ScanError("UNSAFE_PATH")
    absolute = Path(os.path.abspath(repository / path))
    validate_original_ancestors(absolute)
    metadata = absolute.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ScanError("UNSAFE_FILE_IDENTITY")
    # Reject case aliases on case-insensitive filesystems, not just junctions.
    for component in (absolute, *absolute.parents):
        if component == component.parent:
            break
        names = {child.name for child in component.parent.iterdir()}
        if component.name not in names:
            raise ScanError("PATH_ALIAS")
    try:
        name = absolute.relative_to(repository).as_posix()
    except ValueError:
        name = absolute.as_posix()
    return absolute, name


def _read(path: Path) -> bytes:
    validate_original_ancestors(path)
    before = path.stat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise ScanError("UNSAFE_FILE_IDENTITY")
    if before.st_size > MAX_FILE_BYTES:
        raise ScanError("FILE_TOO_LARGE")
    raw = path.read_bytes()
    after = path.stat()
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise ScanError("FILE_CHANGED")
    return raw


def _baseline(raw: bytes) -> dict[str, Any]:
    value = decode_json_strict(raw, maximum_bytes=1024 * 1024)
    if not isinstance(value, dict) or set(value) != {
        "version",
        "plugins_used",
        "filters_used",
        "results",
        "generated_at",
    }:
        raise ScanError("BASELINE_STRUCTURE")
    if value["version"] != "1.5.0" or version("detect-secrets") != "1.5.0":
        raise ScanError("SCANNER_VERSION")
    for key, expected in scanner_configuration().items():
        if value[key] != expected:
            raise ScanError("SCANNER_CONFIGURATION")
    _findings(value)
    return value


def _findings(baseline: dict[str, Any]) -> dict[tuple[str, str, str], dict[str, Any]]:
    results = baseline.get("results")
    if not isinstance(results, dict):
        raise ScanError("BASELINE_FINDINGS")
    output: dict[tuple[str, str, str], dict[str, Any]] = {}
    for name, rows in results.items():
        if not isinstance(name, str) or not isinstance(rows, list):
            raise ScanError("BASELINE_FINDINGS")
        normalized = name.replace("\\", "/")
        if normalized.startswith("/") or any(p in {"", ".", ".."} for p in normalized.split("/")):
            raise ScanError("BASELINE_PATH")
        for row in rows:
            if (
                not isinstance(row, dict)
                or set(row)
                not in (
                    {"type", "filename", "hashed_secret", "is_verified", "line_number"},
                    {
                        "type",
                        "filename",
                        "hashed_secret",
                        "is_verified",
                        "line_number",
                        "is_secret",
                    },
                )
                or row["filename"] != name
                or not isinstance(row["type"], str)
                or not isinstance(row["hashed_secret"], str)
                or re.fullmatch(r"[0-9a-f]{40}", row["hashed_secret"]) is None
                or type(row["is_verified"]) is not bool
                or type(row["line_number"]) is not int
                or row["line_number"] < 1
                or ("is_secret" in row and type(row["is_secret"]) is not bool)
            ):
                raise ScanError("BASELINE_FINDING_FIELDS")
            key = (normalized, row["type"], row["hashed_secret"])
            if key in output:
                raise ScanError("DUPLICATE_FINDING")
            output[key] = row
    return output


def _assert_staged(repository: Path, raw: bytes) -> bytes:
    root = _git(repository, "rev-parse", "--show-toplevel").decode().strip()
    if Path(root).resolve() != repository:
        raise ScanError("REPOSITORY_ROOT")
    entry = _git(repository, "ls-files", "--stage", "-z", "--", BASELINE_NAME)
    match = re.fullmatch(rb"100644 ([0-9a-f]{40}|[0-9a-f]{64}) 0\t\.secrets\.baseline\x00", entry)
    if match is None:
        raise ScanError("BASELINE_INDEX")
    if _git(repository, "diff", "--name-only", "-z", "--", BASELINE_NAME):
        raise ScanError("BASELINE_UNSTAGED")
    staged = _git(repository, "cat-file", "blob", match[1].decode())
    if raw.replace(b"\r\n", b"\n") != staged.replace(b"\r\n", b"\n"):
        raise ScanError("BASELINE_UNSTAGED")
    return entry


@contextmanager
def _offline_scanner() -> Iterator[None]:
    requests = importlib.import_module("requests")
    logger = importlib.import_module("detect_secrets.core.log").log
    disabled = logger.disabled
    logger.disabled = True

    def blocked(*args: object, **kwargs: object) -> None:
        raise requests.exceptions.ConnectionError("OFFLINE_SCANNER")

    def scanner_error(*args: object, **kwargs: object) -> None:
        raise ScanError("SCANNER_INCOMPLETE")

    try:
        with (
            redirect_stdout(io.StringIO()),
            redirect_stderr(io.StringIO()),
            patch.object(requests.sessions.Session, "request", blocked),
            patch.object(requests.sessions.Session, "send", blocked),
            patch.object(socket, "getaddrinfo", blocked),
            patch.object(socket.socket, "connect", blocked),
            patch.object(socket.socket, "connect_ex", blocked),
            patch.object(logger, "warning", scanner_error),
            patch.object(logger, "error", scanner_error),
        ):
            yield
    finally:
        logger.disabled = disabled


@dataclass(frozen=True)
class ScanResult:
    new: tuple[tuple[str, str, int], ...]
    missing: int
    relocated: int
    scanned: int
    candidate: dict[str, Any]

    @property
    def passed(self) -> bool:
        return not (self.new or self.missing or self.relocated)


class _SourceText(io.StringIO):
    def __init__(self, text: str, name: str) -> None:
        super().__init__(text)
        self.name = name


def _source_lines(text: str, name: str, requested: str) -> Iterator[list[str]]:
    """Preserve upstream normal/eager transforms, with stable UTF-8 snapshot ingestion."""
    if requested != name:
        raise ScanError("SCANNER_UNEXPECTED_FILE")
    transform = importlib.import_module("detect_secrets.transformers").get_transformed_file
    with _SourceText(text, name) as stream:
        lines = transform(stream)
        yield lines if lines else stream.readlines()
        stream.seek(0)
        lines = transform(stream, use_eager_transformers=True)
        if lines:
            yield lines


def _inventory(repository: Path) -> tuple[str, ...]:
    raw = _git(repository, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
    if not raw or not raw.endswith(b"\x00"):
        raise ScanError("INCOMPLETE_FILE_INVENTORY")
    return tuple(sorted(set(raw.decode("utf-8").split("\x00")[:-1])))


def scan_files(
    repository: Path, baseline: dict[str, Any], filenames: Sequence[str], *, complete: bool
) -> ScanResult:
    """Internal read-only scanner shared by verification and controlled maintenance."""
    settings = importlib.import_module("detect_secrets.settings")
    scanner = importlib.import_module("detect_secrets.core.scan")
    identify = importlib.import_module("identify.identify")
    expected = _findings(baseline)
    found: dict[tuple[str, str, str], int] = {}
    scanned: set[str] = set()
    before: dict[Path, bytes] = {}
    old_cwd = Path.cwd()
    try:
        os.chdir(repository)
        with (
            _offline_scanner(),
            settings.transient_settings(scanner_configuration()),
            ExitStack() as verification_guards,
        ):
            if len(settings.get_plugins()) != len(PLUGIN_NAMES):
                raise ScanError("SCANNER_PLUGIN_COVERAGE")
            unverified = importlib.import_module(
                "detect_secrets.constants"
            ).VerifiedResult.UNVERIFIED
            for plugin in settings.get_plugins():
                verification_guards.enter_context(
                    patch.object(plugin, "verify", return_value=unverified)
                )
            for supplied in filenames:
                path, name = _path(repository, supplied)
                if name == BASELINE_NAME:
                    continue
                raw = _read(path)
                before[path] = raw
                if "text" not in identify.tags_from_path(str(path)):
                    if not complete:
                        raise ScanError("NON_TEXT_INPUT")
                    continue
                text = raw.decode("utf-8")
                scanned.add(name)

                def source_lines(
                    requested: str, source_text: str = text, source_name: str = name
                ) -> Iterator[list[str]]:
                    return _source_lines(source_text, source_name, requested)

                with patch.object(scanner, "_get_lines_from_file", source_lines):
                    for secret in scanner.scan_file(name):
                        key = (name, str(secret.type), str(secret.secret_hash))
                        found.setdefault(key, int(secret.line_number))
                if _read(path) != raw:
                    raise ScanError("SOURCE_CHANGED")
    finally:
        os.chdir(old_cwd)
        for path, raw in before.items():
            if _read(path) != raw:
                raise ScanError("SOURCE_CHANGED")
    in_scope = expected if complete else {k: v for k, v in expected.items() if k[0] in scanned}
    missing = len(in_scope.keys() - found.keys())
    added = tuple(sorted((k[0], k[1], found[k]) for k in found.keys() - expected.keys()))
    candidate = copy.deepcopy(baseline)
    candidate_rows = _findings(candidate)
    relocated = 0
    for key in found.keys() & expected.keys():
        if expected[key]["line_number"] != found[key]:
            relocated += 1
            candidate_rows[key]["line_number"] = found[key]
    return ScanResult(added, missing, relocated, len(scanned), candidate)


def check(repository: Path, filenames: Sequence[str], *, complete: bool = False) -> ScanResult:
    repository = repository.absolute()
    path, name = _path(repository, BASELINE_NAME)
    if name != BASELINE_NAME:
        raise ScanError("BASELINE_PATH")
    raw = _read(path)
    baseline = _baseline(raw)
    index = _assert_staged(repository, raw)
    inventory = _inventory(repository) if complete else tuple(filenames)
    try:
        result = scan_files(repository, baseline, inventory, complete=complete)
        if complete and _inventory(repository) != inventory:
            raise ScanError("INVENTORY_CHANGED")
        return result
    finally:
        if _read(path) != raw or _assert_staged(repository, raw) != index:
            raise ScanError("BASELINE_OR_INDEX_CHANGED")


def maintain(repository: Path, reference: bytes, reference_sha256: str, output: Path) -> ScanResult:
    """Publish an exclusive candidate, never promote it or change the Git index."""
    if sha256(reference).hexdigest() != reference_sha256:
        raise ScanError("REFERENCE_IDENTITY")
    approved = _baseline(reference)
    canonical, _ = _path(repository, BASELINE_NAME)
    current = _read(canonical)
    current_value = _baseline(current)
    # A reference is authority for metadata only, never a new inventory or configuration.
    old_rows, current_rows = _findings(approved), _findings(current_value)

    def strip(row: dict[str, Any]) -> dict[str, Any]:
        return {k: v for k, v in row.items() if k != "line_number"}

    if old_rows.keys() != current_rows.keys() or any(
        strip(old_rows[key]) != strip(current_rows[key]) for key in old_rows
    ):
        raise ScanError("REFERENCE_FINDINGS_DIFFER")
    root = ensure_external_path(output, MAINTENANCE_PARENT, repository)
    if root.parent != MAINTENANCE_PARENT or not re.fullmatch(
        r"secret-scanning-maintenance-[0-9]{3}", root.name
    ):
        raise ScanError("MAINTENANCE_OUTPUT_SCOPE")
    reserve_operation_directory(root, MAINTENANCE_PARENT, repository)
    for name, payload in (
        ("approved-reference.lf.json", reference),
        ("starting-working.json", current),
    ):
        write_private_bytes_exclusive(
            root / name, payload, allowed_root=root, repository_root=repository
        )
    inventory = _inventory(repository)
    result = scan_files(repository, current_value, inventory, complete=True)
    if result.new or result.missing:
        raise ScanError("MAINTENANCE_SECURITY_DECISION_REQUIRED")
    if _read(canonical) != current or inventory != _inventory(repository):
        raise ScanError("MAINTENANCE_SOURCE_CHANGED")
    candidate = result.candidate
    if result.relocated:
        candidate["generated_at"] = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    payload = (json.dumps(candidate, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    write_private_bytes_exclusive(
        root / "candidate.json", payload, allowed_root=root, repository_root=repository
    )
    receipt = {
        "reference_sha256": reference_sha256,
        "working_sha256": sha256(current).hexdigest(),
        "working_lf_sha256": sha256(current.replace(b"\r\n", b"\n")).hexdigest(),
        "candidate_sha256": sha256(payload).hexdigest(),
        "relocated": result.relocated,
        "finding_identity_and_decisions": "UNCHANGED",
        "scanner_configuration": "UNCHANGED",
        "promotion": "NOT_RUN",
    }
    write_private_bytes_exclusive(
        root / "identities.json",
        (json.dumps(receipt, sort_keys=True) + "\n").encode(),
        allowed_root=root,
        repository_root=repository,
    )
    return result


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    verify = commands.add_parser("check")
    verify.add_argument("--all-files", action="store_true")
    verify.add_argument("files", nargs="*")
    maintenance = commands.add_parser("maintain")
    maintenance.add_argument("--reference-file", type=Path, required=True)
    maintenance.add_argument("--reference-sha256", required=True)
    maintenance.add_argument("--output-directory", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "maintain":
            reference_path = ensure_external_path(
                args.reference_file, MAINTENANCE_PARENT, REPOSITORY
            )
            result = maintain(
                REPOSITORY, _read(reference_path), args.reference_sha256, args.output_directory
            )
            print(f"BASELINE_CANDIDATE=READY_FOR_RECONCILIATION; RELOCATIONS={result.relocated}")
            return 0
        if bool(args.all_files) == bool(args.files):
            raise ScanError("EXACT_SCAN_SCOPE_REQUIRED")
        result = check(REPOSITORY, args.files, complete=args.all_files)
        for name, kind, line in result.new:
            print(json.dumps({"path": name, "type": kind, "line": line}, ensure_ascii=True))
        print(
            f"SCANNED={result.scanned}; NEW={len(result.new)}; "
            f"MISSING={result.missing}; RELOCATED={result.relocated}"
        )
        if not result.passed:
            print("SECRET_SCAN=FAIL")
            return 1
        print("SECRET_SCAN=PASS")
        return 0
    except ScanError as exc:
        print(f"SECRET_SCAN=FAIL; REASON={exc}")
        return 1
    except (ContractError, OSError, ValueError, subprocess.SubprocessError):
        print("SECRET_SCAN=FAIL; REASON=SCANNER_OR_INPUT_FAILURE")
        return 1
    except Exception:
        # Third-party exceptions may contain source text or candidate credentials.
        print("SECRET_SCAN=FAIL; REASON=UNEXPECTED_SCANNER_FAILURE")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
