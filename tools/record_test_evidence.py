"""Emit a redacted W1-003 test-evidence metadata record to standard output."""

from __future__ import annotations

import argparse
import json
import re
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import PurePosixPath
from typing import Protocol

SCHEMA_VERSION = "1.0"
TODO_MARKER = "TODO_USER"
ALLOWED_ENVIRONMENTS = frozenset({"sandbox"})
ALLOWED_RESULTS = frozenset({"PASS", "FAIL", "NOT_RUN", "INDETERMINATE"})
ALLOWED_GIT_STATES = frozenset({"DIRTY", "UNCOMMITTED"})

_DOCUMENT_ARGUMENT = re.compile(r"(?i)(?:^|\s)--?(?:content|document|prompt|text)(?:\s|=)")
_BEARER_TOKEN = re.compile(r"(?i)(authorization\s*:\s*bearer\s+)\S+")
_SENSITIVE_ASSIGNMENT = re.compile(
    r"(?i)\b(?P<name>[a-z0-9_-]*(?:api[_-]?key|access[_-]?key|authorization|"
    r"password|secret|token))(?P<separator>\s*[:=]\s*|\s+)"
    r"(?P<value>\"[^\"]*\"|'[^']*'|\S+)"
)
_AWS_ACCESS_KEY = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
_COMMITTED_SHA = re.compile(r"[0-9a-fA-F]{40}")


class Clock(Protocol):
    """Clock contract used to make timestamp tests deterministic."""

    def now_utc(self) -> datetime:
        """Return the current timezone-aware UTC time."""
        ...


class SystemClock:
    """Production clock that performs no external I/O."""

    def now_utc(self) -> datetime:
        return datetime.now(UTC)


@dataclass(frozen=True)
class EvidenceRecord:
    """Approved stdout-only evidence metadata schema."""

    schema_version: str
    command: str
    timestamp_utc: str
    git_sha: str
    git_state: str
    environment: str
    result: str
    report_path: str

    def to_json(self) -> str:
        """Serialize deterministically without writing a file."""
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))


def redact_command(command: str) -> str:
    """Redact common secret forms and reject document-content arguments."""
    normalized = command.strip()
    if not normalized:
        raise ValueError("command must not be empty")
    if len(normalized) > 2048:
        raise ValueError("command exceeds the 2048-character evidence limit")
    if "\n" in normalized or "\r" in normalized:
        raise ValueError("command must be a single line")
    if _DOCUMENT_ARGUMENT.search(normalized):
        raise ValueError("document content must not be included in evidence metadata")

    redacted = _BEARER_TOKEN.sub(r"\1[REDACTED]", normalized)
    redacted = _SENSITIVE_ASSIGNMENT.sub(
        lambda match: f"{match.group('name')}{match.group('separator')}[REDACTED]",
        redacted,
    )
    return _AWS_ACCESS_KEY.sub("[REDACTED_AWS_ACCESS_KEY]", redacted)


def validate_git_metadata(git_sha: str, git_state: str) -> tuple[str, str]:
    """Validate explicit Git metadata without running Git or inventing a SHA."""
    normalized_sha = git_sha.strip()
    normalized_state = git_state.strip().upper()
    if normalized_state not in ALLOWED_GIT_STATES:
        raise ValueError("git_state must be DIRTY or UNCOMMITTED")
    if normalized_sha == "UNCOMMITTED":
        if normalized_state != "UNCOMMITTED":
            raise ValueError("UNCOMMITTED git_sha requires UNCOMMITTED git_state")
        return normalized_sha, normalized_state
    if _COMMITTED_SHA.fullmatch(normalized_sha) is None:
        raise ValueError("git_sha must be UNCOMMITTED or a 40-character hexadecimal SHA")
    if normalized_state != "DIRTY":
        raise ValueError("a committed SHA in this workflow requires DIRTY git_state")
    return normalized_sha.casefold(), normalized_state


def validate_report_path(report_path: str) -> str:
    """Require a redacted repository-relative path under docs/test-evidence."""
    normalized = report_path.strip().replace("\\", "/")
    path = PurePosixPath(normalized)
    if not normalized or path.is_absolute() or ".." in path.parts:
        raise ValueError("report_path must be a safe repository-relative path")
    if path.parts[:2] != ("docs", "test-evidence"):
        raise ValueError("report_path must remain under docs/test-evidence")
    if TODO_MARKER.casefold() in normalized.casefold():
        raise ValueError("report_path must not contain TODO_USER")
    return path.as_posix()


def build_evidence_record(
    *,
    command: str,
    git_sha: str,
    git_state: str,
    environment: str,
    result: str,
    report_path: str,
    clock: Clock | None = None,
) -> EvidenceRecord:
    """Build a validated record using injected time and explicit Git state."""
    normalized_environment = environment.strip().casefold()
    if normalized_environment not in ALLOWED_ENVIRONMENTS:
        raise ValueError("environment must be sandbox")
    normalized_result = result.strip().upper()
    if normalized_result not in ALLOWED_RESULTS:
        raise ValueError("result is not an approved evidence value")
    normalized_sha, normalized_state = validate_git_metadata(git_sha, git_state)

    current_time = (clock or SystemClock()).now_utc()
    if current_time.utcoffset() != UTC.utcoffset(current_time):
        raise ValueError("clock must return a timezone-aware UTC timestamp")
    timestamp = current_time.replace(microsecond=0).isoformat().replace("+00:00", "Z")

    return EvidenceRecord(
        schema_version=SCHEMA_VERSION,
        command=redact_command(command),
        timestamp_utc=timestamp,
        git_sha=normalized_sha,
        git_state=normalized_state,
        environment=normalized_environment,
        result=normalized_result,
        report_path=validate_report_path(report_path),
    )


def build_parser() -> argparse.ArgumentParser:
    """Build the bounded stdout-only command interface."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--command", required=True)
    parser.add_argument("--git-sha", required=True)
    parser.add_argument("--git-state", required=True, choices=sorted(ALLOWED_GIT_STATES))
    parser.add_argument("--environment", required=True, choices=sorted(ALLOWED_ENVIRONMENTS))
    parser.add_argument("--result", required=True, choices=sorted(ALLOWED_RESULTS))
    parser.add_argument("--report-path", required=True)
    return parser


def main(argv: Sequence[str] | None = None, *, clock: Clock | None = None) -> int:
    """Validate supplied metadata and print one compact JSON record."""
    parser = build_parser()
    arguments = parser.parse_args(argv)
    try:
        record = build_evidence_record(
            command=arguments.command,
            git_sha=arguments.git_sha,
            git_state=arguments.git_state,
            environment=arguments.environment,
            result=arguments.result,
            report_path=arguments.report_path,
            clock=clock,
        )
    except ValueError as exc:
        parser.error(str(exc))
    print(record.to_json())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
