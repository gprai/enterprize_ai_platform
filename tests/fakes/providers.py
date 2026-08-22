"""Predictable providers that perform no network, file, or cloud I/O."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime


@dataclass(frozen=True)
class FixedClock:
    """Return one owner-independent UTC timestamp."""

    value: datetime = datetime(2026, 1, 1, tzinfo=UTC)

    def now_utc(self) -> datetime:
        return self.value


@dataclass(frozen=True)
class FakeGitMetadataProvider:
    """Return explicit uncommitted metadata without invoking Git."""

    git_sha: str = "UNCOMMITTED"
    git_state: str = "UNCOMMITTED"

    def metadata(self) -> tuple[str, str]:
        return self.git_sha, self.git_state


@dataclass(frozen=True)
class FakeEnvironmentProvider:
    """Return the owner-approved local environment name."""

    environment: str = "sandbox"

    def name(self) -> str:
        return self.environment


@dataclass(frozen=True)
class FakeAnswerProvider:
    """Return a fixed answer without loading a model or document."""

    answer_text: str = "Deterministic fake answer"

    def answer(self, _question: str) -> str:
        return self.answer_text
