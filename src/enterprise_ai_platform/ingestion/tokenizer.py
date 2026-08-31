"""Token-span protocols for deterministic tests and the approved offline tokenizer."""

from __future__ import annotations

import importlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from .errors import IngestionContractError
from .models import APPROVED_TOKENIZER_ID, APPROVED_TOKENIZER_REVISION

_APPROVED_MODEL_CACHE_DIRECTORY = "models--sentence-transformers--all-MiniLM-L6-v2"
_REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


@dataclass(frozen=True, slots=True)
class TokenSpan:
    start: int
    end: int


@runtime_checkable
class IngestionTokenizer(Protocol):
    @property
    def tokenizer_id(self) -> str: ...

    @property
    def tokenizer_revision(self) -> str: ...

    def token_spans(self, text: str) -> tuple[TokenSpan, ...]: ...


class DeterministicTestTokenizer(IngestionTokenizer):
    """Stable fake tokenizer used only for ordinary tests and synthetic CLI runs."""

    _pattern = re.compile(r"\S+")

    @property
    def tokenizer_id(self) -> str:
        return "enterprise-ai/deterministic-test-tokenizer"

    @property
    def tokenizer_revision(self) -> str:
        return "w2-003-v1"

    def token_spans(self, text: str) -> tuple[TokenSpan, ...]:
        return tuple(
            TokenSpan(match.start(), match.end()) for match in self._pattern.finditer(text)
        )


class MiniLmTokenizer(IngestionTokenizer):
    """Lazily load tokenizer.json from the exact verified W2-002 snapshot."""

    def __init__(self, snapshot_path: Path) -> None:
        self._snapshot_path = snapshot_path
        self._tokenizer: Any | None = None

    @property
    def tokenizer_id(self) -> str:
        return APPROVED_TOKENIZER_ID

    @property
    def tokenizer_revision(self) -> str:
        return APPROVED_TOKENIZER_REVISION

    def _load(self) -> Any:
        if self._tokenizer is not None:
            return self._tokenizer
        try:
            snapshot = self._snapshot_path.resolve(strict=True)
        except OSError:
            raise IngestionContractError from None
        tokenizer_file = snapshot / "tokenizer.json"
        if (
            not snapshot.is_absolute()
            or snapshot.name != APPROVED_TOKENIZER_REVISION
            or snapshot.parent.name != "snapshots"
            or snapshot.parent.parent.name != _APPROVED_MODEL_CACHE_DIRECTORY
            or snapshot.is_relative_to(_REPOSITORY_ROOT)
            or not tokenizer_file.is_file()
        ):
            raise IngestionContractError
        try:
            module = importlib.import_module("tokenizers")
            self._tokenizer = module.Tokenizer.from_file(str(tokenizer_file))
        except Exception:
            raise IngestionContractError from None
        return self._tokenizer

    def token_spans(self, text: str) -> tuple[TokenSpan, ...]:
        try:
            encoding = self._load().encode(text, add_special_tokens=False)
            spans = tuple(
                TokenSpan(int(start), int(end))
                for start, end in encoding.offsets
                if int(end) > int(start)
            )
        except IngestionContractError:
            raise
        except Exception:
            raise IngestionContractError from None
        if any(span.end > len(text) for span in spans):
            raise IngestionContractError
        return spans
