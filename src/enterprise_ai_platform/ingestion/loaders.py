"""Bounded local source loading with fail-closed type and PDF controls."""

from __future__ import annotations

from dataclasses import dataclass
from io import BytesIO
from pathlib import Path, PurePosixPath

from pypdf import PdfReader

from .errors import IngestionSourceError
from .models import (
    MAX_EXTRACTED_CHARACTERS,
    MAX_FILE_BYTES,
    MAX_PDF_PAGES,
    CorpusDocument,
)
from .normalization import decode_and_normalize, normalize_text


@dataclass(frozen=True, slots=True, repr=False)
class LoadedSource:
    original_bytes: bytes
    normalized_text: str
    media_type: str


def resolve_contained_source(source_root: Path, relative_path: str) -> Path:
    """Resolve an existing regular file while rejecting traversal and symlinks."""

    if not relative_path or "\\" in relative_path:
        raise IngestionSourceError
    pure_path = PurePosixPath(relative_path)
    if pure_path.is_absolute() or any(part in {"", ".", ".."} for part in pure_path.parts):
        raise IngestionSourceError
    absolute_root = source_root.absolute()
    if any(
        component.is_symlink()
        for component in (absolute_root, *absolute_root.parents)
    ):
        raise IngestionSourceError
    try:
        root = source_root.resolve(strict=True)
    except OSError:
        raise IngestionSourceError from None
    candidate = root
    for part in pure_path.parts:
        candidate = candidate / part
        if candidate.is_symlink():
            raise IngestionSourceError
    try:
        resolved = candidate.resolve(strict=True)
    except OSError:
        raise IngestionSourceError from None
    if not resolved.is_relative_to(root) or not resolved.is_file():
        raise IngestionSourceError
    return resolved


def _load_pdf(original_bytes: bytes) -> str:
    if not original_bytes.startswith(b"%PDF-"):
        raise IngestionSourceError
    try:
        reader = PdfReader(BytesIO(original_bytes), strict=True)
        if reader.is_encrypted or len(reader.pages) > MAX_PDF_PAGES:
            raise IngestionSourceError
        extracted: list[str] = []
        character_count = 0
        for page in reader.pages:
            page_text = page.extract_text() or ""
            character_count += len(page_text)
            if character_count > MAX_EXTRACTED_CHARACTERS:
                raise IngestionSourceError
            extracted.append(page_text)
    except IngestionSourceError:
        raise
    except Exception:
        raise IngestionSourceError from None
    normalized = normalize_text("\n".join(extracted))
    if not normalized.strip():
        raise IngestionSourceError
    return normalized


def load_source(source_root: Path, source: CorpusDocument) -> LoadedSource:
    """Read one approved source into bounded memory and validate its real type."""

    path = resolve_contained_source(source_root, source.source_path)
    try:
        size = path.stat().st_size
    except OSError:
        raise IngestionSourceError from None
    if size <= 0 or size > MAX_FILE_BYTES:
        raise IngestionSourceError
    try:
        original_bytes = path.read_bytes()
    except OSError:
        raise IngestionSourceError from None
    if len(original_bytes) != size or len(original_bytes) > MAX_FILE_BYTES:
        raise IngestionSourceError

    suffix = path.suffix.casefold()
    expected = {
        ".txt": "text/plain",
        ".md": "text/markdown",
        ".pdf": "application/pdf",
    }.get(suffix)
    if expected is None or source.media_type != expected:
        raise IngestionSourceError
    if expected == "application/pdf":
        normalized = _load_pdf(original_bytes)
    else:
        if b"\x00" in original_bytes or original_bytes.startswith(b"%PDF-"):
            raise IngestionSourceError
        normalized = decode_and_normalize(original_bytes)
    return LoadedSource(
        original_bytes=original_bytes,
        normalized_text=normalized,
        media_type=expected,
    )
