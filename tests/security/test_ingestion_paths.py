"""Security tests for source containment, types, size, and symlink controls."""

from __future__ import annotations

from pathlib import Path

import pytest

from enterprise_ai_platform.ingestion.errors import IngestionSourceError
from enterprise_ai_platform.ingestion.loaders import load_source, resolve_contained_source
from enterprise_ai_platform.ingestion.models import MAX_FILE_BYTES, CorpusDocument
from enterprise_ai_platform.retrieval.models import Classification, Role


def source(path: str, media_type: str = "text/plain") -> CorpusDocument:
    return CorpusDocument(
        source_path=path,
        source_id="DOC-PATH-SECURITY",
        tenant_id="tenant-a",
        classification=Classification.INTERNAL,
        allowed_roles=(Role.READER,),
        allowed_groups=(),
        data_owner="Gyan Prakash Rai",
        media_type=media_type,
    )


@pytest.mark.parametrize(
    "unsafe_path",
    ("../outside.txt", "/absolute.txt", "C:/absolute.txt", "approved\\source.txt"),
)
def test_traversal_absolute_and_non_posix_paths_are_rejected(
    tmp_path: Path,
    unsafe_path: str,
) -> None:
    with pytest.raises(IngestionSourceError):
        resolve_contained_source(tmp_path, unsafe_path)


def test_any_symlink_component_is_rejected_without_following_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "target.txt"
    target.write_text("approved", encoding="utf-8")
    original = Path.is_symlink

    def marked_symlink(path: Path) -> bool:
        return path.name == "link.txt" or original(path)

    monkeypatch.setattr(Path, "is_symlink", marked_symlink)
    with pytest.raises(IngestionSourceError):
        resolve_contained_source(tmp_path, "link.txt")


def test_symlink_source_root_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = Path.is_symlink

    def marked_root(path: Path) -> bool:
        return path == tmp_path.absolute() or original(path)

    monkeypatch.setattr(Path, "is_symlink", marked_root)
    with pytest.raises(IngestionSourceError):
        resolve_contained_source(tmp_path, "source.txt")


def test_extension_declared_type_binary_content_and_pdf_disguise_are_rejected(
    tmp_path: Path,
) -> None:
    path = tmp_path / "source.txt"
    path.write_text("approved text", encoding="utf-8")
    with pytest.raises(IngestionSourceError):
        load_source(tmp_path, source("source.txt", "text/markdown"))

    path.write_bytes(b"binary\x00content")
    with pytest.raises(IngestionSourceError):
        load_source(tmp_path, source("source.txt"))

    path.write_bytes(b"%PDF-disguised-as-text")
    with pytest.raises(IngestionSourceError):
        load_source(tmp_path, source("source.txt"))


def test_empty_invalid_utf8_and_oversized_sources_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "source.txt"
    path.write_bytes(b"")
    with pytest.raises(IngestionSourceError):
        load_source(tmp_path, source("source.txt"))

    path.write_bytes(b"\xff\xfe")
    with pytest.raises(IngestionSourceError):
        load_source(tmp_path, source("source.txt"))

    path.write_bytes(b"x" * (MAX_FILE_BYTES + 1))
    with pytest.raises(IngestionSourceError):
        load_source(tmp_path, source("source.txt"))
