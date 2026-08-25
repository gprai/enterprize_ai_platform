"""Unit tests for deterministic token-span chunking."""

import pytest

from enterprise_ai_platform.ingestion.chunking import chunk_text
from enterprise_ai_platform.ingestion.errors import IngestionSourceError
from enterprise_ai_platform.ingestion.tokenizer import DeterministicTestTokenizer


def test_chunks_are_stable_bounded_and_overlap_by_exact_tokens() -> None:
    text = " ".join(f"token-{index}" for index in range(500))
    tokenizer = DeterministicTestTokenizer()

    first = chunk_text(text, tokenizer)
    second = chunk_text(text, tokenizer)

    assert first == second
    assert [chunk.chunk_index for chunk in first] == [0, 1, 2]
    assert [chunk.token_count for chunk in first] == [200, 200, 150]
    first_tokens = first[0].text.split()
    second_tokens = first[1].text.split()
    assert first_tokens[-25:] == second_tokens[:25]


def test_chunker_preserves_case_punctuation_and_internal_spacing() -> None:
    text = "Alpha,  Beta.\n\nGamma"
    chunks = chunk_text(
        text,
        DeterministicTestTokenizer(),
        target_tokens=2,
        overlap_tokens=1,
    )

    assert chunks[0].text == "Alpha,  Beta."
    assert chunks[1].text == "Beta.\n\nGamma"


@pytest.mark.parametrize(
    ("target", "overlap"),
    ((0, 0), (10, -1), (10, 10), (10, 11)),
)
def test_invalid_chunk_bounds_fail_closed(target: int, overlap: int) -> None:
    with pytest.raises(IngestionSourceError):
        chunk_text(
            "approved text",
            DeterministicTestTokenizer(),
            target_tokens=target,
            overlap_tokens=overlap,
        )


def test_empty_or_whitespace_only_text_is_rejected() -> None:
    with pytest.raises(IngestionSourceError):
        chunk_text("  \n\t", DeterministicTestTokenizer())
