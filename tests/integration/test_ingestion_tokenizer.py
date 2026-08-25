"""Owner-opted offline MiniLM tokenizer integration contract."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from enterprise_ai_platform.ingestion.models import APPROVED_TOKENIZER_REVISION
from enterprise_ai_platform.ingestion.tokenizer import MiniLmTokenizer

RUN_REAL_TOKENIZER = "RUN_W2_003_REAL_TOKENIZER_TEST"
MODEL_SNAPSHOT = "W2_002_MODEL_SNAPSHOT"
MODEL_CACHE_DIRECTORY = "models--sentence-transformers--all-MiniLM-L6-v2"


def approved_snapshot() -> Path:
    if os.getenv(RUN_REAL_TOKENIZER) != "1":
        pytest.skip("real tokenizer test is owner-controlled and opt-in")
    if os.getenv("HF_HUB_OFFLINE") != "1" or os.getenv("TRANSFORMERS_OFFLINE") != "1":
        pytest.fail("offline Hugging Face and Transformers controls are required")
    raw_path = os.getenv(MODEL_SNAPSHOT)
    if raw_path is None:
        pytest.fail("the verified W2-002 snapshot path is required")
    path = Path(raw_path)
    if (
        not path.is_absolute()
        or path.name != APPROVED_TOKENIZER_REVISION
        or path.parent.name != "snapshots"
        or path.parent.parent.name != MODEL_CACHE_DIRECTORY
    ):
        pytest.fail("the tokenizer snapshot must be the exact approved revision")
    return path


def test_verified_minilm_tokenizer_operates_offline_without_model_loading() -> None:
    tokenizer = MiniLmTokenizer(approved_snapshot())

    spans = tokenizer.token_spans("Approved synthetic tokenizer integration text.")

    assert spans
    assert tokenizer.tokenizer_revision == APPROVED_TOKENIZER_REVISION
    assert all(span.end > span.start for span in spans)
