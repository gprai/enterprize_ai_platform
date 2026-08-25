"""Smoke tests for explicit fake-only ingestion CLI behavior."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from enterprise_ai_platform.ingestion.pipeline import main

ROOT = Path(__file__).resolve().parents[2]


def approved_args() -> list[str]:
    return [
        "ingest",
        "--corpus-manifest",
        str(ROOT / "data" / "sample" / "corpus-manifest.json"),
        "--pii-policy",
        str(ROOT / "configs" / "pii-policy.yaml"),
        "--source-root",
        str(ROOT / "data" / "sample"),
        "--tenant-id",
        "tenant-a",
        "--embedder-provider",
        "fake",
        "--vector-store-provider",
        "fake",
        "--pii-provider",
        "deterministic",
    ]


def test_cli_requires_explicit_providers_and_returns_strict_json(
    capsys: pytest.CaptureFixture[str],
) -> None:
    missing_provider = approved_args()[:-2]
    assert main(missing_provider) == 2
    first = capsys.readouterr()
    assert json.loads(first.out)["exit_code"] == 2
    assert "configuration" in first.err.casefold()

    assert main(approved_args()) == 0
    second = capsys.readouterr()
    manifest = json.loads(second.out)
    assert manifest["exit_code"] == 0
    assert manifest["selected_count"] == 2
    assert manifest["indexed_count"] == 2
    assert second.err == ""
    encoded = json.dumps(manifest)
    assert "Source of Truth v1.1" not in encoded
    assert '"embedding":' not in encoded.casefold()


def test_cli_creates_no_repository_manifest_or_quarantine_directory() -> None:
    assert not (ROOT / "manifest").exists()
    assert not (ROOT / "manifests").exists()
    assert not (ROOT / "quarantine").exists()
