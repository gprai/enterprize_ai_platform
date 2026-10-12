"""Static cleanliness contract for the local-only W7-001 implementation."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_w7_source_declares_no_repository_or_cloud_persistence() -> None:
    source = "\n".join(
        (ROOT / path).read_text(encoding="utf-8")
        for path in (
            "src/enterprise_ai_platform/ingestion/governance.py",
            "src/enterprise_ai_platform/ingestion/workflow.py",
            "tests/fakes/w7_001_data_foundation.py",
        )
    ).casefold()
    for forbidden in ("import boto3", "dynamodb", "sleep(", "open(", "write_text("):
        assert forbidden not in source
