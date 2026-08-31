"""Security tests for evidence redaction and path/content rejection."""

from __future__ import annotations

from pathlib import Path

import pytest
from tools.record_test_evidence import redact_command, validate_report_path

SYNTHETIC_MARKER_PARTS = ("AKIA", "W108SEC003TESTXY")


@pytest.mark.parametrize(
    ("command", "secret"),
    [
        ("pytest --token synthetic-token", "synthetic-token"),
        ("pytest --api-key=synthetic-key", "synthetic-key"),
        ("pytest PASSWORD=synthetic-password", "synthetic-password"),
        ("pytest Authorization:Bearer synthetic-bearer", "synthetic-bearer"),
    ],
)
def test_sensitive_command_values_are_redacted(command: str, secret: str) -> None:
    redacted = redact_command(command)
    assert secret not in redacted
    assert "REDACTED" in redacted


def test_runtime_constructed_aws_key_shaped_value_is_redacted(
    tmp_path: Path,
) -> None:
    fixture_path = tmp_path / "w1-08-redaction-fixture.txt"
    fixture_path.write_text("".join(SYNTHETIC_MARKER_PARTS), encoding="utf-8")

    try:
        secret = fixture_path.read_text(encoding="utf-8")
        redacted = redact_command(f"pytest {secret}")
        assert secret not in redacted
        assert "REDACTED" in redacted
    finally:
        fixture_path.unlink(missing_ok=True)

    assert not fixture_path.exists()


@pytest.mark.parametrize(
    "command",
    [
        "pytest --document sensitive.txt",
        "pytest --content=raw-text",
        "pytest --prompt private-document-text",
        "pytest --text raw-document-text",
    ],
)
def test_document_content_arguments_are_rejected(command: str) -> None:
    with pytest.raises(ValueError, match="document content"):
        redact_command(command)


@pytest.mark.parametrize(
    "report_path",
    [
        "C:/Users/owner/report.json",
        "../docs/test-evidence/report.json",
        "docs/other/report.json",
        "docs/test-evidence/TODO_USER.json",
    ],
)
def test_unsafe_report_paths_are_rejected(report_path: str) -> None:
    with pytest.raises(ValueError):
        validate_report_path(report_path)
