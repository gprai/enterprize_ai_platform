"""Security tests for evidence redaction and path/content rejection."""

from __future__ import annotations

import pytest
from tools.record_test_evidence import redact_command, validate_report_path


@pytest.mark.parametrize(
    ("command", "secret"),
    [
        ("pytest --token synthetic-token", "synthetic-token"),
        ("pytest --api-key=synthetic-key", "synthetic-key"),
        ("pytest PASSWORD=synthetic-password", "synthetic-password"),
        ("pytest Authorization:Bearer synthetic-bearer", "synthetic-bearer"),
        ("pytest AKIA1234567890ABCDEF", "AKIA1234567890ABCDEF"),
    ],
)
def test_sensitive_command_values_are_redacted(command: str, secret: str) -> None:
    redacted = redact_command(command)
    assert secret not in redacted
    assert "REDACTED" in redacted


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
