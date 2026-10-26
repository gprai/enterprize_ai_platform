"""The image scan gate rejects malformed and unresolved findings."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from tools.w12_001_images import ImageScanError, evaluate_scan


def _write(path: Path, value: object) -> Path:
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def test_clean_scan_documents_pass(tmp_path: Path) -> None:
    trivy = _write(tmp_path / "trivy.json", {"Results": [{"Vulnerabilities": [], "Secrets": []}]})
    grype = _write(tmp_path / "grype.json", {"matches": []})
    assert evaluate_scan(trivy, grype) == (0, 0, 0)


@pytest.mark.parametrize("severity", ["HIGH", "CRITICAL"])
def test_high_or_critical_trivy_finding_blocks(tmp_path: Path, severity: str) -> None:
    trivy = _write(
        tmp_path / "trivy.json", {"Results": [{"Vulnerabilities": [{"Severity": severity}]}]}
    )
    grype = _write(tmp_path / "grype.json", {"matches": []})
    assert evaluate_scan(trivy, grype)[0] == 1


def test_secret_and_grype_high_both_block(tmp_path: Path) -> None:
    trivy = _write(tmp_path / "trivy.json", {"Results": [{"Secrets": [{"RuleID": "synthetic"}]}]})
    grype = _write(tmp_path / "grype.json", {"matches": [{"vulnerability": {"severity": "High"}}]})
    assert evaluate_scan(trivy, grype) == (0, 1, 1)


def test_missing_scanner_results_fail_closed(tmp_path: Path) -> None:
    trivy = _write(tmp_path / "trivy.json", {})
    grype = _write(tmp_path / "grype.json", {"matches": []})
    with pytest.raises(ImageScanError):
        evaluate_scan(trivy, grype)
