"""The image scan gate rejects malformed and unresolved findings."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from tools.w12_001_images import (
    ImageScanError,
    evaluate_approved_scan,
    evaluate_scan,
    finding_digest,
)


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


def test_exact_time_bounded_exception_and_changed_findings(tmp_path: Path) -> None:
    trivy_document = {
        "Results": [
            {
                "Type": "debian",
                "Secrets": [],
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-SYNTHETIC-1",
                        "PkgName": "example",
                        "InstalledVersion": "1.0",
                        "Severity": "HIGH",
                        "FixedVersion": "1.1",
                    }
                ],
            }
        ]
    }
    grype_document = {
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-SYNTHETIC-1",
                    "namespace": "example",
                    "severity": "High",
                    "fix": {"state": "fixed", "versions": ["1.1"]},
                },
                "artifact": {"name": "example", "version": "1.0", "type": "deb"},
            }
        ]
    }
    trivy = _write(tmp_path / "trivy.json", trivy_document)
    grype = _write(tmp_path / "grype.json", grype_document)
    source = tmp_path / "source.json"
    source.write_text("{}", encoding="utf-8")
    approved = datetime(2026, 10, 26, tzinfo=UTC)
    exception = {
        "schema_version": "w12-001.exact-image-scan-exception.v1",
        "approved_at_utc": approved.isoformat(),
        "expires_at_utc": (approved + timedelta(days=7)).isoformat(),
        "pinned_source_manifest_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "images": {
            name: {
                scanner: {
                    "high_critical_count": 1,
                    "finding_sha256": finding_digest(path, scanner)[1],
                }
                for scanner, path in (("trivy", trivy), ("grype", grype))
            }
            for name in ("toolchain", "codebuild")
        },
    }
    exception_path = _write(tmp_path / "exception.json", exception)
    kwargs = {
        "image_name": "toolchain",
        "exception_path": exception_path,
        "source_manifest_path": source,
    }
    assert evaluate_approved_scan(trivy, grype, now=approved + timedelta(days=1), **kwargs) == (
        1,
        0,
        1,
    )
    with pytest.raises(ImageScanError, match="not currently valid"):
        evaluate_approved_scan(trivy, grype, now=approved + timedelta(days=7), **kwargs)
    source.write_text('{"changed": true}', encoding="utf-8")
    with pytest.raises(ImageScanError, match="recipe identity changed"):
        evaluate_approved_scan(trivy, grype, now=approved + timedelta(days=1), **kwargs)
    source.write_text("{}", encoding="utf-8")
    trivy_document["Results"][0]["Vulnerabilities"][0]["InstalledVersion"] = "1.0.1"
    _write(trivy, trivy_document)
    with pytest.raises(ImageScanError, match="findings differ"):
        evaluate_approved_scan(trivy, grype, now=approved + timedelta(days=1), **kwargs)
    trivy_document["Results"][0]["Secrets"] = [{"RuleID": "synthetic"}]
    _write(trivy, trivy_document)
    with pytest.raises(ImageScanError, match="Secret findings"):
        evaluate_approved_scan(trivy, grype, now=approved + timedelta(days=1), **kwargs)
