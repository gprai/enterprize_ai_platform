"""The image scan gate rejects malformed and unresolved findings."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from tools.w12_001_images import (
    ImageScanError,
    diagnostic_code,
    evaluate_approved_scan,
    evaluate_scan,
    finding_digest,
    main,
    scan_summary,
)

ROOT = Path(__file__).resolve().parents[2]


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
    source.write_bytes(b"{\r\n}\r\n")
    approved = datetime(2026, 10, 26, tzinfo=UTC)
    exception = {
        "schema_version": "w12-001.exact-image-scan-exception.v1",
        "approved_at_utc": approved.isoformat(),
        "expires_at_utc": (approved + timedelta(days=7)).isoformat(),
        "pinned_source_manifest_sha256": hashlib.sha256(
            source.read_bytes().replace(b"\r\n", b"\n")
        ).hexdigest(),
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
    source.write_bytes(b"{\r\n}\r\n")
    trivy_document["Results"][0]["Vulnerabilities"][0]["InstalledVersion"] = "1.0.1"
    _write(trivy, trivy_document)
    with pytest.raises(ImageScanError, match="findings differ") as changed:
        evaluate_approved_scan(trivy, grype, now=approved + timedelta(days=1), **kwargs)
    assert diagnostic_code(changed.value) == "FINDING_SET_MISMATCH"
    trivy_document["Results"][0]["Secrets"] = [{"RuleID": "synthetic"}]
    _write(trivy, trivy_document)
    with pytest.raises(ImageScanError, match="Secret findings"):
        evaluate_approved_scan(trivy, grype, now=approved + timedelta(days=1), **kwargs)


def test_scan_summary_contains_only_counts_and_finding_set_hashes(tmp_path: Path) -> None:
    trivy = _write(
        tmp_path / "trivy.json",
        {
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
        },
    )
    grype = _write(
        tmp_path / "grype.json",
        {
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
        },
    )
    summary = scan_summary(trivy, grype)
    assert summary[:3] == (1, 0, 1)
    assert all(len(value) == 64 for value in summary[3:])
    assert all("CVE-SYNTHETIC-1" not in value for value in summary[3:])


def test_cli_reports_only_sanitized_finding_set_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    trivy_document = {
        "Results": [
            {
                "Type": "debian",
                "Secrets": [],
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-SYNTHETIC-PRIVATE",
                        "PkgName": "private-package-name",
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
                    "id": "CVE-SYNTHETIC-PRIVATE",
                    "namespace": "private-namespace",
                    "severity": "High",
                    "fix": {"state": "fixed", "versions": ["1.1"]},
                },
                "artifact": {
                    "name": "private-package-name",
                    "version": "1.0",
                    "type": "deb",
                },
            }
        ]
    }
    trivy = _write(tmp_path / "toolchain-trivy.json", trivy_document)
    grype = _write(tmp_path / "toolchain-grype.json", grype_document)
    _write(tmp_path / "codebuild-trivy.json", trivy_document)
    _write(tmp_path / "codebuild-grype.json", grype_document)
    source = tmp_path / "source.json"
    source.write_bytes(b"{\r\n}\r\n")
    now = datetime.now(UTC)
    exception = {
        "schema_version": "w12-001.exact-image-scan-exception.v1",
        "approved_at_utc": (now - timedelta(hours=1)).isoformat(),
        "expires_at_utc": (now + timedelta(hours=1)).isoformat(),
        "pinned_source_manifest_sha256": hashlib.sha256(
            source.read_bytes().replace(b"\r\n", b"\n")
        ).hexdigest(),
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
    trivy_document["Results"][0]["Vulnerabilities"][0]["InstalledVersion"] = "1.0.1"
    _write(trivy, trivy_document)
    monkeypatch.setattr(
        "sys.argv",
        [
            "w12_001_images.py",
            str(tmp_path),
            "--exception",
            str(exception_path),
            "--source-manifest",
            str(source),
        ],
    )
    assert main() == 1
    output = capsys.readouterr().out
    assert "toolchain: observed Trivy high/critical=1, secrets=0, finding_sha256=" in output
    assert "toolchain: observed Grype high/critical=1, finding_sha256=" in output
    assert "codebuild: observed Trivy high/critical=1, secrets=0, finding_sha256=" in output
    assert "codebuild: observed Grype high/critical=1, finding_sha256=" in output
    assert "scan gate blocked code=FINDING_SET_MISMATCH" in output
    assert "CVE-SYNTHETIC-PRIVATE" not in output
    assert "private-package-name" not in output


def test_public_ecr_reader_cannot_publish_or_manage_aws_resources() -> None:
    source = (ROOT / "infra/bootstrap/modules/platform-iam/w12_prerequisite_images.tf").read_text(
        encoding="utf-8"
    )
    reader = source.split('data "aws_iam_policy_document" "w12_public_ecr_reader"', 1)[1]
    reader = reader.split('resource "aws_iam_role_policy" "w12_public_ecr_reader"', 1)[0]
    assert "ecr-public:GetAuthorizationToken" in reader
    assert "sts:GetServiceBearerToken" in reader
    assert "sts:AWSServiceName" not in reader
    assert "ecr-public.amazonaws.com" not in reader
    assert reader.count('resources = ["*"]') == 2
    for prohibited in (
        "ecr:PutImage",
        "ecr-public:PutImage",
        "ecr:CreateRepository",
        "ecr-public:CreateRepository",
        "iam:",
        "ec2:",
        "kms:",
    ):
        assert prohibited not in reader


def test_prerequisite_roles_use_only_the_immutable_repository_subject() -> None:
    source = (ROOT / "infra/bootstrap/modules/platform-iam/w12_prerequisite_images.tf").read_text(
        encoding="utf-8"
    )
    assert "${local.github_repository_subject}:environment:${var.github_environment}" in source
    assert "repo:${var.github_organization}/${var.github_repository}" not in source


def test_private_publisher_credentials_remain_after_the_scan_gate() -> None:
    workflow = (ROOT / ".github/workflows/w12-prerequisite-images.yml").read_text(encoding="utf-8")
    scan = workflow.index("Scan both final images against the exact approved exception")
    private_assumption = workflow.index("Assume only the dedicated prerequisite publisher role")
    push = workflow.index("Push only scanned images and read back immutable registry digests")
    assert scan < private_assumption < push


def test_public_ecr_login_and_build_share_the_bounded_docker_config() -> None:
    workflow = (ROOT / ".github/workflows/w12-prerequisite-images.yml").read_text(encoding="utf-8")
    authentication = workflow.split(
        "- name: Authenticate only to Public ECR for the pinned base pull", 1
    )[1].split("- name: Build both pinned Linux AMD64 images", 1)[0]
    assert 'public_config="$RUNNER_TEMP/w12-public-ecr-docker-config"' in authentication
    assert 'mkdir -m 700 "$public_config"' in authentication
    assert 'export DOCKER_CONFIG="$public_config"' in authentication
    assert 'echo "DOCKER_CONFIG=$public_config" >> "$GITHUB_ENV"' in authentication
    assert authentication.index('export DOCKER_CONFIG="$public_config"') < authentication.index(
        "docker login --username AWS --password-stdin public.ecr.aws"
    )
    cleanup = workflow.split("- name: Remove temporary Public ECR authentication", 1)[1]
    cleanup = cleanup.split("- name: Test image compatibility", 1)[0]
    assert "docker logout public.ecr.aws" in cleanup
    assert 'rm -rf -- "$DOCKER_CONFIG"' in cleanup
