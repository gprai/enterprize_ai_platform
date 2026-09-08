"""Feature tests for one reconciled W5-002 Python 3.13 OCI candidate."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from tools import w5_002_ci

DIGEST = "sha256:" + "d" * 64
OTHER_DIGEST = "sha256:" + "e" * 64
DATABASE_DIGEST = "sha256:" + "f" * 64


def _qualified(role: str) -> dict[str, object]:
    if role == "builder":
        return {
            "architecture": "amd64",
            "glibc": "2.44-r5",
            "index_digest": w5_002_ci.BUILDER_INDEX_DIGEST,
            "manifest_digest": w5_002_ci.BUILDER_MANIFEST_DIGEST,
            "os": "linux",
            "os_family": "wolfi",
            "python_package": "3.13.15-r7",
            "reference": w5_002_ci.BUILDER_IMAGE,
            "tag": w5_002_ci.BUILDER_TAG,
        }
    return {
        "architecture": "amd64",
        "glibc": "2.44-r5",
        "index_digest": w5_002_ci.RUNTIME_INDEX_DIGEST,
        "manifest_digest": w5_002_ci.RUNTIME_MANIFEST_DIGEST,
        "os": "linux",
        "os_family": "wolfi",
        "python_package": "3.13.15-r7",
        "reference": w5_002_ci.RUNTIME_IMAGE,
        "tag": w5_002_ci.RUNTIME_TAG,
    }


def _image() -> dict[str, object]:
    return {
        "application_image": {
            "configuration_digest": OTHER_DIGEST,
            "manifest_digest": DIGEST,
            "oci_archive_sha256": OTHER_DIGEST,
        },
        "builder_image": _qualified("builder"),
        "inputs": {
            "dockerfile_sha256": OTHER_DIGEST,
            "requirements_checkov_lock_sha256": OTHER_DIGEST,
            "requirements_ci_lock_sha256": OTHER_DIGEST,
            "requirements_runtime_lock_sha256": OTHER_DIGEST,
        },
        "platform": "linux/amd64",
        "python_version": "3.13.15",
        "runtime_image": _qualified("runtime"),
        "schema_version": w5_002_ci.IMAGE_SCHEMA,
        "source_identity": {
            "baseline_head": w5_002_ci.BASELINE_HEAD,
            "source_commit": None,
            "source_composition_sha256": OTHER_DIGEST,
        },
    }


def _write_inputs(directory: Path, *, critical: bool = False) -> None:
    directory.mkdir()
    identity = directory / "image-identity.json"
    w5_002_ci.write_json(identity, _image())
    severity = "CRITICAL" if critical else "HIGH"
    scanner = {"Results": [{"Vulnerabilities": [{"Severity": severity}]}]}
    for name, scope in (
        ("trivy-filesystem.json", "filesystem"),
        ("trivy-image.json", "oci"),
    ):
        raw = directory.parent / f"raw-{name}"
        raw.write_text(json.dumps(scanner) + "\n", encoding="utf-8")
        w5_002_ci.write_scan_summary(
            raw,
            directory / name,
            identity,
            "trivy",
            scope,
            DATABASE_DIGEST,
        )
        raw.unlink()
    grype = {"matches": [{"vulnerability": {"severity": severity.title()}}]}
    raw_grype = directory.parent / "raw-grype.json"
    raw_grype.write_text(json.dumps(grype) + "\n", encoding="utf-8")
    w5_002_ci.write_scan_summary(
        raw_grype,
        directory / "grype-image.json",
        identity,
        "grype",
        "oci",
        DATABASE_DIGEST,
    )
    raw_grype.unlink()
    (directory / "sbom.spdx.json").write_text(
        '{"packages":[{"name":"application"}],"spdxVersion":"SPDX-2.3"}\n',
        encoding="utf-8",
    )
    (directory / "sbom.cyclonedx.json").write_text(
        '{"bomFormat":"CycloneDX","components":[{"name":"application"}]}\n',
        encoding="utf-8",
    )
    w5_002_ci.write_cleanup_retention(directory / "cleanup-retention.json")


def test_one_v2_candidate_reconciles_across_scans_sboms_and_eligibility(
    tmp_path: Path,
) -> None:
    reports = tmp_path / "reports"
    _write_inputs(reports)
    w5_002_ci.write_supply_chain_records(reports)
    w5_002_ci.validate_report_set(reports, "supply-chain")
    eligibility = json.loads((reports / "eligibility.json").read_text(encoding="utf-8"))

    assert eligibility["application_manifest_digest"] == DIGEST
    assert eligibility["critical_vulnerabilities"] == {"grype": 0, "trivy": 0}
    assert eligibility["eligible_for_owner_approval"] is True
    assert eligibility["deployable"] is False
    assert eligibility["formal_w5_002_status"] == "FAIL"
    assert eligibility["vulnerability_free_claim"] is False
    assert eligibility["provenance_report_sha256"].startswith("sha256:")
    assert eligibility["rollback_identity_report_sha256"].startswith("sha256:")
    assert eligibility["cleanup_retention_report_sha256"].startswith("sha256:")
    assert (reports / "rollback-identity.json").is_file()
    assert (reports / "provenance.json").is_file()


def test_every_critical_finding_rejects_without_a_waiver(tmp_path: Path) -> None:
    reports = tmp_path / "reports"
    _write_inputs(reports, critical=True)

    with pytest.raises(w5_002_ci.ContractError, match="CRITICAL"):
        w5_002_ci.write_supply_chain_records(reports)
    eligibility = json.loads((reports / "eligibility.json").read_text(encoding="utf-8"))

    assert eligibility["critical_vulnerabilities"] == {"grype": 1, "trivy": 2}
    assert eligibility["eligible_for_owner_approval"] is False
    assert eligibility["formal_w5_002_status"] == "FAIL"


def test_stale_or_mismatched_v2_identity_is_rejected() -> None:
    identity = _image()
    identity["python_version"] = "3.11.16"
    with pytest.raises(w5_002_ci.ContractError, match="Python"):
        w5_002_ci.validate_image_identity(identity)

    identity = _image()
    runtime = dict(identity["runtime_image"])  # type: ignore[arg-type]
    runtime["manifest_digest"] = OTHER_DIGEST
    identity["runtime_image"] = runtime
    with pytest.raises(w5_002_ci.ContractError, match="runtime image"):
        w5_002_ci.validate_image_identity(identity)


def test_scanner_database_or_application_identity_disagreement_is_rejected(
    tmp_path: Path,
) -> None:
    reports = tmp_path / "reports"
    _write_inputs(reports)
    trivy = json.loads((reports / "trivy-image.json").read_text(encoding="utf-8"))
    trivy["scanner_database_identity"] = "sha256:" + "1" * 64
    w5_002_ci.write_json(reports / "trivy-image.json", trivy)

    with pytest.raises(w5_002_ci.ContractError, match="one database identity"):
        w5_002_ci.write_supply_chain_records(reports)
