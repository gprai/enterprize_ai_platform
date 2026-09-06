"""Feature tests for one reconciled W5-002 OCI candidate identity."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from tools import w5_002_ci

SOURCE = "c" * 40
DIGEST = "sha256:" + "d" * 64


def _write_inputs(directory: Path, *, critical: bool = False) -> None:
    directory.mkdir()
    w5_002_ci.write_image_identity(directory / "image-identity.json", SOURCE, DIGEST)
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
            SOURCE,
            DIGEST,
            "trivy",
            scope,
        )
        raw.unlink()
    grype = {"matches": [{"vulnerability": {"severity": severity.title()}}]}
    raw_grype = directory.parent / "raw-grype.json"
    raw_grype.write_text(json.dumps(grype) + "\n", encoding="utf-8")
    w5_002_ci.write_scan_summary(
        raw_grype,
        directory / "grype-image.json",
        SOURCE,
        DIGEST,
        "grype",
        "oci",
    )
    raw_grype.unlink()
    for name in ("sbom.spdx.json", "sbom.cyclonedx.json"):
        (directory / name).write_text('{"packages":[]}\n', encoding="utf-8")


def test_one_candidate_identity_reconciles_across_scans_sboms_and_eligibility(
    tmp_path: Path,
) -> None:
    reports = tmp_path / "reports"
    _write_inputs(reports)
    w5_002_ci.write_supply_chain_records(reports, SOURCE, DIGEST)
    w5_002_ci.validate_report_set(reports, "supply-chain")
    eligibility = json.loads((reports / "eligibility.json").read_text(encoding="utf-8"))

    assert eligibility["image_digest"] == DIGEST
    assert eligibility["critical_vulnerabilities"] == 0
    assert eligibility["eligible_for_owner_approval"] is True
    assert eligibility["deployable"] is False
    assert eligibility["w5_001_status"] == "FAIL"


def test_every_critical_finding_rejects_without_a_phase_a_waiver(tmp_path: Path) -> None:
    reports = tmp_path / "reports"
    _write_inputs(reports, critical=True)

    with pytest.raises(w5_002_ci.ContractError, match="CRITICAL"):
        w5_002_ci.write_supply_chain_records(reports, SOURCE, DIGEST)
    eligibility = json.loads((reports / "eligibility.json").read_text(encoding="utf-8"))
    assert eligibility["critical_vulnerabilities"] == 3
    assert eligibility["eligible_for_owner_approval"] is False


def test_stale_or_mismatched_identity_is_rejected(tmp_path: Path) -> None:
    identity = {
        "base_image": w5_002_ci.BASE_IMAGE,
        "image_digest": DIGEST,
        "platform": "linux/amd64",
        "schema_version": w5_002_ci.IMAGE_SCHEMA,
        "source_commit": SOURCE,
    }
    with pytest.raises(w5_002_ci.ContractError):
        w5_002_ci.validate_image_identity({**identity, "source_commit": "short"})
    with pytest.raises(w5_002_ci.ContractError):
        w5_002_ci.validate_image_identity({**identity, "image_digest": "sha256:latest"})
