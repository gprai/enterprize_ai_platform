"""Fail-closed, metadata-only gate for the two W12 prerequisite image scans."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any


class ImageScanError(ValueError):
    """An image scan is missing, malformed, or has unresolved findings."""


def _document(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ImageScanError("Scanner report root must be an object")
    return value


def evaluate_scan(trivy_path: Path, grype_path: Path) -> tuple[int, int, int]:
    """Return high/critical Trivy, secret, and high/critical Grype counts."""
    trivy = _document(trivy_path)
    grype = _document(grype_path)
    if not isinstance(trivy.get("Results"), list) or not isinstance(grype.get("matches"), list):
        raise ImageScanError("Required scanner results are absent")
    vulnerabilities = 0
    secrets = 0
    for result in trivy["Results"]:
        if not isinstance(result, dict):
            raise ImageScanError("Malformed Trivy result")
        for finding in result.get("Vulnerabilities") or []:
            if not isinstance(finding, dict) or not finding.get("Severity"):
                raise ImageScanError("Malformed Trivy vulnerability")
            if finding["Severity"].upper() in {"HIGH", "CRITICAL"}:
                vulnerabilities += 1
        secrets += len(result.get("Secrets") or [])
    grype_high = 0
    for match in grype["matches"]:
        if not isinstance(match, dict) or not isinstance(match.get("vulnerability"), dict):
            raise ImageScanError("Malformed Grype match")
        severity = match["vulnerability"].get("severity")
        if not isinstance(severity, str):
            raise ImageScanError("Missing Grype severity")
        if severity.lower() in {"high", "critical"}:
            grype_high += 1
    return vulnerabilities, secrets, grype_high


def _required_text(value: object, label: str, *, empty_allowed: bool = False) -> str:
    if not isinstance(value, str) or (not empty_allowed and not value):
        raise ImageScanError(f"Missing or invalid {label}")
    return value


def finding_digest(path: Path, scanner: str) -> tuple[int, str]:
    """Hash the complete High/Critical finding multiset without retaining raw findings."""
    document = _document(path)
    rows: list[tuple[str, ...]] = []
    if scanner == "trivy":
        results = document.get("Results")
        if not isinstance(results, list):
            raise ImageScanError("Trivy results are absent")
        for result in results:
            if not isinstance(result, dict):
                raise ImageScanError("Malformed Trivy result")
            result_type = _required_text(result.get("Type"), "Trivy result type")
            vulnerabilities = result.get("Vulnerabilities") or []
            if not isinstance(vulnerabilities, list):
                raise ImageScanError("Malformed Trivy vulnerability list")
            for finding in vulnerabilities:
                if not isinstance(finding, dict):
                    raise ImageScanError("Malformed Trivy vulnerability")
                severity = _required_text(finding.get("Severity"), "Trivy severity").upper()
                if severity not in {"HIGH", "CRITICAL"}:
                    continue
                rows.append(
                    (
                        result_type,
                        _required_text(finding.get("VulnerabilityID"), "Trivy vulnerability ID"),
                        _required_text(finding.get("PkgName"), "Trivy package name"),
                        _required_text(finding.get("InstalledVersion"), "Trivy package version"),
                        severity,
                        _required_text(
                            finding.get("FixedVersion", ""),
                            "Trivy fixed version",
                            empty_allowed=True,
                        ),
                    )
                )
    elif scanner == "grype":
        matches = document.get("matches")
        if not isinstance(matches, list):
            raise ImageScanError("Grype matches are absent")
        for match in matches:
            if not isinstance(match, dict):
                raise ImageScanError("Malformed Grype match")
            vulnerability = match.get("vulnerability")
            artifact = match.get("artifact")
            if not isinstance(vulnerability, dict) or not isinstance(artifact, dict):
                raise ImageScanError("Malformed Grype finding")
            severity = _required_text(vulnerability.get("severity"), "Grype severity").upper()
            if severity not in {"HIGH", "CRITICAL"}:
                continue
            fix = vulnerability.get("fix") or {}
            if not isinstance(fix, dict):
                raise ImageScanError("Malformed Grype fix metadata")
            versions = fix.get("versions") or []
            if not isinstance(versions, list) or any(not isinstance(v, str) for v in versions):
                raise ImageScanError("Malformed Grype fixed versions")
            rows.append(
                (
                    _required_text(vulnerability.get("id"), "Grype vulnerability ID"),
                    _required_text(vulnerability.get("namespace"), "Grype namespace"),
                    _required_text(artifact.get("name"), "Grype package name"),
                    _required_text(artifact.get("version"), "Grype package version"),
                    _required_text(artifact.get("type"), "Grype package type"),
                    severity,
                    _required_text(fix.get("state", ""), "Grype fix state", empty_allowed=True),
                    ",".join(sorted(versions)),
                )
            )
    else:
        raise ImageScanError("Unsupported scanner")
    payload = json.dumps(sorted(rows), separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return len(rows), hashlib.sha256(payload).hexdigest()


def evaluate_approved_scan(
    trivy_path: Path,
    grype_path: Path,
    *,
    image_name: str,
    exception_path: Path,
    source_manifest_path: Path,
    now: datetime | None = None,
) -> tuple[int, int, int]:
    """Accept only the owner's time-bounded, exact finding sets for one reviewed image."""
    counts = evaluate_scan(trivy_path, grype_path)
    if counts[1]:
        raise ImageScanError("Secret findings cannot be excepted")
    if counts[0] == 0 and counts[2] == 0:
        return counts
    exception = _document(exception_path)
    if exception.get("schema_version") != "w12-001.exact-image-scan-exception.v1":
        raise ImageScanError("Unrecognized scan exception")
    approved_at = datetime.fromisoformat(
        _required_text(exception.get("approved_at_utc"), "approval time").replace("Z", "+00:00")
    )
    expires_at = datetime.fromisoformat(
        _required_text(exception.get("expires_at_utc"), "expiry time").replace("Z", "+00:00")
    )
    current = now or datetime.now(UTC)
    if any(
        value.tzinfo is None or value.utcoffset() != timedelta(0)
        for value in (approved_at, expires_at, current)
    ):
        raise ImageScanError("Scan exception times must be UTC")
    if expires_at <= approved_at or expires_at - approved_at > timedelta(days=7):
        raise ImageScanError("Scan exception window exceeds seven days")
    if current < approved_at or current >= expires_at:
        raise ImageScanError("Scan exception is not currently valid")
    expected_source = _required_text(
        exception.get("pinned_source_manifest_sha256"), "pinned source manifest hash"
    )
    actual_source = hashlib.sha256(source_manifest_path.read_bytes()).hexdigest()
    if actual_source != expected_source:
        raise ImageScanError("Pinned recipe identity changed")
    images = exception.get("images")
    if not isinstance(images, dict) or set(images) != {"toolchain", "codebuild"}:
        raise ImageScanError("Scan exception image scope changed")
    if image_name not in images or not isinstance(images[image_name], dict):
        raise ImageScanError("Unapproved image")
    for scanner, path, observed_count in (
        ("trivy", trivy_path, counts[0]),
        ("grype", grype_path, counts[2]),
    ):
        approved = images[image_name].get(scanner)
        if not isinstance(approved, dict):
            raise ImageScanError("Scanner exception is absent")
        finding_count, digest = finding_digest(path, scanner)
        if finding_count != observed_count:
            raise ImageScanError("Scanner count disagrees with report")
        if (
            approved.get("high_critical_count") != finding_count
            or approved.get("finding_sha256") != digest
        ):
            raise ImageScanError("Scanner findings differ from the approved set")
    return counts


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("report_dir", type=Path)
    parser.add_argument("--exception", type=Path)
    parser.add_argument("--source-manifest", type=Path)
    args = parser.parse_args()
    blocked = False
    for name in ("toolchain", "codebuild"):
        try:
            trivy_path = args.report_dir / f"{name}-trivy.json"
            grype_path = args.report_dir / f"{name}-grype.json"
            if args.exception is None:
                counts = evaluate_scan(trivy_path, grype_path)
                blocked |= any(counts)
            else:
                if args.source_manifest is None:
                    raise ImageScanError("Pinned source manifest path is required")
                counts = evaluate_approved_scan(
                    trivy_path,
                    grype_path,
                    image_name=name,
                    exception_path=args.exception,
                    source_manifest_path=args.source_manifest,
                )
        except (ImageScanError, OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
            print(f"{name}: scan report invalid ({type(exc).__name__})")
            return 1
        print(f"{name}: Trivy high/critical={counts[0]}, secrets={counts[1]}")
        print(f"{name}: Grype high/critical={counts[2]}")
    if blocked:
        print("Image scan gate failed; publication is blocked")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
