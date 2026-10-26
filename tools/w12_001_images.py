"""Fail-closed, metadata-only gate for the two W12 prerequisite image scans."""

from __future__ import annotations

import argparse
import json
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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("report_dir", type=Path)
    args = parser.parse_args()
    blocked = False
    for name in ("toolchain", "codebuild"):
        try:
            counts = evaluate_scan(
                args.report_dir / f"{name}-trivy.json",
                args.report_dir / f"{name}-grype.json",
            )
        except (ImageScanError, OSError, UnicodeError, json.JSONDecodeError) as exc:
            print(f"{name}: scan report invalid ({type(exc).__name__})")
            return 1
        print(f"{name}: Trivy high/critical={counts[0]}, secrets={counts[1]}")
        print(f"{name}: Grype high/critical={counts[2]}")
        blocked |= any(counts)
    if blocked:
        print("Image scan gate failed; publication is blocked")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
