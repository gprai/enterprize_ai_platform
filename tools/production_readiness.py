"""Offline, fail-closed production-readiness review validation."""

from __future__ import annotations

from pathlib import Path
from typing import Final

import yaml

SCHEMA_VERSION: Final = "w7-001.production-readiness.v1"
REVIEWER: Final = "Gyan Prakash Rai"
SECTIONS: Final = (
    "identity",
    "security",
    "privacy",
    "threat_model",
    "capacity",
    "slo_evidence",
    "resilience",
    "disaster_recovery",
    "operations_and_support",
    "cost",
    "compliance_controls",
    "change_and_rollback",
    "residual_risks",
)


class ProductionReadinessError(ValueError):
    pass


def load_review(path: Path) -> dict[str, object]:
    raw = path.read_bytes()
    if raw.startswith(b"\xef\xbb\xbf"):
        raise ProductionReadinessError("UTF-8 BOM is prohibited")
    try:
        value = yaml.safe_load(raw.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ProductionReadinessError("readiness review must be strict UTF-8 YAML") from exc
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ProductionReadinessError("readiness review must be one mapping")
    return value


def validate_review(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ProductionReadinessError("readiness review must be one mapping")
    expected = {
        "schema_version",
        "classification",
        "reviewer",
        "decision",
        "decided_at",
        "sections",
    }
    if set(value) != expected:
        raise ProductionReadinessError("readiness review is not a closed schema")
    if value["schema_version"] != SCHEMA_VERSION:
        raise ProductionReadinessError("readiness schema differs")
    if value["classification"] != "NOT ESTABLISHED":
        raise ProductionReadinessError("production readiness must remain NOT ESTABLISHED")
    if (
        value["reviewer"] != REVIEWER
        or value["decision"] is not None
        or value["decided_at"] is not None
    ):
        raise ProductionReadinessError("reviewer does not imply a decision or timestamp")
    sections = value["sections"]
    if not isinstance(sections, dict) or tuple(sections) != SECTIONS:
        raise ProductionReadinessError("production-readiness sections differ")
    for name, section in sections.items():
        if section != {"status": "NOT RUN", "evidence": None, "limitations": []}:
            raise ProductionReadinessError(f"section {name} must remain unexecuted")
    return value
