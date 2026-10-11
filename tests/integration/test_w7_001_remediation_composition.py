"""Offline composition checks for the complete W7-001 contract."""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml
from tools.w5_002_ci import validate_config
from tools.w6_002_observability import PASS_STATUS, validate

ROOT = Path(__file__).resolve().parents[2]


def test_remediation_configs_compose_without_live_authority() -> None:
    ci = json.loads((ROOT / "configs/ci/w5-002.json").read_text(encoding="utf-8"))
    validate_config(ci)
    assert validate(ROOT) == PASS_STATUS
    readiness = yaml.safe_load(
        (ROOT / "configs/readiness/production-readiness.yaml").read_text(encoding="utf-8")
    )
    assert readiness["classification"] == "NOT ESTABLISHED"
    assert all(section["status"] == "NOT RUN" for section in readiness["sections"].values())


def test_future_backend_and_historical_dynamodb_are_distinct() -> None:
    future = (ROOT / "infra/environments/sandbox/backend.hcl.example").read_text(encoding="utf-8")
    historical = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (ROOT / "infra").rglob("*.tf")
        if "bootstrap" in path.parts
    )
    assert re.search(r"(?m)^use_lockfile\s*=\s*true\s*$", future)
    assert "dynamodb_table" not in future
    assert "dynamodb" in historical.casefold()
