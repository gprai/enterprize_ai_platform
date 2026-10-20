from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from enterprise_ai_platform.incident_operations import (
    IncidentContractError,
    IncidentPolicy,
    PowerShellRequest,
    canonical_json_bytes,
    canonical_sha256,
    load_incident_policy,
)
from tests.fakes.w11_004_incident_operations import ROOT, policy

CONFIG = ROOT / "configs/incidents/incident-operations.yaml"


def test_policy_has_canonical_stable_identity() -> None:
    value = policy()
    assert canonical_json_bytes(value).endswith(b"\n")
    assert len(canonical_sha256(value)) == 64
    assert value.schema_version == "w11-004.incident-operations.v1"


def test_unknown_or_missing_field_fails_closed() -> None:
    raw = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    raw["unexpected"] = True
    with pytest.raises(ValidationError):
        IncidentPolicy.model_validate(raw, strict=False)
    del raw["unexpected"]
    del raw["execution_bounds"]
    with pytest.raises(ValidationError):
        IncidentPolicy.model_validate(raw, strict=False)


def test_duplicate_yaml_key_is_rejected(tmp_path: Path) -> None:
    duplicate = tmp_path / "incident.yaml"
    duplicate.write_text(
        CONFIG.read_text(encoding="utf-8") + "\nschema_version: duplicate\n",
        encoding="utf-8",
    )
    with pytest.raises(IncidentContractError, match="duplicate YAML key"):
        load_incident_policy(duplicate, repository_root=tmp_path)


def test_yaml_alias_is_rejected(tmp_path: Path) -> None:
    aliased = tmp_path / "incident.yaml"
    aliased.write_text("schema_version: &version value\ncopy: *version\n", encoding="utf-8")
    with pytest.raises(IncidentContractError, match="aliases and anchors"):
        load_incident_policy(aliased, repository_root=tmp_path)


def test_reordered_scenarios_fail_closed() -> None:
    raw = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    raw["scenarios"].reverse()
    with pytest.raises(ValidationError, match="scenarios must be complete and ordered"):
        IncidentPolicy.model_validate(raw, strict=False)


def test_powershell_request_rejects_command_strings_and_unknown_fields(tmp_path: Path) -> None:
    request = {
        "schema_version": "w11-004.powershell-request.v1",
        "command": [str((tmp_path / "pwsh.exe").resolve()), "-NoProfile"],
        "working_directory": str(tmp_path.resolve()),
        "timeout_seconds": 30,
        "progress_interval_seconds": 5,
        "maximum_output_bytes": 8388608,
        "expected_absence": False,
        "expected_identity": "a" * 64,
        "native_verification": {
            "observed_identity": "a" * 64,
            "identity_match": True,
            "integrity_ok": True,
            "health_ok": True,
            "native_absent": False,
            "residue_count": 0,
        },
    }
    assert PowerShellRequest.model_validate(request, strict=False).command[1] == "-NoProfile"
    request["command"] = "pwsh.exe -NoProfile"
    with pytest.raises(ValidationError):
        PowerShellRequest.model_validate(request, strict=False)
    request["command"] = [str((tmp_path / "pwsh.exe").resolve())]
    request["unknown"] = True
    with pytest.raises(ValidationError):
        PowerShellRequest.model_validate(request, strict=False)
