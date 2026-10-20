from __future__ import annotations

from pathlib import Path

from tools import incidentctl

from enterprise_ai_platform.incident_operations import redact_output
from tests.fakes.w11_004_incident_operations import evidence

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "configs/incidents/incident-operations.yaml"


def test_repository_evidence_destination_is_rejected(capsys: object) -> None:
    result = incidentctl.main(
        [
            "rehearse",
            "--config",
            str(CONFIG),
            "--scenario",
            "CAPACITY",
            "--runner-profile",
            "powershell-7",
            "--evidence-root",
            str((ROOT / "reports/w11-004").resolve()),
            "--approval-reference",
            "OWNER-TEST-001-W11-004",
        ]
    )
    assert result == 1
    assert "outside the repository" in capsys.readouterr().err  # type: ignore[attr-defined]


def test_redaction_is_case_insensitive_and_preserves_no_secret_value() -> None:
    value = redact_output("PASSWORD=hunter2 Api-Key=value Authorization: bearer")
    assert "hunter2" not in value
    assert "value" not in value
    assert "bearer" not in value


def test_powershell_sources_do_not_use_dynamic_evaluation() -> None:
    for path in (ROOT / "tools/powershell").glob("*incident-command*"):
        text = path.read_text(encoding="utf-8")
        assert "Invoke-Expression" not in text
        assert "cmd /c" not in text.casefold()


def test_local_evidence_cannot_claim_tenant_data_or_live_classification() -> None:
    value = evidence()
    assert value.tenant_boundary == "NO_TENANT_DATA_LOCAL_FAKE"
    assert value.privacy_boundary == "NO_USER_CONTENT"
    assert value.classification == "source-contract-not-live-evidence"
