from __future__ import annotations

import json
from pathlib import Path

from tools import incidentctl

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "configs/incidents/incident-operations.yaml"


def test_validate_cli_reports_blocked_source_contract(capsys: object) -> None:
    assert incidentctl.main(["validate", "--config", str(CONFIG)]) == 0
    output = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert output["status"] == "VALID"
    assert output["tracker_status"] == "Blocked"
    assert output["feature_ids"] == ["INC-001", "RUNNER-001"]


def test_rehearse_and_verify_clean_cli(tmp_path: Path, capsys: object) -> None:
    evidence_root = tmp_path / "owner-test"
    arguments = [
        "rehearse",
        "--config",
        str(CONFIG),
        "--scenario",
        "CAPACITY",
        "--runner-profile",
        "powershell-7",
        "--evidence-root",
        str(evidence_root.resolve()),
        "--approval-reference",
        "OWNER-TEST-001-W11-004",
    ]
    assert incidentctl.main(arguments) == 0
    capsys.readouterr()  # type: ignore[attr-defined]
    evidence_before = (evidence_root / "evidence.json").read_bytes()
    assert (
        incidentctl.main(
            [
                "resume",
                "--config",
                str(CONFIG),
                "--scenario",
                "CAPACITY",
                "--runner-profile",
                "powershell-7",
                "--evidence-root",
                str(evidence_root),
            ]
        )
        == 0
    )
    resume = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert resume["status"] == "REJOINED_COMPLETED"
    assert resume["reexecuted_commands"] == 0
    assert (evidence_root / "evidence.json").read_bytes() == evidence_before
    assert (
        incidentctl.main(
            ["verify-clean", "--config", str(CONFIG), "--evidence-root", str(evidence_root)]
        )
        == 0
    )
    output = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert output == {
        "evidence_count": 1,
        "evidence_retained": True,
        "residue": [],
        "status": "CLEAN",
    }
