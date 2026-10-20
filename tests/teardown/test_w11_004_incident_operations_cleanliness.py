from __future__ import annotations

import json
from pathlib import Path

from tools import incidentctl

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "configs/incidents/incident-operations.yaml"


def test_cleanup_removes_only_known_runtime_residue_and_retains_evidence(
    tmp_path: Path, capsys: object
) -> None:
    evidence_root = tmp_path / "owner-test"
    assert (
        incidentctl.main(
            [
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
        )
        == 0
    )
    capsys.readouterr()  # type: ignore[attr-defined]
    evidence = evidence_root / "evidence.json"
    residue = evidence_root / "runtime-state.json"
    residue.write_text("runtime", encoding="utf-8")
    unrelated = evidence_root / "owner-note.txt"
    unrelated.write_text("keep", encoding="utf-8")

    result = incidentctl.main(
        [
            "cleanup",
            "--config",
            str(CONFIG),
            "--evidence-root",
            str(evidence_root.resolve()),
            "--retain-evidence",
        ]
    )
    assert result == 0
    output = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert output["removed_runtime_residue"] == ["runtime-state.json"]
    assert evidence.exists()
    assert unrelated.exists()
    assert not residue.exists()


def test_repository_contains_no_w11_004_runtime_residue() -> None:
    prohibited = {
        ".pytest_cache",
        ".ruff_cache",
        ".mypy_cache",
        "runtime-state.json",
        "command.lock",
        "child.pid",
    }
    found = [
        path for path in ROOT.rglob("*") if path.name in prohibited and ".git" not in path.parts
    ]
    assert found == []
