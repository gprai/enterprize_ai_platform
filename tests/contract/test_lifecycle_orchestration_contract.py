from pathlib import Path

import pytest
from provision.bootstrap_teardown import main as bootstrap_main
from provision.lifecycle import build_parser


def test_lifecycle_has_three_deployment_commands_and_separate_cleanup() -> None:
    help_text = build_parser().format_help()
    for command in ("prepare", "provision", "release", "rollback", "teardown", "status"):
        assert command in help_text


def test_bootstrap_teardown_is_a_separate_entry_point(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        bootstrap_main(["--help"])
    assert exc.value.code == 0
    help_text = capsys.readouterr().out
    assert "bootstrap teardown" in help_text.lower()
    assert "--run-id" in help_text


def test_runbook_uses_repository_module_entry_points() -> None:
    runbook = Path("docs/runbooks/lifecycle-orchestration.md").read_text(encoding="utf-8")
    assert "python -B -m provision.lifecycle prepare" in runbook
    assert "python -B -m provision.lifecycle provision" in runbook
    assert "python -B -m provision.lifecycle release" in runbook
    assert "python -B -m provision.bootstrap_teardown" in runbook
    assert "python -B provision/lifecycle.py" not in runbook
