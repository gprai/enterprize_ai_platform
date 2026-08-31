"""W4-002 temporary-store and repository-residue cleanliness contract."""

from __future__ import annotations

from pathlib import Path

from enterprise_ai_platform.agent.persistence import SQLiteAgentStateStore

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
AGENT_SOURCE = REPOSITORY_ROOT / "src" / "enterprise_ai_platform" / "agent"
RUNTIME_STORE = Path(r"E:\AI\.runtime\enterprise_ai_platform\w4-002\agent-control-v1.sqlite3")


def test_approved_long_lived_store_is_not_created_by_ordinary_tests() -> None:
    assert not RUNTIME_STORE.exists()
    for suffix in ("-wal", "-shm", "-journal", ".lock"):
        assert not Path(f"{RUNTIME_STORE}{suffix}").exists()


def test_temporary_store_artifacts_are_removable_without_repository_residue(
    tmp_path: Path,
) -> None:
    database = tmp_path / "agent.sqlite3"
    SQLiteAgentStateStore(database)
    for candidate in tuple(tmp_path.iterdir()):
        candidate.unlink()
    assert tuple(tmp_path.iterdir()) == ()
    assert not tuple(REPOSITORY_ROOT.rglob("*.sqlite3"))
    assert not tuple(REPOSITORY_ROOT.rglob("*.sqlite3-wal"))
    assert not tuple(REPOSITORY_ROOT.rglob("*.sqlite3-shm"))
    assert not tuple(REPOSITORY_ROOT.rglob("*.sqlite3-journal"))
    assert not (AGENT_SOURCE / "__pycache__").exists()
    assert not (REPOSITORY_ROOT / ".pytest_cache").exists()
