"""Zero-residue checks for W5-001 Bedrock verification."""

import hashlib
import json
import re
from pathlib import Path
from typing import cast

ROOT = Path(__file__).resolve().parents[2]
VERIFICATION_ROOT = ROOT / "reports" / "verification"
RUN_ID = re.compile(r"W5-001-[0-9]{8}-[0-9]{2}")
REQUIRED_RUN_FILES = frozenset({"manifest.json", "events.jsonl", "result.json", "integrity.json"})
OPTIONAL_CLOSURE_FILES = frozenset({"owner-review.json", "final.json"})


def _mapping(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return cast(dict[str, object], value)


def _verify_integrity(run_directory: Path, integrity: dict[str, object]) -> None:
    files = integrity.get("files")
    assert isinstance(files, dict)
    assert set(files) == {"manifest.json", "events.jsonl", "result.json"}
    for name, raw_entry in files.items():
        assert isinstance(name, str) and isinstance(raw_entry, dict)
        entry = cast(dict[str, object], raw_entry)
        path = run_directory / name
        assert entry == {
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "size_bytes": path.stat().st_size,
        }


def test_retained_verification_evidence_has_only_approved_integrity_bound_runs() -> None:
    if not VERIFICATION_ROOT.exists():
        return

    assert VERIFICATION_ROOT.is_dir() and not VERIFICATION_ROOT.is_symlink()
    for run_directory in VERIFICATION_ROOT.iterdir():
        assert run_directory.is_dir() and not run_directory.is_symlink()
        assert RUN_ID.fullmatch(run_directory.name) is not None
        entries = tuple(run_directory.iterdir())
        assert all(path.is_file() and not path.is_symlink() for path in entries)
        names = {path.name for path in entries}
        assert REQUIRED_RUN_FILES <= names
        assert names <= REQUIRED_RUN_FILES | OPTIONAL_CLOSURE_FILES

        manifest = _mapping(run_directory / "manifest.json")
        result = _mapping(run_directory / "result.json")
        integrity = _mapping(run_directory / "integrity.json")
        assert manifest.get("run_id") == run_directory.name
        assert result.get("run_id") == run_directory.name
        assert integrity.get("run_id") == run_directory.name
        _verify_integrity(run_directory, integrity)

        event_lines = (run_directory / "events.jsonl").read_text(encoding="utf-8").splitlines()
        assert event_lines
        events = tuple(json.loads(line) for line in event_lines)
        assert all(
            isinstance(event, dict) and event.get("run_id") == run_directory.name
            for event in events
        )

        if "owner-review.json" in names:
            owner_review = _mapping(run_directory / "owner-review.json")
            assert owner_review.get("run_id") == run_directory.name
        if "final.json" in names:
            assert "owner-review.json" in names
            final = _mapping(run_directory / "final.json")
            assert final.get("run_id") == run_directory.name
            evidence_hashes = final.get("evidence_hashes")
            assert evidence_hashes == {
                name: hashlib.sha256((run_directory / name).read_bytes()).hexdigest()
                for name in (
                    "manifest.json",
                    "events.jsonl",
                    "result.json",
                    "integrity.json",
                    "owner-review.json",
                )
            }


def test_no_task_local_provider_or_tool_cache_exists() -> None:
    forbidden = (
        ROOT / ".terraform",
        ROOT / ".tflint.d",
        ROOT / ".checkov",
        ROOT / ".opa",
        ROOT / "configs/verification/.aws",
    )

    assert [path.relative_to(ROOT).as_posix() for path in forbidden if path.exists()] == []
