"""W9-004 source validation leaves no repository runtime residue."""

from pathlib import Path


def test_w9_004_runtime_paths_are_absent() -> None:
    for path in (
        Path("reports/w9-004"),
        Path(".w9-004"),
        Path("model.tar"),
        Path("model.safetensors"),
    ):
        assert not path.exists()
