from pathlib import Path


def test_w8_design_creates_no_runtime_resource_manifest(tmp_path: Path) -> None:
    assert list(tmp_path.iterdir()) == []
