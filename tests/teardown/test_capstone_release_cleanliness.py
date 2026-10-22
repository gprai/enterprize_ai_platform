"""W12 temporary input, probe and residue contracts."""

from __future__ import annotations

from pathlib import Path

import pytest
import tools.capstone_release as release


def test_temporary_record_cleanup(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    directory = tmp_path / "w12-record-private"
    directory.mkdir()
    (directory / "release-record.json").write_text("synthetic", encoding="utf-8")
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    monkeypatch.setenv("W12_RECORD_DIR", str(directory))
    release.workflow_cleanup()
    assert not directory.exists()


def test_cleanup_rejects_repository_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    outside = tmp_path / "other"
    outside.mkdir()
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path / "temp"))
    (tmp_path / "temp").mkdir()
    monkeypatch.setenv("W12_RECORD_DIR", str(outside))
    with pytest.raises(release.ReleaseError):
        release.workflow_cleanup()
    assert outside.exists()


def test_result_reports_inventory_without_claiming_cleanliness() -> None:
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    source = (root / "tools/capstone_deploy.py").read_text(encoding="utf-8")
    assert '"cleanliness": "NOT_VERIFIED"' in source
    assert "PROBE_POD_RESIDUE" in source
    assert "job_deleted" in source and "pod_absent" in source


def test_rendered_temporary_material_cleanup() -> None:
    source = (release.ROOT / "tools/capstone_deploy.py").read_text()
    renderer = source.split("def _render_bundle(", 1)[1].split("def _pki_ready(", 1)[0]
    assert "with tempfile.TemporaryDirectory(" in renderer
    assert "render_w12_release(" in renderer


def test_rollback_lineage_runtime_cleanup_and_retention() -> None:
    release_source = (release.ROOT / "tools/capstone_release.py").read_text()
    deploy_source = (release.ROOT / "tools/capstone_deploy.py").read_text()
    assert "publish_verified_pair_and_lineage(" in release_source
    assert "retain_until_utc" in release_source
    assert "load_prior_rollback_lineage(" in deploy_source
    assert "W12_PREVIOUS_GOOD_RECORD_PATH" not in deploy_source
