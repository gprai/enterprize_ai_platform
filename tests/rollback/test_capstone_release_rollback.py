"""W12 rollback must select verified TLS identity or withdraw service."""

from __future__ import annotations

import argparse

import pytest
import tools.capstone_deploy as deploy
from tests.fakes.capstone_release import verified_release_chain
from tools.capstone_release import (
    CONTROL_KEY,
    _release_publication_key,
    _zip_files,
    make_future_lineage_zip,
    validate_future_lineage_zip,
)


def test_missing_verified_predecessor_withdraws_service(monkeypatch: pytest.MonkeyPatch) -> None:
    applied = {"operation": "rollback", "recovery": {"previous_good_record_sha256": None}}
    monkeypatch.setattr(deploy, "_source", lambda _args: (applied, {}, {}, [], []))
    monkeypatch.setattr(deploy, "_read_verified_archive", lambda *_args: ({}, {}))
    calls = []
    monkeypatch.setattr(deploy, "withdraw_service", lambda: calls.append("withdraw"))
    result = deploy.deploy(argparse.Namespace(operation="rollback"))
    assert result["classification"] == "WITHDRAWN"
    assert calls == ["withdraw"]


def test_withdrawal_patches_service_selector_only(monkeypatch: pytest.MonkeyPatch) -> None:
    commands = []
    monkeypatch.setattr(deploy, "_kubectl", lambda *args, **_kwargs: commands.append(args) or "")
    deploy.withdraw_service()
    assert commands[0][:3] == ("patch", "service", deploy.SERVICE)
    assert "withdrawn" in commands[0][-1]
    assert "http://" not in str(commands)


def test_inbound_and_outbound_lineage_are_distinct() -> None:
    chain = verified_release_chain()
    outbound = make_future_lineage_zip(chain)
    members = _zip_files(outbound)
    assert len(members) == 6
    assert "codebuild-handoff.json" not in members
    assert "w12-render-inputs.json" not in members
    assert validate_future_lineage_zip(outbound, raws=chain)["operation"] == "deploy"
    record_id = "123e4567-e89b-42d3-a456-426614174000"
    assert _release_publication_key(record_id, "future_lineage") != CONTROL_KEY


def test_rollback_has_no_w6_v2_fallback() -> None:
    source = (deploy.ROOT / "tools/capstone_deploy.py").read_text()
    adapter = source.split("def _render_bundle(", 1)[1].split("def _pki_ready(", 1)[0]
    assert "render_w12_release(" in adapter
    assert "bind_release(" not in adapter
    assert "build_release_files(" not in adapter


def test_verified_tls_predecessor_chain_required() -> None:
    import tools.capstone_release as release

    source = (release.ROOT / "tools/capstone_release.py").read_text()
    loader = source.split("def load_prior_rollback_lineage(", 1)[1].split(
        "def application_image_from_ready(", 1
    )[0]
    assert "validate_future_lineage_zip(" in loader
    assert '"root_fingerprint_sha256"' in source
    assert '"trust_bundle_sha256"' in source


def test_rollback_target_matches_verified_release_roles() -> None:
    source = (deploy.ROOT / "tools/capstone_deploy.py").read_text()
    preflight = source.split("def _source(", 1)[1].split("def _record(", 1)[0]
    assert "application_image_from_ready(prior_records[1])" in preflight
    assert 'prior_records[1]["artifacts"]["otel_collector_image"]' in preflight
    assert 'prior_render["bedrock_inference_profile_arn"]' in preflight


def test_rollback_uses_verified_rendered_archive() -> None:
    source = (deploy.ROOT / "tools/capstone_deploy.py").read_text()
    runtime = source.split("def deploy(", 1)[1].split("def withdraw_service(", 1)[0]
    reader = source.split("def _read_verified_archive(", 1)[1].split("def preflight(", 1)[0]
    assert "_read_verified_archive(" in runtime
    assert "_s3_version(" in reader
    assert "validate_rendered_release(" in reader
