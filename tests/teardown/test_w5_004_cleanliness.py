"""Teardown tests for bootstrap-last ordering and exact external residue semantics."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest
from tools.platformctl.contracts import ContractError
from tools.platformctl.destroy import (
    S3PurgeInventory,
    validate_destroy_order,
    validate_s3_purge_inventory,
)
from tools.platformctl.lifecycle_io import reserve_operation_directory

ROOT = Path(__file__).resolve().parents[2]


def test_bootstrap_destroy_is_strictly_last() -> None:
    with pytest.raises(ContractError, match="prior platform cleanliness"):
        validate_destroy_order((), "bootstrap", platform_clean=False)
    validate_destroy_order(("platform",), "bootstrap", platform_clean=True)


def test_transient_creation_collision_never_deletes_existing_file(tmp_path: Path) -> None:
    from tools.platformctl.lifecycle_io import private_transient_bytes

    repository = tmp_path / "repository"
    repository.mkdir()
    external = tmp_path / "external"
    reserve_operation_directory(external, external, repository)
    target = external / "existing.json"
    original = b"owner-controlled"
    target.write_bytes(original)
    with pytest.raises(ContractError):
        with private_transient_bytes(
            target, b"new", allowed_root=external, repository_root=repository
        ):
            raise AssertionError("collision reached the consumer")
    assert target.read_bytes() == original


def test_transient_consumer_failure_leaves_no_owned_file(tmp_path: Path) -> None:
    from tools.platformctl.lifecycle_io import private_transient_bytes

    repository = tmp_path / "repository"
    repository.mkdir()
    external = tmp_path / "external"
    reserve_operation_directory(external, external, repository)
    target = external / "private.json"
    with pytest.raises(RuntimeError, match="consumer"):
        with private_transient_bytes(
            target, b"{}", allowed_root=external, repository_root=repository
        ):
            raise RuntimeError("consumer")
    assert not target.exists()


def test_transient_replacement_is_preserved(tmp_path: Path) -> None:
    from tools.platformctl.lifecycle_io import private_transient_bytes

    repository = tmp_path / "repository"
    repository.mkdir()
    external = tmp_path / "external"
    reserve_operation_directory(external, external, repository)
    target = external / "private.json"
    displaced = external / "displaced.json"
    with pytest.raises(ContractError, match="TRANSIENT_OWNERSHIP_CHANGED"):
        with private_transient_bytes(
            target, b"{}", allowed_root=external, repository_root=repository
        ):
            target.rename(displaced)
            target.write_bytes(b"owner replacement")
    assert target.read_bytes() == b"owner replacement"
    assert displaced.read_bytes() == b"{}"


def test_private_protection_failure_cleans_only_created_empty_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tools.platformctl import lifecycle_io

    repository = tmp_path / "repository"
    repository.mkdir()
    external = tmp_path / "external"
    reserve_operation_directory(external, external, repository)
    target = external / "private.json"
    original = lifecycle_io._create_private_file

    def rejected_protection(path: Path, created: Callable[[int], None]) -> int:
        original(path, created)
        assert path.stat().st_size == 0
        raise ContractError("PRIVATE_PROTECTION_UNVERIFIED")

    monkeypatch.setattr(lifecycle_io, "_create_private_file", rejected_protection)
    with pytest.raises(ContractError, match="PRIVATE_PROTECTION_UNVERIFIED"):
        with lifecycle_io.private_transient_bytes(
            target, b"private input", allowed_root=external, repository_root=repository
        ):
            raise AssertionError("unverified protection reached a consumer")
    assert not target.exists()


def test_repository_contains_no_w5_004_runtime_artifacts() -> None:
    forbidden = {"operation.lock.json", "plan.tfplan", "terraform.tfstate"}
    protected = ROOT / "infra/bootstrap/terraform.tfstate"
    assert [path for path in ROOT.rglob("*") if path.name in forbidden and path != protected] == []


def test_w6_12_is_reuse_only_and_not_run() -> None:
    config = json.loads((ROOT / "configs/lifecycle/w5-004.json").read_text(encoding="utf-8"))
    assert config["lifecycle"]["w6_12_status"] == "IMPLEMENTATION_REUSE_ONLY_NOT_RUN"


def test_s3_purge_requires_complete_sorted_versioned_inventory() -> None:
    validate_s3_purge_inventory(
        S3PurgeInventory(
            bucket="enterprise-ai-platform-sandbox",
            object_versions=("key-a/version-1", "key-b/version-2"),
            delete_markers=("key-a/marker-1",),
            multipart_uploads=("key-c/upload-1",),
        )
    )
    with pytest.raises(ContractError, match="sorted"):
        validate_s3_purge_inventory(
            S3PurgeInventory(
                bucket="enterprise-ai-platform-sandbox",
                object_versions=("key-b/version-2", "key-a/version-1"),
                delete_markers=(),
                multipart_uploads=(),
            )
        )
