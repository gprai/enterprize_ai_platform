"""No-mutation recovery rehearsal coverage for W7-001."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from tools.platformctl.contracts import ContractError
from tools.platformctl.lifecycle_models import (
    W7_001_SCHEMA_VERSION,
    ControlResult,
    RecoverySnapshotContract,
)
from tools.platformctl.rollback import validate_no_mutation_recovery_rehearsal


def test_encrypted_external_snapshot_is_identity_bound_but_not_applied(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    external = tmp_path / "external"
    repository.mkdir()
    external.mkdir()
    snapshot = RecoverySnapshotContract(
        W7_001_SCHEMA_VERSION,
        "recovery-001",
        str(external / "snapshot.enc"),
        "lineage-001",
        7,
        "a" * 64,
        "kms:alias/recovery",
        "role:recovery",
        "2026-10-12T00:00:00Z",
        "Gyan Prakash Rai",
        False,
        False,
        ControlResult.NOT_RUN,
    )
    assert (
        validate_no_mutation_recovery_rehearsal(
            snapshot,
            allowed_root=external,
            repository_root=repository,
            now=datetime(2026, 10, 11, tzinfo=UTC),
        )
        == snapshot
    )
    with pytest.raises(ContractError, match="MUST_REMAIN_NOT_RUN"):
        validate_no_mutation_recovery_rehearsal(
            RecoverySnapshotContract(**{**snapshot.__dict__, "mutation_allowed": True}),
            allowed_root=external,
            repository_root=repository,
            now=datetime(2026, 10, 11, tzinfo=UTC),
        )
