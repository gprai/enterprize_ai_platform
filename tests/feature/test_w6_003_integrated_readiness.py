from __future__ import annotations

from copy import deepcopy

import pytest
from tools import w6_003_readiness

from tests.fakes import readiness


def _validate_complete_handover(handover: dict[str, object]) -> None:
    proof = readiness.local_proof()
    rollback = readiness.local_rollback()
    w6_003_readiness.validate_local_proof(proof, now=readiness.NOW)
    w6_003_readiness.validate_local_rollback(rollback, now=readiness.NOW)
    w6_003_readiness.validate_handover(
        handover,
        local_proof_sha256=w6_003_readiness.sha256_bytes(
            w6_003_readiness.canonical_json_bytes(proof)
        ),
        local_rollback_sha256=w6_003_readiness.sha256_bytes(
            w6_003_readiness.canonical_json_bytes(rollback)
        ),
        now=readiness.NOW,
    )


def test_integrated_local_proof_is_valid_but_live_entry_remains_blocked() -> None:
    handover = readiness.handover()
    _validate_complete_handover(handover)

    assert handover["w6_004_entry_decision"] == "BLOCKED_PENDING_W6_004_STAGE_A"
    assert handover["stage_a_known_good_promotion_required"] is True
    assert "AWS infrastructure creation" in handover["not_run_activities"]
    assert "cloud rollback and complete teardown" in handover["not_run_activities"]


def test_changed_nested_proof_identity_stops_handover() -> None:
    handover = deepcopy(readiness.handover())
    reference = handover["local_proof"]
    assert isinstance(reference, dict)
    reference["sha256"] = "0" * 64

    with pytest.raises(w6_003_readiness.W6003Error, match="hash differs"):
        _validate_complete_handover(handover)
