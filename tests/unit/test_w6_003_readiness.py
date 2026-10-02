from __future__ import annotations

from copy import deepcopy
from datetime import timedelta

import pytest
from tools import w6_003_readiness

from tests.fakes import readiness


def test_canonical_json_is_stable_strict_and_newline_terminated() -> None:
    first = w6_003_readiness.canonical_json_bytes({"z": 1, "a": [True, None]})
    second = w6_003_readiness.canonical_json_bytes({"a": [True, None], "z": 1})

    assert first == second == b'{"a":[true,null],"z":1}\n'
    assert len(w6_003_readiness.sha256_bytes(first)) == 64


def test_local_proof_preserves_all_approved_statuses() -> None:
    proof = readiness.local_proof()
    proof["test_results"] = [
        {
            "check_name": status.casefold(),
            "status": status,
            "scope": "mandatory-local" if status == "PASS" else "historical",
        }
        for status in ("PASS", "FAIL", "NOT RUN", "INDETERMINATE", "NO_DATA")
    ]

    w6_003_readiness.validate_local_proof(proof, now=readiness.NOW)


def test_evidence_expiry_and_unknown_fields_fail_closed() -> None:
    proof = readiness.local_proof()
    proof["expires_at"] = (readiness.NOW + timedelta(hours=25)).isoformat().replace("+00:00", "Z")
    with pytest.raises(w6_003_readiness.W6003Error, match="exactly 24 hours"):
        w6_003_readiness.validate_local_proof(proof, now=readiness.NOW)

    proof = readiness.local_proof()
    proof["unexpected"] = True
    with pytest.raises(w6_003_readiness.W6003Error, match="closed schema"):
        w6_003_readiness.validate_local_proof(proof, now=readiness.NOW)


def test_handover_requires_absent_live_known_good_identities() -> None:
    proof = readiness.local_proof()
    rollback = readiness.local_rollback()
    handover = readiness.handover(proof, rollback)

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

    changed = deepcopy(handover)
    application = changed["known_good_application"]
    assert isinstance(application, dict)
    application["registry_digest"] = f"sha256:{'6' * 64}"
    with pytest.raises(
        w6_003_readiness.W6003Error,
        match="must remain absent",
    ):
        w6_003_readiness.validate_handover(
            changed,
            local_proof_sha256=w6_003_readiness.sha256_bytes(
                w6_003_readiness.canonical_json_bytes(proof)
            ),
            local_rollback_sha256=w6_003_readiness.sha256_bytes(
                w6_003_readiness.canonical_json_bytes(rollback)
            ),
            now=readiness.NOW,
        )
