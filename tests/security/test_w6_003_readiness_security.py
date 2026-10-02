from __future__ import annotations

from copy import deepcopy
from datetime import timedelta
from pathlib import Path

import pytest
from tools import w6_003_readiness

from tests.fakes import readiness


def test_duplicate_non_finite_and_noncanonical_json_are_rejected(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text(
        '{"schema_version":"a","schema_version":"b"}\n',
        encoding="utf-8",
    )
    with pytest.raises(w6_003_readiness.W6003Error, match="duplicate JSON key"):
        w6_003_readiness.load_strict_json(duplicate)

    non_finite = tmp_path / "non-finite.json"
    non_finite.write_text('{"value":NaN}\n', encoding="utf-8")
    with pytest.raises(w6_003_readiness.W6003Error, match="non-finite"):
        w6_003_readiness.load_strict_json(non_finite)

    noncanonical = tmp_path / "noncanonical.json"
    noncanonical.write_text('{ "value": 1 }\n', encoding="utf-8")
    with pytest.raises(w6_003_readiness.W6003Error, match="canonical JSON"):
        w6_003_readiness.load_strict_json(noncanonical)


def test_sensitive_field_output_root_and_expired_evidence_fail_closed() -> None:
    proof = readiness.local_proof()
    proof["prompt_content"] = "forbidden"
    with pytest.raises(w6_003_readiness.W6003Error, match="closed schema"):
        w6_003_readiness.validate_local_proof(proof, now=readiness.NOW)

    proof = readiness.local_proof()
    proof["output_root"] = r"E:\AI\.runtime\outside"
    with pytest.raises(w6_003_readiness.W6003Error, match="approved private evidence root"):
        w6_003_readiness.validate_local_proof(proof, now=readiness.NOW)

    proof = readiness.local_proof()
    with pytest.raises(w6_003_readiness.W6003Error, match="expired"):
        w6_003_readiness.validate_local_proof(
            proof,
            now=readiness.NOW + timedelta(hours=24),
        )


def test_tampered_owner_decision_or_live_identity_is_rejected() -> None:
    proof = readiness.local_proof()
    rollback = readiness.local_rollback()
    handover = deepcopy(readiness.handover())
    handover["owner_decisions"] = ["silently approve live deployment"]
    with pytest.raises(w6_003_readiness.W6003Error, match="owner decisions differ"):
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
