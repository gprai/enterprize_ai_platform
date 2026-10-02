from __future__ import annotations

import threading
from pathlib import Path

from tools import w6_003_readiness

from tests.fakes import readiness

ROOT = Path(__file__).resolve().parents[2]


def test_readiness_validation_creates_no_file_thread_or_external_residue(tmp_path: Path) -> None:
    before_files = tuple(tmp_path.iterdir())
    before_threads = {thread.ident for thread in threading.enumerate()}
    output_existed = Path(w6_003_readiness.ALLOWED_OUTPUT_ROOT).exists()
    temporary_existed = Path(w6_003_readiness.TEMPORARY_ROOT).exists()
    proof = readiness.local_proof()
    rollback = readiness.local_rollback()

    assert (
        w6_003_readiness.validate_config(ROOT, ROOT / "configs/readiness/w6-003.yaml")
        == w6_003_readiness.VALIDATION_MESSAGE
    )
    w6_003_readiness.validate_local_proof(proof, now=readiness.NOW)
    w6_003_readiness.validate_local_rollback(rollback, now=readiness.NOW)
    w6_003_readiness.validate_handover(
        readiness.handover(proof, rollback),
        local_proof_sha256=w6_003_readiness.sha256_bytes(
            w6_003_readiness.canonical_json_bytes(proof)
        ),
        local_rollback_sha256=w6_003_readiness.sha256_bytes(
            w6_003_readiness.canonical_json_bytes(rollback)
        ),
        now=readiness.NOW,
    )

    assert tuple(tmp_path.iterdir()) == before_files
    assert {thread.ident for thread in threading.enumerate()} == before_threads
    assert Path(w6_003_readiness.ALLOWED_OUTPUT_ROOT).exists() is output_existed
    assert Path(w6_003_readiness.TEMPORARY_ROOT).exists() is temporary_existed
