"""Security regression checks for unsafe model artifacts."""

import io
import tarfile
from pathlib import Path

from enterprise_ai_platform.model_supply_chain import (
    EvidenceStatus,
    inspect_model_archive,
    load_supply_chain_policy,
)


def test_pickle_weight_and_archive_traversal_fail_closed(tmp_path: Path) -> None:
    archive = tmp_path / "candidate.tar"
    with tarfile.open(archive, "w") as stream:
        content = b"not-a-model"
        member = tarfile.TarInfo("../model.pkl")
        member.size = len(content)
        stream.addfile(member, io.BytesIO(content))
    inventory = inspect_model_archive(archive, load_supply_chain_policy())
    assert inventory.status is EvidenceStatus.FAIL
    assert inventory.forbidden_files == ("../model.pkl",)
