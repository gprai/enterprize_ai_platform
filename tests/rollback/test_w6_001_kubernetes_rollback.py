"""Rollback identity tests for W6-001 immutable releases."""

from pathlib import Path

import pytest
from tests.unit.test_w6_001_k8s import DIGEST, valid_binding
from tools import w6_001_k8s


def test_rollback_requires_an_exact_previous_digest(tmp_path: Path) -> None:
    binding = valid_binding(tmp_path / "operation", tmp_path)
    previous = "sha256:" + "d" * 64
    assert w6_001_k8s.DIGEST_RE.fullmatch(previous)
    assert previous != DIGEST
    binding["digest"] = previous
    for field in ("oci_identity", "trivy", "grype", "provenance", "image_composition_identity"):
        binding[field]["image_digest"] = previous  # type: ignore[index]
    images = w6_001_k8s.validate_release_binding(
        binding,
        source_template_sha256=binding["source_identity"]["template_sha256"],  # type: ignore[index]
    )
    assert images[0].endswith("@" + previous)


@pytest.mark.parametrize("previous", ["latest", "sha256:short", "sha256:" + "D" * 64])
def test_rollback_rejects_mutable_or_malformed_previous_identity(previous: str) -> None:
    assert w6_001_k8s.DIGEST_RE.fullmatch(previous) is None


def test_rollout_undo_is_not_an_approved_rollback_contract() -> None:
    source = Path(w6_001_k8s.__file__).read_text(encoding="utf-8")
    assert "rollout undo" not in source
    assert "kubectl" not in source
