"""Unit contracts for deterministic W5-002 CI report handling."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from tools import w5_002_ci

ROOT = Path(__file__).resolve().parents[2]
SOURCE = "a" * 40
DIGEST = "sha256:" + "b" * 64


def _image_identity() -> dict[str, object]:
    return {
        "base_image": w5_002_ci.BASE_IMAGE,
        "image_digest": DIGEST,
        "platform": "linux/amd64",
        "schema_version": w5_002_ci.IMAGE_SCHEMA,
        "source_commit": SOURCE,
    }


def test_canonical_json_is_sorted_finite_and_has_one_final_newline() -> None:
    assert w5_002_ci.canonical_json({"z": 2, "a": 1}) == '{"a":1,"z":2}\n'
    with pytest.raises(w5_002_ci.ContractError, match="non-finite"):
        w5_002_ci.canonical_json({"value": float("nan")})


def test_strict_loader_rejects_duplicate_keys_and_bom(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"a":1,"a":2}\n', encoding="utf-8")
    with pytest.raises(w5_002_ci.ContractError, match="duplicate"):
        w5_002_ci.load_json(duplicate)

    bom = tmp_path / "bom.json"
    bom.write_bytes(b"\xef\xbb\xbf{}\n")
    with pytest.raises(w5_002_ci.ContractError, match="BOM"):
        w5_002_ci.load_json(bom)


def test_configuration_is_canonical_and_preserves_w5_001_fail() -> None:
    path = ROOT / "configs/ci/w5-002.json"
    value = w5_002_ci.load_json(path)

    assert path.read_text(encoding="utf-8") == w5_002_ci.canonical_json(value)
    assert w5_002_ci.validate_config(value)["w5_001"] == {"formal_status": "FAIL"}


def _write_lock(path: Path, packages: tuple[tuple[str, str], ...], *, cpu: bool) -> None:
    lines = ["# generated test lock"]
    if cpu:
        lines.append(f"--extra-index-url {w5_002_ci.PYTORCH_INDEX_URL}")
    for name, version in packages:
        lines.extend((f"{name}=={version} \\", f"    --hash=sha256:{'a' * 64}"))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_dependency_locks_require_cpu_torch_and_keep_checkov_isolated(
    tmp_path: Path,
) -> None:
    runtime = tmp_path / "requirements-runtime.lock"
    checkov = tmp_path / "requirements-checkov.lock"
    _write_lock(runtime, (("fastapi", "0.139.0"), ("torch", "2.13.0+cpu")), cpu=True)
    _write_lock(checkov, (("checkov", "3.3.16"),), cpu=False)

    assert w5_002_ci.validate_dependency_lock(runtime, "runtime")["torch"] == ("2.13.0+cpu")
    assert w5_002_ci.validate_dependency_lock(checkov, "checkov") == {"checkov": "3.3.16"}


@pytest.mark.parametrize("package", ("cuda-bindings", "nvidia-cublas", "triton"))
def test_dependency_lock_rejects_every_prohibited_gpu_package(
    tmp_path: Path,
    package: str,
) -> None:
    lock = tmp_path / "requirements-runtime.lock"
    _write_lock(
        lock,
        (("torch", "2.13.0+cpu"), (package, "1.0.0")),
        cpu=True,
    )

    with pytest.raises(w5_002_ci.ContractError, match="prohibited GPU package"):
        w5_002_ci.validate_dependency_lock(lock, "runtime")


def test_dependency_lock_rejects_wrong_torch_or_missing_cpu_index(tmp_path: Path) -> None:
    wrong_torch = tmp_path / "wrong-torch.lock"
    missing_index = tmp_path / "missing-index.lock"
    _write_lock(wrong_torch, (("torch", "2.14.0"),), cpu=True)
    _write_lock(missing_index, (("torch", "2.13.0+cpu"),), cpu=False)

    with pytest.raises(w5_002_ci.ContractError, match="Torch 2.13 CPU"):
        w5_002_ci.validate_dependency_lock(wrong_torch, "runtime")
    with pytest.raises(w5_002_ci.ContractError, match="PyTorch CPU index"):
        w5_002_ci.validate_dependency_lock(missing_index, "runtime")


def test_all_four_generated_schemas_fail_closed() -> None:
    image = w5_002_ci.validate_schema(_image_identity())
    provenance = {
        "image_digest": DIGEST,
        "reports": [f"{name}:sha256:{'e' * 64}" for name in w5_002_ci.SUPPLY_CHAIN_NAMES[:6]],
        "schema_version": w5_002_ci.PROVENANCE_SCHEMA,
        "source_commit": SOURCE,
        "tool_versions": w5_002_ci.EXPECTED_TOOL_VERSIONS,
    }
    eligibility = {
        "critical_vulnerabilities": 0,
        "deployable": False,
        "eligible_for_owner_approval": True,
        "image_digest": DIGEST,
        "mandatory_gates": {
            "candidate_identity": True,
            "cyclonedx_sbom": True,
            "grype_image": True,
            "spdx_sbom": True,
            "trivy_filesystem": True,
            "trivy_image": True,
        },
        "schema_version": w5_002_ci.ELIGIBILITY_SCHEMA,
        "source_commit": SOURCE,
        "w5_001_status": "FAIL",
    }
    plan = {
        "changes": {"add": 1, "change": 0, "destroy": 0, "no_op": 0, "read": 0},
        "environment": "sandbox",
        "expires_at": "2099-09-05T01:00:00+00:00",
        "generated_at": "2099-09-05T00:00:00+00:00",
        "raw_plan_retained": False,
        "redacted": True,
        "ref": "refs/heads/main",
        "repository": "gprai/enterprize_ai_platform",
        "schema_version": w5_002_ci.PLAN_SCHEMA,
        "source_commit": SOURCE,
        "terraform_version": "1.16.1",
    }

    assert image["image_digest"] == DIGEST
    assert w5_002_ci.validate_schema(provenance)["source_commit"] == SOURCE
    assert w5_002_ci.validate_schema(eligibility)["deployable"] is False
    assert w5_002_ci.validate_schema(plan)["redacted"] is True
    for invalid in ({**image, "extra": True}, {**eligibility, "w5_001_status": "PASS"}):
        with pytest.raises(w5_002_ci.ContractError):
            w5_002_ci.validate_schema(invalid)


def test_sensitive_content_is_rejected_without_echoing_the_value() -> None:
    sensitive_value = "joined-" + "private-" + "material"
    with pytest.raises(w5_002_ci.ContractError) as raised:
        w5_002_ci.assert_content_safe({"private" + "_key": sensitive_value})
    assert sensitive_value not in str(raised.value)


def test_plan_summary_counts_only_approved_action_sequences(tmp_path: Path) -> None:
    output = tmp_path / "summary.json"
    plan = {
        "resource_changes": [
            {"change": {"actions": ["create"]}},
            {"change": {"actions": ["update"]}},
            {"change": {"actions": ["delete"]}},
        ]
    }
    w5_002_ci.write_plan_summary(output, plan, SOURCE, "2099-09-05T00:00:00+00:00")
    summary = json.loads(output.read_text(encoding="utf-8"))

    assert summary["changes"] == {
        "add": 1,
        "change": 1,
        "destroy": 1,
        "no_op": 0,
        "read": 0,
    }
    assert summary["raw_plan_retained"] is False


def test_report_size_and_candidate_identity_mismatch_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(w5_002_ci, "MAXIMUM_FILE_BYTES", 8)
    oversized = tmp_path / "oversized.json"
    oversized.write_text('{"value":1}\n', encoding="utf-8")
    with pytest.raises(w5_002_ci.ContractError, match="maximum size"):
        w5_002_ci.load_json(oversized)

    with pytest.raises(w5_002_ci.ContractError, match="digest"):
        w5_002_ci.validate_image_identity({**_image_identity(), "image_digest": "latest"})
