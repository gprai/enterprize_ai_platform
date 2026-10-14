"""Zero-residue assertions for the source-only W9-001 contract."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_source_only_contract_contains_no_runtime_or_evidence_residue() -> None:
    for relative in (
        "reports/W9/W9-001",
        "evidence/W9/W9-001",
        ".pytest_cache",
        "configs/training/w9-001-runtime.json",
    ):
        assert not (ROOT / relative).exists()


def test_training_package_contains_no_network_or_provisioning_client() -> None:
    package = ROOT / "src/enterprise_ai_platform/training"
    rendered = "\n".join(path.read_text(encoding="utf-8") for path in package.glob("*.py"))

    for forbidden in ("boto3", "requests.", "httpx", "subprocess", "create_training_job"):
        assert forbidden not in rendered


def test_no_task_specific_cache_or_model_material_exists_in_repository() -> None:
    for relative in (".cache/w9-001", "models/w9-001", "artifacts/w9-001"):
        assert not (ROOT / relative).exists()
