"""Zero-residue checks for source-only W8-004 work."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_source_contract_creates_no_runtime_or_evidence_residue() -> None:
    for relative in (
        "reports/W8/W8-004",
        "evidence/W8/W8-004",
        ".pytest_cache",
        "configs/capacity/w8-004-runtime.json",
    ):
        assert not (ROOT / relative).exists()


def test_capacity_package_contains_no_network_or_provisioning_client() -> None:
    package = ROOT / "src/enterprise_ai_platform/capacity"
    rendered = "\n".join(path.read_text(encoding="utf-8") for path in package.glob("*.py"))

    for forbidden in ("boto3", "requests.", "httpx", "subprocess", "kubectl", "terraform"):
        assert forbidden not in rendered
