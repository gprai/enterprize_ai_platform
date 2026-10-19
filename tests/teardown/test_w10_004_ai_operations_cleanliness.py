"""Zero-residue checks for source-only W10-004 validation."""

from pathlib import Path

from enterprise_ai_platform.telemetry.ai_operations import load_ai_operations_policy


def test_policy_loading_creates_no_repository_residue() -> None:
    root = Path(__file__).resolve().parents[2]
    before = {path.relative_to(root) for path in root.rglob("*.tmp")}
    load_ai_operations_policy(root / "configs/observability/ai-operations-policy.yaml")
    after = {path.relative_to(root) for path in root.rglob("*.tmp")}
    assert after == before
