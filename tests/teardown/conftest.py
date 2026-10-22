"""Collection boundaries for ignored owner-local teardown artifacts."""

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
OWNER_PROTECTED_STATE = ROOT / "infra/bootstrap/terraform.tfstate"
OWNER_STATE_TEST = (
    "tests/teardown/test_terraform_state_boundary.py::"
    "test_owner_protected_bootstrap_state_is_unchanged_and_ignored"
)


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Skip only the exact owner-state assertion when its ignored input is absent."""
    if OWNER_PROTECTED_STATE.is_file():
        return
    for item in items:
        if item.nodeid.replace("\\", "/").endswith(OWNER_STATE_TEST):
            item.add_marker(
                pytest.mark.skip(reason="ignored owner-local bootstrap state is absent")
            )
