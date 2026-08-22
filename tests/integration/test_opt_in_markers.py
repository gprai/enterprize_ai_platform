"""Integration tests for automatic categories and opt-in cost/access markers."""

from __future__ import annotations

import pytest


def test_integration_directory_marker_is_automatic(
    request: pytest.FixtureRequest,
) -> None:
    assert request.node.get_closest_marker("integration") is not None


@pytest.mark.aws
def test_aws_canary_never_connects_implicitly() -> None:
    pytest.skip("AWS execution requires separate owner access approval")


@pytest.mark.paid
def test_paid_canary_never_incurs_cost_implicitly() -> None:
    pytest.skip("paid execution requires separate owner budget approval")
