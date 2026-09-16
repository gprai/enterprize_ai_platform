"""Rollback tests preserving release/infrastructure/teardown distinctions."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime

import pytest
from tests.unit.test_platformctl_plan_identity import identity
from tools.platformctl.contracts import Action, ContractError
from tools.platformctl.plan import validate_plan_identity


def test_last_known_good_identity_drift_stops_infrastructure_rollback() -> None:
    approved = identity()
    drifted = replace(approved, state_serial=1)
    with pytest.raises(ContractError, match="state_serial"):
        validate_plan_identity(
            approved,
            drifted,
            datetime(2026, 9, 8, 0, 30, tzinfo=UTC),
        )


def test_infrastructure_rollback_is_not_release_rollback_or_destroy() -> None:
    assert Action.INFRASTRUCTURE_ROLLBACK.value == "INFRASTRUCTURE-ROLLBACK"
    assert "RELEASE" not in Action.INFRASTRUCTURE_ROLLBACK.value
    assert "DESTROY" not in Action.INFRASTRUCTURE_ROLLBACK.value


def test_v2_rollback_without_last_known_good_is_not_authorized() -> None:
    from tests.fakes.platform_lifecycle import FrozenClock, reviewed_package_fixture
    from tools.platformctl.contracts import validate_review_package
    from tools.platformctl.lifecycle_models import ChangeProfile

    package, _, reader, revalidator = reviewed_package_fixture()
    profile = replace(
        package.profile, profile=ChangeProfile.ROLLBACK, action=Action.INFRASTRUCTURE_ROLLBACK
    )
    package = replace(package, action=Action.INFRASTRUCTURE_ROLLBACK, profile=profile)
    with pytest.raises(ContractError, match="LAST_KNOWN_GOOD"):
        validate_review_package(package, now=FrozenClock().now(), reader=reader)
    assert not revalidator.consumed
