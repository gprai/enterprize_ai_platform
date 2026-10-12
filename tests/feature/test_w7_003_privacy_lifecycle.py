"""Feature coverage for W7-003 approval, privacy, and deletion behavior."""

import pytest

from enterprise_ai_platform.ingestion.pii import StaticPiiAnalyzer
from enterprise_ai_platform.ingestion.privacy_lifecycle import (
    PrivacyCoordinator,
    PrivacyDisposition,
)
from tests.fakes.w7_003_privacy_lifecycle import (
    FakeMacieBoundary,
    discovery,
    pii_policy,
    source,
)


@pytest.mark.asyncio
async def test_injected_privacy_boundaries_clear_only_matching_source() -> None:
    target = source()
    coordinator = PrivacyCoordinator(
        analyzer=StaticPiiAnalyzer(),
        macie=FakeMacieBoundary(discovery(target.identity)),
        pii_policy=pii_policy(),
    )
    result = await coordinator.assess(
        text="synthetic internal text",
        source=target,
        classification="INTERNAL",
    )
    assert result.disposition is PrivacyDisposition.CLEAR


@pytest.mark.asyncio
async def test_boundary_exception_is_safe_and_fail_closed() -> None:
    class FailingMacie:
        async def discover(self, source):
            del source
            raise RuntimeError("provider detail must not escape")

    coordinator = PrivacyCoordinator(
        analyzer=StaticPiiAnalyzer(),
        macie=FailingMacie(),
        pii_policy=pii_policy(),
    )
    result = await coordinator.assess(
        text="synthetic internal text",
        source=source(),
        classification="INTERNAL",
    )
    assert result.disposition is PrivacyDisposition.QUARANTINED
    assert result.safe_reason_code == "DISCOVERY_NOT_PASS"
    assert "provider detail" not in result.model_dump_json()
