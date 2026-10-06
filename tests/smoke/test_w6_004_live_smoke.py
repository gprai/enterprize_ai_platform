import pytest

pytestmark = pytest.mark.skip(
    reason="W6-004 live smoke is owner-executed only after deployment approval"
)


def test_owner_executes_live_clusterip_smoke_from_an_in_cluster_job() -> None:
    raise AssertionError("owner-only live test must never run in the local suite")
