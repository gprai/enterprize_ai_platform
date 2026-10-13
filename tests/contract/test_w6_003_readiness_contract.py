from __future__ import annotations

from pathlib import Path

from tools import w6_003_readiness

ROOT = Path(__file__).resolve().parents[2]


def test_exact_repository_readiness_contract_is_local_and_closed() -> None:
    result = w6_003_readiness.validate_config(
        ROOT,
        ROOT / "configs/readiness/local-integrated-readiness.yaml",
    )

    assert result == w6_003_readiness.VALIDATION_MESSAGE
    assert w6_003_readiness.RETAINED_FILES == (
        "local-proof.json",
        "local-rollback-rehearsal.json",
        "w6-004-readiness-manifest.json",
    )
    assert w6_003_readiness.VALIDITY_HOURS == 24
    assert len(w6_003_readiness.repository_composition_sha256(ROOT)) == 64


def test_cloud_lifecycle_and_known_good_creation_remain_w6_004_work() -> None:
    config = w6_003_readiness.load_config(
        ROOT / "configs/readiness/local-integrated-readiness.yaml"
    )
    w6_003_readiness.validate_config_values(config)

    execution = config["execution"]
    known_good = config["known_good"]
    assert isinstance(execution, dict)
    assert isinstance(known_good, dict)
    assert execution["cloud_activity"] == "NOT RUN"
    application = known_good["application"]
    infrastructure = known_good["infrastructure"]
    assert isinstance(application, dict)
    assert isinstance(infrastructure, dict)
    assert application["deployable_identity_status"] == "MISSING"
    assert infrastructure["deployable_identity_status"] == "MISSING"
    assert tuple(config["lifecycle"]) == w6_003_readiness.LIFECYCLE
