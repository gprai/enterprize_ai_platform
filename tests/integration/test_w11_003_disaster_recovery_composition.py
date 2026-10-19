"""W11-003 composes existing governed identities without a live restore."""

from datetime import timedelta
from pathlib import Path

from tools.platformctl.lifecycle_io import validate_recovery_snapshot
from tools.platformctl.lifecycle_models import (
    W7_001_SCHEMA_VERSION,
    ControlResult,
    RecoverySnapshotContract,
)

from enterprise_ai_platform.disaster_recovery import (
    DEFAULT_RECOVERY_POLICY_PATH,
    SOURCE_PATHS,
    RecoveryScope,
    canonical_sha256,
    load_recovery_policy,
)
from enterprise_ai_platform.ingestion.governance import SourceIdentity
from enterprise_ai_platform.model_registry.models import ModelArtifactIdentity
from enterprise_ai_platform.retrieval.models import CollectionSpec
from tests.fakes.w11_003_disaster_recovery import NOW, asset, digest

ROOT = Path(__file__).resolve().parents[2]


def test_policy_pins_every_declared_existing_recovery_producer() -> None:
    policy = load_recovery_policy(ROOT / DEFAULT_RECOVERY_POLICY_PATH, repository_root=ROOT)
    assert tuple(policy.source_identities.model_dump()) == tuple(SOURCE_PATHS)
    assert len(SOURCE_PATHS) == 22


def test_s3_opensearch_and_model_identities_remain_provider_neutral() -> None:
    source = SourceIdentity(
        schema_version="w7-001.source.v1",
        bucket="enterprise-ai-platform-526338061652-ap-southeast-1-sandbox",
        key="raw/tenant-a/document.md",
        s3_version_id="version-1",
        etag="etag-1",
        byte_count=100,
        media_type="text/markdown",
        original_content_sha256=digest("content"),
    )
    collection = CollectionSpec(name="enterprise_ai_sandbox_recovery_candidate")
    artifact = ModelArtifactIdentity(
        source_uri=(
            "s3://enterprise-ai-platform-526338061652-ap-southeast-1-sandbox/models/model.bin"
        ),
        object_version_id="version-1",
        sha256=digest("model"),
        size_bytes=1024,
    )
    assert len(canonical_sha256(source)) == 64
    assert len(canonical_sha256(collection)) == 64
    assert artifact.region == "ap-southeast-1"
    collection_identity = asset(
        RecoveryScope.OPENSEARCH_INDEX, artifact="candidate"
    ).collection_spec_sha256
    assert collection_identity


def test_existing_w7_snapshot_validator_preserves_lineage_and_no_mutation(
    tmp_path: Path,
) -> None:
    external = tmp_path / "external"
    external.mkdir()
    snapshot = RecoverySnapshotContract(
        schema_version=W7_001_SCHEMA_VERSION,
        operation_id="w11-003-test",
        external_path=str(external / "snapshot.enc"),
        state_lineage="lineage-1",
        state_serial=12,
        content_sha256=digest("state"),
        encryption_identity="kms-key-identity",
        recovery_principal="recovery-principal",
        retention_until=(NOW + timedelta(days=1)).isoformat().replace("+00:00", "Z"),
        cleanup_owner="owner",
        plaintext_retained=False,
        mutation_allowed=False,
        rehearsal_status=ControlResult.NOT_RUN,
    )
    assert (
        validate_recovery_snapshot(
            snapshot,
            allowed_root=external,
            repository_root=ROOT,
            now=NOW,
        )
        == snapshot
    )
