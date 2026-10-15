"""Zero-residue and bounded-retention tests for the local registry."""

from datetime import timedelta

from enterprise_ai_platform.model_registry import ApprovalState, fingerprint
from tests.fakes.w9_003_model_registry import NOW, make_auth, make_package, make_service


def test_disabled_registry_exports_before_exact_owner_approved_purge() -> None:
    admin = make_auth()
    service, store = make_service()
    record = service.register(make_package(auth=admin), admin, now=NOW)
    retired = record.model_copy(
        update={
            "approval_state": ApprovalState.SUPERSEDED,
            "retired_at": NOW - timedelta(days=181),
        }
    )
    store._records[record.package.package_id] = type(record).model_validate(  # noqa: SLF001
        retired.model_dump(mode="python"), strict=True
    )

    service.disable()
    exported = service.export(now=NOW)
    cleanup = service.cleanup_plan(now=NOW)

    assert cleanup.exact_package_ids == (record.package.package_id,)
    assert cleanup.audit_export_identity_sha256 == fingerprint(exported)
    assert cleanup.retain_failed_candidates is True
    assert cleanup.retain_audit_evidence is True
    assert cleanup.delete_shared_resources is False
    assert cleanup.status == "NOT_RUN"

    store.purge(
        cleanup.exact_package_ids,
        audit_export_identity_sha256=fingerprint(exported),
        owner_approval_reference_sha256="a" * 64,
        actor_reference_sha256="b" * 64,
        now=NOW,
    )
    assert store.list() == ()
