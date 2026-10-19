"""Offline W11-003 recovery-policy validation and memory-only rehearsal."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE_PATH = (ROOT / "src").resolve()
if str(SOURCE_PATH) not in sys.path:
    sys.path.insert(0, str(SOURCE_PATH))

from enterprise_ai_platform.disaster_recovery import (  # noqa: E402
    DEFAULT_RECOVERY_POLICY_PATH,
    InMemoryNativeVerifier,
    InMemoryRecoveryTarget,
    RecoveryAssetIdentity,
    RecoveryOperation,
    RecoveryPlan,
    RecoveryScope,
    RecoveryStatus,
    SystemClock,
    canonical_sha256,
    load_recovery_policy,
    run_local_rehearsal,
)
from enterprise_ai_platform.retrieval.models import (  # noqa: E402
    AuthContext,
    Classification,
    Role,
)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _asset(
    scope: RecoveryScope,
    *,
    artifact: str,
    recovery_point_at: datetime,
) -> RecoveryAssetIdentity:
    common: dict[str, object] = {
        "scope": scope,
        "tenant_id": "tenant-a",
        "classification": Classification.INTERNAL,
        "account_id": "526338061652",
        "region": "ap-southeast-1",
        "source_identity_sha256": _digest("w11-003-source"),
        "artifact_identity_sha256": _digest(artifact),
        "kms_identity_sha256": _digest("w11-003-kms"),
        "iam_identity_sha256": _digest("w11-003-iam"),
        "recovery_point_at": recovery_point_at,
    }
    if scope in {RecoveryScope.S3_GOVERNED_SOURCE, RecoveryScope.MODEL_ARTIFACT}:
        common["object_version_id"] = "synthetic-version-1"
    elif scope is RecoveryScope.OPENSEARCH_INDEX:
        common["collection_spec_sha256"] = _digest("w11-003-collection")
    elif scope is RecoveryScope.MODEL_REGISTRY:
        common["registry_export_sha256"] = _digest("w11-003-registry-export")
    else:
        common["state_lineage"] = "synthetic-lineage"
        common["state_serial"] = 12
    return RecoveryAssetIdentity.model_validate(common)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate")
    validate.add_argument("--config", type=Path, default=DEFAULT_RECOVERY_POLICY_PATH)
    rehearse = commands.add_parser("rehearse")
    rehearse.add_argument("--config", type=Path, default=DEFAULT_RECOVERY_POLICY_PATH)
    rehearse.add_argument(
        "--operation", choices=[item.value for item in RecoveryOperation], required=True
    )
    rehearse.add_argument("--scope", choices=[item.value for item in RecoveryScope], required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        policy = load_recovery_policy(args.config, repository_root=ROOT)
        if args.command == "validate":
            output = {
                "feature_ids": list(policy.feature_ids),
                "live_status": policy.live_execution_status,
                "multi_region_readiness": policy.multi_region_readiness,
                "policy_sha256": canonical_sha256(policy),
                "schema_version": policy.schema_version,
                "status": "VALID",
                "target_rpo_seconds": policy.objectives.target_rpo_seconds,
                "target_rto_seconds": policy.objectives.target_rto_seconds,
            }
            print(json.dumps(output, sort_keys=True, separators=(",", ":")))
            return 0
        if args.command != "rehearse" or args.operation is None or args.scope is None:
            raise ValueError("unsupported recovery command")
        clock = SystemClock()
        now = clock.now_utc()
        scope = RecoveryScope(args.scope)
        operation = RecoveryOperation(args.operation)
        source = _asset(scope, artifact="source", recovery_point_at=now - timedelta(hours=1))
        target = _asset(scope, artifact="candidate", recovery_point_at=now - timedelta(hours=1))
        plan = RecoveryPlan(
            operation_id="w11-003-local-rehearsal",
            operation=operation,
            scope=scope,
            source=source,
            expected_target=target,
            approval_reference_sha256=_digest("w11-003-source-only-approval"),
            policy_sha256=canonical_sha256(policy),
            requested_at=now,
            deadline_at=now + timedelta(seconds=30),
        )
        auth = AuthContext(
            subject_id="w11-003-owner",
            tenant_id="tenant-a",
            roles=frozenset({Role.ADMIN}),
            clearance=Classification.INTERNAL,
            expires_at=now + timedelta(minutes=5),
        )
        evidence = run_local_rehearsal(
            policy,
            plan,
            auth_context=auth,
            target=InMemoryRecoveryTarget(),
            verifier=InMemoryNativeVerifier(),
            clock=clock,
        )
        print(
            json.dumps(
                evidence.model_dump(mode="json"),
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0 if evidence.local_contract_status is RecoveryStatus.PASS else 3
    except (OSError, UnicodeError, ValueError, PermissionError):
        print("W11-003 validation failed", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
