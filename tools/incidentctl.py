"""Owner-operated CLI for W11-004 local incident rehearsals."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE_PATH = (ROOT / "src").resolve()
if str(SOURCE_PATH) not in sys.path:
    sys.path.insert(0, str(SOURCE_PATH))

from enterprise_ai_platform.incident_operations import (  # noqa: E402
    DEFAULT_INCIDENT_POLICY_PATH,
    IncidentContractError,
    RunnerProfileId,
    ScenarioId,
    build_offline_game_day_evidence,
    canonical_json_bytes,
    canonical_sha256,
    evidence_from_json,
    load_incident_policy,
    parse_runner_profile,
    parse_scenario,
)

RUNTIME_RESIDUE_NAMES = frozenset({"runtime-state.json", "command.lock", "child.pid"})


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate or rehearse W11-004 incident operations")
    subcommands = parser.add_subparsers(dest="command", required=True)

    validate = subcommands.add_parser("validate", help="validate the incident policy")
    validate.add_argument("--config", type=Path, default=DEFAULT_INCIDENT_POLICY_PATH)

    rehearse = subcommands.add_parser("rehearse", help="write one local/fake game-day evidence set")
    rehearse.add_argument("--config", type=Path, default=DEFAULT_INCIDENT_POLICY_PATH)
    rehearse.add_argument("--scenario", choices=[item.value for item in ScenarioId], required=True)
    rehearse.add_argument(
        "--runner-profile", choices=[item.value for item in RunnerProfileId], required=True
    )
    rehearse.add_argument("--required-terminal-action", choices=["ROLLBACK", "RECOVERY"])
    rehearse.add_argument("--evidence-root", type=Path, required=True)
    rehearse.add_argument("--approval-reference", required=True)

    resume = subcommands.add_parser("resume", help="rejoin completed evidence without rerun")
    resume.add_argument("--config", type=Path, default=DEFAULT_INCIDENT_POLICY_PATH)
    resume.add_argument("--scenario", choices=[item.value for item in ScenarioId], required=True)
    resume.add_argument(
        "--runner-profile", choices=[item.value for item in RunnerProfileId], required=True
    )
    resume.add_argument("--evidence-root", type=Path, required=True)

    cleanup = subcommands.add_parser("cleanup", help="remove only known runtime residue")
    cleanup.add_argument("--config", type=Path, default=DEFAULT_INCIDENT_POLICY_PATH)
    cleanup.add_argument("--evidence-root", type=Path, required=True)
    cleanup.add_argument("--retain-evidence", action="store_true", required=True)

    verify = subcommands.add_parser("verify-clean", help="verify residue and retained evidence")
    verify.add_argument("--config", type=Path, default=DEFAULT_INCIDENT_POLICY_PATH)
    verify.add_argument("--evidence-root", type=Path, required=True)
    return parser


def _external_path(path: Path, *, must_exist: bool) -> Path:
    if not path.is_absolute():
        raise IncidentContractError("evidence root must be absolute")
    for candidate in (path, *path.parents):
        if candidate.exists() and candidate.is_symlink():
            raise IncidentContractError("evidence root may not traverse a symbolic link")
    resolved = path.resolve(strict=must_exist)
    repository = ROOT.resolve(strict=True)
    if resolved == repository or resolved.is_relative_to(repository):
        raise IncidentContractError("evidence root must be outside the repository")
    cursor = resolved if resolved.exists() else resolved.parent
    while not cursor.exists() and cursor != cursor.parent:
        cursor = cursor.parent
    if cursor.is_symlink():
        raise IncidentContractError("evidence root may not traverse a symbolic link")
    return resolved


def _write_exclusive(path: Path, payload: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _validate(args: argparse.Namespace) -> int:
    policy = load_incident_policy(args.config, repository_root=ROOT)
    print(
        json.dumps(
            {
                "feature_ids": list(policy.feature_ids),
                "policy_sha256": canonical_sha256(policy),
                "runner_profiles": [item.profile_id for item in policy.runner_profiles],
                "scenarios": [item.scenario_id for item in policy.scenarios],
                "schema_version": policy.schema_version,
                "status": "VALID",
                "tracker_status": policy.tracker_status,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


def _rehearse(args: argparse.Namespace) -> int:
    policy = load_incident_policy(args.config, repository_root=ROOT)
    scenario = parse_scenario(args.scenario)
    runner_profile = parse_runner_profile(args.runner_profile)
    scenario_policy = next(item for item in policy.scenarios if item.scenario_id is scenario)
    if (
        args.required_terminal_action is not None
        and scenario_policy.required_terminal_action.value != args.required_terminal_action
    ):
        raise IncidentContractError("required terminal action differs from the incident policy")
    root = _external_path(args.evidence_root, must_exist=False)
    if root.exists():
        raise IncidentContractError(
            "evidence root already exists; resume may not overwrite evidence"
        )
    root.mkdir(parents=True, mode=0o700)
    run_id = f"w11-004-{scenario.value.casefold()}-{runner_profile.value.replace('.', '-')}"
    evidence = build_offline_game_day_evidence(
        policy,
        scenario_id=scenario,
        runner_profile=runner_profile,
        run_id=run_id,
        approval_reference=args.approval_reference,
    )
    evidence_path = root / "evidence.json"
    journal_path = root / "journal.jsonl"
    _write_exclusive(evidence_path, canonical_json_bytes(evidence))
    journal_entry = {
        "event": "EVIDENCE_RETAINED",
        "evidence_sha256": canonical_sha256(evidence),
        "recorded_at": datetime.now(UTC).isoformat(),
        "run_id": evidence.run_id,
        "status": evidence.status,
    }
    _write_exclusive(journal_path, canonical_json_bytes(journal_entry))
    print(
        json.dumps(
            {
                "evidence_path": str(evidence_path),
                "evidence_sha256": canonical_sha256(evidence),
                "network": "NOT USED",
                "scope": evidence.scope,
                "status": evidence.status,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0 if evidence.status.value == "PASS" else 1


def _cleanup(args: argparse.Namespace) -> int:
    load_incident_policy(args.config, repository_root=ROOT)
    root = _external_path(args.evidence_root, must_exist=True)
    evidence_paths = sorted(root.rglob("evidence.json"))
    if not evidence_paths:
        raise IncidentContractError("cleanup requires retained W11-004 evidence")
    for evidence_path in evidence_paths:
        evidence_from_json(evidence_path.read_bytes())
    removed: list[str] = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.name in RUNTIME_RESIDUE_NAMES:
            path.unlink()
            removed.append(str(path.relative_to(root)))
    print(
        json.dumps(
            {"evidence_retained": True, "removed_runtime_residue": removed, "status": "CLEANED"},
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


def _resume(args: argparse.Namespace) -> int:
    policy = load_incident_policy(args.config, repository_root=ROOT)
    root = _external_path(args.evidence_root, must_exist=True)
    evidence_path = root / "evidence.json"
    if not evidence_path.is_file():
        raise IncidentContractError("resume requires one completed evidence identity")
    evidence = evidence_from_json(evidence_path.read_bytes())
    if evidence.policy_sha256 != canonical_sha256(policy):
        raise IncidentContractError("resume policy identity differs")
    if evidence.scenario_id is not parse_scenario(args.scenario):
        raise IncidentContractError("resume scenario identity differs")
    if evidence.runner_profile is not parse_runner_profile(args.runner_profile):
        raise IncidentContractError("resume runner identity differs")
    print(
        json.dumps(
            {
                "evidence_sha256": canonical_sha256(evidence),
                "reexecuted_commands": 0,
                "run_id": evidence.run_id,
                "status": "REJOINED_COMPLETED",
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


def _verify_clean(args: argparse.Namespace) -> int:
    load_incident_policy(args.config, repository_root=ROOT)
    root = _external_path(args.evidence_root, must_exist=True)
    residue = sorted(
        str(path.relative_to(root))
        for path in root.rglob("*")
        if path.is_file() and path.name in RUNTIME_RESIDUE_NAMES
    )
    evidence_paths = sorted(root.rglob("evidence.json"))
    for path in evidence_paths:
        evidence_from_json(path.read_bytes())
    status = "CLEAN" if not residue and evidence_paths else "INDETERMINATE"
    print(
        json.dumps(
            {
                "evidence_count": len(evidence_paths),
                "evidence_retained": bool(evidence_paths),
                "residue": residue,
                "status": status,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0 if status == "CLEAN" else 1


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "validate":
            return _validate(args)
        if args.command == "rehearse":
            return _rehearse(args)
        if args.command == "resume":
            return _resume(args)
        if args.command == "cleanup":
            return _cleanup(args)
        if args.command == "verify-clean":
            return _verify_clean(args)
        parser.error("unknown command")
    except (IncidentContractError, OSError) as error:
        print(f"incidentctl: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
