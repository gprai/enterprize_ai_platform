"""Offline W11-002 policy validation and one-scenario synthetic rehearsal."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE_PATH = (ROOT / "src").resolve()
if str(SOURCE_PATH) not in sys.path:
    sys.path.insert(0, str(SOURCE_PATH))

from enterprise_ai_platform.chaos import (  # noqa: E402
    DEFAULT_CHAOS_POLICY_PATH,
    InMemoryFaultTarget,
    SystemClock,
    load_chaos_policy,
    policy_sha256,
    run_local_rehearsal,
    synthetic_observer,
)
from enterprise_ai_platform.telemetry.ai_reliability import DecisionStatus  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    validate = subcommands.add_parser("validate")
    validate.add_argument("--config", type=Path, default=DEFAULT_CHAOS_POLICY_PATH)
    rehearse = subcommands.add_parser("rehearse")
    rehearse.add_argument("--config", type=Path, default=DEFAULT_CHAOS_POLICY_PATH)
    rehearse.add_argument("--scenario", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        policy = load_chaos_policy(args.config, repository_root=ROOT)
        if args.command == "validate":
            output = {
                "classification": policy.classification,
                "live_status": policy.live_execution_status,
                "policy_sha256": policy_sha256(policy),
                "scenario_count": len(policy.scenarios),
                "schema_version": policy.schema_version,
                "status": "VALID",
            }
            print(json.dumps(output, sort_keys=True, separators=(",", ":")))
            return 0
        if args.command != "rehearse":
            raise ValueError("unsupported command")
        clock = SystemClock()
        result = run_local_rehearsal(
            policy,
            args.scenario,
            fault=InMemoryFaultTarget(),
            observer=synthetic_observer(policy, args.scenario, observed_at=clock.now_utc()),
            clock=clock,
        )
        print(json.dumps(result.model_dump(mode="json"), sort_keys=True, separators=(",", ":")))
        return (
            0
            if result.local_control_status is DecisionStatus.PASS
            and result.residue_status is DecisionStatus.PASS
            else 3
        )
    except (OSError, UnicodeError, ValueError):
        print("W11-002 validation failed", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
