"""Read-only W11-001 AI reliability policy and decision CLI."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, cast

ROOT = Path(__file__).resolve().parents[1]
SOURCE_PATH = (ROOT / "src").resolve()
if str(SOURCE_PATH) not in sys.path:
    sys.path.insert(0, str(SOURCE_PATH))

from enterprise_ai_platform.telemetry.ai_reliability import (  # noqa: E402
    DEFAULT_AI_RELIABILITY_POLICY_PATH,
    EvaluationBatch,
    evaluate_batch,
    load_ai_reliability_policy,
)

MAXIMUM_INPUT_BYTES = 1_048_576


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _reject_non_finite(value: str) -> None:
    raise ValueError(f"non-finite JSON value: {value}")


def _read_batch(path: Path) -> EvaluationBatch:
    if not path.is_file() or path.stat().st_size > MAXIMUM_INPUT_BYTES:
        raise ValueError("evidence input must be a bounded regular JSON file")
    payload = path.read_bytes()
    if not payload or payload.startswith((b"\xff\xfe", b"\xfe\xff")):
        raise ValueError("evidence input encoding is invalid")
    raw = json.loads(
        payload.decode("utf-8", errors="strict"),
        object_pairs_hook=_reject_duplicate_pairs,
        parse_constant=_reject_non_finite,
    )
    return EvaluationBatch.model_validate(cast(object, raw), strict=False)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    validate = subcommands.add_parser("validate")
    validate.add_argument("--config", type=Path, default=DEFAULT_AI_RELIABILITY_POLICY_PATH)
    evaluate = subcommands.add_parser("evaluate")
    evaluate.add_argument("--config", type=Path, default=DEFAULT_AI_RELIABILITY_POLICY_PATH)
    evaluate.add_argument("--input", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        policy = load_ai_reliability_policy(arguments.config)
        if arguments.command == "validate":
            print(
                json.dumps(
                    {
                        "classification": policy.classification,
                        "prompt_id": policy.prompt_id,
                        "schema_version": policy.schema_version,
                        "sli_count": len(policy.slis),
                        "status": "VALID",
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
            return 0
        if arguments.command != "evaluate":
            raise ValueError("unsupported command")
        evaluations, burn, decision = evaluate_batch(policy, _read_batch(arguments.input))
        print(
            json.dumps(
                {
                    "burn_evaluations": [item.model_dump(mode="json") for item in burn],
                    "decision": decision.model_dump(mode="json"),
                    "sli_evaluations": [item.model_dump(mode="json") for item in evaluations],
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0 if decision.release_allowed else 3
    except (OSError, UnicodeError, ValueError) as error:
        print(f"W11-001 validation failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
