"""Fixed local launcher for the owner-controlled W4-11 release rollback drill."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from pydantic import BaseModel

if __package__ in {None, ""}:
    repository_root = Path(__file__).resolve().parents[1]
    source_root = repository_root / "src"
    if str(source_root) not in sys.path:
        sys.path.insert(0, str(source_root))

from enterprise_ai_platform.release_rollback.errors import (  # noqa: E402
    ReleaseRollbackError,
)
from enterprise_ai_platform.release_rollback.service import (  # noqa: E402
    cleanup,
    rollback_release,
    smoke,
    validate,
    verify_clean,
    verify_zero_residue,
)

_COMMANDS = (
    "validate",
    "rollback-release",
    "smoke",
    "verify-clean",
    "cleanup",
    "verify-zero-residue",
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run one owner-controlled local W4-11 release step"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in _COMMANDS:
        subparser = subparsers.add_parser(command)
        if command == "cleanup":
            subparser.add_argument(
                "--owner-output-captured",
                action="store_true",
                help="Confirm the owner captured complete local output",
            )
    return parser


def _payload(value: BaseModel) -> dict[str, object]:
    return value.model_dump(mode="json")


def _dispatch(arguments: argparse.Namespace) -> dict[str, object]:
    command = arguments.command
    if command == "validate":
        return _payload(validate())
    if command == "rollback-release":
        return _payload(asyncio.run(rollback_release()))
    if command == "smoke":
        return _payload(asyncio.run(smoke()))
    if command == "verify-clean":
        return _payload(verify_clean())
    if command == "cleanup":
        return _payload(
            cleanup(owner_output_captured=arguments.owner_output_captured)
        )
    if command == "verify-zero-residue":
        return _payload(verify_zero_residue())
    raise TypeError


def main(argv: Sequence[str] | None = None) -> int:
    try:
        result = _dispatch(build_parser().parse_args(argv))
    except ReleaseRollbackError as exc:
        result = {"status": "ERROR", "error_code": exc.code}
        exit_code = 1
    except (KeyboardInterrupt, asyncio.CancelledError):
        result = {"status": "ERROR", "error_code": "release_rollback_error"}
        exit_code = 1
    except Exception:
        result = {"status": "ERROR", "error_code": "release_rollback_error"}
        exit_code = 1
    else:
        exit_code = 0
    print(json.dumps(result, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
