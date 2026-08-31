"""Fixed local launcher for the owner-controlled W3-004 rollback drill."""

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

from enterprise_ai_platform.rag_rollback.errors import RAGRollbackError  # noqa: E402
from enterprise_ai_platform.rag_rollback.service import (  # noqa: E402
    activate_regression,
    cleanup,
    evaluate_regression,
    evaluate_restored,
    finalize,
    initialize,
    rollback,
    validate,
    verify_clean,
    verify_zero_residue,
)

_COMMANDS = (
    "validate",
    "initialize",
    "activate-regression",
    "evaluate-regression",
    "rollback",
    "evaluate-restored",
    "finalize",
    "verify-clean",
    "cleanup",
    "verify-zero-residue",
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run one owner-controlled local W3-004 rollback step"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in _COMMANDS:
        subparser = subparsers.add_parser(command)
        if command == "cleanup":
            subparser.add_argument(
                "--external-archive-verified",
                action="store_true",
                help="Confirm owner-controlled external archival succeeded",
            )
    return parser


def _payload(value: BaseModel) -> dict[str, object]:
    return value.model_dump(mode="json")


def _dispatch(arguments: argparse.Namespace) -> dict[str, object]:
    command = arguments.command
    if command == "validate":
        return _payload(validate())
    if command == "initialize":
        return _payload(initialize())
    if command == "activate-regression":
        return _payload(activate_regression())
    if command == "evaluate-regression":
        return _payload(asyncio.run(evaluate_regression()))
    if command == "rollback":
        return _payload(rollback())
    if command == "evaluate-restored":
        return _payload(asyncio.run(evaluate_restored()))
    if command == "finalize":
        return _payload(finalize())
    if command == "verify-clean":
        return _payload(verify_clean())
    if command == "cleanup":
        return _payload(cleanup(external_archive_verified=arguments.external_archive_verified))
    if command == "verify-zero-residue":
        return _payload(verify_zero_residue())
    raise TypeError


def main(argv: Sequence[str] | None = None) -> int:
    try:
        result = _dispatch(build_parser().parse_args(argv))
    except RAGRollbackError as exc:
        result = {"status": "ERROR", "error_code": exc.code}
        exit_code = 1
    except KeyboardInterrupt:
        result = {"status": "ERROR", "error_code": "rag_rollback_error"}
        exit_code = 1
    except Exception:
        result = {"status": "ERROR", "error_code": "rag_rollback_error"}
        exit_code = 1
    else:
        exit_code = 0
    print(json.dumps(result, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
