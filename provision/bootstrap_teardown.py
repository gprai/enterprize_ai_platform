"""Separate, owner-approved HCP bootstrap destruction entry point."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path

from tools.capstone_release import ReleaseError

from provision.lifecycle import (
    DEFAULT_CONTEXT_ROOT,
    ContextStore,
    LifecycleError,
    _report,
    _teardown,
)
from provision.services import ServiceError


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Separately authorized HCP bootstrap teardown")
    parser.add_argument("--context-root", type=Path, default=DEFAULT_CONTEXT_ROOT)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--plan-only", action="store_true")
    parser.add_argument("--new-attempt", action="store_true")
    args = parser.parse_args(argv)
    try:
        result = _teardown(args, ContextStore(args.context_root), bootstrap=True)
        code = 0
    except (LifecycleError, ServiceError, ReleaseError) as exc:
        result = {
            "Result": "BOOTSTRAP_TEARDOWN_STOPPED",
            "ErrorCode": exc.code,
            "Classification": exc.classification,
        }
        code = 2
    except Exception:
        result = {
            "Result": "BOOTSTRAP_TEARDOWN_STOPPED",
            "ErrorCode": "SERVICE_OR_CONTRACT_FAILURE",
            "Classification": "INDETERMINATE",
        }
        code = 3
    report = _report("bootstrap-teardown", result, args.run_id)
    print(json.dumps({**result, "Report": str(report)}, indent=2))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
