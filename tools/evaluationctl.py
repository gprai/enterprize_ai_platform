"""Repository-local command bootstrap for W3-002 evaluation operations."""

from __future__ import annotations

import json
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

_COMMANDS = frozenset({"candidate", "promotion"})
_BOOTSTRAP_ERROR = {"error_code": "evaluation_bootstrap_error", "status": "ERROR"}


def _fail_closed() -> int:
    print(json.dumps(_BOOTSTRAP_ERROR, sort_keys=True))
    return 1


def _prepare_source_path() -> bool:
    repository_root = Path(__file__).resolve().parents[1]
    source_path = (repository_root / "src").resolve()
    package_path = (source_path / "enterprise_ai_platform").resolve()
    if (
        source_path.parent != repository_root
        or package_path.parent != source_path
        or not source_path.is_dir()
        or not package_path.is_dir()
        or not (package_path / "__init__.py").is_file()
    ):
        return False
    source = str(source_path)
    if source not in sys.path:
        sys.path.insert(0, source)
    return True


def _entry_point(command: str) -> Callable[[Sequence[str] | None], int] | None:
    try:
        if command == "candidate":
            from enterprise_ai_platform.evaluation.runner import main

            return main
        if command == "promotion":
            from enterprise_ai_platform.evaluation.promotion import main

            return main
    except ImportError:
        return None
    return None


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if not arguments or arguments[0] not in _COMMANDS or not _prepare_source_path():
        return _fail_closed()
    entry_point = _entry_point(arguments[0])
    if entry_point is None:
        return _fail_closed()
    return entry_point(arguments[1:])


if __name__ == "__main__":
    raise SystemExit(main())
