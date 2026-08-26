"""Owner-run strict validation command for the W3-002 golden dataset."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from enterprise_ai_platform.evaluation.dataset import load_golden_dataset  # noqa: E402
from enterprise_ai_platform.evaluation.errors import EvaluationError  # noqa: E402


def main(arguments: list[str] | None = None) -> int:
    values = sys.argv[1:] if arguments is None else arguments
    if len(values) != 1:
        print(json.dumps({"status": "ERROR", "error_code": "invalid_dataset"}))
        return 2
    try:
        dataset = load_golden_dataset(Path(values[0]))
    except EvaluationError as exc:
        print(json.dumps({"status": "ERROR", "error_code": exc.code}))
        return 1
    except Exception:
        print(json.dumps({"status": "ERROR", "error_code": "evaluation_error"}))
        return 1
    print(
        json.dumps(
            {
                "status": "PASS",
                "dataset_version": dataset.version,
                "case_count": len(dataset.cases),
                "checksum_sha256": dataset.checksum_sha256,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
