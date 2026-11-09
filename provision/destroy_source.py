"""Explicit, reviewable Terraform overrides for separately authorized bootstrap teardown.

This prepares source only. The owner must commit/review/merge the generated files;
the ordinary HCP VCS configuration/run path remains the sole Terraform executor.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from provision.services import ServiceError, command

DIRECTORIES = ("infra/bootstrap", "infra/bootstrap/modules/platform-iam")
FILENAME = "zz_authorized_destroy_override.tf.json"


def expected(root: Path) -> dict[Path, str]:
    result = {}
    for directory in DIRECTORIES:
        resources: dict[str, dict[str, object]] = {}
        for path in sorted((root / directory).glob("*.tf")):
            for kind, name, body in re.findall(
                r'^resource\s+"([^"\n]+)"\s+"([^"\n]+)"\s*\{(.*?)^}',
                path.read_text(encoding="utf-8"),
                re.MULTILINE | re.DOTALL,
            ):
                if re.search(r"\bprevent_destroy\s*=\s*true\b", body):
                    if not kind.startswith("aws_iam_"):
                        raise ServiceError("DESTROY_SOURCE_UNEXPECTED_PROTECTED_RESOURCE")
                    resources.setdefault(kind, {})[name] = {"lifecycle": {"prevent_destroy": False}}
        if not resources:
            raise ServiceError("DESTROY_SOURCE_PROTECTED_INVENTORY_MISSING")
        result[root / directory / FILENAME] = (
            json.dumps({"resource": resources}, indent=2, sort_keys=True) + "\n"
        )
    return result


def assert_mode(root: Path, operation: str) -> None:
    paths = [root / directory / FILENAME for directory in DIRECTORIES]
    if operation != "bootstrap-teardown":
        if any(path.exists() for path in paths):
            raise ServiceError("DESTROY_OVERRIDE_SOURCE_CANNOT_DEPLOY")
        return
    for path, content in expected(root).items():
        if not path.is_file() or path.read_text(encoding="utf-8") != content:
            raise ServiceError("REVIEWED_BOOTSTRAP_DESTROY_OVERRIDES_REQUIRED")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--restore-protection", action="store_true")
    args = parser.parse_args()
    root = Path.cwd().resolve()
    if root != Path(r"E:\AI\enterprise_ai_platform").resolve():
        raise ServiceError("MAIN_TRACKED_CHECKOUT_REQUIRED")
    if Path(command(["git", "rev-parse", "--show-toplevel"], root)).resolve() != root:
        raise ServiceError("MAIN_TRACKED_CHECKOUT_REQUIRED")
    content = expected(root)
    # Never overwrite/delete an unrelated pre-existing override.
    for path, text in content.items():
        if path.exists() and path.read_text(encoding="utf-8") != text:
            raise ServiceError("DESTROY_OVERRIDE_ALREADY_EXISTS_DIFFERENT_BYTES")
    action = (
        "RESTORE BOOTSTRAP PROTECTION"
        if args.restore_protection
        else "PREPARE BOOTSTRAP DESTRUCTION SOURCE"
    )
    if input(f"Type {action}: ").strip() != action:
        raise ServiceError("OWNER_SOURCE_PREPARATION_NOT_APPROVED")
    for path, text in content.items():
        if args.restore_protection:
            path.unlink(missing_ok=True)
        else:
            path.write_text(text, encoding="utf-8", newline="\n")
    print(
        json.dumps(
            {
                "Result": "SOURCE_PREPARED_REVIEW_AND_MERGE_REQUIRED",
                "Files": [str(p) for p in content],
                "CloudMutation": False,
                "TerraformExecuted": False,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
