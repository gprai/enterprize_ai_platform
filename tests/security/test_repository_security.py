"""Security checks for the non-mutating repository skeleton."""

from __future__ import annotations

import ast
import json
import re
import unittest
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
PLATFORMCTL_ROOT = REPOSITORY_ROOT / "tools" / "platformctl"


class RepositorySecurityTests(unittest.TestCase):
    def test_new_runtime_files_contain_no_plaintext_secret_patterns(self) -> None:
        runtime_files = [
            REPOSITORY_ROOT / "Makefile",
            REPOSITORY_ROOT / "feature-matrix.yaml",
            *PLATFORMCTL_ROOT.glob("*.py"),
        ]
        patterns = (
            re.compile(r"AKIA[0-9A-Z]{16}"),
            re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
            re.compile(r"https?://[^/\s]+:[^/@\s]+@"),
        )
        findings: list[str] = []
        for path in runtime_files:
            content = path.read_text(encoding="utf-8")
            for pattern in patterns:
                if pattern.search(content):
                    findings.append(f"{path.name}: {pattern.pattern}")
        self.assertEqual([], findings)

    def test_platformctl_limits_live_and_write_capability_to_approved_adapters(self) -> None:
        forbidden_imports = {
            "boto3",
            "http",
            "requests",
            "socket",
            "subprocess",
            "urllib",
        }
        forbidden_methods = {
            "chmod",
            "mkdir",
            "rename",
            "replace",
            "rmdir",
            "touch",
            "unlink",
            "write_bytes",
            "write_text",
        }
        approved_write_modules = {"lifecycle_io.py", "operation_state.py"}
        findings: list[str] = []

        for path in PLATFORMCTL_ROOT.glob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for imported in node.names:
                        if imported.name.split(".")[0] in forbidden_imports and not (
                            path.name == "process_runner.py" and imported.name == "subprocess"
                        ):
                            findings.append(f"{path.name}: import {imported.name}")
                elif isinstance(node, ast.ImportFrom) and node.module:
                    is_bounded_uri_decoding = (
                        path.name == "image_lifecycle.py" and node.module == "urllib.parse"
                    )
                    if (
                        node.module.split(".")[0] in forbidden_imports
                        and not is_bounded_uri_decoding
                    ):
                        findings.append(f"{path.name}: from {node.module}")
                elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    is_utc_isoformat_normalization = (
                        node.func.attr == "replace"
                        and isinstance(node.func.value, ast.Call)
                        and isinstance(node.func.value.func, ast.Attribute)
                        and node.func.value.func.attr == "isoformat"
                        and not node.keywords
                        and len(node.args) == 2
                        and all(isinstance(argument, ast.Constant) for argument in node.args)
                        and [argument.value for argument in node.args] == ["+00:00", "Z"]
                    )
                    is_datetime_precision_normalization = (
                        node.func.attr == "replace"
                        and not node.args
                        and len(node.keywords) == 1
                        and node.keywords[0].arg == "microsecond"
                        and isinstance(node.keywords[0].value, ast.Constant)
                        and node.keywords[0].value.value == 0
                    )
                    is_bounded_string_normalization = (
                        node.func.attr == "replace"
                        and path.name in {"kubernetes_lifecycle.py", "policy_runner.py"}
                        and not node.keywords
                        and len(node.args) == 2
                        and all(isinstance(argument, ast.Constant) for argument in node.args)
                    )
                    if (
                        node.func.attr in forbidden_methods
                        and path.name not in approved_write_modules
                        and not is_utc_isoformat_normalization
                        and not is_datetime_precision_normalization
                        and not is_bounded_string_normalization
                    ):
                        findings.append(f"{path.name}: call {node.func.attr}")

        self.assertEqual([], findings)

    def test_live_aws_and_process_boundaries_are_not_ambient(self) -> None:
        files = {
            path.name: path.read_text(encoding="utf-8") for path in PLATFORMCTL_ROOT.glob("*.py")
        }
        for name, source in files.items():
            if name != "aws_live.py":
                self.assertNotIn("get_caller_identity", source)
                self.assertNotIn("client_factory", source)
            if name != "terraform_runner.py":
                self.assertNotIn('"apply", "-input=false"', source)

    def test_feature_matrix_contains_no_secret_fields(self) -> None:
        matrix = json.loads((REPOSITORY_ROOT / "feature-matrix.yaml").read_text(encoding="utf-8"))
        forbidden_keys = {
            "api_key",
            "credential",
            "password",
            "private_key",
            "secret",
            "token",
        }
        findings: list[str] = []

        def inspect(value: object, location: str = "root") -> None:
            if isinstance(value, dict):
                for key, child in value.items():
                    if key.casefold() in forbidden_keys:
                        findings.append(f"{location}.{key}")
                    inspect(child, f"{location}.{key}")
            elif isinstance(value, list):
                for index, child in enumerate(value):
                    inspect(child, f"{location}[{index}]")

        inspect(matrix)
        self.assertEqual([], findings)


if __name__ == "__main__":
    unittest.main()
