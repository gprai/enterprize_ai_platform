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

    def test_platformctl_has_no_network_process_or_write_capability(self) -> None:
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
        findings: list[str] = []

        for path in PLATFORMCTL_ROOT.glob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for imported in node.names:
                        if imported.name.split(".")[0] in forbidden_imports:
                            findings.append(f"{path.name}: import {imported.name}")
                elif isinstance(node, ast.ImportFrom) and node.module:
                    if node.module.split(".")[0] in forbidden_imports:
                        findings.append(f"{path.name}: from {node.module}")
                elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    if node.func.attr in forbidden_methods:
                        findings.append(f"{path.name}: call {node.func.attr}")

        self.assertEqual([], findings)

    def test_feature_matrix_contains_no_secret_fields(self) -> None:
        matrix = json.loads(
            (REPOSITORY_ROOT / "feature-matrix.yaml").read_text(encoding="utf-8")
        )
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
