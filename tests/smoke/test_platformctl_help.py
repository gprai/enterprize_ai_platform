"""Smoke tests for the local platformctl entry point."""

from __future__ import annotations

import io
import unittest
from contextlib import redirect_stdout

from tools.platformctl.cli import build_parser, main


class PlatformCtlSmokeTests(unittest.TestCase):
    def test_request_options_do_not_enable_execution_by_default(self) -> None:
        arguments = build_parser().parse_args(
            [
                "platform-plan",
                "--environment",
                "sandbox",
                "--target",
                "platform",
            ]
        )
        self.assertFalse(arguments.execute)
        self.assertIsNone(arguments.request_file)
        self.assertIsNone(arguments.request_sha256)

    def test_help_is_available(self) -> None:
        help_text = build_parser().format_help()
        self.assertIn("--version", help_text)
        for command in (
            "validate",
            "bootstrap-plan",
            "bootstrap-apply",
            "platform-plan",
            "policy-review",
            "cost-review",
            "platform-apply",
            "aws-verify",
            "infrastructure-rollback",
            "destroy-plan",
            "purge-sandbox",
            "platform-destroy",
            "bootstrap-destroy",
            "verify-clean",
        ):
            self.assertIn(command, help_text)
        self.assertNotIn("--execute", help_text)

    def test_validate_completes_read_only_contract(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            return_code = main(["validate"])
        self.assertEqual(0, return_code, output.getvalue())
        self.assertIn("CODE-STAGE VALIDATION PASS", output.getvalue())


if __name__ == "__main__":
    unittest.main()
