"""Cross-shell assumptions remain data contracts, not shell execution."""

from __future__ import annotations

import codecs
from pathlib import Path

from tools.platformctl.process_runner import ProcessRequest, decode_utf8_output


def test_windows_paths_and_immutable_argv_do_not_require_shell_quoting(tmp_path: Path) -> None:
    executable = tmp_path / "Program Files" / "tool.exe"
    executable.parent.mkdir()
    executable.write_bytes(b"offline fixture")
    request = ProcessRequest(
        argv=(str(executable.resolve()), "-NoProfile", "-File", "script with spaces.ps1"),
        cwd=tmp_path.resolve(),
        environment=(("SYSTEMROOT", r"C:\Windows"),),
        timeout_seconds=30,
        executable_sha256="a" * 64,
        executable_version="PowerShell-5.1-or-7",
    )
    request.validate()
    assert isinstance(request.argv, tuple)
    assert request.argv[3] == "script with spaces.ps1"


def test_powershell_utf8_bom_and_utf8_no_bom_decode_identically() -> None:
    text = "PowerShell 5.1 and PowerShell 7"
    assert decode_utf8_output(codecs.BOM_UTF8 + text.encode("utf-8")) == text
    assert decode_utf8_output(text.encode("utf-8")) == text
