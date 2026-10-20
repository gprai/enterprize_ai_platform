from __future__ import annotations

from pathlib import Path

import pytest
from tools.platformctl.contracts import ContractError
from tools.platformctl.process_runner import (
    PowerShellHost,
    PowerShellHostProfile,
    build_powershell_process_request,
)

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "tools/powershell/incident-command-runner-v1.psm1"
WINDOWS_WRAPPER = ROOT / "tools/powershell/invoke-incident-command-windows-powershell-5.1-v1.ps1"
PS7_WRAPPER = ROOT / "tools/powershell/invoke-incident-command-powershell-7-v1.ps1"


def test_versioned_runners_share_one_module_and_exact_request_array() -> None:
    module = MODULE.read_text(encoding="utf-8")
    assert "Invoke-IncidentCommandV1" in module
    assert "Resolve-IncidentNotFoundV1" in module
    assert "Invoke-Expression" not in module
    for wrapper in (WINDOWS_WRAPPER, PS7_WRAPPER):
        text = wrapper.read_text(encoding="utf-8")
        assert "incident-command-runner-v1.psm1" in text
        assert "@($request.command)" in text
        assert "Invoke-Expression" not in text


def test_process_request_builds_fixed_host_argv(tmp_path: Path) -> None:
    executable = tmp_path / "pwsh.exe"
    executable.write_bytes(b"host")
    wrapper = tmp_path / PS7_WRAPPER.name
    wrapper.write_text("# wrapper\n", encoding="utf-8")
    request_file = tmp_path / "request.json"
    request_file.write_text("{}\n", encoding="utf-8")
    profile = PowerShellHostProfile(
        PowerShellHost.POWERSHELL_7,
        executable.resolve(),
        wrapper.resolve(),
        "a" * 64,
        "7.6.5",
    )
    request = build_powershell_process_request(
        profile,
        request_path=request_file.resolve(),
        cwd=tmp_path.resolve(),
        environment={"PATH": str(tmp_path)},
        timeout_seconds=30,
    )
    assert request.argv == (
        str(executable.resolve()),
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(wrapper.resolve()),
        "-RequestPath",
        str(request_file.resolve()),
    )


def test_profile_rejects_cross_host_wrapper(tmp_path: Path) -> None:
    executable = tmp_path / "powershell.exe"
    executable.write_bytes(b"host")
    wrapper = tmp_path / PS7_WRAPPER.name
    wrapper.write_text("# wrapper\n", encoding="utf-8")
    profile = PowerShellHostProfile(
        PowerShellHost.WINDOWS_POWERSHELL_5_1,
        executable.resolve(),
        wrapper.resolve(),
        "a" * 64,
        "5.1",
    )
    with pytest.raises(ContractError, match="PROFILE_MISMATCH"):
        profile.validate()


def test_profile_rejects_wrong_host_version(tmp_path: Path) -> None:
    executable = tmp_path / "pwsh.exe"
    executable.write_bytes(b"host")
    wrapper = tmp_path / PS7_WRAPPER.name
    wrapper.write_text("# wrapper\n", encoding="utf-8")
    profile = PowerShellHostProfile(
        PowerShellHost.POWERSHELL_7,
        executable.resolve(),
        wrapper.resolve(),
        "a" * 64,
        "5.1",
    )
    with pytest.raises(ContractError, match="HOST_IDENTITY_MISMATCH"):
        profile.validate()
