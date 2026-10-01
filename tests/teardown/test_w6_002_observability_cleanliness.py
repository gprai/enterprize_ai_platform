import threading

from enterprise_ai_platform.config import Settings
from enterprise_ai_platform.telemetry import build_exporting_telemetry
from tests.fakes.observability import RecordingExportSink


def test_export_worker_terminates_without_residue(export_settings: Settings) -> None:
    composition = build_exporting_telemetry(
        settings=export_settings,
        sink=RecordingExportSink(),
    )
    assert composition.runtime.shutdown() is True
    assert not any(
        thread.name == "w6-002-telemetry-export" and thread.is_alive()
        for thread in threading.enumerate()
    )
