from enterprise_ai_platform.app import create_app
from enterprise_ai_platform.config import Settings
from enterprise_ai_platform.telemetry import (
    SafeTelemetryAttributes,
    TelemetryEventName,
    TelemetryOperation,
    TelemetryOutcome,
    TelemetryStage,
    build_exporting_telemetry,
)
from tests.fakes.observability import RecordingExportSink


def test_injected_export_composition_is_bounded_and_network_free(
    export_settings: Settings,
) -> None:
    sink = RecordingExportSink()
    composition = build_exporting_telemetry(settings=export_settings, sink=sink)
    create_app(export_settings, telemetry_runtime=composition.runtime)
    composition.runtime.emit_event(
        TelemetryEventName.STAGE_COMPLETED,
        SafeTelemetryAttributes(
            stage=TelemetryStage.TELEMETRY,
            operation=TelemetryOperation.EXPORT,
            outcome=TelemetryOutcome.SUCCESS,
        ),
    )

    assert composition.runtime.force_flush() is True
    assert sum(len(batch) for batch in sink.batches) == 1
    assert sink.timeouts == [1.0]
    assert composition.runtime.shutdown() is True
    assert sink.shutdown_calls == 1
