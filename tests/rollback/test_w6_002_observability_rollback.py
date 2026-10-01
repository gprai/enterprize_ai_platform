from enterprise_ai_platform.config import Settings
from enterprise_ai_platform.telemetry import NullTelemetryRuntime, telemetry_for_application


def test_default_rollback_profile_has_no_exporter_or_worker(
    valid_settings: Settings,
) -> None:
    assert valid_settings.telemetry_exporter == "none"
    assert valid_settings.telemetry_otlp_endpoint is None
    assert valid_settings.telemetry_queue_capacity == 0
    assert valid_settings.telemetry_background_workers == 0
    assert isinstance(
        telemetry_for_application(enabled=False, injected=None),
        NullTelemetryRuntime,
    )
