from pathlib import Path

import yaml
from tools.w6_002_observability import EXPECTED_LOCAL_REHEARSALS

from enterprise_ai_platform.config import Settings
from enterprise_ai_platform.telemetry import (
    SafeTelemetryAttributes,
    TelemetryEventName,
    TelemetryOperation,
    TelemetryOutcome,
    TelemetryStage,
    build_exporting_telemetry,
)
from tests.fakes.observability import FailingExportSink

ROOT = Path(__file__).resolve().parents[2]


def test_exporter_failure_does_not_escape_business_flow(
    export_settings: Settings,
) -> None:
    composition = build_exporting_telemetry(
        settings=export_settings,
        sink=FailingExportSink(),
    )
    composition.runtime.emit_event(
        TelemetryEventName.STAGE_COMPLETED,
        SafeTelemetryAttributes(
            stage=TelemetryStage.API,
            operation=TelemetryOperation.REQUEST,
            outcome=TelemetryOutcome.SUCCESS,
        ),
    )

    assert composition.runtime.force_flush() is True
    assert any(
        record.event_name is TelemetryEventName.EXPORT_FAILURE
        for record in composition.local.log_sink.records()
    )
    assert composition.runtime.shutdown() is True


def test_all_approved_failures_are_fake_provider_rehearsals() -> None:
    plan = yaml.safe_load((ROOT / "configs/chaos/fis-plan.yaml").read_text(encoding="utf-8"))
    assert plan["local_rehearsals"]["execution"] == "fake-provider-only"
    assert set(plan["local_rehearsals"]["scenarios"]) == EXPECTED_LOCAL_REHEARSALS
    assert plan["execution_authority"] == "W6-004-owner-approval-required"
