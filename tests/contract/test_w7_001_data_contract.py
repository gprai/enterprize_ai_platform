"""Contract coverage for W7-001 event, catalog, and strict schema boundaries."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from enterprise_ai_platform.ingestion.governance import (
    CatalogColumn,
    CatalogContract,
    GovernanceContractError,
    load_ingestion_event_json,
)
from tests.fakes.w7_001_data_foundation import make_event


def test_event_contract_rejects_unknown_fields_and_unsupported_classification() -> None:
    event = make_event()
    payload = event.model_dump(mode="python")
    payload["unexpected"] = True
    with pytest.raises(ValidationError):
        type(event).model_validate(payload)
    payload.pop("unexpected")
    payload["governance"]["classification"] = "CONFIDENTIAL"
    with pytest.raises(ValidationError):
        type(event).model_validate(payload)


def test_catalog_contract_preserves_ordered_unique_columns() -> None:
    with pytest.raises(ValidationError):
        CatalogContract(
            database_name="enterprise_ai",
            table_name="processed_documents",
            columns=(
                CatalogColumn(name="tenant_id", type="string", nullable=False),
                CatalogColumn(name="tenant_id", type="string", nullable=False),
            ),
            partition_keys=("tenant_id",),
            schema_version="w7-001.catalog.v1",
            location_prefix="processed/",
        )


def test_duplicate_event_json_keys_are_rejected() -> None:
    with pytest.raises(GovernanceContractError):
        load_ingestion_event_json('{"schema_version":"one","schema_version":"two"}')
